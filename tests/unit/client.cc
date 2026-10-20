#include <gtest/gtest.h>
#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <span>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

#include "blook/drv/wire.hpp"
#include "policy/hook.hpp"

// Only the transport boundary is faked: the fallback transport of
// detail::connection (the host has no driver and no VM), and the session is
// adopted from that fake connection instead of being attached to a real
// kchannel region. Every handle the tests own is a real, harmless event object.
#include "blook/drv/ept.hpp"

namespace fake {
inline bool fail_call{};
inline bool short_response{};
inline bool wrong_header{};
inline unsigned calls{};
inline wire::WatchRequest last_watch{};
inline wire::QueryPageRequest last_page{};
inline wire::QueryPageResponse page_response{};
inline wire::ConfigurationRequest last_configuration{};
inline wire::FeaturesRequest last_features{};
// What the fake driver hands out as a finished dump.
inline std::array<std::uint8_t, 8> dump_bytes{0x30, 0x31, 0x32, 0x33,
                                              0x34, 0x35, 0x36, 0x37};

// Returns a blook-kchannel status: 0 is KC_OK.
inline int call(void*, uint16_t code, const void* input, uint32_t input_size,
                void* output, uint32_t size, uint32_t* returned) {
    if (returned)
        *returned = size;
    ++calls;
    if (fail_call)
        return 7;  // KC_ERR_TIMEOUT ("driver not responding")
    if (code == wire::opcode(wire::op::query) &&
        size == sizeof(wire::QueryResponse)) {
        const wire::QueryResponse info{
            .version = 3, .running = 1, .abi = wire::abi_version};
        std::memcpy(output, &info, sizeof(info));
    }
    if (code == wire::opcode(wire::op::configuration) && input &&
        size == sizeof(wire::ConfigurationResponse)) {
        last_configuration =
            *static_cast<const wire::ConfigurationRequest*>(input);
        wire::ConfigurationResponse response{};
        response.header = {wire::abi_version, sizeof(response)};
        response.generation = 123;
        response.features = 7;
        response.restart_required = 1;
        std::memcpy(output, &response, sizeof(response));
    }
    if (code == wire::opcode(wire::op::features) && input &&
        size == sizeof(wire::FeaturesResponse)) {
        last_features = *static_cast<const wire::FeaturesRequest*>(input);
        wire::FeaturesResponse response{};
        response.header = {wire::abi_version, sizeof(response)};
        response.desired = 7;
        response.effective = 3;
        response.unsupported = 4;
        std::memcpy(output, &response, sizeof(response));
    }
    if (code == wire::opcode(wire::op::query_page) && input &&
        size == sizeof(wire::QueryPageResponse)) {
        last_page = *static_cast<const wire::QueryPageRequest*>(input);
        // The response is handed over verbatim: the test controls the header
        // so malformed replies are actually exercised.
        auto response = page_response;
        std::memcpy(output, &response, sizeof(response));
    }
    if (code == wire::opcode(wire::op::install) && input &&
        size == sizeof(wire::InstallResponse)) {
        const wire::InstallResponse made{.id = 0xabc};
        std::memcpy(output, &made, sizeof(made));
    }
    if ((code == wire::opcode(wire::op::remove) ||
         code == wire::opcode(wire::op::refresh)) &&
        input) {
        last_watch.id = static_cast<const wire::HookRequest*>(input)->id;
    }
    if (code == wire::opcode(wire::op::hide) && input)
        last_page.pid = static_cast<const wire::HideRequest*>(input)->pid;
    if (code == wire::opcode(wire::op::watch) && input) {
        if (size == sizeof(wire::WatchResponse)) {
            last_watch = *static_cast<const wire::WatchRequest*>(input);
            const wire::WatchResponse made{.id = 0xdef};
            std::memcpy(output, &made, sizeof(made));
        }
    }
    if (code == wire::opcode(wire::op::dump) && input &&
        size == sizeof(wire::DumpResponse)) {
        const auto* request = static_cast<const wire::DumpRequest*>(input);
        wire::DumpResponse made{};
        made.state = blook::watch_hit;
        made.total = dump_bytes.size();
        made.hit_rip = 0x1234;
        made.hit_cr3 = 1;
        if (request->offset < dump_bytes.size()) {
            const auto available = dump_bytes.size() - request->offset;
            const auto take = request->length < available
                                  ? request->length
                                  : static_cast<uint32_t>(available);
            std::memcpy(made.data, dump_bytes.data() + request->offset, take);
            made.copied = take;
        }
        std::memcpy(output, &made, sizeof(made));
    }
    if (wrong_header && (code == wire::opcode(wire::op::configuration) ||
                         code == wire::opcode(wire::op::features)))
        static_cast<wire::Header*>(output)->version = wire::abi_version - 1;
    if (short_response && returned && size)
        *returned = size - 1;
    return 0;
}

inline std::shared_ptr<blook::client::detail::connection> connection() {
    auto link = std::make_shared<blook::client::detail::connection>();
    link->test_call = &call;
    return link;
}
}  // namespace fake
namespace {
// Opens a session over the fake transport. `fail_call` and the other fake
// switches now live behind the kchannel call, which is exactly the boundary the
// SDK has to handle.
inline blook::client::result<blook::client::session> open_session(
    blook::client::open_mode mode = blook::client::open_mode::read_write) {
    auto link = fake::connection();
    if (mode == blook::client::open_mode::read_write) {
        auto request = wire::request<wire::EnableRequest>();
        const auto status = link->call(wire::opcode(wire::op::enable), &request,
                                       sizeof(request), nullptr, 0);
        if (!status)
            return std::unexpected(status.error());
    }
    return blook::client::session::adopt(std::move(link));
}
}  // namespace

namespace {
bool valid(HANDLE handle) {
    DWORD flags{};
    return GetHandleInformation(handle, &flags) != FALSE;
}
template <class T>
bool denied(const std::expected<T, std::error_code>& status, DWORD code) {
    return !status && status.error() == std::error_code{static_cast<int>(code),
                                                        std::system_category()};
}
}  // namespace

namespace {
using namespace blook::client;

class ClientTest : public ::testing::Test {
   protected:
    void SetUp() override {
        fake::fail_call = false;
        fake::short_response = false;
        fake::wrong_header = false;
        fake::calls = 0;
        fake::last_watch = {};
        fake::last_page = {};
        fake::last_configuration = {};
        fake::last_features = {};
        fake::page_response = {};
        fake::page_response.header = {wire::abi_version,
                                      sizeof(wire::QueryPageResponse)};
        fake::page_response.domain = wire::page_domain_user;
        fake::dump_bytes = {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};
        SetLastError(ERROR_SUCCESS);
    }
};

static_assert(!std::is_copy_constructible_v<unique_handle>);
static_assert(!std::is_copy_assignable_v<unique_handle>);
static_assert(std::is_nothrow_move_constructible_v<unique_handle>);
static_assert(std::is_nothrow_move_assignable_v<unique_handle>);
static_assert(!std::is_copy_assignable_v<detail::connection>);
static_assert(!std::is_copy_constructible_v<detail::connection>);
static_assert(!std::is_move_constructible_v<detail::connection>);
static_assert(!std::is_copy_constructible_v<session>);
static_assert(std::is_nothrow_move_constructible_v<session>);
static_assert(!std::is_copy_constructible_v<hook>);
static_assert(std::is_nothrow_move_constructible_v<hook>);
static_assert(byte_range<std::uint8_t[4]>);
static_assert(byte_range<std::array<std::byte, 4>>);
static_assert(byte_range<std::vector<std::uint8_t>>);
static_assert(byte_range<std::span<const std::byte>>);
static_assert(!byte_range<std::uint16_t[4]>);
static_assert(!byte_range<int>);

TEST_F(ClientTest, UniqueHandleTransfersAndReleasesOwnership) {
    unique_handle empty;
    unique_handle null{nullptr};
    ASSERT_TRUE((!empty && !null)) << "both invalid sentinels are empty";
    unique_handle first{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    ASSERT_TRUE((static_cast<bool>(first))) << "create event";
    const auto original = first.get();
    unique_handle second{std::move(first)};
    ASSERT_TRUE((!first && second.get() == original))
        << "move transfers ownership";
    second.reset(second.get());
    ASSERT_TRUE((valid(original))) << "reset to same handle is harmless";
    const auto detached = second.release();
    ASSERT_TRUE((!second && valid(detached))) << "release does not close";
    first.reset(detached);
    SetLastError(ERROR_ACCESS_DENIED);
    first.reset();
    ASSERT_TRUE((GetLastError() == ERROR_ACCESS_DENIED))
        << "cleanup preserves last error";
    ASSERT_TRUE((!valid(original))) << "reset closes owned object";
}

TEST_F(ClientTest, UniqueHandleMoveAssignmentClosesPreviousOwner) {
    unique_handle first;
    unique_handle second;
    first.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    second.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    ASSERT_TRUE((first && second)) << "create move-assignment events";
    const auto replaced = second.get();
    second = std::move(first);
    ASSERT_TRUE((!first && second && !valid(replaced)))
        << "move assignment closes old owner";
    second = std::move(second);
    ASSERT_TRUE((static_cast<bool>(second))) << "self move keeps owner";
}

TEST_F(ClientTest, EntryJumpEncodesReachableLiteralAndRejectsOutOfRange) {
    // The entry-jump helper: reachable literal encodes ff 25 rel32, an
    // out-of-range literal is an empty optional instead of a sentinel array.
    auto near_jump = entry_jump(reinterpret_cast<void*>(0x10000000),
                                reinterpret_cast<void*>(0x10001000));
    ASSERT_TRUE((near_jump && (*near_jump)[0] == std::byte{0xff} &&
                 (*near_jump)[1] == std::byte{0x25}))
        << "entry jump encodes rip-relative indirect jmp";
    ASSERT_TRUE(
        (!entry_jump(reinterpret_cast<void*>(std::uintptr_t{0x10000000}),
                     reinterpret_cast<void*>(std::uintptr_t{0x90000007}))))
        << "out-of-reach literal rejected";
    ASSERT_TRUE(
        (!entry_jump(reinterpret_cast<void*>(std::uintptr_t{0x80000000}),
                     reinterpret_cast<void*>(std::uintptr_t{0x0}))))
        << "below-range literal rejected";
}

TEST_F(ClientTest, OpenWithoutTransportReportsInvalidHandle) {
    // A session adopted from a connection with neither a transport nor the test
    // seam is exactly what a caller gets when the channel could not start.
    auto bare = session::adopt(std::make_shared<detail::connection>());
    const auto invalid = bare.query();
    ASSERT_TRUE((!invalid)) << "query without a transport must fail, not hang";
}

TEST_F(ClientTest, OpenEnableFailureClosesConnection) {
    fake::fail_call = true;
    auto failed = open_session();
    ASSERT_TRUE((!failed &&
                 failed.error().value() == static_cast<int>(ERROR_NOT_READY)))
        << "enable failure propagated as a transport error";
}

TEST_F(ClientTest, ReadOnlySessionMoveAndDestruction) {
    {
        const auto before = fake::calls;
        auto opened = open_session(open_mode::read_only);
        ASSERT_TRUE((opened.has_value())) << "open readonly connection";
        ASSERT_TRUE((fake::calls == before))
            << "read_only open does not enable session";
        auto moved = std::move(*opened);
        const auto invalid = opened->query();
        ASSERT_TRUE((!invalid && invalid.error().value() ==
                                     static_cast<int>(ERROR_INVALID_HANDLE)))
            << "moved-from query is safe";
        const auto info = moved.query();
        ASSERT_TRUE((info && info->abi == wire::abi_version && info->running &&
                     !info->enabled && !info->hidden))
            << "query decodes response";
    }
}

TEST_F(ClientTest,
       ConfigurationAndFeaturesUseReadOnlyConnectionAndExactRequests) {
    auto opened = open_session(open_mode::read_only);
    ASSERT_TRUE(opened);
    EXPECT_EQ(fake::calls, 0u);
    auto configuration = opened->query_configuration();
    ASSERT_TRUE(configuration);
    EXPECT_EQ(configuration->generation, 123u);
    EXPECT_EQ(configuration->features, 7u);
    EXPECT_EQ(configuration->restart_required, 1u);
    EXPECT_TRUE(wire::valid_header(fake::last_configuration));
    EXPECT_EQ(fake::last_configuration.reload, 0u);
    EXPECT_EQ(fake::last_configuration.reserved, 0u);
    ASSERT_TRUE(opened->reload_configuration());
    EXPECT_EQ(fake::last_configuration.reload, 1u);
    auto features = opened->query_features();
    ASSERT_TRUE(features);
    EXPECT_TRUE(wire::valid_header(fake::last_features));
    EXPECT_EQ(fake::last_features.action, 0u);
    EXPECT_EQ(fake::last_features.reserved, 0u);
    EXPECT_EQ(features->desired, 7u);
    EXPECT_EQ(features->effective, 3u);
    EXPECT_EQ(features->unsupported, 4u);
    ASSERT_TRUE(opened->set_feature(2, true));
    EXPECT_EQ(fake::last_features.action, 1u);
    EXPECT_EQ(fake::last_features.id, 2u);
    EXPECT_EQ(fake::last_features.enabled, 1u);
    ASSERT_TRUE(opened->set_feature(2, false));
    EXPECT_EQ(fake::last_features.enabled, 0u);
    EXPECT_EQ(fake::calls, 5u);  // no implicit ENABLE
}

TEST_F(ClientTest, ConfigurationAndFeaturesPropagateBoundaryErrors) {
    auto opened = open_session(open_mode::read_only);
    ASSERT_TRUE(opened);
    fake::short_response = true;
    EXPECT_TRUE(denied(opened->query_configuration(), ERROR_INVALID_DATA));
    EXPECT_TRUE(denied(opened->query_features(), ERROR_INVALID_DATA));
    EXPECT_TRUE(denied(opened->set_feature(0, true), ERROR_INVALID_DATA));
    fake::short_response = false;
    fake::fail_call = true;
    EXPECT_TRUE(denied(opened->reload_configuration(), ERROR_NOT_READY));
    EXPECT_TRUE(denied(opened->query_features(), ERROR_NOT_READY));
    EXPECT_TRUE(denied(opened->set_feature(0, true), ERROR_NOT_READY));
    auto moved = std::move(*opened);
    EXPECT_TRUE(denied(opened->query_configuration(), ERROR_INVALID_HANDLE));
    EXPECT_TRUE(denied(opened->query_features(), ERROR_INVALID_HANDLE));
    EXPECT_TRUE(denied(opened->set_feature(0, true), ERROR_INVALID_HANDLE));
}

TEST_F(ClientTest, QueryPageIsReadOnlyAndPreservesDomainPidAndState) {
    auto opened = open_session(open_mode::read_only);
    ASSERT_TRUE(opened);
    EXPECT_EQ(fake::calls, 0u);
    auto& raw = fake::page_response;
    raw.page_base = 0x12000;
    raw.pid = 42;
    raw.registered_count = raw.entry_count = 2;
    raw.armed_count = raw.dormant_count = 1;
    raw.entries[0] = {7, 0x12010, 42, wire::page_domain_user, 0, 1};
    raw.entries[1] = {8, 0x12f00, 42, wire::page_domain_user, 1, 0};
    const auto result =
        opened->query_page(reinterpret_cast<void*>(0x12345), pid{42});
    ASSERT_TRUE(result);
    EXPECT_EQ(fake::calls, 1u);
    EXPECT_TRUE(wire::valid_header(fake::last_page));
    EXPECT_EQ(fake::last_page.address, 0x12345u);
    EXPECT_EQ(fake::last_page.pid, 42u);
    EXPECT_EQ(fake::last_page.domain, wire::page_domain_user);
    EXPECT_EQ(result->entries[1].id, 8u);
    EXPECT_EQ(result->entries[1].dormant, 1u);
    EXPECT_EQ(result->armed_count, 1u);
}

TEST_F(ClientTest, QueryPageKernelIsCountsOnlyAndValidatesArguments) {
    auto opened = open_session(open_mode::read_only);
    ASSERT_TRUE(opened);
    auto& raw = fake::page_response;
    raw.domain = wire::page_domain_kernel;
    raw.flags = wire::page_query_counts_only;
    raw.registered_count = 3;
    const auto address = reinterpret_cast<void*>(0xffff800000001234ull);
    auto result = opened->query_page(address, {}, wire::page_domain_kernel);
    ASSERT_TRUE(result);
    EXPECT_EQ(result->entry_count, 0u);
    EXPECT_EQ(result->page_base, 0u);
    EXPECT_EQ(result->registered_count, 3u);
    const auto before = fake::calls;
    EXPECT_TRUE(
        denied(opened->query_page(address, pid{1}, wire::page_domain_kernel),
               ERROR_INVALID_PARAMETER));
    EXPECT_TRUE(
        denied(opened->query_page(address, {}, 99), ERROR_INVALID_PARAMETER));
    EXPECT_EQ(fake::calls, before);
    raw.entry_count = 1;
    EXPECT_TRUE(
        denied(opened->query_page(address, {}, wire::page_domain_kernel),
               ERROR_INVALID_DATA));
}

TEST_F(ClientTest, QueryPageRejectsMalformedResponseAndPropagatesErrors) {
    auto opened = open_session(open_mode::read_only);
    ASSERT_TRUE(opened);
    const auto address = reinterpret_cast<void*>(0x10000);
    EXPECT_TRUE(opened->query_page(address));  // empty page is success
    EXPECT_EQ(fake::last_page.pid, 0u);
    fake::page_response.registered_count = 65;
    EXPECT_TRUE(denied(opened->query_page(address), ERROR_INVALID_DATA));
    fake::page_response.registered_count = 0;
    fake::page_response.armed_count = 1;
    EXPECT_TRUE(denied(opened->query_page(address), ERROR_INVALID_DATA));
    fake::page_response.armed_count = 0;
    fake::short_response = true;
    EXPECT_TRUE(denied(opened->query_page(address), ERROR_INVALID_DATA));
    fake::short_response = false;
    fake::page_response.header.version = 0;
    EXPECT_TRUE(denied(opened->query_page(address), ERROR_INVALID_DATA));
    fake::fail_call = true;
    EXPECT_TRUE(denied(opened->query_page(address), ERROR_NOT_READY));
    auto moved = std::move(*opened);
    EXPECT_TRUE(denied(opened->query_page(address), ERROR_INVALID_HANDLE));
}

TEST_F(ClientTest, QueryRejectsTruncatedResponse) {
    auto opened = open_session(open_mode::read_only);
    ASSERT_TRUE(opened.has_value());
    auto moved = std::move(*opened);
    fake::short_response = true;
    const auto truncated = moved.query();
    ASSERT_TRUE((!truncated && truncated.error().value() ==
                                   static_cast<int>(ERROR_INVALID_DATA)))
        << "reject short response";
}

TEST_F(ClientTest, QueryPropagatesDeviceFailure) {
    auto opened = open_session(open_mode::read_only);
    ASSERT_TRUE(opened.has_value());
    auto moved = std::move(*opened);
    fake::fail_call = true;
    const auto unavailable = moved.query();
    ASSERT_TRUE((!unavailable && unavailable.error().value() ==
                                     static_cast<int>(ERROR_NOT_READY)))
        << "query error propagated";
}

TEST_F(ClientTest, PatchValidatesRangesBeforeIoctl) {
    auto opened = open_session(open_mode::read_only);
    ASSERT_TRUE(opened.has_value());
    auto moved = std::move(*opened);
    // Patch validation is client-side and precedes any IOCTL: empty
    // ranges, page-crossing ranges and oversized patches are rejected
    // before the device is touched.
    fake::calls = 0;
    const std::array<std::uint8_t, 2> pair{0x90, 0x90};
    ASSERT_TRUE(
        (denied(moved.patch(reinterpret_cast<void*>(0x1ffff), pair, pid{}),
                ERROR_INVALID_PARAMETER)))
        << "page-crossing patch rejected";
    ASSERT_TRUE(
        (denied(moved.patch(nullptr, std::span<const std::byte>{}, pid{}),
                ERROR_INVALID_PARAMETER)))
        << "empty byte range rejected";
    const std::vector<std::byte> wide(65, std::byte{0x90});
    ASSERT_TRUE(
        (denied(moved.patch(nullptr, wide, pid{}), ERROR_INVALID_PARAMETER)))
        << "oversized patch rejected";
    ASSERT_TRUE((fake::calls == 0)) << "validation reaches no ioctl";
}

TEST_F(ClientTest, ValidPatchIssuesOneIoctl) {
    auto opened = open_session(open_mode::read_only);
    ASSERT_TRUE(opened.has_value());
    auto moved = std::move(*opened);
    const std::array<std::uint8_t, 1> nop{0x90};
    const auto installed = moved.patch(
        reinterpret_cast<void*>(std::uintptr_t{0x10000}), nop, pid::current());
    ASSERT_TRUE(
        (installed.has_value() && installed->id() == 0xabc && fake::calls == 1))
        << "valid patch issues one ioctl";
}

TEST_F(ClientTest, AbsoluteWatchArmEncodesAddresses) {
    auto opened = open_session(open_mode::read_only);
    ASSERT_TRUE((opened.has_value())) << "open session for watch tests";
    fake::calls = 0;
    auto armed = opened->watch_execute(
        reinterpret_cast<void*>(std::uintptr_t{0x700080}),
        reinterpret_cast<void*>(std::uintptr_t{0x710000}), 0x1020, pid{1234});
    ASSERT_TRUE((armed && armed->id() == 0xdef && fake::calls == 1))
        << "absolute watch arm issues one ioctl";
    ASSERT_TRUE(
        (fake::last_watch.action == wire::watch_arm &&
         fake::last_watch.pid == 1234 && fake::last_watch.address == 0x700080 &&
         fake::last_watch.base == 0 && fake::last_watch.dump_base == 0x710000 &&
         fake::last_watch.dump_size == 0x1020))
        << "arm request carries absolute VAs";
}

TEST_F(ClientTest, ModuleRelativeWatchArmEncodesOffsets) {
    auto opened = open_session(open_mode::read_only);
    ASSERT_TRUE((opened.has_value())) << "open session for watch tests";
    fake::calls = 0;
    const auto via_module = opened->watch_execute_at(
        reinterpret_cast<void*>(std::uintptr_t{0x10000000}), 0x80, 0x1000, 4096,
        pid{42});
    ASSERT_TRUE((via_module && fake::last_watch.base == 0x10000000 &&
                 fake::last_watch.address == 0x80 &&
                 fake::last_watch.dump_base == 0x1000 &&
                 fake::last_watch.pid == 42))
        << "module-relative arm keeps base + offsets";
}

TEST_F(ClientTest, WatchRejectsInvalidAddressAndDumpSize) {
    auto opened = open_session(open_mode::read_only);
    ASSERT_TRUE((opened.has_value())) << "open session for watch tests";
    fake::calls = 0;
    ASSERT_TRUE(
        (denied(opened->watch_execute(
                    nullptr, reinterpret_cast<void*>(std::uintptr_t{0x710000}),
                    0x1020, pid{1}),
                ERROR_INVALID_PARAMETER)))
        << "null address rejected client-side";
    ASSERT_TRUE((denied(
        opened->watch_execute(reinterpret_cast<void*>(std::uintptr_t{0x700080}),
                              reinterpret_cast<void*>(std::uintptr_t{0x710000}),
                              blook::max_dump + 1, pid{1}),
        ERROR_INVALID_PARAMETER)))
        << "oversized dump rejected client-side";
    ASSERT_EQ(fake::calls, 0u);
}

TEST_F(ClientTest, WatchPollReportsHit) {
    auto opened = open_session(open_mode::read_only);
    ASSERT_TRUE((opened.has_value())) << "open session for watch tests";
    fake::calls = 0;
    auto armed = opened->watch_execute(
        reinterpret_cast<void*>(std::uintptr_t{0x700080}),
        reinterpret_cast<void*>(std::uintptr_t{0x710000}), 0x1020, pid{1234});
    ASSERT_TRUE((armed && armed->id() == 0xdef && fake::calls == 1))
        << "absolute watch arm issues one ioctl";
    const auto hit = armed->poll();
    ASSERT_TRUE((hit && hit->ready && hit->rip == 0x1234 && hit->cr3 == 1 &&
                 hit->total == fake::dump_bytes.size()))
        << "poll reports the hit";
}

TEST_F(ClientTest, WatchReadMapsChunkOffsets) {
    auto opened = open_session(open_mode::read_only);
    ASSERT_TRUE((opened.has_value())) << "open session for watch tests";
    fake::calls = 0;
    auto armed = opened->watch_execute(
        reinterpret_cast<void*>(std::uintptr_t{0x700080}),
        reinterpret_cast<void*>(std::uintptr_t{0x710000}), 0x1020, pid{1234});
    ASSERT_TRUE((armed && armed->id() == 0xdef && fake::calls == 1))
        << "absolute watch arm issues one ioctl";
    std::array<std::byte, 3> slice{};
    const auto piece = armed->read(2, slice);
    ASSERT_TRUE((piece && *piece == 3 &&
                 slice[0] == std::byte{fake::dump_bytes[2]} &&
                 slice[2] == std::byte{fake::dump_bytes[4]}))
        << "chunked read maps offsets";
}

TEST_F(ClientTest, WatchDumpReassemblesChunks) {
    auto opened = open_session(open_mode::read_only);
    ASSERT_TRUE((opened.has_value())) << "open session for watch tests";
    fake::calls = 0;
    auto armed = opened->watch_execute(
        reinterpret_cast<void*>(std::uintptr_t{0x700080}),
        reinterpret_cast<void*>(std::uintptr_t{0x710000}), 0x1020, pid{1234});
    ASSERT_TRUE((armed && armed->id() == 0xdef && fake::calls == 1))
        << "absolute watch arm issues one ioctl";
    const auto full = armed->dump();
    ASSERT_TRUE(
        (full && full->size() == fake::dump_bytes.size() &&
         std::memcmp(full->data(), fake::dump_bytes.data(), full->size()) == 0))
        << "full dump reassembles chunks";
}

TEST_F(ClientTest, MovedWatchIsInertAndDisarmClearsOwnership) {
    auto opened = open_session(open_mode::read_only);
    ASSERT_TRUE((opened.has_value())) << "open session for watch tests";
    fake::calls = 0;
    auto armed = opened->watch_execute(
        reinterpret_cast<void*>(std::uintptr_t{0x700080}),
        reinterpret_cast<void*>(std::uintptr_t{0x710000}), 0x1020, pid{1234});
    ASSERT_TRUE((armed && armed->id() == 0xdef && fake::calls == 1))
        << "absolute watch arm issues one ioctl";
    // The RAII tail: moved-from handles are inert, destruction disarms.
    auto moved_watch = std::move(*armed);
    ASSERT_TRUE((armed->id() == 0 && !*armed && armed->disarm().has_value()))
        << "moved-from watch is inert";
    ASSERT_TRUE((moved_watch.disarm().has_value() && moved_watch.id() == 0))
        << "disarm clears the handle";
}

TEST_F(ClientTest, EmptyConnectionRejectsCall) {
    detail::connection unopened;
    const auto invalid = unopened.call(0, nullptr, 0, nullptr, 0);
    ASSERT_TRUE((!invalid && invalid.error().value() ==
                                 static_cast<int>(ERROR_INVALID_HANDLE)))
        << "empty connection rejected";
}

TEST_F(ClientTest, HookRetainsSharedConnectionUntilLastOwner) {
    std::weak_ptr<detail::connection> observer;
    {
        auto connection = std::make_shared<detail::connection>();
        observer = connection;
        hook owner{connection, 0};
        connection.reset();
        ASSERT_TRUE((!observer.expired()))
            << "hook retains the shared connection";
        hook moved_owner{std::move(owner)};
        ASSERT_TRUE((owner.id() == 0 && !owner && owner.remove().has_value()))
            << "moved hook cleanup is inert";
        ASSERT_TRUE((!observer.expired()))
            << "the move kept the connection, the moved-from hook did not drop "
               "it";
    }
    ASSERT_TRUE((observer.expired()))
        << "last shared owner releases the connection";
}

TEST_F(ClientTest, NullHookConnectionRejectsRemoveAndRefresh) {
    hook invalid_owner{nullptr, 1};
    const auto invalid_remove = invalid_owner.remove();
    const auto invalid_refresh = invalid_owner.refresh();
    ASSERT_TRUE((denied(invalid_remove, ERROR_INVALID_HANDLE)))
        << "null hook connection rejected";
    ASSERT_TRUE((denied(invalid_refresh, ERROR_INVALID_HANDLE)))
        << "null hook refresh rejected";
}
}  // namespace

TEST(PageQueryClient, RejectsInvalidLogicalCountsAndOldAbi) {
    using namespace blook::client;
    fake::fail_call = false;
    fake::short_response = false;
    auto opened = open_session(open_mode::read_only);
    ASSERT_TRUE(opened);
    auto& out = fake::page_response;
    out = {};
    out.header = {wire::abi_version, sizeof(out)};
    out.domain = wire::page_domain_kernel;
    out.flags = wire::page_query_counts_only;
    out.registered_count = 1;
    out.armed_count = 1;
    out.logical_count = 4;
    out.enabled_logical_count = 2;
    const auto query = [&] {
        return opened->query_page(
            reinterpret_cast<void*>(0xffff800000010000ull), {},
            wire::page_domain_kernel);
    };
    ASSERT_TRUE(query());
    out.enabled_logical_count = 5;
    EXPECT_TRUE(denied(query(), ERROR_INVALID_DATA));
    out.enabled_logical_count = 2;
    out.opaque_count = 2;
    EXPECT_TRUE(denied(query(), ERROR_INVALID_DATA));
    out.opaque_count = 0;
    out.reserved2 = 1;
    EXPECT_TRUE(denied(query(), ERROR_INVALID_DATA));
    out.reserved2 = 0;
    out.header.version = 5;
    EXPECT_TRUE(denied(query(), ERROR_INVALID_DATA));
}

TEST_F(ClientTest,
       TypedFeatureIdRejectsInvalidIdsWithoutIoctlAndValidatesHeaders) {
    auto opened = open_session(open_mode::read_only);
    ASSERT_TRUE(opened);
    ASSERT_TRUE(opened->set_feature(blook::feature::id::window_list, true));
    EXPECT_EQ(fake::last_features.id,
              static_cast<uint32_t>(blook::feature::id::window_list));
    const auto calls = fake::calls;
    EXPECT_TRUE(denied(opened->set_feature(blook::feature::id::count, true),
                       ERROR_INVALID_PARAMETER));
    EXPECT_TRUE(
        denied(opened->set_feature(256, true), ERROR_INVALID_PARAMETER));
    EXPECT_EQ(fake::calls, calls);
    fake::wrong_header = true;
    EXPECT_TRUE(denied(opened->query_features(), ERROR_INVALID_DATA));
    EXPECT_TRUE(denied(opened->set_feature(0, true), ERROR_INVALID_DATA));
    EXPECT_TRUE(denied(opened->reload_configuration(), ERROR_INVALID_DATA));
    fake::wrong_header = false;
}
