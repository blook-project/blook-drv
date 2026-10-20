#pragma once
#include <windows.h>

#include <array>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <memory>
#include <optional>
#include <ranges>
#include <span>
#include <system_error>
#include <type_traits>
#include <utility>
#include <vector>

#include "blook/drv/handle.hpp"
#include "blook/drv/transport.hpp"
#include "blook/drv/wire.hpp"
#include "policy/hook.hpp"
#include "policy/dispatch.hpp"
#include "policy/features.hpp"

// User-mode side of the driver ABI.
//
// A session belongs to the process that opened the device, but a single
// session can hook *any* process it can name: `session::patch` installs an
// EPT hook that only takes effect in that process, without touching a single
// byte of its memory. Reads through the region still return the original
// code, so the target cannot discover the hook by comparing its own bytes.
// Any number of non-overlapping hooks can share one page; the driver merges
// them into a single shadow page per process.
namespace blook::client {

// Use one redirect to a correctly typed dispatcher in the target process, then
// compose any number (up to Capacity) of logical handlers with this chain.
// Publish immutable snapshots and provide a valid original callable; raw patch
// bytes cannot be automatically composed or ABI-inferred by the driver.
template <class Signature, size_t Capacity = 32>
using dispatch_chain = blook::dispatch_chain<Signature, Capacity>;

template <class T>
using result = std::expected<T, std::error_code>;

[[nodiscard]] inline std::error_code last_error() noexcept {
    return {static_cast<int>(GetLastError()), std::system_category()};
}

// Strong process id. The default-constructed value (0) asks the driver to
// target the calling process; `pid::current()` names it explicitly.
struct pid {
    uint32_t value{};
    [[nodiscard]] static pid current() noexcept {
        return pid{GetCurrentProcessId()};
    }
    friend bool operator==(pid, pid) = default;
};

enum class process_role : uint32_t {
    tool = wire::hide_role_tool,
    target = wire::hide_role_target,
};

enum class scrub : uint32_t {
    peb = wire::scrub_peb,
    heap = wire::scrub_heap,
    all = wire::scrub_all,
};

// Any contiguous sequence of 1-byte trivially-copyable values: std::byte,
// std::uint8_t, char buffers, std::vector<std::uint8_t>, C arrays, ...
template <class Range>
concept byte_range =
    std::ranges::contiguous_range<Range> &&
    std::is_trivially_copyable_v<std::ranges::range_value_t<Range>> &&
    sizeof(std::ranges::range_value_t<Range>) == 1;

template <byte_range Range>
[[nodiscard]] std::span<const std::byte> bytes_of(Range&& range) noexcept {
    return std::as_bytes(std::span{std::data(range), std::size(range)});
}

// Maps a blook-kchannel status onto a Win32 error code. The transport is the
// only place a status crosses the boundary; everything above it speaks
// std::error_code like the rest of the SDK.
[[nodiscard]] inline std::error_code transport_error(int status) noexcept {
    switch (status) {
        case 0:  // KC_OK
            return {};
        case 1:  // KC_ERR_PARAM
            return {ERROR_INVALID_PARAMETER, std::system_category()};
        case 2:  // KC_ERR_NOMEM
            return {ERROR_NOT_ENOUGH_MEMORY, std::system_category()};
        case 5:  // KC_ERR_STATE
            return {ERROR_INVALID_STATE, std::system_category()};
        case 6:  // KC_ERR_AUTH
            return {ERROR_ACCESS_DENIED, std::system_category()};
        case 7:  // KC_ERR_TIMEOUT
            return {ERROR_NOT_READY, std::system_category()};
        case 8:  // KC_ERR_BUSY
            return {ERROR_BUSY, std::system_category()};
        case 11:  // KC_ERR_NOT_FOUND
            return {ERROR_NOT_FOUND, std::system_category()};
        case 12:  // KC_ERR_ALREADY
            return {ERROR_ALREADY_EXISTS, std::system_category()};
        case 14:  // KC_ERR_PEER_GONE
            return {ERROR_CONNECTION_ABORTED, std::system_category()};
        case 16:  // KC_ERR_UNSUPPORTED
            return {ERROR_NOT_SUPPORTED, std::system_category()};
        default:
            return {ERROR_GEN_FAILURE, std::system_category()};
    }
}

namespace detail {
struct connection final {
    std::shared_ptr<transport::attachment> link;

    // Test seam: when set, every request goes through this function instead of
    // the kchannel attachment. It exists so the wire encoding and the RAII
    // contracts can be tested on a host with no driver and no VM, and it is the
    // only way a fake transport can be injected.
    using call_fn = int (*)(void* context, uint16_t op, const void* in,
                            uint32_t in_len, void* out, uint32_t out_cap,
                            uint32_t* out_len);
    call_fn test_call{};
    void* test_context{};

    connection() = default;
    connection(const connection&) = delete;
    connection& operator=(const connection&) = delete;
    connection(connection&&) = delete;
    connection& operator=(connection&&) = delete;

    [[nodiscard]] result<void> call(uint16_t op, const void* input,
                                    DWORD input_size, void* output,
                                    DWORD output_size) const noexcept {
        std::uint32_t returned{};
        if (!test_call && !link)
            return std::unexpected(
                std::error_code{ERROR_INVALID_HANDLE, std::system_category()});
        const auto status = [&] {
            if (test_call)
                return test_call(test_context, op, input, input_size, output,
                                 output_size, &returned);
            return transport::call(*link, op, input, input_size, output,
                                   output_size, &returned, 5000);
        }();
        if (const auto error = transport_error(status))
            return std::unexpected(error);
        if (returned != output_size)
            return std::unexpected(
                std::error_code{ERROR_INVALID_DATA, std::system_category()});
        return {};
    }
};
}  // namespace detail

// An entry jump that can be handed to `session::patch`: `jmp qword ptr
// [rip+rel32]` through a literal that lives outside the patched page and
// stays mapped for the lifetime of the hook. The literal cannot be part of
// the patch itself: the page is executed through a shadow that is mapped
// execute-only, so a read of it is answered from the untouched page and
// would deliver the wrong bytes. An empty optional means the literal is out
// of the +-2 GiB the encoding can reach, in which case the caller must not
// install the hook.
[[nodiscard]] inline std::optional<
    std::array<std::byte, blook::jump_patch_length>>
entry_jump(const void* target, const void* literal) noexcept {
    std::array<std::byte, blook::jump_patch_length> result{};
    result[0] = std::byte{0xff};
    result[1] = std::byte{0x25};
    const auto displacement =
        static_cast<int64_t>(reinterpret_cast<uintptr_t>(literal)) -
        static_cast<int64_t>(reinterpret_cast<uintptr_t>(target) +
                             blook::jump_patch_length);
    if (displacement > 0x7fffffffll || displacement < -0x80000000ll)
        return std::nullopt;
    const auto rel = static_cast<int32_t>(displacement);
    std::memcpy(result.data() + 2, &rel, sizeof(rel));
    return result;
}

// A installed hook. Move-only; destroying the last handle removes the hook
// from the driver. A moved-from hook is inert.
class hook final {
    std::shared_ptr<detail::connection> connection_;
    uint64_t id_{};

   public:
    hook(std::shared_ptr<detail::connection> connection, uint64_t id) noexcept
        : connection_(std::move(connection)), id_(id) {}
    hook(const hook&) = delete;
    hook& operator=(const hook&) = delete;
    hook(hook&& other) noexcept
        : connection_(std::move(other.connection_)),
          id_(std::exchange(other.id_, 0)) {}
    hook& operator=(hook&& other) noexcept {
        if (this != &other) {
            (void)remove();
            connection_ = std::move(other.connection_);
            id_ = std::exchange(other.id_, 0);
        }
        return *this;
    }
    ~hook() { (void)remove(); }

    [[nodiscard]] uint64_t id() const noexcept { return id_; }
    [[nodiscard]] explicit operator bool() const noexcept { return id_ != 0; }

    [[nodiscard]] result<void> remove() noexcept {
        if (!id_)
            return {};
        if (!connection_)
            return std::unexpected(
                std::error_code{ERROR_INVALID_HANDLE, std::system_category()});
        auto request = wire::request<wire::HookRequest>();
        request.id = id_;
        auto status = connection_->call(wire::opcode(wire::op::remove), &request,
                                        sizeof(request), nullptr, 0);
        if (status)
            id_ = 0;
        return status;
    }

    // Caller must quiesce execution while changing source code or refreshing
    // its snapshot.
    [[nodiscard]] result<void> refresh() const noexcept {
        if (!id_ || !connection_)
            return std::unexpected(
                std::error_code{ERROR_INVALID_HANDLE, std::system_category()});
        auto request = wire::request<wire::HookRequest>();
        request.id = id_;
        return connection_->call(wire::opcode(wire::op::refresh), &request,
                                 sizeof(request), nullptr, 0);
    }
};

// What `watch::poll` / `watch::dump` report once the watched address has been
// executed: the same fields the hypervisor publishes in the record.
struct watch_hit {
    uint64_t rip{};
    uint64_t cr3{};
    uint64_t total{};
    bool ready{};
};

// An armed execute watch. Move-only; destroying the last handle disarms it in
// the driver. The watch is one-shot: once `poll().ready` is true the dump
// stays fetchable for the lifetime of the handle.
class watch final {
    std::shared_ptr<detail::connection> connection_;
    uint64_t id_{};

   public:
    watch(std::shared_ptr<detail::connection> connection, uint64_t id) noexcept
        : connection_(std::move(connection)), id_(id) {}
    watch(const watch&) = delete;
    watch& operator=(const watch&) = delete;
    watch(watch&& other) noexcept
        : connection_(std::move(other.connection_)),
          id_(std::exchange(other.id_, 0)) {}
    watch& operator=(watch&& other) noexcept {
        if (this != &other) {
            (void)disarm();
            connection_ = std::move(other.connection_);
            id_ = std::exchange(other.id_, 0);
        }
        return *this;
    }
    ~watch() { (void)disarm(); }

    [[nodiscard]] uint64_t id() const noexcept { return id_; }
    [[nodiscard]] explicit operator bool() const noexcept { return id_ != 0; }

    [[nodiscard]] result<void> disarm() noexcept {
        if (!id_)
            return {};
        if (!connection_)
            return std::unexpected(
                std::error_code{ERROR_INVALID_HANDLE, std::system_category()});
        auto request = wire::request<wire::WatchRequest>();
        request.action = wire::watch_disarm;
        request.id = id_;
        auto status = connection_->call(wire::opcode(wire::op::watch), &request,
                                        sizeof(request), nullptr, 0);
        if (status)
            id_ = 0;
        return status;
    }

    // A length-0 fetch: state and hit metadata only, no payload.
    [[nodiscard]] result<watch_hit> poll() const noexcept {
        if (!id_ || !connection_)
            return std::unexpected(
                std::error_code{ERROR_INVALID_HANDLE, std::system_category()});
        auto request = wire::request<wire::DumpRequest>();
        request.id = id_;
        wire::DumpResponse response{};
        auto status =
            connection_->call(wire::opcode(wire::op::dump), &request, sizeof(request),
                              &response, sizeof(response));
        if (!status)
            return std::unexpected(status.error());
        return watch_hit{.rip = response.hit_rip,
                         .cr3 = response.hit_cr3,
                         .total = response.total,
                         .ready = response.state == blook::watch_hit};
    }

    // Read up to `out.size()` bytes of the dump at `offset`; the returned
    // count is what actually arrived (the range may end mid-request).
    [[nodiscard]] result<uint32_t> read(uint64_t offset,
                                        std::span<std::byte> out) const {
        if (!id_ || !connection_)
            return std::unexpected(
                std::error_code{ERROR_INVALID_HANDLE, std::system_category()});
        if (out.size() > wire::dump_chunk_size)
            return std::unexpected(std::error_code{ERROR_INVALID_PARAMETER,
                                                   std::system_category()});
        auto request = wire::request<wire::DumpRequest>();
        request.id = id_;
        request.offset = offset;
        request.length = static_cast<uint32_t>(out.size());
        wire::DumpResponse response{};
        auto status =
            connection_->call(wire::opcode(wire::op::dump), &request, sizeof(request),
                              &response, sizeof(response));
        if (!status)
            return std::unexpected(status.error());
        if (response.state != blook::watch_hit)
            return std::unexpected(
                std::error_code{ERROR_NOT_READY, std::system_category()});
        if (response.copied > out.size())
            return std::unexpected(
                std::error_code{ERROR_INVALID_DATA, std::system_category()});
        std::memcpy(out.data(), response.data, response.copied);
        return response.copied;
    }

    // The whole dump, chunked. Fails with ERROR_NOT_READY while the watched
    // address has not been executed yet.
    [[nodiscard]] result<std::vector<std::byte>> dump() const {
        const auto hit = poll();
        if (!hit)
            return std::unexpected(hit.error());
        if (!hit->ready)
            return std::unexpected(
                std::error_code{ERROR_NOT_READY, std::system_category()});
        std::vector<std::byte> out(hit->total);
        uint64_t offset = 0;
        while (offset < hit->total) {
            std::array<std::byte, wire::dump_chunk_size> chunk{};
            const auto copied = read(
                offset,
                std::span{chunk}.first(static_cast<size_t>(
                    (hit->total - offset < chunk.size()) ? hit->total - offset
                                                         : chunk.size())));
            if (!copied)
                return std::unexpected(copied.error());
            if (!*copied)
                break;
            std::memcpy(out.data() + offset, chunk.data(), *copied);
            offset += *copied;
        }
        out.resize(static_cast<size_t>(offset));
        return out;
    }
};

// Decoded `session::query` response. Field-for-field the wire protocol, but
// with flags as bools so call sites do not reinterpret integers.
struct session_info {
    uint32_t abi{};
    uint32_t version{};
    bool running{};
    bool enabled{};
    uint32_t hooks{};
    bool hidden{};
    int32_t backend_status{};
    uint32_t window_hooks{};
};

enum class open_mode {
    read_write,  // open the device and enable the session
    read_only,   // open the device without enabling it
};

class session final {
    std::shared_ptr<detail::connection> connection_;
    explicit session(std::shared_ptr<detail::connection> connection) noexcept
        : connection_(std::move(connection)) {}

    [[nodiscard]] result<void> call(uint16_t op, const void* input,
                                    DWORD input_size, void* output,
                                    DWORD output_size) const noexcept {
        if (!connection_)
            return std::unexpected(
                std::error_code{ERROR_INVALID_HANDLE, std::system_category()});
        return connection_->call(op, input, input_size, output, output_size);
    }


    [[nodiscard]] static result<session> finish_open(
        open_mode mode, std::shared_ptr<detail::connection> connection) {
        if (mode == open_mode::read_write) {
            auto request = wire::request<wire::EnableRequest>();
            auto status = connection->call(wire::opcode(wire::op::enable),
                                           &request, sizeof(request), nullptr,
                                           0);
            if (!status)
                return std::unexpected(status.error());
        }
        return session{std::move(connection)};
    }

   public:
    session(const session&) = delete;
    session& operator=(const session&) = delete;
    session(session&&) noexcept = default;
    session& operator=(session&&) noexcept = default;
    ~session() = default;

    // Embeds an already established connection. Used by the host tests (fake
    // transport) and by callers that bring their own attachment.
    [[nodiscard]] static session adopt(
        std::shared_ptr<detail::connection> connection) noexcept {
        return session{std::move(connection)};
    }

    // Service-mode attach (development and e2e): create the blook-kchannel
    // region, hand the bootstrap descriptor to the driver through its service
    // key, start the service and complete the handshake. A manual-map client
    // (blook-kdu) uses attach_mapped() instead; there is no third path.
    [[nodiscard]] static result<session> open(
        open_mode mode = open_mode::read_write,
        const wchar_t* service_name = L"BlookDrv") {
        std::error_code error;
        transport::attach_options options{};
        auto link = transport::begin(options, error);
        if (!link)
            return std::unexpected(error);
        if (auto status =
                transport::write_service_bootstrap(service_name, *link))
            return std::unexpected(status);
        if (auto status = transport::start_service(service_name))
            return std::unexpected(status);
        if (auto status = transport::finish(*link, 5000))
            return std::unexpected(status);
        auto connection = std::make_shared<detail::connection>();
        connection->link = std::move(link);
        return finish_open(mode, std::move(connection));
    }

    // Manual-map attach: the caller maps the image with the bootstrap blob and
    // returns only after the driver's entry point has completed.
    class mapper {
       public:
        mapper() = default;
        mapper(const mapper&) = delete;
        mapper& operator=(const mapper&) = delete;
        virtual ~mapper() = default;
        [[nodiscard]] virtual std::error_code load(
            std::span<const std::byte> bootstrap) = 0;
    };

    [[nodiscard]] static result<session> attach_mapped(
        mapper& loader, open_mode mode = open_mode::read_write,
        transport::attach_options options = {}) {
        std::error_code error;
        auto link = transport::begin(options, error);
        if (!link)
            return std::unexpected(error);
        const auto blob = transport::bootstrap(*link);
        if (blob.empty())
            return std::unexpected(std::error_code{
                ERROR_INVALID_DATA, std::system_category()});
        if (auto status = loader.load(blob))
            return std::unexpected(status);
        if (auto status = transport::finish(*link, 5000))
            return std::unexpected(status);
        auto connection = std::make_shared<detail::connection>();
        connection->link = std::move(link);
        return finish_open(mode, std::move(connection));
    }

    [[nodiscard]] result<session_info> query() const noexcept {
        wire::QueryResponse raw{};
        auto status =
            call(wire::opcode(wire::op::query), nullptr, 0, &raw, sizeof(raw));
        if (!status)
            return std::unexpected(status.error());
        return session_info{.abi = raw.abi,
                            .version = raw.version,
                            .running = raw.running != 0,
                            .enabled = raw.enabled != 0,
                            .hooks = raw.hooks,
                            .hidden = raw.hidden != 0,
                            .backend_status = raw.backend_status,
                            .window_hooks = raw.window_hooks};
    }

    // Read-only logical page snapshot. User rows/counts are restricted to this
    // connection's hooks (including remote PID targets). A different session,
    // even in the same process, cannot enumerate them. Kernel is counts-only.
    [[nodiscard]] result<wire::QueryPageResponse> query_page(
        const void* address, pid target = {},
        uint32_t domain = wire::page_domain_user) const noexcept {
        if ((domain != wire::page_domain_user &&
             domain != wire::page_domain_kernel) ||
            (domain == wire::page_domain_kernel && target.value))
            return std::unexpected(std::error_code{ERROR_INVALID_PARAMETER,
                                                   std::system_category()});
        auto request = wire::request<wire::QueryPageRequest>();
        request.address = reinterpret_cast<uint64_t>(address);
        request.pid = target.value;
        request.domain = domain;
        wire::QueryPageResponse response{};
        auto status = call(wire::opcode(wire::op::query_page), &request,
                           sizeof(request), &response, sizeof(response));
        if (!status)
            return std::unexpected(status.error());
        const bool user = domain == wire::page_domain_user;
        if (response.header.version != wire::abi_version ||
            response.header.size != sizeof(response) ||
            response.domain != domain || response.reserved ||
            response.reserved2 ||
            response.enabled_logical_count > response.logical_count ||
            response.opaque_count > response.registered_count ||
            response.logical_count > response.registered_count * 4u ||
            response.registered_count > wire::page_hook_capacity ||
            response.entry_count > wire::page_hook_capacity ||
            response.armed_count > response.registered_count ||
            response.dormant_count >
                response.registered_count - response.armed_count ||
            (user && (response.entry_count != response.registered_count ||
                      response.flags != 0)) ||
            (!user &&
             (response.entry_count || response.page_base || response.pid ||
              response.flags != wire::page_query_counts_only)))
            return std::unexpected(
                std::error_code{ERROR_INVALID_DATA, std::system_category()});
        return response;
    }

    // Install `bytes` at `address` in the address space of `target`
    // (default: this process). The patch must lie within one 4 KiB page; the
    // driver extends it to whole instructions. Non-overlapping patches on the
    // same page coexist and are merged into one shadow page.
    //
    // The target page must be committed but does not have to be executable
    // yet: a patch installed on a non-executable page (e.g. a JIT or
    // shellcode allocation in its read-write stage) is registered dormant and
    // arms itself the moment a protection change makes the page executable,
    // before that VirtualProtect call returns.
    //
    // Documented limitation: no instruction in `bytes` may read or write the
    // patched page itself (e.g. a RIP-relative load of the patch's own
    // immediate). No single EPT view can express "fetch the shadow, read the
    // original"; such an instruction single-steps from the original page,
    // which runs the original bytes and bypasses the patch for that one
    // execution. Jump patches (what `redirect` builds) never do this.
    // Nested-virtualisation and anti-detection state. These are the knobs the
    // e2e suite reads to tell "the mitigation is off" from "the mitigation
    // failed": hv_info reports what the CPU/host allows, detect_probe reports
    // which mitigations are enabled, trace_scan reports what a detector could
    // still find.
    [[nodiscard]] result<wire::HvInfoResponse> hv_info() const noexcept {
        wire::HvInfoResponse response{};
        auto status = call(wire::opcode(wire::op::hv_info), nullptr, 0,
                           &response, sizeof(response));
        if (!status)
            return std::unexpected(status.error());
        return response;
    }

    [[nodiscard]] result<wire::TraceScanResponse> trace_scan(
        uint32_t what = wire::trace_all) const noexcept {
        auto request = wire::request<wire::TraceScanRequest>();
        request.what = what;
        wire::TraceScanResponse response{};
        auto status = call(wire::opcode(wire::op::trace_scan), &request,
                           sizeof(request), &response, sizeof(response));
        if (!status)
            return std::unexpected(status.error());
        return response;
    }

    [[nodiscard]] result<wire::HideSelfResponse> hide_self(
        uint32_t flags = wire::selfhide_all) const noexcept {
        auto request = wire::request<wire::HideSelfRequest>();
        request.flags = flags;
        wire::HideSelfResponse response{};
        auto status = call(wire::opcode(wire::op::hide_self), &request,
                           sizeof(request), &response, sizeof(response));
        if (!status)
            return std::unexpected(status.error());
        return response;
    }

    [[nodiscard]] result<wire::DetectProbeResponse> detect_probe(
        uint32_t checks = wire::detect_check_all,
        uint32_t rounds = 0) const noexcept {
        auto request = wire::request<wire::DetectProbeRequest>();
        request.checks = checks;
        request.rounds = rounds;
        wire::DetectProbeResponse response{};
        auto status = call(wire::opcode(wire::op::detect_probe), &request,
                           sizeof(request), &response, sizeof(response));
        if (!status)
            return std::unexpected(status.error());
        return response;
    }

    // External-process hardware-breakpoint hook. The client must arm the CPU
    // registers itself with SetThreadContext (that is what the network of
    // NtSetContextThread hooks expects); the driver records the breakpoint so
    // it can attribute #DB and hide every trace of it.
    [[nodiscard]] result<wire::HwBreakResponse> hwbreak_arm(
        pid process, uint32_t thread_id, uint32_t dr_index, void* address,
        uint32_t access = wire::hwbreak_execute,
        uint32_t length = wire::hwbreak_len_1) const noexcept {
        auto request = wire::request<wire::HwBreakArmRequest>();
        request.pid = process.value;
        request.tid = thread_id;
        request.dr_index = dr_index;
        request.access = access;
        request.length = length;
        request.address = reinterpret_cast<uint64_t>(address);
        wire::HwBreakResponse response{};
        auto status = call(wire::opcode(wire::op::hwbreak_arm), &request,
                           sizeof(request), &response, sizeof(response));
        if (!status)
            return std::unexpected(status.error());
        return response;
    }

    [[nodiscard]] result<wire::HwBreakResponse> hwbreak_disarm(
        uint64_t id) const noexcept {
        auto request = wire::request<wire::HwBreakArmRequest>();
        request.id = id;
        wire::HwBreakResponse response{};
        auto status = call(wire::opcode(wire::op::hwbreak_disarm), &request,
                           sizeof(request), &response, sizeof(response));
        if (!status)
            return std::unexpected(status.error());
        return response;
    }

    [[nodiscard]] result<wire::HwBreakQueryResponse> hwbreak_query(
        pid process, uint32_t thread_id) const noexcept {
        auto request = wire::request<wire::HwBreakQueryRequest>();
        request.pid = process.value;
        request.tid = thread_id;
        wire::HwBreakQueryResponse response{};
        auto status = call(wire::opcode(wire::op::hwbreak_query), &request,
                           sizeof(request), &response, sizeof(response));
        if (!status)
            return std::unexpected(status.error());
        return response;
    }

    // External-process software-breakpoint hook (int3 shadow page, #BP VM-exit,
    // single-step of the original instruction). `flags` selects execute or
    // write trapping.
    [[nodiscard]] result<wire::SwBreakResponse> swbreak_arm(
        pid process, void* address,
        uint32_t flags = wire::swbreak_execute) const noexcept {
        auto request = wire::request<wire::SwBreakArmRequest>();
        request.pid = process.value;
        request.flags = flags;
        request.address = reinterpret_cast<uint64_t>(address);
        wire::SwBreakResponse response{};
        auto status = call(wire::opcode(wire::op::swbreak_arm), &request,
                           sizeof(request), &response, sizeof(response));
        if (!status)
            return std::unexpected(status.error());
        return response;
    }

    [[nodiscard]] result<wire::SwBreakResponse> swbreak_disarm(
        uint64_t id, pid process = {}, void* address = nullptr) const noexcept {
        auto request = wire::request<wire::SwBreakArmRequest>();
        request.id = static_cast<uint32_t>(id);
        request.pid = process.value;
        request.address = reinterpret_cast<uint64_t>(address);
        wire::SwBreakResponse response{};
        auto status = call(wire::opcode(wire::op::swbreak_disarm), &request,
                           sizeof(request), &response, sizeof(response));
        if (!status)
            return std::unexpected(status.error());
        return response;
    }

    [[nodiscard]] result<wire::SwBreakResponse> swbreak_query(
        pid process, void* address) const noexcept {
        auto request = wire::request<wire::SwBreakArmRequest>();
        request.pid = process.value;
        request.address = reinterpret_cast<uint64_t>(address);
        wire::SwBreakResponse response{};
        auto status = call(wire::opcode(wire::op::swbreak_query), &request,
                           sizeof(request), &response, sizeof(response));
        if (!status)
            return std::unexpected(status.error());
        return response;
    }

    template <byte_range Bytes>
    [[nodiscard]] result<hook> patch(void* address, Bytes&& bytes,
                                     pid target = pid::current()) const {
        const auto view = bytes_of(bytes);
        const auto at = reinterpret_cast<uint64_t>(address);
        if (!blook::valid_patch(at, view.size()) ||
            view.size() > sizeof(wire::InstallRequest::bytes))
            return std::unexpected(std::error_code{ERROR_INVALID_PARAMETER,
                                                   std::system_category()});
        auto request = wire::request<wire::InstallRequest>();
        request.pid = target.value;
        request.target = at;
        request.length = static_cast<uint32_t>(view.size());
        std::memcpy(request.bytes, view.data(), view.size());
        wire::InstallResponse response{};
        auto status = call(wire::opcode(wire::op::install), &request, sizeof(request),
                           &response, sizeof(response));
        if (!status)
            return std::unexpected(status.error());
        return hook{connection_, response.id};
    }

    // Redirect an entry point to a replacement of the caller's own, e.g. a
    // handler inside a DLL that is mapped into the target process.
    [[nodiscard]] result<hook> redirect(void* target, void* replacement,
                                        pid owner = pid::current()) const {
        if (!connection_)
            return std::unexpected(
                std::error_code{ERROR_INVALID_HANDLE, std::system_category()});
        const auto destination = reinterpret_cast<uint64_t>(replacement);
        if (!blook::user_address(destination))
            return std::unexpected(std::error_code{ERROR_INVALID_PARAMETER,
                                                   std::system_category()});
        // Park the literal in a page of its own, on the far side of the
        // patched one. It is deliberately never freed: the patch can execute
        // for as long as the hook lives, so the literal has to stay readable
        // and at the same address.
        void* literal = nullptr;
        if (owner.value == 0 || owner == pid::current()) {
            literal = VirtualAlloc(nullptr, sizeof(uint64_t),
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (literal)
                std::memcpy(literal, &destination, sizeof(destination));
        } else {
            HANDLE process = OpenProcess(
                PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, owner.value);
            if (process) {
                literal =
                    VirtualAllocEx(process, nullptr, sizeof(uint64_t),
                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (literal)
                    WriteProcessMemory(process, literal, &destination,
                                       sizeof(destination), nullptr);
                CloseHandle(process);
            }
        }
        if (!literal)
            return std::unexpected(std::error_code{ERROR_INVALID_PARAMETER,
                                                   std::system_category()});
        auto bytes = entry_jump(target, literal);
        if (!bytes)  // literal out of reach
            return std::unexpected(std::error_code{ERROR_INVALID_PARAMETER,
                                                   std::system_category()});
        return patch(target, *bytes, owner);
    }

    // Arm an execute watch on `address` in `target` (default: this process).
    // The first time the process executes exactly that address, the driver
    // dumps [dump_base, dump_base + dump_size) of the same process out of
    // physical memory and keeps it fetchable via the returned watch. This is
    // the anti self-decrypting-shell path: the dump does not go through any
    // user-mode API, so the sample cannot see it coming.
    //
    // `address` must be committed but does not have to be executable yet: a
    // watch armed on a non-executable page is registered dormant and is
    // published the moment a protection change makes the page executable.
    [[nodiscard]] result<watch> watch_execute(
        void* address, void* dump_base, size_t dump_size,
        pid target = pid::current()) const {
        if (!address || !dump_base || !dump_size || dump_size > blook::max_dump)
            return std::unexpected(std::error_code{ERROR_INVALID_PARAMETER,
                                                   std::system_category()});
        auto request = wire::request<wire::WatchRequest>();
        request.action = wire::watch_arm;
        request.pid = target.value;
        request.address = reinterpret_cast<uint64_t>(address);
        request.dump_base = reinterpret_cast<uint64_t>(dump_base);
        request.dump_size = dump_size;
        wire::WatchResponse response{};
        auto status = call(wire::opcode(wire::op::watch), &request, sizeof(request),
                           &response, sizeof(response));
        if (!status)
            return std::unexpected(status.error());
        return watch{connection_, response.id};
    }

    // Module-relative form: the watched address is base + offset, the dump
    // starts at base + dump_offset. With this the caller only has to know the
    // module's base in the target process and the RVAs of interest.
    [[nodiscard]] result<watch> watch_execute_at(
        void* base, size_t offset, size_t dump_offset, size_t dump_size,
        pid target = pid::current()) const {
        if (!base || !dump_size || dump_size > blook::max_dump)
            return std::unexpected(std::error_code{ERROR_INVALID_PARAMETER,
                                                   std::system_category()});
        auto request = wire::request<wire::WatchRequest>();
        request.action = wire::watch_arm;
        request.pid = target.value;
        request.base = reinterpret_cast<uint64_t>(base);
        request.address = offset;
        request.dump_base = dump_offset;
        request.dump_size = dump_size;
        wire::WatchResponse response{};
        auto status = call(wire::opcode(wire::op::watch), &request, sizeof(request),
                           &response, sizeof(response));
        if (!status)
            return std::unexpected(status.error());
        return watch{connection_, response.id};
    }

    [[nodiscard]] result<wire::ConfigurationResponse> query_configuration(
        bool reload = false) const noexcept {
        auto request = wire::request<wire::ConfigurationRequest>();
        request.reload = reload ? 1u : 0u;
        wire::ConfigurationResponse response{};
        auto status = call(wire::opcode(wire::op::configuration), &request,
                           sizeof(request), &response, sizeof(response));
        if (!status)
            return std::unexpected(status.error());
        if (response.header.version != wire::abi_version ||
            response.header.size != sizeof(response))
            return std::unexpected(
                std::error_code{ERROR_INVALID_DATA, std::system_category()});
        return response;
    }
    [[nodiscard]] result<wire::ConfigurationResponse> reload_configuration()
        const noexcept {
        return query_configuration(true);
    }
    [[nodiscard]] result<wire::FeaturesResponse> query_features()
        const noexcept {
        auto request = wire::request<wire::FeaturesRequest>();
        wire::FeaturesResponse response{};
        auto status = call(wire::opcode(wire::op::features), &request, sizeof(request),
                           &response, sizeof(response));
        if (!status)
            return std::unexpected(status.error());
        if (response.header.version != wire::abi_version ||
            response.header.size != sizeof(response))
            return std::unexpected(
                std::error_code{ERROR_INVALID_DATA, std::system_category()});
        return response;
    }
    [[nodiscard]] result<wire::FeaturesResponse> set_feature(
        uint32_t id, bool enabled) const noexcept {
        if (id >= static_cast<uint32_t>(blook::feature::id::count))
            return std::unexpected(std::error_code{ERROR_INVALID_PARAMETER,
                                                   std::system_category()});
        auto request = wire::request<wire::FeaturesRequest>();
        request.action = 1;
        request.id = id;
        request.enabled = enabled ? 1u : 0u;
        wire::FeaturesResponse response{};
        auto status = call(wire::opcode(wire::op::features), &request, sizeof(request),
                           &response, sizeof(response));
        if (!status)
            return std::unexpected(status.error());
        if (response.header.version != wire::abi_version ||
            response.header.size != sizeof(response))
            return std::unexpected(
                std::error_code{ERROR_INVALID_DATA, std::system_category()});
        return response;
    }

    [[nodiscard]] result<wire::FeaturesResponse> set_feature(
        blook::feature::id id, bool enabled) const noexcept {
        return set_feature(static_cast<uint32_t>(id), enabled);
    }

    [[nodiscard]] result<void> hide(bool enable) const noexcept {
        auto request = wire::request<wire::HideRequest>();
        request.enable_hide = enable ? 1u : 0u;
        return call(wire::opcode(wire::op::hide), &request, sizeof(request), nullptr,
                    0);
    }

    [[nodiscard]] result<void> hide_windows(bool enable) const noexcept {
        auto request = wire::request<wire::HideRequest>();
        request.enable_hide =
            enable ? wire::hide_windows_on : wire::hide_windows_off;
        return call(wire::opcode(wire::op::hide), &request, sizeof(request), nullptr,
                    0);
    }

    [[nodiscard]] result<void> pin(pid process,
                                   process_role role) const noexcept {
        auto request = wire::request<wire::HideRequest>();
        request.enable_hide = 2;
        request.pid = process.value;
        request.role = static_cast<uint32_t>(role);
        return call(wire::opcode(wire::op::hide), &request, sizeof(request), nullptr,
                    0);
    }

    [[nodiscard]] result<void> unpin(pid process) const noexcept {
        auto request = wire::request<wire::HideRequest>();
        request.enable_hide = 3;
        request.pid = process.value;
        return call(wire::opcode(wire::op::hide), &request, sizeof(request), nullptr,
                    0);
    }

    // Clear the debug artefacts a process can read out of its own structures.
    [[nodiscard]] result<void> scrub(pid process,
                                     scrub flags = scrub::all) const noexcept {
        auto request = wire::request<wire::ScrubRequest>();
        request.pid = process.value;
        request.flags = static_cast<uint32_t>(flags);
        return call(wire::opcode(wire::op::scrub), &request, sizeof(request), nullptr,
                    0);
    }
};
}  // namespace blook::client
