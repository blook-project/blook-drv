#include "blook/drv/wire.hpp"

#include <gtest/gtest.h>

#include <array>
#include <concepts>
#include <cstddef>
#include <initializer_list>
#include <type_traits>

namespace {
template <class... Ts>
constexpr bool wire_value_types =
    ((std::is_standard_layout_v<Ts> && std::is_trivially_copyable_v<Ts>) &&
     ...);

static_assert(
    wire_value_types<wire::Header, wire::PingRequest, wire::PingResponse,
                     wire::VersionInfo, wire::EnableRequest, wire::InstallRequest,
                     wire::InstallResponse, wire::HookRequest, wire::HideRequest,
                     wire::ScrubRequest, wire::QueryResponse, wire::WatchRequest,
                     wire::WatchResponse, wire::DumpRequest, wire::DumpResponse>);

template <class T>
concept HasFactory = requires {
    { wire::request<T>() } noexcept -> std::same_as<T>;
};
template <class T>
concept HasHeaderValidator = requires(const T& value) {
    { wire::valid_header<T>(value) } noexcept -> std::same_as<bool>;
};

struct HeaderLookalike {
    wire::Header header{};
};
struct DerivedRequest : wire::EnableRequest {};

template <class... Ts>
constexpr bool rejected_types =
    ((!HasFactory<Ts> && !HasHeaderValidator<Ts>) && ...);
static_assert(
    rejected_types<int, wire::Header, wire::PingResponse, wire::VersionInfo,
                   wire::InstallResponse, wire::QueryResponse, wire::WatchResponse,
                   wire::DumpResponse, HeaderLookalike, DerivedRequest,
                   const wire::PingRequest, volatile wire::PingRequest,
                   wire::PingRequest&>);

constexpr bool initialized_fields(const wire::PingRequest& value) {
    return value.magic == 0;
}
constexpr bool initialized_fields(const wire::EnableRequest&) {
    return true;  // No payload fields.
}
constexpr bool initialized_fields(const wire::InstallRequest& value) {
    if (value.pid != 0 || value.flags != 0 || value.target != 0 ||
        value.length != 0 || value.reserved != 0)
        return false;
    for (const auto byte : value.bytes)
        if (byte != 0)
            return false;
    return true;
}
constexpr bool initialized_fields(const wire::HookRequest& value) {
    return value.id == 0;
}
constexpr bool initialized_fields(const wire::HideRequest& value) {
    return value.enable_hide == 0 && value.pid == 0 && value.role == 0 &&
           value.reserved == 0;
}
constexpr bool initialized_fields(const wire::ScrubRequest& value) {
    return value.pid == 0 && value.flags == 0;
}
constexpr bool initialized_fields(const wire::WatchRequest& value) {
    return value.address == 0 && value.base == 0 && value.dump_base == 0 &&
           value.dump_size == 0 && value.id == 0 && value.pid == 0 &&
           value.action == 0;
}
constexpr bool initialized_fields(const wire::ConfigurationRequest& value) {
    return !value.reload && !value.reserved;
}
constexpr bool initialized_fields(const wire::FeaturesRequest& value) {
    return !value.action && !value.id && !value.enabled && !value.reserved;
}
constexpr bool initialized_fields(const wire::QueryPageRequest& value) {
    return !value.address && !value.pid && !value.domain && !value.reserved &&
           !value.reserved2;
}
constexpr bool initialized_fields(const wire::DumpRequest& value) {
    return value.id == 0 && value.offset == 0 && value.length == 0 &&
           value.reserved == 0;
}

template <wire::WireRequest T>
constexpr bool factory_contract() {
    const auto value = wire::request<T>();
    return HasFactory<T> && HasHeaderValidator<T> &&
           value.header.version == wire::abi_version &&
           value.header.size == sizeof(T) && wire::valid_header(value) &&
           initialized_fields(value);
}
static_assert(factory_contract<wire::PingRequest>());
static_assert(factory_contract<wire::EnableRequest>());
static_assert(factory_contract<wire::InstallRequest>());
static_assert(factory_contract<wire::HookRequest>());
static_assert(factory_contract<wire::HideRequest>());
static_assert(factory_contract<wire::ScrubRequest>());
static_assert(factory_contract<wire::WatchRequest>());
static_assert(factory_contract<wire::DumpRequest>());
static_assert(factory_contract<wire::QueryPageRequest>());
static_assert(factory_contract<wire::ConfigurationRequest>());
static_assert(factory_contract<wire::FeaturesRequest>());
static_assert(
    wire_value_types<wire::ConfigurationRequest, wire::ConfigurationResponse,
                     wire::FeaturesRequest, wire::FeaturesResponse>);
static_assert(
    rejected_types<wire::ConfigurationResponse, wire::FeaturesResponse>);
static_assert(alignof(wire::ConfigurationRequest) == 4);
static_assert(offsetof(wire::ConfigurationRequest, reload) == 8);
static_assert(offsetof(wire::ConfigurationRequest, reserved) == 12);
static_assert(alignof(wire::ConfigurationResponse) == 8);
static_assert(offsetof(wire::ConfigurationResponse, generation) == 8);
static_assert(offsetof(wire::ConfigurationResponse, features) == 16);
static_assert(offsetof(wire::ConfigurationResponse, allow_users) == 24);
static_assert(offsetof(wire::ConfigurationResponse, restart_required) == 28);
static_assert(offsetof(wire::ConfigurationResponse, last_status) == 32);
static_assert(offsetof(wire::ConfigurationResponse, error_line) == 36);
static_assert(alignof(wire::FeaturesRequest) == 4);
static_assert(offsetof(wire::FeaturesRequest, action) == 8);
static_assert(offsetof(wire::FeaturesRequest, id) == 12);
static_assert(offsetof(wire::FeaturesRequest, enabled) == 16);
static_assert(offsetof(wire::FeaturesRequest, reserved) == 20);
static_assert(alignof(wire::FeaturesResponse) == 8);
static_assert(offsetof(wire::FeaturesResponse, desired) == 8);
static_assert(offsetof(wire::FeaturesResponse, effective) == 16);
static_assert(offsetof(wire::FeaturesResponse, unsupported) == 24);
static_assert(offsetof(wire::FeaturesResponse, last_status) == 32);
static_assert(offsetof(wire::FeaturesResponse, reserved) == 36);
static_assert(wire_value_types<wire::QueryPageRequest, wire::PageHookRow,
                               wire::QueryPageResponse>);
static_assert(rejected_types<wire::QueryPageResponse, wire::PageHookRow>);
static_assert(wire::page_hook_capacity == 64);
static_assert(sizeof(wire::QueryPageResponse) < 4096);

static_assert(wire::abi_version == 7);
static_assert(wire::PingRequest::kMagic == 0x424c4f4b);
static_assert(wire::PingResponse::kMagic == 0x4b4f4c42);
static_assert(wire::PingResponse::kStatusOk == 0);
static_assert(wire::kDriverVersion.major == 4 &&
              wire::kDriverVersion.minor == 0 &&
              wire::kDriverVersion.patch == 0 &&
              wire::kDriverVersion.reserved == 0);
static_assert(wire::hide_role_tool == 1 && wire::hide_role_target == 2);
static_assert(wire::hide_windows_on == 4 && wire::hide_windows_off == 5);
static_assert(wire::scrub_peb == 1 && wire::scrub_heap == 2 &&
              wire::scrub_all == 3);
static_assert(wire::watch_arm == 1 && wire::watch_disarm == 2);

// Every message is one kchannel application opcode (>= 0x8000, see the
// blook-kchannel ABI). The table is the whole wire surface: a duplicate would
// route two payload types into one handler, and an opcode below the application
// range would collide with the transport's own opcodes.
constexpr std::array opcodes{
    wire::opcode(wire::op::ping),           wire::opcode(wire::op::get_version),
    wire::opcode(wire::op::enable),         wire::opcode(wire::op::install),
    wire::opcode(wire::op::remove),         wire::opcode(wire::op::refresh),
    wire::opcode(wire::op::query),          wire::opcode(wire::op::hide),
    wire::opcode(wire::op::scrub),          wire::opcode(wire::op::stats),
    wire::opcode(wire::op::probe),          wire::opcode(wire::op::watch),
    wire::opcode(wire::op::dump),           wire::opcode(wire::op::query_page),
    wire::opcode(wire::op::configuration),  wire::opcode(wire::op::features),
    wire::opcode(wire::op::hide_self),      wire::opcode(wire::op::swbreak_arm),
    wire::opcode(wire::op::swbreak_disarm), wire::opcode(wire::op::swbreak_query),
    wire::opcode(wire::op::hwbreak_arm),    wire::opcode(wire::op::hwbreak_disarm),
    wire::opcode(wire::op::hwbreak_query),  wire::opcode(wire::op::detect_probe),
    wire::opcode(wire::op::hv_info),        wire::opcode(wire::op::trace_scan),
};
constexpr bool opcode_contract() {
    for (std::size_t i = 0; i < opcodes.size(); ++i) {
        const auto code = opcodes[i];
        if (code < 0x8000u || code >= 0x9000u)
            return false;
        for (std::size_t j = i + 1; j < opcodes.size(); ++j)
            if (code == opcodes[j])
                return false;
    }
    return true;
}
static_assert(opcode_contract());

template <wire::WireRequest T>
void test_request() {
    auto value = wire::request<T>();
    ASSERT_TRUE((value.header.version == wire::abi_version))
        << "factory initializes the current ABI";
    ASSERT_TRUE((value.header.size == sizeof(T)))
        << "factory initializes exact wire size";
    ASSERT_TRUE((wire::valid_header(value)))
        << "factory produces a valid header";
    // Inspect named fields only: padding bytes are not part of this contract.
    ASSERT_TRUE((initialized_fields(value)))
        << "factory initializes all payload fields";
    ASSERT_TRUE((!wire::valid_header(T{}))) << "default request lacks wire size";

    for (const uint32_t version : {0u, 3u, 4u, wire::abi_version - 1,
                                   wire::abi_version + 1, 0xffffffffu}) {
        value = wire::request<T>();
        value.header.version = version;
        ASSERT_TRUE((!wire::valid_header(value)))
            << "reject unsupported version with valid size";
    }
    for (const uint32_t size :
         {0u, static_cast<uint32_t>(sizeof(T) - 1),
          static_cast<uint32_t>(sizeof(T) + 1), 0xffffffffu}) {
        value = wire::request<T>();
        value.header.size = size;
        ASSERT_TRUE((!wire::valid_header(value)))
            << "reject invalid size with valid version";
    }
    value.header.version = 0;
    ASSERT_TRUE((!wire::valid_header(value)))
        << "reject invalid version and size together";
    value = wire::request<T>();
    ASSERT_TRUE((wire::valid_header(value))) << "restored header is valid";
}

TEST(ProtocolTest, ResponseValueInitialization) {
    const wire::Header header{};
    ASSERT_TRUE((header.version == wire::abi_version && header.size == 0))
        << "header member defaults";
    const wire::PingResponse ping{};
    ASSERT_TRUE((ping.magic == 0 && ping.status == 0))
        << "ping response member defaults";
    const wire::VersionInfo version{};
    ASSERT_TRUE((version.major == 0 && version.minor == 0 &&
                 version.patch == 0 && version.reserved == 0))
        << "version value initialization";
    const wire::InstallResponse install{};
    ASSERT_TRUE((install.id == 0)) << "install response member defaults";
    const wire::QueryResponse query{};
    ASSERT_TRUE((query.version == 0 && query.running == 0 &&
                 query.enabled == 0 && query.hooks == 0 && query.hidden == 0 &&
                 query.abi == 0 && query.backend_status == 0 &&
                 query.window_hooks == 0 && query.hv_flags == 0 &&
                 query.swbreak_count == 0 && query.hwbreak_count == 0 &&
                 query.self_hidden == 0))
        << "query response member defaults";
}

TEST(ProtocolTest, OpcodeRangeAndUniqueness) {
    for (std::size_t i = 0; i < opcodes.size(); ++i) {
        const auto code = opcodes[i];
        ASSERT_TRUE((code >= 0x8000u && code < 0x9000u))
            << "application opcode stays in the kchannel client range";
        for (std::size_t j = i + 1; j < opcodes.size(); ++j)
            ASSERT_TRUE((code != opcodes[j]))
                << "opcodes are pairwise unique";
    }
}

TEST(ProtocolTest, PingRequestFactoryAndHeaderValidation) {
    test_request<wire::PingRequest>();
}

TEST(ProtocolTest, EnableRequestFactoryAndHeaderValidation) {
    test_request<wire::EnableRequest>();
}

TEST(ProtocolTest, InstallRequestFactoryAndHeaderValidation) {
    test_request<wire::InstallRequest>();
}

TEST(ProtocolTest, HookRequestFactoryAndHeaderValidation) {
    test_request<wire::HookRequest>();
}

TEST(ProtocolTest, HideRequestFactoryAndHeaderValidation) {
    test_request<wire::HideRequest>();
}

TEST(ProtocolTest, ScrubRequestFactoryAndHeaderValidation) {
    test_request<wire::ScrubRequest>();
}

TEST(ProtocolTest, WatchRequestFactoryAndHeaderValidation) {
    test_request<wire::WatchRequest>();
}

TEST(ProtocolTest, ConfigurationAndFeatureRequestFactoryAndHeaderValidation) {
    test_request<wire::ConfigurationRequest>();
    test_request<wire::FeaturesRequest>();
}

TEST(ProtocolTest, QueryPageRequestFactoryAndHeaderValidation) {
    test_request<wire::QueryPageRequest>();
    const wire::QueryPageResponse response{};
    EXPECT_EQ(response.entry_count, 0u);
    EXPECT_EQ(response.registered_count, 0u);
    for (const auto& row : response.entries) {
        EXPECT_EQ(row.id, 0u);
        EXPECT_EQ(row.target, 0u);
        EXPECT_EQ(row.armed, 0u);
        EXPECT_EQ(row.dormant, 0u);
    }
}

TEST(ProtocolTest, DumpRequestFactoryAndHeaderValidation) {
    test_request<wire::DumpRequest>();
}
}  // namespace
