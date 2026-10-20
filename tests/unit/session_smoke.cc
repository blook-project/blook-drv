// Live smoke test: requires an installed BlookDrv service, an administrator
// token and a CPU with VT-x. Runs only when explicitly requested; the host-only
// suite never builds it.
#include <gtest/gtest.h>
#include <windows.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "blook/drv/ept.hpp"

namespace {
using namespace blook::client;

// A page we own, executable, aligned to a page boundary. The hook tests patch
// this process's own code, never another process's.
struct code_page {
    void* memory{};
    code_page() {
        memory = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE);
    }
    ~code_page() {
        if (memory)
            VirtualFree(memory, 0, MEM_RELEASE);
    }
    code_page(const code_page&) = delete;
    code_page& operator=(const code_page&) = delete;
};

std::uint32_t call_returns_7() {
    return 7;
}
}  // namespace

TEST(SessionSmoke, OpensAndReportsState) {
    auto opened = session::open(open_mode::read_only);
    ASSERT_TRUE(opened.has_value()) << "attach to the driver";
    const auto info = opened->query();
    ASSERT_TRUE(info.has_value()) << "query";
    EXPECT_TRUE(info->running) << "hypervisor is virtualizing every CPU";
    EXPECT_EQ(info->abi, wire::abi_version);
    const auto hv = opened->hv_info();
    ASSERT_TRUE(hv.has_value()) << "hv_info";
    EXPECT_NE(hv->flags & wire::hv_flag_running, 0u);
}

TEST(SessionSmoke, PatchOwnCodeAndRemove) {
    auto opened = session::open();
    ASSERT_TRUE(opened.has_value());
    // The hook may only cover whole instructions: mov eax, 42; ret is 6 bytes.
    const std::array<std::byte, 6> patch{std::byte{0xb8}, std::byte{42},
                                         std::byte{0},    std::byte{0},
                                         std::byte{0},    std::byte{0xc3}};
    auto installed =
        opened->patch(reinterpret_cast<void*>(&call_returns_7), patch);
    ASSERT_TRUE(installed.has_value()) << "install hook";
    EXPECT_EQ(call_returns_7(), 42u) << "hooked call returns the patched value";
    EXPECT_TRUE(installed->remove().has_value()) << "remove hook";
    EXPECT_EQ(call_returns_7(), 7u) << "original restored";
}

TEST(SessionSmoke, HideSelfAndTraceScan) {
    auto opened = session::open();
    ASSERT_TRUE(opened.has_value());
    const auto scan = opened->trace_scan();
    ASSERT_TRUE(scan.has_value()) << "trace_scan";
    // Before hiding, the module list must contain us.
    EXPECT_NE(scan->found & wire::trace_module_list, 0u);
    EXPECT_TRUE(opened->hide_self().has_value()) << "hide self";
    const auto after = opened->trace_scan();
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(after->found & wire::trace_module_list, 0u) << "unlinked";
    EXPECT_EQ(after->found & (wire::trace_device | wire::trace_symlink), 0u)
        << "there is no device and no symbolic link by design";
}
