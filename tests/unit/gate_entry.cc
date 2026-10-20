#include <gtest/gtest.h>

#include <array>
#include <initializer_list>
#include <vector>

#include "policy/gate_entry.hpp"

namespace {
using blook::x86::gate_patch_bytes;
using blook::x86::safe_gate_entry_length;

void accepts(std::initializer_list<uint8_t> bytes) {
    const std::vector<uint8_t> code(bytes);
    EXPECT_EQ(safe_gate_entry_length(code.data(), code.size()), code.size());
    // Every truncated view must be rejected, including missing displacement
    // and immediate bytes. This exercises the input contract without padding.
    for (size_t n = 0; n < code.size(); ++n)
        EXPECT_EQ(safe_gate_entry_length(code.data(), n), 0u) << n;
}

void rejects(std::initializer_list<uint8_t> bytes) {
    const std::vector<uint8_t> code(bytes);
    EXPECT_EQ(safe_gate_entry_length(code.data(), code.size()), 0u);
}

TEST(GateEntry, AcceptsKnownRegisterAndStackMoves) {
    accepts({0x48, 0x89, 0xe5});  // mov rbp,rsp
    accepts({0x48, 0x8b, 0xec});  // mov rbp,rsp (other direction encoding)
    accepts({0x4c, 0x8b, 0xdc});  // mov r11,rsp
    accepts({0x49, 0x89, 0xca});  // mov r10,rcx
    accepts({0x44, 0x8b, 0xc1});  // mov r8d,ecx
    accepts({0x48, 0x89, 0x5c, 0x24, 0x08});  // mov [rsp+8],rbx
    accepts({0x4c, 0x89, 0x04, 0x24});        // mov [rsp],r8
    accepts({0x48, 0x8b, 0x84, 0x24, 0x00, 0x01, 0x00, 0x00});
    accepts({0x48, 0x89, 0x6d, 0xf0});  // mov [rbp-16],rbp
    accepts({0x48, 0x8b, 0x85, 0x00, 0xff, 0xff, 0xff});
}

TEST(GateEntry, AcceptsOnlyExactStackArithmeticForms) {
    accepts({0x48, 0x83, 0xec, 0x28});
    accepts({0x48, 0x83, 0xc4, 0x28});
    accepts({0x48, 0x81, 0xec, 0x00, 0x01, 0x00, 0x00});
    accepts({0x48, 0x81, 0xc4, 0x00, 0x01, 0x00, 0x00});
    rejects({0x40, 0x83, 0xec, 0x28});        // sub esp
    rejects({0x49, 0x83, 0xec, 0x28});        // sub r12
    rejects({0x48, 0x83, 0xe4, 0xf0});        // and rsp
    rejects({0x48, 0x83, 0xed, 0x28});        // sub rbp
    rejects({0x48, 0x83, 0x2c, 0x24, 0x28});  // sub [rsp]
}

TEST(GateEntry, EndbrIsExactAndDecoderChecked) {
    accepts({0xf3, 0x0f, 0x1e, 0xfa});
    rejects({0xf3, 0x0f, 0x1e, 0xfb});  // ENDBR32
    rejects({0x0f, 0x1e, 0xfa});
    rejects({0xf2, 0x0f, 0x1e, 0xfa});
    rejects({0xf3, 0xf3, 0x0f, 0x1e, 0xfa});
}

TEST(GateEntry, RejectsEveryLegacyPrefixOnOtherwiseSafeInstructions) {
    constexpr uint8_t prefixes[] = {0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65,
                                    0x66, 0x67, 0xf0, 0xf2, 0xf3};
    for (auto prefix : prefixes) {
        const uint8_t mov[] = {prefix, 0x48, 0x89, 0x5c, 0x24, 0x08};
        const uint8_t sub[] = {prefix, 0x48, 0x81, 0xec, 0, 1, 0, 0};
        const uint8_t endbr[] = {prefix, 0xf3, 0x0f, 0x1e, 0xfa};
        const uint8_t reordered[] = {0x48, prefix, 0x89, 0xe5};
        EXPECT_EQ(safe_gate_entry_length(mov, sizeof(mov)), 0u) << +prefix;
        EXPECT_EQ(safe_gate_entry_length(sub, sizeof(sub)), 0u) << +prefix;
        EXPECT_EQ(safe_gate_entry_length(endbr, sizeof(endbr)), 0u) << +prefix;
        EXPECT_EQ(safe_gate_entry_length(reordered, sizeof(reordered)), 0u);
    }
    rejects({0x48, 0x48, 0x89, 0xe5});
    rejects({0x67, 0x48, 0x8b, 0x05, 0, 0, 0, 0});
    rejects({0x66, 0x81, 0xec, 0x28, 0, 0x90, 0x90});
}

TEST(GateEntry, RejectsRelocationAndUnknownAddressing) {
    rejects({0x48, 0x8b, 0x05, 0, 0, 0, 0});        // RIP load
    rejects({0x48, 0x89, 0x05, 0, 0, 0, 0});        // RIP store
    rejects({0x48, 0x8d, 0x05, 0, 0, 0, 0});        // RIP lea
    rejects({0x48, 0x8b, 0x04, 0x25, 0, 0, 0, 0});  // absolute SIB
    rejects({0x48, 0x8b, 0x04, 0x64});  // noncanonical no-index scale
    rejects({0x48, 0x8b, 0x04, 0x4c});  // [rsp+rcx*2]
    rejects({0x4a, 0x8b, 0x04, 0x24});  // [rsp+r12]
    rejects({0x49, 0x8b, 0x04, 0x24});  // [r12]
    rejects({0x49, 0x8b, 0x45, 0x00});  // [r13]
    rejects({0x48, 0x8b, 0x01});        // [rcx]: outside whitelist
    rejects({0xe8, 0, 0, 0, 0});
    rejects({0xe9, 0, 0, 0, 0});
    rejects({0xeb, 0, 0x90});
    rejects({0x0f, 0x85, 0, 0, 0, 0});
    rejects({0x75, 0, 0x90});
    rejects({0xe2, 0, 0x90});
    rejects({0x48, 0xff, 0xd0});  // indirect call
    rejects({0x48, 0xff, 0xe0});  // indirect jump
    rejects({0x48, 0x31, 0xc0});  // unlisted arithmetic
    rejects({0x0f, 0x01, 0xc1});  // VMCALL itself
    rejects({0xc5, 0xf8, 0x77});
    rejects({0x0f, 0x1f, 0x00});  // optional NOP support not enabled
}

TEST(GateEntry, NeverCombinesAnythingButRegisterPushes) {
    rejects({0x55, 0x48, 0x89, 0xe5});  // push then mov: mixed run
    rejects({0x90, 0x90, 0x90});        // short instructions are not padding
    rejects({0x40, 0x55, 0x90});        // push then nop: mixed run
    const uint8_t code[] = {0x48, 0x89, 0xe5, 0xe8, 0, 0, 0, 0};
    EXPECT_EQ(safe_gate_entry_length(code, sizeof(code)), 3u);
    EXPECT_EQ(safe_gate_entry_length(nullptr, 0), 0u);
    EXPECT_EQ(safe_gate_entry_length(nullptr, 15), 0u);
}

TEST(GateEntry, AcceptsOnlyExactRegisterPushRuns) {
    const auto run = [](std::initializer_list<uint8_t> bytes) {
        const std::vector<uint8_t> code(bytes);
        return safe_gate_entry_length(code.data(), code.size());
    };
    // The saved-register prologue of the current nt!NtQueryInformationProcess:
    // push rbx; push rsi is the first run that reaches the 3-byte gate.
    EXPECT_EQ(run({0x40, 0x53, 0x56}), 3u);
    EXPECT_EQ(run({0x40, 0x53, 0x56, 0x57}), 3u);  // stops on the boundary
    EXPECT_EQ(run({0x55, 0x56, 0x57}), 3u);
    EXPECT_EQ(run({0x56, 0x41, 0x54}), 3u);
    EXPECT_EQ(run({0x41, 0x54, 0x41, 0x55}), 4u);  // two prefixed pushes

    // Anything that is not a pure 64-bit register push run stays refused.
    EXPECT_EQ(run({0x50, 0x58, 0x5c}), 0u);  // push/pop mix
    EXPECT_EQ(run({0x5c, 0x5c, 0x5c}), 0u);  // pops
    EXPECT_EQ(run({0x50, 0x90, 0x90}), 0u);  // push then nop
    EXPECT_EQ(run({0x41, 0x54, 0x90}), 0u);
    EXPECT_EQ(run({0x40, 0x53}), 0u);        // shorter than the gate
    EXPECT_EQ(run({0x40, 0x40, 0x53}), 0u);  // double REX
    EXPECT_EQ(run({0x40, 0x53, 0x40}), 0u);  // dangling REX
}

TEST(GateEntry, PatchCoversTheWholePushRun) {
    const uint8_t code[] = {0x40, 0x53, 0x56, 0x57, 0xcc};
    std::array<uint8_t, 5> out;
    out.fill(0xa5);
    ASSERT_EQ(gate_patch_bytes(code, sizeof(code), out.data(), out.size()), 3u);
    const std::array<uint8_t, 5> expected = {0x0f, 0x01, 0xc1, 0xa5, 0xa5};
    EXPECT_EQ(out, expected);
}

TEST(GateEntry, PatchFillsExactlyOneInstructionAndSupportsAliasing) {
    const uint8_t code[] = {0x48, 0x81, 0xec, 0, 1, 0, 0, 0xcc};
    std::array<uint8_t, 9> out;
    out.fill(0xa5);
    ASSERT_EQ(gate_patch_bytes(code, sizeof(code), out.data(), out.size()), 7u);
    const std::array<uint8_t, 9> expected = {0x0f, 0x01, 0xc1, 0x90, 0x90,
                                             0x90, 0x90, 0xa5, 0xa5};
    EXPECT_EQ(out, expected);
    uint8_t inplace[] = {0x48, 0x89, 0xe5, 0xcc};
    ASSERT_EQ(
        gate_patch_bytes(inplace, sizeof(inplace), inplace, sizeof(inplace)),
        3u);
    EXPECT_EQ(inplace[0], 0x0f);
    EXPECT_EQ(inplace[1], 0x01);
    EXPECT_EQ(inplace[2], 0xc1);
    EXPECT_EQ(inplace[3], 0xcc);
}

TEST(GateEntry, PatchFailureDoesNotWrite) {
    const uint8_t code[] = {0x48, 0x83, 0xec, 0x28};
    const uint8_t unsafe[] = {0xe8, 0, 0, 0, 0};
    std::array<uint8_t, 8> out;
    out.fill(0xa5);
    const auto original = out;
    EXPECT_EQ(gate_patch_bytes(code, sizeof(code), out.data(), 3), 0u);
    EXPECT_EQ(out, original);
    EXPECT_EQ(gate_patch_bytes(unsafe, sizeof(unsafe), out.data(), out.size()),
              0u);
    EXPECT_EQ(out, original);
    EXPECT_EQ(gate_patch_bytes(code, 3, out.data(), out.size()), 0u);
    EXPECT_EQ(out, original);
    EXPECT_EQ(gate_patch_bytes(nullptr, 8, out.data(), out.size()), 0u);
    EXPECT_EQ(out, original);
    EXPECT_EQ(gate_patch_bytes(code, sizeof(code), nullptr, 8), 0u);
}
}  // namespace
