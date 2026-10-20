#pragma once

#include <stddef.h>
#include <stdint.h>

#include "x86_length.hpp"

namespace blook::x86 {

// Deliberately narrower than instruction_length: one understood, position-
// independent instruction large enough for VMCALL. This is an internal gate
// policy, not a general relocator and not the policy for raw hooks. The caller
// must provide readable bytes and separately preserve/replay this instruction.
//
// Services whose prologue opens with a saved-register block (current
// NtQueryInformationProcess: 40 53 56 57 ...) have no first instruction large
// enough for the 3-byte gate, so an exact run of register pushes is admitted
// as a whole. Pushes of 64-bit registers touch no memory, carry no
// instruction-address dependency and replay verbatim from the trampoline, so
// the position independence the gate needs still holds. Nothing else is ever
// combined: no mixed runs, no other short instructions, no tail inspection.
inline size_t push_run_length(const uint8_t* code, size_t available) {
    size_t total = 0;
    while (total < 3) {
        // push r64 with an optional REX prefix. The REX byte is admitted only
        // as part of that push, so a lone prefix can never be consumed.
        if (total < available && code[total] >= 0x50 && code[total] <= 0x57)
            total += 1;
        else if (total + 1 < available && (code[total] & 0xf0) == 0x40 &&
                 code[total + 1] >= 0x50 && code[total + 1] <= 0x57)
            total += 2;
        else
            return 0;
    }
    // The loop stops at the first instruction boundary at or past the gate
    // size, so a run covers three or four bytes and never more.
    return total;
}
inline size_t safe_gate_entry_length(const uint8_t* code, size_t available) {
    if (!code || available < 3)
        return 0;

    size_t expected = 0;
    // Only this exact legacy-prefix form is admitted. In particular, address-
    // size, operand-size, segment, LOCK, REP and repeated REX prefixes must not
    // inherit the permissive length decoder's interpretation.
    if (available >= 4 && code[0] == 0xf3 && code[1] == 0x0f &&
        code[2] == 0x1e && code[3] == 0xfa) {
        expected = 4;  // ENDBR64 (not ENDBR32)
    } else if ((code[0] & 0xf0) == 0x40) {
        const uint8_t rex = code[0];
        const uint8_t op = code[1];
        const uint8_t modrm = code[2];
        const unsigned mod = modrm >> 6;
        const unsigned rm = modrm & 7;
        if (op == 0x89 || op == 0x8b) {
            // MOV r32/r64, r32/r64; no instruction-address dependency.
            if (mod == 3) {
                expected = 3;
            } else {
                // Admit only [rsp + disp] and [rbp + disp], not r12/r13,
                // indexed SIB, absolute addressing, or RIP-relative addressing.
                if ((rex & 3) != 0)
                    return 0;  // REX.X / REX.B
                const size_t disp = mod == 1 ? 1 : (mod == 2 ? 4 : 0);
                if (rm == 4) {
                    if (available < 4 || code[3] != 0x24)
                        return 0;  // SIB: scale=0, no index, base=rsp
                    expected = 4 + disp;
                } else if (rm == 5 && mod != 0) {
                    expected = 3 + disp;
                } else {
                    return 0;
                }
            }
        } else if (rex == 0x48 && (op == 0x81 || op == 0x83) &&
                   (modrm == 0xc4 || modrm == 0xec)) {
            // ADD/SUB rsp, sign-extended imm8/imm32. Do not accept ESP or
            // similarly encoded arithmetic on another register or memory.
            expected = op == 0x83 ? 4 : 7;
        }
    }

    if (expected >= 3 && expected <= available && expected <= 15)
        // Decode only the selected first instruction; fail closed on
        // disagreement with the length decoder.
        return instruction_length(code, expected) == expected ? expected : 0;
    return push_run_length(code, available);
}

// Build the entire first-instruction patch without touching following bytes.
// A rejected input or insufficient capacity leaves output unchanged. Output
// may alias code because validation finishes before any writes are performed.
inline size_t gate_patch_bytes(const uint8_t* code, size_t available,
                               uint8_t* output, size_t capacity) {
    const size_t length = safe_gate_entry_length(code, available);
    if (!length || !output || capacity < length)
        return 0;
    output[0] = 0x0f;
    output[1] = 0x01;
    output[2] = 0xc1;
    for (size_t i = 3; i < length; ++i)
        output[i] = 0x90;
    return length;
}

}  // namespace blook::x86
