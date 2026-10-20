#include "gate_landing.hpp"
#include <ntimage.h>
#include "policy/x86_length.hpp"

namespace blook {
void* system_return_landing() {
    // Decode from an exported function boundary, never search for a C3 byte
    // inside an immediate. Refuse control transfers before the return.
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"PsGetCurrentProcessId");
    auto* start = static_cast<unsigned char*>(MmGetSystemRoutineAddress(&name));
    if (!start)
        return nullptr;
    // The WDK declares RtlPcToFileHeader for user mode only, so resolve the
    // kernel export by name instead of pulling in the user-mode headers.
    using pc_to_file_header = PVOID(NTAPI*)(PVOID, PVOID*);
    UNICODE_STRING resolver = RTL_CONSTANT_STRING(L"RtlPcToFileHeader");
    const auto pc_to_file = reinterpret_cast<pc_to_file_header>(
        MmGetSystemRoutineAddress(&resolver));
    if (!pc_to_file)
        return nullptr;
    void* image{};
    if (!pc_to_file(start, &image) || !image)
        return nullptr;
    __try {
        const auto* base = static_cast<const unsigned char*>(image);
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 ||
            dos->e_lfanew > 0x100000)
            return nullptr;
        const auto* nt =
            reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return nullptr;
        const auto* sections = IMAGE_FIRST_SECTION(nt);
        size_t available = 0;
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            const auto& section = sections[i];
            const auto begin =
                reinterpret_cast<uintptr_t>(base) + section.VirtualAddress;
            const auto end = begin + section.Misc.VirtualSize;
            const auto at = reinterpret_cast<uintptr_t>(start);
            if (at >= begin && at < end &&
                (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) &&
                (section.Characteristics & IMAGE_SCN_MEM_NOT_PAGED) &&
                !(section.Characteristics & IMAGE_SCN_MEM_DISCARDABLE)) {
                available = static_cast<size_t>(end - at);
                break;
            }
        }
        if (available > 64)
            available = 64;
        for (size_t offset = 0; offset < available;) {
            const auto* code = start + offset;
            if (*code == 0xc3)
                return start + offset;
            // A tiny allowlist is intentional: this known getter is straight
            // line MOV code. Refuse jumps, calls, arbitrary opcode guesses.
            size_t opcode = 0;
            if (code[opcode] == 0x65)
                ++opcode;
            if (opcode < available - offset && (code[opcode] & 0xf0) == 0x40)
                ++opcode;
            if (opcode >= available - offset ||
                (code[opcode] != 0x8b && code[opcode] != 0x89))
                return nullptr;
            const auto step = x86::instruction_length(code, available - offset);
            if (!step || step > 15)
                return nullptr;
            offset += static_cast<size_t>(step);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
    return nullptr;
}
}  // namespace blook
