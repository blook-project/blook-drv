#pragma once
#include <ntifs.h>
#include <stddef.h>

namespace hv {
struct vcpu;

namespace hook_gate {
inline constexpr size_t capacity = 64;

// Guest-mode management only. Callers serialize this lifecycle with patch
// installation/removal. All addresses must be resident kernel code. prepare
// must validate that ret is a C3 instruction in a trusted, nonpageable external
// kernel image and that covered is exactly ONE decoded instruction (3..15).
// Every registration in a session uses the same ret landing address.
NTSTATUS register_gate(void const* target, void const* shim, void const* ret,
                       size_t covered);
// Publish BEFORE the first CPU's patch is armed. Once armed, metadata is never
// removed/reused until every CPU has stopped virtualization, even on rollback.
NTSTATUS mark_armed(void const* target);
NTSTATUS unregister_unarmed(void const* target);

// Closing rejects management additions, NOT entries through existing gates.
// Required teardown: closing -> all-CPU unpatch ACK -> count zero -> all-CPU
// stop ACK -> reset/free. count zero alone does NOT retire a root-mode tail.
void mark_closing();
bool is_closing();
LONG64 inflight_count();
// Power resume only, after all-CPU unpatch and drain. Keeps armed metadata.
NTSTATUS reopen_after_drain();
// Caller must have all-CPU stop ACK. Refuses reset while references remain.
NTSTATUS reset_after_stop();

// Root-mode: exact CPL0/RIP recognition, no allocation/OS calls/guest-stack
// access. Preserves every guest GPR and RSP. True includes a rejected leave
// (injected #UD), so normal tagged hypercall dispatch must not run afterwards.
bool handle_gate_vmcall(vcpu* cpu);
}  // namespace hook_gate
}  // namespace hv
