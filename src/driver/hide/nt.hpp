#pragma once
#include <ntifs.h>
#include "policy/features.hpp"

namespace blook::hide::nt {
// Legacy NT preset wrappers; remove is logical disable, not physical removal.
// Fine-grained callers use driver/features.hpp instead.
NTSTATUS install();
// Called under the feature writer lock; only installs required services.
feature::mask ensure_features(feature::mask requested);
void remove();
[[nodiscard]] bool installed();

// Core VM hooks (NtProtectVirtualMemory, NtWriteVirtualMemory), independent
// of the profile: they keep session hooks alive across copy-on-write by
// re-arming a hook whose virtual page changed its physical backing. Installed
// while the hypervisor runs; remove_core does not remove live trampolines.
NTSTATUS install_core();
void remove_core();
// Only after global hook teardown and invocation-reader quiescence.
void reset_after_shutdown();

// Drop the one-shot scrub bookkeeping for a process that is going away, so a
// recycled PID still gets its PEB cleared.
void forget_process(ULONG pid);
}  // namespace blook::hide::nt
