#pragma once
#include <ntifs.h>
#include "policy/features.hpp"

// Window hides. The analyst tools' windows must not be discoverable from the
// sample, and the sample must not be able to name the process that owns them.
//
// This resolves win32kfull.sys exports by name, which is build independent: no
// syscall numbers, no shadow SSDT offsets. Everything is validated before a
// hook is installed, and a module that cannot be resolved cleanly simply
// leaves the window hides off.
namespace blook::hide::win32k {
NTSTATUS install();
feature::mask ensure_features(feature::mask requested);
void remove();
// Only after global hook teardown and invocation-reader quiescence.
void reset_after_shutdown();
[[nodiscard]] bool installed();
[[nodiscard]] ULONG hook_count();
}  // namespace blook::hide::win32k
