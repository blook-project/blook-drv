#pragma once
#include <ntifs.h>
namespace blook {
// Returns a genuine RET in a permanent, executable, nonpageable ntoskrnl
// section. No copied code or driver-owned memory is used by a retired caller.
void* system_return_landing();
}  // namespace blook
