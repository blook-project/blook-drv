#pragma once
#include <ntifs.h>

#include "policy/integer.hpp"

// Startup tuning and bring-up tracing.
//
// The hypervisor has optional interception paths that can be the difference
// between "boots everywhere" and "boots here": RDTSCP interception and the
// debug-register interception added for the hardware-breakpoint hooks. Being
// able to switch them off from the service key without a rebuild is what makes
// a machine-specific failure bisectable in the field (and in the nested VM,
// where VMX capability MSRs are the intersection with the host's policy).
//
// Every value is read once at PASSIVE_LEVEL during DriverEntry, before any VMCS
// exists, and is immutable afterwards. The reads use the service key that the
// SCM passed to DriverEntry, so nothing is written or created by the driver.
namespace blook::tuning {

inline constexpr uint32_t default_intercept_debug = 1;
inline constexpr uint32_t default_intercept_rdtscp = 0;

void initialize(PCUNICODE_STRING service_path);

// MOV DRn + #DB/#BP interception (hardware-breakpoint hooks).
bool intercept_debug();
// RDTSCP interception. Off by default: the TSC offset already hides the world
// switch, and emulating RDTSCP means re-executing it in root mode, which is the
// one place where the instruction's behaviour differs across CPUs and nested
// hosts.
bool intercept_rdtscp();
// Bring-up tracing into the service key (off unless asked for).
bool trace_markers();
// Startup-only bisect switch: skip the VMCALL-based timing calibration in
// hv::start(). That calibration is the only bring-up step that round-trips
// through VMCALL with interrupts disabled, so it is the first suspect when a
// nested host freezes right after the hypervisor starts.
bool skip_timing_calibration();

// Records a phase marker (best effort, PASSIVE_LEVEL only, ignores failures).
void mark(uint32_t phase, uint32_t extra = 0);

}  // namespace blook::tuning