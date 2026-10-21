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
// Minimal bring-up preset (Parameters\BringupMinimal): only the VMX controls
// required to enter and leave guest mode. No MSR bitmaps, no CR exits, no
// exception interception, no timing calibration, no maintenance hooks. Used to
// bisect a nested host that freezes during hv::start(); hooks and hiding are
// offline until the preset is turned off.
bool bringup_minimal();
// Bring-up stage bisect (Parameters\StartStage): 0 = full, 1 = VMXON + VMCS
// load + VMXOFF only (never enters guest mode), 2 = full but without EPT.
uint32_t start_stage();
// Evidence/fallback mode (Parameters\NoHypervisor): the driver loads, serves
// the kchannel session, self-hides and answers queries, but never starts the
// hypervisor. Used to run the non-hypervisor e2e cases for real on a host where
// nested VM entry is not usable; hook operations then fail cleanly with
// STATUS_DEVICE_NOT_READY instead of pretending to work.
bool no_hypervisor();
// Debug switch (Parameters\MaxCpus): virtualise only the first N logical
// processors (0 = all). Nested AP bring-up can be tested on one vCPU.
uint32_t max_cpus();
// Debug switch (Parameters\BringupNoEpt): leave EPT disabled (hooks offline).
bool bringup_no_ept();
// Debug switch (Parameters\HostPageTables, default 1): 0 makes root mode run on
// the guest CR3 instead of the private identity page tables. Bisects a nested
// wedge that happens on the first VM exit (host CR3 switch).
bool host_page_tables();
// Debug switch (Parameters\ProbeExits): after virtualising, force a CPUID and a
// VMCALL round trip in guest mode, recording a breadcrumb before each step. The
// marks land in the service key (on disk), so they survive a guest freeze and a
// host-side VM reset: the highest TraceLast tells us which step wedged.
bool probe_exits();
// Debug switch (Parameters\RawEntryCtls, nonzero): write this value into
// VMCS_CTRL_VMENTRY_CONTROLS verbatim instead of merging with the capability
// MSRs. VMware nested VMX can expose entry-control capability values that do
// not behave like bare metal, so the merge has to be bypassable to test.
uint32_t raw_entry_ctls();
// Same raw overrides for the other control groups (see raw_entry_ctls). Used to
// pin the nested configuration to the capability MSRs allowed-0 values only.
uint32_t raw_pin_ctls();
uint32_t raw_exit_ctls();
// Debug switch (Parameters\BareEntry): write the absolute minimum VMCS control
// set - no pin/primary controls at all, no EPT/secondary controls, only the
// 64-bit host address-space exit bit and IA-32e guest entry. The last
// meaningful difference between our configuration and a hand-built nested VMCS.
bool bare_entry();

// Records a phase marker (best effort, PASSIVE_LEVEL only, ignores failures).
void mark(uint32_t phase, uint32_t extra = 0);

}  // namespace blook::tuning