#pragma once
#include <ntifs.h>

#include "policy/integer.hpp"

// Bring-up diagnostics for a nested host.
//
// A hypervisor that hangs a guest is the worst kind of bug: nothing is logged
// and nothing crashes. The two tools here make that state diagnosable from the
// host:
//
//  * `stage()` writes a one-line breadcrumb to the kernel debug port (the guest
//    has `debug on` with a serial port), so the last completed bring-up stage
//    is visible in serial.log;
//  * an exit-storm watchdog notices a processor that takes the same
//    (exit reason, guest RIP) over and over - the signature of a handler that
//    fails to advance the guest instruction - records it and aborts
//    virtualisation on that processor instead of spinning forever.
namespace hv::bringup {

inline constexpr uint32_t storm_threshold = 4096;

struct exit_storm {
    uint32_t reason{};
    uint32_t cpu{};
    uint64_t rip{};
    uint32_t count{};
    uint32_t active{};
};

extern exit_storm last_storm;
// Serial of the last stage reached (stage() increments it) and the processor it
// ran on. The call order is fixed: vmxon, vmptrld, vmcs-ready, vmxon-only-ok /
// launched, per processor. publish_stage() writes it to the service key so the
// last stage survived a guest freeze.
extern volatile uint32_t stage_serial;
extern volatile uint32_t stage_cpu;
// First guest->root transition taken while ProbeExits is on (root-mode stores,
// persisted by the stage thread).
extern volatile uint32_t first_exit_reason;
extern volatile uint64_t first_exit_rip;
// Entry-state snapshot taken immediately before VMLAUNCH; persisted as
// Entry* values so a wedged guest still reports what it was launched with.
extern volatile uint64_t entry_controls;
extern volatile uint64_t entry_efer;
extern volatile uint64_t entry_cr0;
extern volatile uint64_t entry_cr4;
extern volatile uint64_t entry_activity;
extern volatile uint64_t entry_gdtr_limit;
extern volatile uint64_t entry_idtr_limit;
extern volatile uint64_t entry_interruptibility;
extern volatile uint64_t entry_pending_debug;
extern volatile uint64_t entry_link_pointer;
extern volatile uint64_t entry_eptp;
extern volatile uint64_t host_cr0;
extern volatile uint64_t host_cr4;
extern volatile uint64_t host_rsp;
extern volatile uint64_t host_rip;
extern volatile uint64_t host_efer;
// VM-instruction error read in root mode on the first VM exit (0 = VMLAUNCH
// reported success).
extern volatile uint32_t first_launch_error;
// IA32_VMX_ENTRY_CTLS allowed-0 / allowed-1 halves, for the comparison table.
extern volatile uint64_t entry_ctls_allowed0;
extern volatile uint64_t entry_ctls_allowed1;
void publish_stage();
// First-exit probe breadcrumbs (Parameters\ProbeExits); they go to the
// independent bring-up key so a self-hide on failure cannot erase them.
void publish_probe(uint32_t code, uint32_t extra = 0);
// Stage watchdog thread: while armed, a PASSIVE thread rewrites
// StageNum/StageCpu into the persistent key every 50 ms. When the guest dies
// mid-bring-up (no bugcheck, no debugger), the last value on disk names the
// stage that killed it.
void start_stage_thread();
void disarm_stage_thread();
// VMX instruction error from the last failed VMLAUNCH
// (VMCS_VM_INSTRUCTION_ERROR).
extern volatile uint64_t launch_error;
void record_launch_error(uint64_t error);
// First VMCS field whose VMWRITE failed (0 = none). A failed write is recorded
// and the bring-up fails cleanly instead of bugchecking inside root mode.
extern volatile uint64_t vmwrite_error;
void record_vmwrite_failure(uint64_t field);
extern volatile uint32_t storm_count;
void publish_stage();
// VMX instruction error from the last failed VMLAUNCH
// (VMCS_VM_INSTRUCTION_ERROR).
extern volatile uint64_t launch_error;
void record_launch_error(uint64_t error);
// First VMCS field whose VMWRITE failed (0 = none). A failed write is recorded
// and the bring-up fails cleanly instead of bugchecking inside root mode.
extern volatile uint64_t vmwrite_error;
void record_vmwrite_failure(uint64_t field);

// Breadcrumb with a stage name and the logical processor index.
void stage(const char* name, uint32_t cpu);
// Emit text on the emulated COM1 UART (file-backed serial.log). Safe in root
// mode: plain port I/O, no locks, no allocation, no debugger protocol.
void serial_out(char c);
void serial_hex(uint32_t value);
void serial_mark(char tag, uint32_t first = 0, uint32_t second = 0);
void serial_exit(uint32_t reason, uint64_t rip);
// Records an exit storm (called from root mode: no allocation, no locks).
void record_storm(uint32_t cpu, uint32_t reason, uint64_t rip, uint32_t count);
// Writes the last storm into the service key (PASSIVE_LEVEL, best effort) so a
// host-side test can read it after the driver failed to start.
void publish_storm();
void remember_service_path(PCUNICODE_STRING path);

}  // namespace hv::bringup