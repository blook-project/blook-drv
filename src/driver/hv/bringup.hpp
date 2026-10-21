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
void publish_stage();
extern volatile uint32_t storm_count;
void publish_stage();

// Breadcrumb with a stage name and the logical processor index.
void stage(const char* name, uint32_t cpu);
// Records an exit storm (called from root mode: no allocation, no locks).
void record_storm(uint32_t cpu, uint32_t reason, uint64_t rip, uint32_t count);
// Writes the last storm into the service key (PASSIVE_LEVEL, best effort) so a
// host-side test can read it after the driver failed to start.
void publish_storm();
void remember_service_path(PCUNICODE_STRING path);

}  // namespace hv::bringup