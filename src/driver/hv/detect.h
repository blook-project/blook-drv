#pragma once
#include <ntifs.h>

#include "blook/drv/wire.hpp"

// Driver-side anti-detection report.
//
// This is not a detector: the honest detection work is done in user mode by
// tests/guest/antidetect (a VMAware-style suite) which runs the checks a real
// anti-cheat would run. This module answers the *other* half of the question -
// "which of the mitigation vectors is actually switched on in this build, on
// this CPU, and with the current configuration" - so the e2e suite can tell a
// detection that happened *despite* the mitigation from one that happened
// because a mitigation was off.
namespace hv::detect {

struct state {
    uint64_t active{};  // mitigations that are on (wire::detect_check_*)
    uint64_t failed{};  // mitigations that are off or impossible here
    uint64_t tsc_offset_ticks{};
    uint64_t exit_latency_ticks{};
    uint32_t masked_msrs{};
    uint32_t vmx_msr_reads_blocked{};
};

// Fills the report. PASSIVE_LEVEL; the cached measurements are taken once at
// startup by initialize().
NTSTATUS probe(const wire::DetectProbeRequest& request,
               wire::DetectProbeResponse& reply);

// Called once from hv::start() before the first VMCS is written.
void initialize();

// Accumulates one masked MSR (read or write) for the report.
void note_masked_msr(uint32_t msr);

const state& current();

}  // namespace hv::detect
