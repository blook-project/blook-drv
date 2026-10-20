// Driver-side anti-detection state report (see detect.h).
#include "detect.h"

#include <intrin.h>

#include "driver/hv/hv.h"
#include "driver/hv/nested.h"
#include "driver/hv/timing.h"
#include "hwbreak.hpp"
#include "swbreak.hpp"

namespace hv::detect {
namespace {
state cached{};
bool initialized{};
uint32_t masked_msr_bitmap[1024 / 32]{};  // one bit per MSR index, MSRs < 0x400
}  // namespace

void note_masked_msr(uint32_t msr) {
    if (msr < 0x400)
        masked_msr_bitmap[msr / 32] |= 1u << (msr % 32);
}

void initialize() {
    if (initialized)
        return;
    initialized = true;

    // Every vector this hypervisor actively masks. The bits that stay out of
    // `active` are the honest gaps: memory-latency and exception-timing
    // artefacts cannot be removed completely while EPT is used for the hooks,
    // and the report says so instead of pretending.
    cached.active = wire::detect_check_cpuid_hypervisor_bit |
                    wire::detect_check_cpuid_vendor |
                    wire::detect_check_cpuid_features |
                    wire::detect_check_cpuid_leaf_max |
                    wire::detect_check_msr_vmx |
                    wire::detect_check_exception;

    if (timing_hidden()) {
        cached.active |= wire::detect_check_tsc | wire::detect_check_rdtscp |
                         wire::detect_check_aperf_mperf;
    } else {
        cached.failed |= wire::detect_check_tsc | wire::detect_check_rdtscp |
                         wire::detect_check_aperf_mperf;
    }

    // A nested host can mask the very counters the compensation relies on.
    const auto& host = nested::probe();
    if (host.nested) {
        if (!host.preemption_timer) {
            // The TSC offset is resynchronised on every exit instead of on the
            // preemption timer; the compensation still works but is coarser.
            cached.active |= wire::detect_check_tsc;
        }
        if (!host.rdtscp) {
            cached.failed |= wire::detect_check_rdtscp;
            cached.active &= ~static_cast<uint64_t>(wire::detect_check_rdtscp);
        }
    }

    // EPT itself is measurable (a hooked page faults differently from an
    // unhooked one); the mitigation is that the hook only fires on execute and
    // the data view is unchanged. Reported as a gap.
    cached.failed |= wire::detect_check_memory_latency;

    cached.tsc_offset_ticks = 0;
    cached.exit_latency_ticks = 0;
    cached.masked_msrs = 0;
    cached.vmx_msr_reads_blocked = 0;
}

const state& current() {
    return cached;
}

NTSTATUS probe(const wire::DetectProbeRequest& request,
               wire::DetectProbeResponse& reply) {
    const auto checks = request.checks & wire::detect_check_all;
    auto run = 0u;
    for (unsigned bit = 0; bit < 16; ++bit) {
        if (checks & (1u << bit))
            ++run;
    }
    reply.checks_run = run;

    // Refresh the counters that only the hypervisor knows.
    cached.masked_msrs = 0;
    for (unsigned index = 0; index < 1024 / 32; ++index) {
        uint32_t word = masked_msr_bitmap[index];
        while (word) {
            word &= word - 1;
            ++cached.masked_msrs;
        }
    }
    cached.vmx_msr_reads_blocked = cached.masked_msrs;
    reply.masked_msrs = cached.masked_msrs;
    reply.vmx_msr_reads_blocked = cached.vmx_msr_reads_blocked;
    reply.tsc_offset_ticks = cached.tsc_offset_ticks;
    reply.exit_latency_ticks = cached.exit_latency_ticks;

    const auto failing = cached.failed & checks;
    reply.flags = failing;
    auto failed = 0u;
    for (unsigned bit = 0; bit < 16; ++bit) {
        if (failing & (1u << bit))
            ++failed;
    }
    reply.checks_failed = failed;

    const auto& host = nested::probe();
    reply.nested_host_vendor = (static_cast<uint64_t>(host.vendor_leaf[1]) << 32) |
                               host.vendor_leaf[2];
    return STATUS_SUCCESS;
}
}  // namespace hv::detect
