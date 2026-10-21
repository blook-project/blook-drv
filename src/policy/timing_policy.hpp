#pragma once
#include "policy/integer.hpp"

// TSC / performance-counter compensation math.
//
// The hypervisor removes the cost of the world switch from the guest clock by
// adjusting the TSC offset, and keeps APERF/MPERF/PERF_GLOBAL_CTRL continuous
// by snapshotting them on exit and restoring them on entry. The arithmetic is
// pure and unit-tested here; `hv/timing.cpp` only performs the VMCS/MSR side
// effects.
namespace blook::policy {

// What the vm-exit path should do to the guest clock for this exit.
struct tsc_compensation {
    // Subtract this many TSC ticks from the guest-visible clock (the offset
    // delta; the caller applies it to its running offset).
    uint64_t subtract_ticks{};
    // Resynchronise instead of accumulating: true for exits that cannot be
    // attributed to one instruction (exceptions, NMI delivery, preemption) and
    // for outliers where compensation would add error rather than remove it.
    bool resynchronise{};
    // Preemption-timer ticks until the next forced resynchronisation (0 = leave
    // the timer alone / not supported).
    uint64_t preemption_ticks{};
    // Whether the performance counters have to be restored at all.
    bool restore_perf_counters{};
};

// Upper bound on a single exit's overhead that is still attributable to the
// intercepted instruction. A larger value means the exit was preempted or the
// measurement itself is broken, and compensating for it would drift.
inline constexpr uint64_t max_attributable_overhead = 10000;
// The preemption timer must never be programmed below this many ticks.
inline constexpr uint64_t min_preemption_ticks = 2;
// Desired resynchronisation interval in guest TSC ticks.
inline constexpr uint64_t resync_interval_ticks = 10000;

// `timing_hidden` is the startup switch; `attributable` says the exit came from
// an intercepted instruction; `overhead` is the measured world-switch cost for
// this exit; `timer_shift` is IA32_VMX_MISC's preemption-timer/tsc
// relationship.
inline tsc_compensation compensate(bool timing_hidden, bool attributable,
                                   uint64_t overhead, uint32_t timer_shift) {
    tsc_compensation result;
    if (!timing_hidden)
        return result;
    result.restore_perf_counters = true;
    if (!attributable || overhead > max_attributable_overhead) {
        result.resynchronise = true;
        return result;
    }
    result.subtract_ticks = overhead;
    auto ticks = resync_interval_ticks >> timer_shift;
    if (ticks < min_preemption_ticks)
        ticks = min_preemption_ticks;
    result.preemption_ticks = ticks;
    return result;
}

// APERF/MPERF restore value: the snapshot taken on exit minus the constant cost
// of the MSR loads/stores themselves. Saturating, because the snapshot can be
// smaller than the overhead on a very short measurement.
inline uint64_t adjust_perf_counter(uint64_t snapshot, uint64_t overhead) {
    return snapshot > overhead ? snapshot - overhead : 0;
}

// Whether IA32_FIXED_CTR2 (the reference TSC counter) is counting this context
// and therefore needs the same correction. `cpl` is the guest CPL (0 or 3),
// `enable_os`/`enable_user` are the EN2_OS/EN2_USR bits of IA32_FIXED_CTR_CTRL.
inline bool fixed_ctr2_counting(uint32_t cpl, bool enable_os,
                                bool enable_user) {
    return (cpl == 0 && enable_os) || (cpl == 3 && enable_user);
}

}  // namespace blook::policy