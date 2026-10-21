// TSC / performance-counter compensation math: the arithmetic that decides how
// much of a world switch the guest is allowed to see.
#include <gtest/gtest.h>

#include "policy/timing_policy.hpp"

namespace {
using namespace blook::policy;
}  // namespace

TEST(TimingPolicy, HiddenTimingRestoresPerfCounters) {
    const auto plan = compensate(true, true, 100, 0);
    EXPECT_TRUE(plan.restore_perf_counters);
}

TEST(TimingPolicy, TimingHidingOffDoesNothing) {
    const auto plan = compensate(false, true, 100, 0);
    EXPECT_FALSE(plan.restore_perf_counters);
    EXPECT_FALSE(plan.resynchronise);
    EXPECT_EQ(plan.subtract_ticks, 0u);
    EXPECT_EQ(plan.preemption_ticks, 0u);
}

TEST(TimingPolicy, AttributableExitIsCompensated) {
    const auto plan = compensate(true, true, 500, 0);
    EXPECT_FALSE(plan.resynchronise);
    EXPECT_EQ(plan.subtract_ticks, 500u);
    EXPECT_EQ(plan.preemption_ticks, resync_interval_ticks);
}

TEST(TimingPolicy, NonAttributableExitResynchronises) {
    const auto plan = compensate(true, false, 500, 0);
    EXPECT_TRUE(plan.resynchronise);
    EXPECT_EQ(plan.subtract_ticks, 0u);
}

TEST(TimingPolicy, OutlierOverheadResynchronisesInsteadOfDrifting) {
    const auto plan = compensate(true, true, max_attributable_overhead + 1, 0);
    EXPECT_TRUE(plan.resynchronise);
    EXPECT_EQ(plan.subtract_ticks, 0u);
}

TEST(TimingPolicy, OverheadAtTheBoundaryIsStillCompensated) {
    const auto plan = compensate(true, true, max_attributable_overhead, 0);
    EXPECT_FALSE(plan.resynchronise);
    EXPECT_EQ(plan.subtract_ticks, max_attributable_overhead);
}

TEST(TimingPolicy, PreemptionTicksFollowTheTimerShiftAndNeverCollapse) {
    // IA32_VMX_MISC gives the preemption timer / TSC relationship; a larger
    // shift means fewer timer ticks for the same interval.
    const auto plain = compensate(true, true, 100, 0);
    const auto shifted = compensate(true, true, 100, 5);
    EXPECT_LT(shifted.preemption_ticks, plain.preemption_ticks);
    // Even an absurd shift never programs fewer than the architectural minimum.
    const auto extreme = compensate(true, true, 100, 40);
    EXPECT_EQ(extreme.preemption_ticks, min_preemption_ticks);
}

TEST(TimingPolicy, PerformanceCounterAdjustmentSaturates) {
    EXPECT_EQ(adjust_perf_counter(1000, 100), 900u);
    EXPECT_EQ(adjust_perf_counter(50, 100), 0u) << "never underflows";
    EXPECT_EQ(adjust_perf_counter(0, 0), 0u);
}

TEST(TimingPolicy, FixedCounterTwoCountsOnlyInTheEnabledContexts) {
    EXPECT_TRUE(fixed_ctr2_counting(0, true, false));
    EXPECT_FALSE(fixed_ctr2_counting(0, false, true));
    EXPECT_TRUE(fixed_ctr2_counting(3, false, true));
    EXPECT_FALSE(fixed_ctr2_counting(3, true, false));
    EXPECT_FALSE(fixed_ctr2_counting(0, false, false));
}