#include <gtest/gtest.h>
#include <vector>
#include "policy/hook_shutdown.hpp"

namespace {
struct backend {
    unsigned callers{}, delayed_waits{}, waits{};
    bool closed{}, unpatched{}, stopped{}, freed{}, root_tail{};
    std::vector<int> events;
    void close_and_unpatch() {
        EXPECT_FALSE(stopped);
        EXPECT_FALSE(freed);
        closed = true;
        events.push_back(1);
        // All CPU ACKs, not merely the first CPU's acknowledgement.
        for (int cpu = 0; cpu < 4; ++cpu)
            events.push_back(10 + cpu);
        unpatched = true;
    }
    unsigned inflight() {
        EXPECT_TRUE(unpatched);
        return callers;
    }
    void wait() {
        EXPECT_TRUE(closed);
        EXPECT_TRUE(unpatched);
        EXPECT_FALSE(stopped);
        EXPECT_FALSE(freed);
        ++waits;
        events.push_back(2);
        if (waits > delayed_waits) {
            --callers;
            root_tail = true;  // zero references alone does NOT retire root
        }
    }
    void stop_cpus() {
        EXPECT_TRUE(unpatched);
        EXPECT_EQ(callers, 0u);
        EXPECT_FALSE(freed);
        for (int cpu = 0; cpu < 4; ++cpu)
            events.push_back(20 + cpu);
        root_tail = false;
        stopped = true;
    }
    void release() {
        EXPECT_TRUE(stopped);
        EXPECT_FALSE(root_tail);
        EXPECT_EQ(callers, 0u);
        freed = true;
        events.push_back(3);
    }
};
}  // namespace
TEST(HookShutdown, ExistingInvocationReturnsBeforeAnyCpuStops) {
    backend b;
    b.callers = 2;
    blook::drain_hook_shutdown(b);
    EXPECT_TRUE(b.freed);
    EXPECT_EQ(b.waits, 2u);
    EXPECT_EQ(b.events,
              (std::vector<int>{1, 10, 11, 12, 13, 2, 2, 20, 21, 22, 23, 3}));
}
TEST(HookShutdown, DelayedOriginalNeverPermitsTimeoutFree) {
    backend b;
    b.callers = 1;
    b.delayed_waits = 1000;
    blook::drain_hook_shutdown(b);
    EXPECT_EQ(b.waits, 1001u);
    EXPECT_TRUE(b.freed);
}
TEST(HookShutdown, EmptyOrFailedStartupStillNeedsUnpatchAndStopBarriers) {
    backend b;
    blook::drain_hook_shutdown(b);
    EXPECT_EQ(b.waits, 0u);
    EXPECT_EQ(b.events,
              (std::vector<int>{1, 10, 11, 12, 13, 20, 21, 22, 23, 3}));
}
