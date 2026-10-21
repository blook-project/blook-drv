// Software/hardware breakpoint state machine: the exact once-only-execution
// invariant the target can observe, tested against a simulated exit stream.
#include <gtest/gtest.h>

#include "policy/breakpoint_policy.hpp"

namespace {
using namespace blook::policy;

constexpr uint64_t code = 0x00007FF612340000ull;
}  // namespace

TEST(BreakpointPolicy, ArmHitStepRearm) {
    breakpoint_table table;
    const auto id = table.arm(code);
    ASSERT_NE(id, 0u);
    EXPECT_EQ(table.state(id), breakpoint_state::armed);

    const auto hit = table.on_breakpoint(code);
    EXPECT_TRUE(hit.handled);
    EXPECT_TRUE(hit.rewind);
    EXPECT_EQ(hit.rewind_to, code);
    EXPECT_EQ(hit.id, id);
    EXPECT_EQ(table.state(id), breakpoint_state::stepping);

    // The original instruction runs once from the original bytes; the single
    // step then reports exactly that instruction.
    const auto step = table.on_single_step();
    EXPECT_TRUE(step.handled);
    EXPECT_EQ(step.completed, code);
    EXPECT_EQ(table.state(id), breakpoint_state::armed);

    // The breakpoint fires again on the next execution: it was re-armed, not
    // consumed.
    const auto second = table.on_breakpoint(code);
    EXPECT_TRUE(second.handled);
    EXPECT_EQ(table.hits(id), 2u);
}

TEST(BreakpointPolicy, BreakpointOnAnUnarmedAddressIsNotOurs) {
    breakpoint_table table;
    table.arm(code);
    const auto hit = table.on_breakpoint(code + 0x10);
    EXPECT_FALSE(hit.handled);
    EXPECT_FALSE(hit.rewind);
}

TEST(BreakpointPolicy, DisarmWhileSteppingIsRejected) {
    breakpoint_table table;
    const auto id = table.arm(code);
    table.on_breakpoint(code);
    EXPECT_FALSE(table.disarm(id))
        << "a stepping breakpoint cannot be removed under the processor";
    table.on_single_step();
    EXPECT_TRUE(table.disarm(id));
    EXPECT_EQ(table.state(id), breakpoint_state::free);
}

TEST(BreakpointPolicy, InvalidOrDuplicateAddressesAreRejected) {
    breakpoint_table table;
    EXPECT_EQ(table.arm(0), 0u);
    EXPECT_EQ(table.arm(0x0000800000000000ull), 0u) << "non-canonical";
    const auto id = table.arm(code);
    ASSERT_NE(id, 0u);
    EXPECT_EQ(table.arm(code), 0u) << "duplicate";
    EXPECT_NE(table.arm(code + 1), 0u) << "second slot works";
}

TEST(BreakpointPolicy, CapacityIsBounded) {
    breakpoint_table table;
    for (size_t i = 0; i < breakpoint_table::capacity; ++i)
        ASSERT_NE(table.arm(code + i * 0x10), 0u) << i;
    EXPECT_EQ(table.size(), breakpoint_table::capacity);
    EXPECT_EQ(table.arm(code + 0x1000), 0u) << "table full";
}

TEST(BreakpointPolicy, OnlyOneEntryCanStepAtATime) {
    breakpoint_table table;
    const auto first = table.arm(code);
    const auto second = table.arm(code + 0x10);
    ASSERT_NE(first, 0u);
    ASSERT_NE(second, 0u);
    EXPECT_TRUE(table.on_breakpoint(code).handled);
    // A second #BP while the first is being single-stepped cannot start another
    // step: the caller must reflect it instead.
    EXPECT_FALSE(table.on_breakpoint(code + 0x10).handled);
    EXPECT_EQ(table.on_single_step().id, first);
    EXPECT_TRUE(table.on_breakpoint(code + 0x10).handled);
}

TEST(BreakpointPolicy, DebugRegisterReadsHideOwnedAddresses) {
    const uint64_t owned[4] = {code, 0, 0, 0};
    const auto hidden = read_debug_register(owned, 0, code);
    EXPECT_TRUE(hidden.handled);
    EXPECT_EQ(hidden.value, 0u) << "the driver's address never leaks";

    const auto foreign = read_debug_register(owned, 1, 0x1234);
    EXPECT_TRUE(foreign.handled);
    EXPECT_EQ(foreign.value, 0x1234u) << "a register we do not own passes";

    // DR6/DR7 are always answered from the driver's shadow.
    EXPECT_TRUE(read_debug_register(owned, 6, 0x4000).handled);
}

TEST(BreakpointPolicy, DebugRegisterWriteThatClearsOurBreakpointIsSwallowed) {
    const uint64_t owned[4] = {code, 0, 0, 0};
    const auto clearing = write_debug_register(owned, 0, code, 0);
    EXPECT_TRUE(clearing.handled);
    EXPECT_TRUE(clearing.swallowed);

    const auto moving = write_debug_register(owned, 0, code, 0x5000);
    EXPECT_TRUE(moving.swallowed);

    const auto unrelated = write_debug_register(owned, 1, 0, 0x5000);
    EXPECT_TRUE(unrelated.handled);
    EXPECT_FALSE(unrelated.swallowed) << "registers we do not own pass";
}

TEST(BreakpointPolicy, Dr7HelpersCoverAllFourRegisters) {
    EXPECT_EQ(dr7_enable_bit(0), 1ull);
    EXPECT_EQ(dr7_enable_bit(3), 0x40ull);
    EXPECT_EQ(dr7_control_mask(0), 0xFull << 16);
    EXPECT_EQ(dr7_control_mask(3), 0xFull << 28);
}
TEST(BreakpointPolicy, StepStateRunsTheOriginalExactlyOnce) {
    step_state state;
    breakpoint_action action;
    action.handled = true;
    action.rewind = true;
    action.id = 7;
    action.rewind_to = code;
    EXPECT_TRUE(begin_step(action, state));
    EXPECT_TRUE(state.active);
    // A second begin on the same processor is refused: the trap flag is already
    // set and the original instruction has not run yet.
    EXPECT_FALSE(begin_step(action, state));
    uint64_t id{};
    EXPECT_TRUE(end_step(state, id));
    EXPECT_EQ(id, 7u);
    EXPECT_FALSE(state.active);
    // After the step the breakpoint is armed again, so the next execution
    // starts a new step.
    EXPECT_TRUE(begin_step(action, state));
}

TEST(BreakpointPolicy, StepStateIsEmptyUntilABreakpointIsHit) {
    step_state state;
    uint64_t id{};
    EXPECT_FALSE(end_step(state, id));
    breakpoint_action ignored;
    EXPECT_FALSE(begin_step(ignored, state));
}
