#include <gtest/gtest.h>

#include "policy/dispatch.hpp"

namespace {
using chain = blook::dispatch_chain<int(int), 4>;
int original_calls;
int original(int value) {
    ++original_calls;
    return value;
}
int add(void* context, chain::continuation next, int value) {
    return next(value + *static_cast<int*>(context));
}
int multiply(void*, chain::continuation next, int value) {
    return next(value * 2);
}
int stop(void*, chain::continuation, int) {
    return 42;
}
}  // namespace

TEST(DispatchTest, SameEntryRunsMultipleHandlersInStablePriorityOrder) {
    chain hooks;
    int one = 1;
    ASSERT_TRUE(hooks.add({1, add, &one, 20}));
    ASSERT_TRUE(hooks.add({2, multiply, nullptr, 10}));
    ASSERT_TRUE(hooks.add({3, add, &one, 20}));
    original_calls = 0;
    EXPECT_EQ(hooks.invoke(original, 3), 8);
    EXPECT_EQ(original_calls, 1);
}
TEST(DispatchTest, RemoveMiddlePreservesOtherHandlersAndSnapshots) {
    chain hooks;
    int one = 1;
    ASSERT_TRUE(hooks.add({1, add, &one, 0}));
    ASSERT_TRUE(hooks.add({2, multiply, nullptr, 0}));
    ASSERT_TRUE(hooks.add({3, add, &one, 0}));
    const auto old = hooks;
    EXPECT_TRUE(hooks.remove(2));
    EXPECT_FALSE(hooks.remove(2));
    EXPECT_EQ(hooks.invoke(original, 3), 5);
    EXPECT_EQ(old.invoke(original, 3), 9);
}
TEST(DispatchTest, ShortCircuitDoesNotCallOriginal) {
    chain hooks;
    ASSERT_TRUE(hooks.add({1, stop, nullptr, 0}));
    original_calls = 0;
    EXPECT_EQ(hooks.invoke(original, 0), 42);
    EXPECT_EQ(original_calls, 0);
}
TEST(DispatchTest, ValidatesIdentityHandlerAndCapacity) {
    chain hooks;
    EXPECT_FALSE(hooks.add({0, stop}));
    EXPECT_FALSE(hooks.add({1, nullptr}));
    for (unsigned id = 1; id <= 4; ++id)
        EXPECT_TRUE(hooks.add({id, stop}));
    EXPECT_FALSE(hooks.add({1, stop}));
    EXPECT_FALSE(hooks.add({5, stop}));
    EXPECT_EQ(hooks.size(), 4u);
    EXPECT_TRUE(hooks.remove(1));
    EXPECT_TRUE(hooks.add({5, stop}));
}
TEST(DispatchTest, EmptyChainCallsOriginal) {
    chain hooks;
    EXPECT_EQ(hooks.invoke(original, 17), 17);
}

TEST(DispatchTest,
     DisabledHandlersRemainQueryableWithoutChangingOlderSnapshots) {
    chain hooks;
    int one = 1;
    ASSERT_TRUE(hooks.add(
        {1, add, &one, 20, true, "add", "Add one before the original."}));
    ASSERT_TRUE(hooks.add(
        {2, multiply, nullptr, 10, true, "double", "Double the argument."}));
    const auto old = hooks;
    ASSERT_TRUE(hooks.set_enabled(2, false));
    EXPECT_FALSE(hooks.set_enabled(999, false));
    EXPECT_EQ(hooks.size(), 2u);
    EXPECT_EQ(hooks.enabled_count(), 1u);
    ASSERT_NE(hooks.at(0), nullptr);
    EXPECT_EQ(hooks.at(0)->id, 2u);
    EXPECT_FALSE(hooks.at(0)->enabled);
    EXPECT_STREQ(hooks.at(1)->purpose, "Add one before the original.");
    EXPECT_EQ(hooks.at(2), nullptr);
    EXPECT_EQ(hooks.invoke(original, 3), 4);
    EXPECT_EQ(old.invoke(original, 3), 7);
    ASSERT_TRUE(hooks.set_enabled(2, true));
    EXPECT_EQ(hooks.invoke(original, 3), 7);
}
TEST(DispatchTest, VoidAndReferenceSignaturesPreserveArgumentIdentity) {
    using c = blook::dispatch_chain<void(int&), 2>;
    c hooks;
    ASSERT_TRUE(hooks.add({1, [](void*, c::continuation next, int& n) {
                               ++n;
                               next(n);
                           }}));
    int value = 3;
    hooks.invoke([](int& n) { n *= 2; }, value);
    EXPECT_EQ(value, 8);
}

#include <memory>
TEST(DispatchTest, MoveOnlyValueArgumentsCanReachOriginalWithoutCopying) {
    using c = blook::dispatch_chain<int(std::unique_ptr<int>), 1>;
    c hooks;
    ASSERT_TRUE(
        hooks.add({1, [](void*, c::continuation next, std::unique_ptr<int> n) {
                       ++*n;
                       return next(std::move(n));
                   }}));
    EXPECT_EQ(hooks.invoke([](std::unique_ptr<int> n) { return *n; },
                           std::make_unique<int>(4)),
              5);
}
