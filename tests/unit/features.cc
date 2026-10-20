#include <gtest/gtest.h>
#include <cstring>
#include "policy/features.hpp"
#include "policy/dispatch.hpp"

namespace {
using namespace blook;
using query_chain = dispatch_chain<int(unsigned), 3>;
int calls;
int original(unsigned) {
    ++calls;
    return 0;
}
int process(void*, query_chain::continuation next, unsigned c) {
    const auto result = next(c);
    return result + (c == 1 ? 10 : 0);
}
int module(void*, query_chain::continuation next, unsigned c) {
    const auto result = next(c);
    return result + (c == 2 ? 20 : 0);
}
query_chain snapshot(feature::mask mask) {
    query_chain chain;
    if (mask & feature::bit(feature::id::system_process))
        chain.add({1, process});
    if (mask & feature::bit(feature::id::system_module))
        chain.add({2, module});
    return chain;
}
}  // namespace
TEST(FeaturesTest, DescriptorsHaveUniqueStableNamesAndBits) {
    feature::mask seen = 0;
    for (const auto& entry : feature::descriptors) {
        EXPECT_EQ(seen & feature::bit(entry.value), 0u);
        seen |= feature::bit(entry.value);
        EXPECT_NE(entry.purpose[0], '\0');
        EXPECT_EQ(feature::find(entry.name, std::strlen(entry.name)), &entry);
        for (const auto& other : feature::descriptors)
            if (&entry != &other)
                EXPECT_STRNE(entry.name, other.name);
    }
    EXPECT_EQ(seen, feature::known_mask);
    EXPECT_EQ(feature::bit(feature::id::first_contact), 1u);
    EXPECT_EQ(feature::bit(feature::id::window_point), 1ull << 16);
    EXPECT_EQ(feature::find("window", 6), nullptr);
    EXPECT_EQ(feature::find(nullptr, 0), nullptr);
}
TEST(FeaturesTest, OptionalPresetsDoNotOverlap) {
    EXPECT_EQ(feature::nt_preset & feature::window_preset, 0u);
    EXPECT_EQ(feature::nt_preset | feature::window_preset, feature::known_mask);
    EXPECT_TRUE(feature::valid(0));
    EXPECT_TRUE(feature::valid(feature::known_mask));
    EXPECT_FALSE(feature::valid(1ull << 63));
}
TEST(FeaturesTest, PerCallSnapshotsNeverModifyExistingInvocation) {
    const auto old = snapshot(feature::system_query_mask);
    const auto changed = snapshot(feature::bit(feature::id::system_module));
    calls = 0;
    EXPECT_EQ(old.invoke(original, 1), 10);
    EXPECT_EQ(calls, 1);
    EXPECT_EQ(changed.invoke(original, 1), 0);
    EXPECT_EQ(calls, 2);
    EXPECT_EQ(changed.invoke(original, 2), 20);
    EXPECT_EQ(calls, 3);
    EXPECT_EQ(snapshot(0).invoke(original, 1), 0);
    EXPECT_EQ(calls, 4);
}
