#include <gtest/gtest.h>
#include "policy/page_query.hpp"

namespace {
using namespace blook;
using hook_catalog::entry_id;
constexpr uint64_t kernel_page = 0xffff800000010000ull;
}  // namespace
TEST(PageQuery,
     SamePageDifferentFunctionsKeepPhysicalAndLogicalCountsSeparate) {
    wire::QueryPageResponse out;
    page_query::initialize(out, 0, kernel_page, wire::page_domain_kernel);
    const auto effective = feature::bit(feature::id::system_process);
    page_query::append(out,
                       {1, kernel_page + 16, 0, 0, hook_domain::kernel, true,
                        false, entry_id::query_system},
                       0, 0, kernel_page, effective, true);
    page_query::append(out,
                       {2, kernel_page + 128, 0, 0, hook_domain::kernel, true,
                        false, entry_id::write_memory},
                       0, 0, kernel_page, effective, true);
    EXPECT_EQ(out.registered_count, 2u);
    EXPECT_EQ(out.armed_count, 2u);
    EXPECT_EQ(out.logical_count, 6u);  // four QuerySystem + maintenance + scrub
    EXPECT_EQ(out.enabled_logical_count, 2u);  // process filter + maintenance
    EXPECT_EQ(out.opaque_count, 0u);
    EXPECT_EQ(out.entry_count, 0u);
    EXPECT_EQ(out.page_base, 0u);
    EXPECT_EQ(out.pid, 0u);
    for (const auto& row : out.entries) {
        EXPECT_EQ(row.id, 0u);
        EXPECT_EQ(row.target, 0u);
    }
}
TEST(PageQuery, UserRowsAndCountsAreBothOwnerFilteredAndChainsRemainOpaque) {
    wire::QueryPageResponse out;
    page_query::initialize(out, 42, 0x12345, wire::page_domain_user);
    page_query::record mine{1, 0x12080, 7, 42, hook_domain::user, true, false};
    page_query::append(out, mine, 42, 7, 0x12345, 0, true);
    auto other = mine;
    other.id = 2;
    other.token = 8;
    page_query::append(out, other, 42, 7, 0x12345, 0, true);
    other = mine;
    other.pid = 43;
    page_query::append(out, other, 42, 7, 0x12345, 0, true);
    other = mine;
    other.target = 0x13080;
    page_query::append(out, other, 42, 7, 0x12345, 0, true);
    other = mine;
    other.domain = hook_domain::kernel;
    page_query::append(out, other, 42, 7, 0x12345, 0, true);
    EXPECT_EQ(out.registered_count, 1u);
    EXPECT_EQ(out.entry_count, 1u);
    EXPECT_EQ(out.entries[0].id, 1u);
    EXPECT_EQ(out.page_base, 0x12000u);
    EXPECT_EQ(out.opaque_count, 1u);
    EXPECT_EQ(out.logical_count, 0u);
}
TEST(PageQuery, PreparedDormantAndStoppedEntriesAreNotEffective) {
    for (const bool running : {false, true}) {
        wire::QueryPageResponse out;
        page_query::initialize(out, 0, kernel_page, wire::page_domain_kernel);
        page_query::append(out,
                           {1, kernel_page, 0, 0, hook_domain::kernel, false,
                            false, entry_id::query_system},
                           0, 0, kernel_page, feature::known_mask, running);
        page_query::append(out,
                           {2, kernel_page + 32, 0, 0, hook_domain::kernel,
                            false, true, entry_id::write_memory},
                           0, 0, kernel_page, feature::known_mask, running);
        EXPECT_EQ(out.logical_count, 6u);
        EXPECT_EQ(out.enabled_logical_count, 0u);
        EXPECT_EQ(out.armed_count, 0u);
        EXPECT_EQ(out.dormant_count, 1u);
    }
}
TEST(PageQuery, EveryBuiltinCatalogBindingHasStableIdentityAndKnownFeatures) {
    feature::mask all = 0;
    for (uint32_t i = 0; i < static_cast<uint32_t>(entry_id::count); ++i) {
        const auto* entry = hook_catalog::find(static_cast<entry_id>(i));
        ASSERT_NE(entry, nullptr);
        EXPECT_EQ(entry->id, static_cast<entry_id>(i));
        EXPECT_TRUE(feature::valid(entry->optional));
        EXPECT_NE(entry->name[0], '\0');
        all |= entry->optional;
    }
    EXPECT_EQ(all, feature::known_mask);
    EXPECT_EQ(hook_catalog::find(entry_id::opaque), nullptr);
}
