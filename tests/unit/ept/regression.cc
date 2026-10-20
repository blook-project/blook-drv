#include "fixture.hpp"

namespace ept_test {
// The VM-exit dispatcher rearms pending single steps before a removal vmcall.
// Preserve that required ordering before recycling the split's PTE storage.
TEST_F(EptTest, RearmBeforeRemovalKeepsReusedSplitEntriesIndependent) {
    auto old = Hook(1, 0x400, 0x100010);
    old.length = 2;
    old.patch[1] = 43;
    ASSERT_TRUE(hv::install_ept_hook(*cpu, old));
    hv::handle_page_access(*cpu, old.pfn << 12, true, old.target + 1);
    ASSERT_TRUE(platform().mtf);
    ASSERT_EQ(cpu->temporary_count, 1u);
    // src/driver/hv/vcpu.cpp dispatches non-EPT exits only after this rearm.
    hv::rearm_ept(*cpu);
    ASSERT_FALSE(platform().mtf);
    ASSERT_EQ(cpu->temporary_count, 0u);
    hv::remove_ept_hook(*cpu, old.id);
    ASSERT_EQ(hv::get_ept_pte(*cpu, old.pfn << 12), nullptr);

    // New hook occupies offset 1; offset 0 is an unrelated identity RWX page
    // at the exact storage location of the old temporary PTE.
    const auto fresh = Hook(2, 0x801, 0x200010);
    ASSERT_TRUE(hv::install_ept_hook(*cpu, fresh));
    auto* unrelated = hv::get_ept_pte(*cpu, 0x800ull << 12);
    ASSERT_NE(unrelated, nullptr);
    ASSERT_EQ(unrelated->page_frame_number, 0x800u);
    ASSERT_EQ(unrelated->flags & 7, 7u);
    hv::rearm_ept(*cpu);
    EXPECT_FALSE(platform().mtf);
    EXPECT_EQ(unrelated->page_frame_number, 0x800u);
    EXPECT_EQ(unrelated->flags & 7, 7u)
        << "stale temporary PTE re-armed an unhooked page in a reused split";
}
// Owners of a shared PFN need not place their identity pages at the same VA.
class IndependentIdentityTest : public EptTest,
                                public ::testing::WithParamInterface<uint64_t> {
};

TEST_P(IndependentIdentityTest, SelectsSecondOwnerUsingItsOwnIdentityAddress) {
    const auto first = Hook();
    auto second = Hook(2, first.pfn, first.target);
    second.address_space = 200;
    second.identity_address = 0x300000;
    second.patch[0] = 99;
    ASSERT_NE(first.identity_address, second.identity_address);
    ASSERT_TRUE(hv::install_ept_hook(*cpu, first));
    ASSERT_TRUE(hv::install_ept_hook(*cpu, second));
    ASSERT_NE(cpu->hooks[0].group, cpu->hooks[1].group);

    platform().current_cr3 = 2;
    // Override the mock's CR3-only fallback for BOTH VAs: the first owner's
    // VA is either unmapped or mapped to a PFN belonging to neither owner.
    platform().MapUser(platform().current_cr3, first.identity_address,
                       GetParam());
    platform().MapUser(platform().current_cr3, second.identity_address,
                       second.address_space << 12);
    hv::reset_ept_context(*cpu);
    auto* pte = hv::get_ept_pte(*cpu, first.pfn << 12);
    ASSERT_NE(pte, nullptr);
    hv::handle_page_access(*cpu, first.pfn << 12, true, second.target);

    EXPECT_EQ(pte->page_frame_number, ShadowPfn(1));
    EXPECT_NE(pte->page_frame_number, ShadowPfn(0));
    EXPECT_EQ(pte->flags & 7, 4u);
    EXPECT_EQ(cpu->shadow[cpu->hooks[1].group][0], second.patch[0]);
    EXPECT_FALSE(platform().mtf);
    EXPECT_EQ(cpu->temporary_count, 0u);
    EXPECT_EQ(hv::g_stats.identity_ok, 1);
    EXPECT_EQ(hv::g_stats.identity_failed, GetParam() == 0 ? 1 : 0);
    EXPECT_EQ(hv::g_stats.identity_mismatch, GetParam() == 0 ? 0 : 1);
    EXPECT_EQ(hv::g_hook_diag[0].shadow_mapped, 0);
    EXPECT_EQ(hv::g_hook_diag[1].shadow_mapped, 1);
    EXPECT_EQ(hv::g_hook_diag[1].identity_failures, 0);
    EXPECT_EQ(hv::g_hook_diag[1].identity_mismatches, 0);
}

INSTANTIATE_TEST_SUITE_P(FirstOwnerUnmappedOrWrongPfn, IndependentIdentityTest,
                         ::testing::Values(uint64_t{0}, uint64_t{300} << 12));
}  // namespace ept_test

namespace ept_test {
TEST_F(EptTest, QuiesceUnpatchesAllScopesAndPendingStepsBeforeVmxStops) {
    auto first = Hook();
    first.length = 2;
    auto second = Hook(2, first.pfn, first.target + 32);
    ASSERT_TRUE(hv::install_ept_hook(*cpu, first));
    ASSERT_TRUE(hv::install_ept_hook(*cpu, second));
    hv::handle_page_access(*cpu, first.pfn << 12, true, first.target + 1);
    ASSERT_TRUE(platform().mtf);
    blook::watch_spec watch{};
    watch.id = 7;
    watch.pfn = 0x2000;
    watch.target = 0x700080;
    watch.address_space = 100;
    watch.identity_address = 0x900000;
    blook::watch_record record{};
    ASSERT_TRUE(hv::install_ept_watch(*cpu, watch, &record));
    hv::quiesce_ept(*cpu);
    EXPECT_TRUE(cpu->quiescing);
    EXPECT_FALSE(platform().mtf);
    EXPECT_EQ(cpu->temporary_count, 0u);
    for (const auto& hook : cpu->hooks)
        EXPECT_FALSE(hook.active);
    for (const auto& group : cpu->groups)
        EXPECT_FALSE(group.active);
    for (const auto& entry : cpu->watches) {
        EXPECT_FALSE(entry.active);
        EXPECT_EQ(entry.record, nullptr);
    }
    EXPECT_FALSE(hv::install_ept_hook(*cpu, first));
    EXPECT_FALSE(hv::install_ept_watch(*cpu, watch, &record));
    hv::reset_ept_context(*cpu);  // context switches must not re-arm anything
    hv::quiesce_ept(*cpu);        // idempotent partial/final stop
    EXPECT_EQ(cpu->temporary_count, 0u);
    ASSERT_TRUE(hv::prepare_ept(*cpu));  // fresh EPT on power resume
    EXPECT_FALSE(cpu->quiescing);
    EXPECT_TRUE(hv::install_ept_hook(*cpu, first));
}
}  // namespace ept_test
