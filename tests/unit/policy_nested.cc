// Nested-virtualisation degradation matrix: every row is an expectation the e2e
// suite can assert, so "degraded but running" is deterministic.
#include <gtest/gtest.h>

#include "policy/nested_matrix.hpp"

namespace {
using namespace blook::policy;

host_capabilities full_native() {
    host_capabilities caps;
    caps.vmx_msr_readable = true;
    caps.vp_assist = true;
    caps.preemption_timer = true;
    caps.ept_ad = true;
    caps.vpid = true;
    caps.invpcid = true;
    caps.xsaves = true;
    caps.rdtscp = true;
    caps.mtf = true;
    caps.host = host_kind::none;
    return caps;
}
}  // namespace

TEST(NestedMatrix, BareMetalUsesEverythingAvailable) {
    const auto plan = make_plan(full_native());
    EXPECT_TRUE(plan.use_vp_assist);
    EXPECT_TRUE(plan.use_preemption_timer);
    EXPECT_TRUE(plan.use_ept_ad);
    EXPECT_TRUE(plan.use_vpid);
    EXPECT_TRUE(plan.use_invpcid);
    EXPECT_TRUE(plan.use_xsaves);
    EXPECT_TRUE(plan.use_rdtscp);
    EXPECT_TRUE(plan.use_mtf);
    EXPECT_EQ(plan.degradation_flags, 0u);
}

TEST(NestedMatrix, VmwareGuestDegradesWithoutFailing) {
    // The documented VMware nested profile: VMX/EPT are exposed, VP-assist and
    // the preemption timer are not, EPT A/D is not, VPID is not modelled.
    auto caps = full_native();
    caps.host = host_kind::vmware;
    caps.vp_assist = false;
    caps.preemption_timer = false;
    caps.ept_ad = false;
    caps.vpid = false;
    const auto plan = make_plan(caps);
    EXPECT_FALSE(plan.use_vp_assist);
    EXPECT_FALSE(plan.use_preemption_timer);
    EXPECT_FALSE(plan.use_ept_ad);
    EXPECT_FALSE(plan.use_vpid);
    EXPECT_TRUE(plan.use_rdtscp) << "RDTSCP itself is left to the host";
    EXPECT_NE(plan.degradation_flags & flag_nested, 0u);
    EXPECT_NE(plan.degradation_flags & flag_vmware, 0u);
    EXPECT_NE(plan.degradation_flags & flag_no_vp_assist, 0u);
    EXPECT_NE(plan.degradation_flags & flag_no_preemption_timer, 0u);
    EXPECT_NE(plan.degradation_flags & flag_no_ept_ad, 0u);
    EXPECT_NE(plan.degradation_flags & flag_no_vpid, 0u);
}

TEST(NestedMatrix, HyperVGuestKeepsVpidOffButReportsItsHost) {
    auto caps = full_native();
    caps.host = host_kind::hyperv;
    const auto plan = make_plan(caps);
    EXPECT_FALSE(plan.use_vpid) << "nested VPID is not modelled";
    EXPECT_NE(plan.degradation_flags & flag_hyperv, 0u);
    EXPECT_NE(plan.degradation_flags & flag_nested, 0u);
}

TEST(NestedMatrix, KvmGuestWithMissingFeaturesDegradesGracefully) {
    auto caps = full_native();
    caps.host = host_kind::kvm;
    caps.invpcid = false;
    caps.xsaves = false;
    caps.rdtscp = false;
    const auto plan = make_plan(caps);
    EXPECT_FALSE(plan.use_invpcid);
    EXPECT_FALSE(plan.use_xsaves);
    EXPECT_FALSE(plan.use_rdtscp);
    EXPECT_NE(plan.degradation_flags & flag_no_invpcid, 0u);
    EXPECT_NE(plan.degradation_flags & flag_no_xsaves, 0u);
    EXPECT_NE(plan.degradation_flags & flag_no_rdtscp, 0u);
}

TEST(NestedMatrix, MinimalHostStillProducesARunnablePlan) {
    host_capabilities caps;  // everything false, unknown host
    caps.host = host_kind::unknown;
    const auto plan = make_plan(caps);
    // None of the optional controls may be requested.
    EXPECT_FALSE(plan.use_vp_assist);
    EXPECT_FALSE(plan.use_preemption_timer);
    EXPECT_FALSE(plan.use_ept_ad);
    EXPECT_FALSE(plan.use_vpid);
    EXPECT_FALSE(plan.use_invpcid);
    EXPECT_FALSE(plan.use_xsaves);
    EXPECT_FALSE(plan.use_rdtscp);
    EXPECT_FALSE(plan.use_mtf);
    // The reported flags still name the host and every disabled control, so the
    // e2e report can explain the degradation instead of silently dropping it.
    EXPECT_NE(plan.degradation_flags & flag_nested, 0u);
    EXPECT_NE(plan.degradation_flags & flag_no_vp_assist, 0u);
    EXPECT_NE(plan.degradation_flags & flag_no_preemption_timer, 0u);
    EXPECT_NE(plan.degradation_flags & flag_no_ept_ad, 0u);
    EXPECT_NE(plan.degradation_flags & flag_no_vpid, 0u);
    EXPECT_NE(plan.degradation_flags & flag_no_invpcid, 0u);
    EXPECT_NE(plan.degradation_flags & flag_no_xsaves, 0u);
    EXPECT_NE(plan.degradation_flags & flag_no_rdtscp, 0u);
}