// MSR presentation policy: the consistency counterpart of the CPUID policy.
#include <gtest/gtest.h>

#include "policy/msr_policy.hpp"

namespace {
using namespace blook::policy;
}  // namespace

TEST(MsrPolicy, VmxCapabilityMsrsFaultWhenVtXIsHidden) {
    msr_options options;
    for (uint32_t msr = msr_vmx_basic; msr <= msr_vmx_last; ++msr)
        EXPECT_EQ(read(msr, options).action, msr_action::fault)
            << "MSR " << std::hex << msr;
}

TEST(MsrPolicy, VmxCapabilityMsrsPassThroughWhenNotHidden) {
    msr_options options;
    options.hide_virtualization_features = false;
    EXPECT_EQ(read(msr_vmx_basic, options).action, msr_action::passthrough);
}

TEST(MsrPolicy, FeatureControlReportsLockedWithoutVmx) {
    msr_options options;
    const auto decision = read(msr_feature_control, options);
    ASSERT_EQ(decision.action, msr_action::constant);
    EXPECT_EQ(decision.value & 1u, 1u) << "lock bit";
    EXPECT_EQ(decision.value & 4u, 0u) << "VMX outside SMX disabled";
}

TEST(MsrPolicy, NeighbouringMsrsAreNotIntercepted) {
    msr_options options;
    EXPECT_EQ(read(msr_vmx_basic - 1, options).action, msr_action::passthrough);
    EXPECT_EQ(read(msr_vmx_last + 1, options).action, msr_action::passthrough);
    EXPECT_EQ(read(0x10, options).action, msr_action::passthrough) << "TSC";
    EXPECT_EQ(read(0x1B, options).action, msr_action::passthrough)
        << "APICBASE";
}

TEST(MsrPolicy, VmxMsrWriteFaults) {
    msr_options options;
    EXPECT_EQ(write(msr_vmx_basic, 0, options).action, msr_action::fault);
    // Feature control stays writable: a machine whose lock bit is clear is
    // allowed to have it written, and the hardware rejects it otherwise.
    EXPECT_EQ(write(msr_feature_control, 4, options).action,
              msr_action::passthrough);
}

TEST(MsrPolicy, SupervisorCetShadowStackEnableIsFiltered) {
    msr_options options;
    const auto decision = write(0x6A4, 0xFFFFFFFFFFFFFFFFull, options);
    ASSERT_EQ(decision.action, msr_action::passthrough);
    EXPECT_EQ(decision.value & 1u, 0u) << "SH_STK_EN must stay clear";
    EXPECT_EQ(decision.value & ~1ull, ~1ull) << "other bits preserved";
}

TEST(MsrPolicy, CetFilterCanBeDisabled) {
    msr_options options;
    options.filter_supervisor_cet = false;
    const auto decision = write(0x6A4, 0xF, options);
    EXPECT_EQ(decision.value, 0xF);
}