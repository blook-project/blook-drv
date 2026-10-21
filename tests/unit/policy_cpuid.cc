// CPUID presentation policy: what a clean CPUID looks like, leaf by leaf.
#include <gtest/gtest.h>

#include "policy/cpuid_policy.hpp"

namespace {
using namespace blook::policy;

cpuid_reply reply(uint32_t eax, uint32_t ebx, uint32_t ecx, uint32_t edx) {
    return {eax, ebx, ecx, edx};
}

cpuid_reply vmware_host_reply() {
    // 'VMwareVMware'
    cpuid_reply value{};
    value.eax = 0x40000010;
    value.ebx = 0x61774D56;  // 'VMwa'
    value.ecx = 0x4D566572;  // 'reVM'
    value.edx = 0x65726177;  // 'ware'
    return value;
}
}  // namespace

TEST(CpuidPolicy, HypervisorBitIsClearedOnLeafOne) {
    cpuid_options options;
    const auto filtered = filter(reply(0, 0, 0x80000000u, 0), 1, 0, options);
    EXPECT_EQ(filtered.ecx & (1u << 31), 0u);
}

TEST(CpuidPolicy, HypervisorBitCanBeKeptForDiagnostics) {
    cpuid_options options;
    options.hide_hypervisor_bit = false;
    const auto filtered = filter(reply(0, 0, 0x80000000u, 0), 1, 0, options);
    EXPECT_NE(filtered.ecx & (1u << 31), 0u);
}

TEST(CpuidPolicy, VmxAndSmxBitsAreClearedWithTheFeatureOption) {
    cpuid_options options;
    const auto raw = reply(0, 0, (1u << 5) | (1u << 6) | (1u << 4), 0);
    const auto filtered = filter(raw, 1, 0, options);
    EXPECT_EQ(filtered.ecx & (1u << 5), 0u) << "VMX";
    EXPECT_EQ(filtered.ecx & (1u << 6), 0u) << "SMX";
    EXPECT_NE(filtered.ecx & (1u << 4), 0u) << "unrelated feature untouched";
}

TEST(CpuidPolicy, SvmBitsAreClearedOnTheExtendedLeaf) {
    cpuid_options options;
    const auto filtered =
        filter(reply(0, 0, 0x2 | 0x4, 0), leaf_extended_features, 0, options);
    EXPECT_EQ(filtered.ecx & 0x4u, 0u) << "SVM";
    EXPECT_NE(filtered.ecx & 0x2u, 0u) << "unrelated extended feature";
}

TEST(CpuidPolicy, SvmFeatureLeafReadsAsZero) {
    cpuid_options options;
    const auto filtered =
        filter(reply(0x0F, 0x10, 0x20, 0x30), leaf_svm_features, 0, options);
    EXPECT_EQ(filtered.eax, 0u);
    EXPECT_EQ(filtered.ebx, 0u);
    EXPECT_EQ(filtered.ecx, 0u);
    EXPECT_EQ(filtered.edx, 0u);
}

TEST(CpuidPolicy, HypervisorVendorLeavesAreZeroed) {
    cpuid_options options;
    for (uint32_t leaf = leaf_hypervisor_first; leaf <= 0x40000100;
         leaf += 0x40) {
        const auto filtered = filter(vmware_host_reply(), leaf, 0, options);
        EXPECT_EQ(filtered.eax, 0u) << "leaf " << std::hex << leaf;
        EXPECT_EQ(filtered.ebx, 0u) << "leaf " << std::hex << leaf;
        EXPECT_EQ(filtered.ecx, 0u) << "leaf " << std::hex << leaf;
        EXPECT_EQ(filtered.edx, 0u) << "leaf " << std::hex << leaf;
    }
}

TEST(CpuidPolicy, NonHypervisorLeavesPassThroughUnchanged) {
    cpuid_options options;
    const auto raw = reply(0x20, 0x1234, 0x5678, 0x9ABC);
    for (const uint32_t leaf : {0u, 0x7u, 0x15u, 0x80000008u}) {
        const auto filtered = filter(raw, leaf, 0, options);
        EXPECT_EQ(filtered.eax, raw.eax) << "leaf " << std::hex << leaf;
        EXPECT_EQ(filtered.ebx, raw.ebx) << "leaf " << std::hex << leaf;
        EXPECT_EQ(filtered.ecx, raw.ecx) << "leaf " << std::hex << leaf;
        EXPECT_EQ(filtered.edx, raw.edx) << "leaf " << std::hex << leaf;
    }
}

TEST(CpuidPolicy, FilteringIsIdempotent) {
    cpuid_options options;
    const auto once = filter(vmware_host_reply(), 1, 0, options);
    const auto twice = filter(once, 1, 0, options);
    EXPECT_EQ(once.ecx, twice.ecx);
}

TEST(CpuidPolicy, VendorClassification) {
    EXPECT_EQ(classify_host(vmware_host_reply()), host_kind::vmware);
    cpuid_reply hyperv{};
    hyperv.eax = 0x40000006;
    hyperv.ebx = 0x7263694D;
    hyperv.ecx = 0x666F736F;
    hyperv.edx = 0x76482074;
    EXPECT_EQ(classify_host(hyperv), host_kind::hyperv);
    // A reply outside the hypervisor range means bare metal, whatever the
    // register contents happen to be.
    cpuid_reply bare{};
    bare.eax = 0x20;
    EXPECT_EQ(classify_host(bare), host_kind::none);
    // A present vendor leaf with an unknown vendor is still a hypervisor.
    cpuid_reply unknown{};
    unknown.eax = 0x40000000;
    unknown.ebx = 0x41414141;
    EXPECT_EQ(classify_host(unknown), host_kind::unknown);
}

TEST(CpuidPolicy, HypervisorLeafRange) {
    EXPECT_FALSE(is_hypervisor_leaf(0x3FFFFFFF));
    EXPECT_TRUE(is_hypervisor_leaf(leaf_hypervisor_first));
    EXPECT_TRUE(is_hypervisor_leaf(0x4FFFFFFF));
    EXPECT_FALSE(is_hypervisor_leaf(0x50000000));
}