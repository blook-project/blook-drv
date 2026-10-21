#pragma once
#include "policy/cpuid_policy.hpp"
#include "policy/integer.hpp"

// Nested-hypervisor degradation matrix.
//
// A nested VMware guest exposes an intersection of its host's VMX capabilities:
// commonly no VP-assist, no virtual-interrupt delivery, no preemption timer,
// and sometimes no EPT A/D or VPID. Writing a VMCS control the capability MSRs
// say is disallowed makes VM entry fail, which presents as a hang. The plan
// below is what the driver actually enables, chosen by pure logic so every row
// can be tested on the host and so the e2e expectation ("degraded but running")
// is deterministic.
namespace blook::policy {

struct host_capabilities {
    bool vmx_msr_readable{};
    bool vp_assist{};
    bool preemption_timer{};
    bool ept_ad{};
    bool vpid{};
    bool invpcid{};
    bool xsaves{};
    bool rdtscp{};
    bool mtf{};
    host_kind host{host_kind::none};
};

// Bit-for-bit the wire::hv_flag_* values; the unit test asserts that.
inline constexpr uint32_t flag_running = 1u << 0;
inline constexpr uint32_t flag_nested = 1u << 1;
inline constexpr uint32_t flag_vmware = 1u << 2;
inline constexpr uint32_t flag_hyperv = 1u << 3;
inline constexpr uint32_t flag_no_vp_assist = 1u << 4;
inline constexpr uint32_t flag_no_preemption_timer = 1u << 5;
inline constexpr uint32_t flag_no_ept_ad = 1u << 6;
inline constexpr uint32_t flag_no_vpid = 1u << 7;
inline constexpr uint32_t flag_no_invpcid = 1u << 8;
inline constexpr uint32_t flag_no_xsaves = 1u << 9;
inline constexpr uint32_t flag_no_rdtscp = 1u << 10;
inline constexpr uint32_t flag_tsc_scaling = 1u << 11;

struct vmcs_plan {
    bool use_vp_assist{};
    bool use_preemption_timer{};
    bool use_ept_ad{};
    bool use_vpid{};
    bool use_invpcid{};
    bool use_xsaves{};
    bool use_rdtscp{};
    bool use_mtf{};
    uint32_t degradation_flags{};
};

inline vmcs_plan make_plan(const host_capabilities& caps) {
    vmcs_plan plan;
    plan.use_vp_assist = caps.vp_assist;
    plan.use_preemption_timer = caps.preemption_timer;
    plan.use_ept_ad = caps.ept_ad;
    // VPID flush semantics under a nested host are not modelled, and it is only
    // a performance hint: it is used on bare metal only.
    plan.use_vpid = caps.vpid && caps.host == host_kind::none;
    plan.use_invpcid = caps.invpcid;
    plan.use_xsaves = caps.xsaves;
    plan.use_rdtscp = caps.rdtscp;
    plan.use_mtf = caps.mtf;

    if (caps.host != host_kind::none) {
        plan.degradation_flags |= flag_nested;
        if (caps.host == host_kind::vmware)
            plan.degradation_flags |= flag_vmware;
        if (caps.host == host_kind::hyperv)
            plan.degradation_flags |= flag_hyperv;
    }
    if (!plan.use_vp_assist)
        plan.degradation_flags |= flag_no_vp_assist;
    if (!plan.use_preemption_timer)
        plan.degradation_flags |= flag_no_preemption_timer;
    if (!plan.use_ept_ad)
        plan.degradation_flags |= flag_no_ept_ad;
    if (!plan.use_vpid)
        plan.degradation_flags |= flag_no_vpid;
    if (!plan.use_invpcid)
        plan.degradation_flags |= flag_no_invpcid;
    if (!plan.use_xsaves)
        plan.degradation_flags |= flag_no_xsaves;
    if (!plan.use_rdtscp)
        plan.degradation_flags |= flag_no_rdtscp;
    return plan;
}

}  // namespace blook::policy