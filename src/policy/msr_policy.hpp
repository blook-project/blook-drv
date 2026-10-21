#pragma once
#include "policy/integer.hpp"

// Pure MSR presentation policy (complements cpuid_policy.hpp).
//
// Hiding CPUID.1:ECX[5] (VMX) is only consistent if the VMX capability MSRs and
// IA32_FEATURE_CONTROL answer the same way a non-VT-x CPU would. The decision
// is pure so the consistency can be unit-tested without a VM.
namespace blook::policy {

inline constexpr uint32_t msr_feature_control = 0x3A;
inline constexpr uint32_t msr_vmx_basic = 0x480;
inline constexpr uint32_t msr_vmx_last = 0x48F;

// IA32_FEATURE_CONTROL value reported when VT-x is hidden: locked (bit 0) with
// VMX outside SMX disabled (bit 2 clear), which is what a machine with the
// feature locked off reports.
inline constexpr uint64_t feature_control_hidden = 0x1;

struct msr_options {
    bool hide_virtualization_features{true};
    // CET supervisor shadow stacks cannot be enforced while root mode runs with
    // the guest's CET state; the enable bit is cleared on write.
    bool filter_supervisor_cet{true};
};

enum class msr_action {
    passthrough,  // let the hardware handle the access
    fault,        // reflect #GP into the guest
    constant,     // answer with the value below
};

struct msr_read_decision {
    msr_action action{msr_action::passthrough};
    uint64_t value{};
};

struct msr_write_decision {
    msr_action action{msr_action::passthrough};
    // Value to write when action == passthrough (may be filtered, e.g. CET).
    uint64_t value{};
};

inline msr_read_decision read(uint32_t msr, const msr_options& options) {
    if (options.hide_virtualization_features) {
        if (msr >= msr_vmx_basic && msr <= msr_vmx_last)
            return {msr_action::fault, 0};
        if (msr == msr_feature_control)
            return {msr_action::constant, feature_control_hidden};
    }
    return {msr_action::passthrough, 0};
}

inline msr_write_decision write(uint32_t msr, uint64_t value,
                                const msr_options& options) {
    if (options.hide_virtualization_features && msr >= msr_vmx_basic &&
        msr <= msr_vmx_last)
        return {msr_action::fault, 0};
    if (options.filter_supervisor_cet && msr == 0x6A4) {  // IA32_S_CET
        // SH_STK_EN is bit 0; supervisor shadow stacks cannot be enforced.
        return {msr_action::passthrough, value & ~uint64_t{1}};
    }
    return {msr_action::passthrough, value};
}

}  // namespace blook::policy