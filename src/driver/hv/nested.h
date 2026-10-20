#pragma once
#include <ntifs.h>

#include "blook/drv/wire.hpp"

// Nested-virtualisation detection and capability degradation.
//
// The driver must work both on bare metal and inside a VMware Workstation guest
// configured with `vhv.enable = TRUE`. A nested host exposes most of VMX but
// not always all of it, and several VMCS controls that a native run can assume
// are silently masked away (the VMX capability MSRs report the intersection of
// what the L0 hypervisor is willing to emulate). This module probes what this
// particular CPU actually allows *before* the first VMCS is written, so the
// rest of the hypervisor can take a documented degraded path instead of
// failing a VM entry with an "invalid control field" check.
//
// Everything here runs once, at PASSIVE_LEVEL, before hv::start(). The result
// is immutable afterwards and safe to read from vm-exit context.
namespace hv::nested {

enum class host_kind : uint32_t {
    none = 0,  // bare metal, CPUID.1:ECX[31] clear
    vmware = 1,
    hyperv = 2,
    kvm = 3,
    xen = 4,
    virtualbox = 5,
    qemu = 6,
    unknown = 7,
};

struct report {
    bool nested{};
    host_kind host{host_kind::none};
    char vendor[13]{};  // CPUID.0x40000000 signature, NUL terminated
    uint32_t leaf_max{};  // CPUID.0x40000000 EAX
    uint32_t vendor_leaf[4]{};  // EAX/EBX/ECX/EDX as reported by the host
    bool vmx_msr_readable{};
    bool vp_assist{};
    bool preemption_timer{};
    bool ept_ad{};
    bool vpid{};
    bool invpcid{};
    bool xsaves{};
    bool rdtscp{};
    bool mtf{};
    bool tsc_scaling{};
    uint64_t vmx_basic{};
    uint64_t cr4_fixed0{};
    uint64_t cr4_fixed1{};
    uint32_t flags{};  // wire::hv_flag_*: nested/vendor/no_* degradation bits
};

// Probes CPUID and the VMX capability MSRs once (idempotent, PASSIVE_LEVEL).
const report& probe();

// Degradation flags for the wire replies (wire::hv_flag_*).
uint32_t flags();

// True when the host allows the feature on this CPU. Used by vmcs.cpp/vcpu.cpp
// to skip controls that would make VM entry fail.
bool preemption_timer_supported();
bool vp_assist_supported();
bool ept_ad_supported();
bool vpid_supported();
bool invpcid_supported();
bool xsaves_supported();
bool rdtscp_supported();
bool mtf_supported();

// Human-readable vendor name for diagnostics (never NULL).
const char* host_name();

}  // namespace hv::nested
