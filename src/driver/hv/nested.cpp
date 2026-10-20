// Nested-virtualisation probe (see nested.h).
//
// The interesting part is not "am I virtualised" but "which VMX controls did
// the L0 hypervisor actually leave enabled". A nested VMware guest reports
// VMX in CPUID and answers the capability MSRs, but the returned
// allowed-0/allowed-1 sets are the intersection with the L0 policy: for example
// the VMX preemption timer is commonly reported as unsupported, EPT A/D is not
// always available, and IPAT/VPID may be masked. Writing a control the MSR says
// is disallowed makes VM entry fail with VM-entry failure 7 ("invalid control
// field"), which on a nested host usually means an unhandled #UD/#GP in root
// mode and a hang, so the hypervisor must ask first.
#include "nested.h"

#include <intrin.h>

#include "exception-routines.h"
#include "vmx.h"

namespace hv::nested {
namespace {
report cached{};
bool probed{};

uint32_t cpuid_leaf(int leaf, int subleaf, int reg) {
    int regs[4]{};
    __cpuidex(regs, leaf, subleaf);
    return static_cast<uint32_t>(regs[reg]);
}

void read_vendor(report& value) {
    int regs[4]{};
    __cpuidex(regs, 0x40000000, 0);
    value.leaf_max = static_cast<uint32_t>(regs[0]);
    value.vendor_leaf[0] = static_cast<uint32_t>(regs[0]);
    value.vendor_leaf[1] = static_cast<uint32_t>(regs[1]);
    value.vendor_leaf[2] = static_cast<uint32_t>(regs[2]);
    value.vendor_leaf[3] = static_cast<uint32_t>(regs[3]);
    for (int i = 0; i < 3; ++i) {
        const auto word = value.vendor_leaf[1 + i];
        value.vendor[i * 4 + 0] = static_cast<char>(word & 0xFF);
        value.vendor[i * 4 + 1] = static_cast<char>((word >> 8) & 0xFF);
        value.vendor[i * 4 + 2] = static_cast<char>((word >> 16) & 0xFF);
        value.vendor[i * 4 + 3] = static_cast<char>((word >> 24) & 0xFF);
    }
    value.vendor[12] = 0;

    // The vendor strings are the documented CPUID signatures; matching a
    // prefix is enough and avoids being fooled by a trailing version.
    struct entry {
        const char* signature;
        host_kind kind;
    };
    static constexpr entry known[] = {
        {"VMwareVMware", host_kind::vmware},
        {"Microsoft Hv", host_kind::hyperv},
        {"KVMKVMKVM", host_kind::kvm},
        {"XenVMMXenVMM", host_kind::xen},
        {"VBoxVBoxVBox", host_kind::virtualbox},
        {"TCGTCGTCGTCG", host_kind::qemu},
    };
    for (const auto& item : known) {
        bool match = true;
        for (int i = 0; i < 12; ++i) {
            const char expected = item.signature[i];
            if (expected == 0)
                break;
            if (value.vendor[i] != expected) {
                match = false;
                break;
            }
        }
        if (match) {
            value.host = item.kind;
            return;
        }
    }
    // A hypervisor-present bit with an unrecognised signature is still a
    // hypervisor: report it as unknown, never as bare metal.
    value.host = host_kind::unknown;
}

uint64_t read_msr_safe(uint32_t index, bool& ok) {
    host_exception_info e{};
    const auto value = rdmsr_safe(e, index);
    ok = !e.exception_occurred;
    return ok ? value : 0;
}

void probe_capabilities(report& value) {
    // Intel only: the rest of the hypervisor is Intel VT-x. On an AMD part the
    // driver refuses to start anyway (vmx checks the vendor CPUID leaf), so the
    // probe can stop early.
    int vendor_regs[4]{};
    __cpuidex(vendor_regs, 0, 0);
    const bool intel = static_cast<uint32_t>(vendor_regs[1]) == 0x756E6547 &&
                       static_cast<uint32_t>(vendor_regs[3]) == 0x49656E69 &&
                       static_cast<uint32_t>(vendor_regs[2]) == 0x6C65746E;
    if (!intel)
        return;

    bool ok = false;
    value.vmx_basic = read_msr_safe(IA32_VMX_BASIC, ok);
    value.vmx_msr_readable = ok;
    if (!ok) {
        // CPUID advertises VMX but the capability MSRs are not readable: a
        // hypervisor that filters them. There is nothing useful to probe.
        return;
    }

    const auto pin = read_msr_safe(IA32_VMX_PINBASED_CTLS, ok);
    value.preemption_timer = ok && ((pin >> 32) & (1ull << 6)) != 0;

    const auto proc = read_msr_safe(IA32_VMX_PROCBASED_CTLS, ok);
    value.mtf = ok && ((proc >> 32) & (1ull << 27)) != 0;

    const auto proc2 = read_msr_safe(IA32_VMX_PROCBASED_CTLS2, ok);
    const bool have_proc2 = ok;
    value.vp_assist = have_proc2 && ((proc2 >> 32) & (1ull << 7)) != 0;
    value.ept_ad = have_proc2 && ((proc2 >> 32) & (1ull << 21)) != 0;
    value.vpid = have_proc2 && ((proc2 >> 32) & (1ull << 5)) != 0;
    value.invpcid = have_proc2 && ((proc2 >> 32) & (1ull << 12)) != 0;
    value.xsaves = have_proc2 && ((proc2 >> 32) & (1ull << 20)) != 0;
    value.rdtscp = have_proc2 && ((proc2 >> 32) & (1ull << 3)) != 0;

    const auto exit_ctls = read_msr_safe(IA32_VMX_EXIT_CTLS, ok);
    value.tsc_scaling = ok && ((exit_ctls >> 32) & (1ull << 26)) != 0;

    value.cr4_fixed0 = read_msr_safe(IA32_VMX_CR4_FIXED0, ok);
    value.cr4_fixed1 = read_msr_safe(IA32_VMX_CR4_FIXED1, ok);

    if (!value.preemption_timer)
        value.flags |= wire::hv_flag_no_preemption_timer;
    if (!value.vp_assist)
        value.flags |= wire::hv_flag_no_vp_assist;
    if (!value.ept_ad)
        value.flags |= wire::hv_flag_no_ept_ad;
    if (!value.vpid)
        value.flags |= wire::hv_flag_no_vpid;
    if (!value.invpcid)
        value.flags |= wire::hv_flag_no_invpcid;
    if (!value.xsaves)
        value.flags |= wire::hv_flag_no_xsaves;
    if (!value.rdtscp)
        value.flags |= wire::hv_flag_no_rdtscp;
    if (value.tsc_scaling)
        value.flags |= wire::hv_flag_tsc_scaling;
}
}  // namespace

const report& probe() {
    if (probed)
        return cached;
    probed = true;

    int regs[4]{};
    __cpuid(regs, 1);
    cached.nested = (static_cast<uint32_t>(regs[2]) & 0x80000000u) != 0;
    if (!cached.nested) {
        cached.flags = 0;
        return cached;
    }

    read_vendor(cached);
    cached.flags = wire::hv_flag_nested;
    switch (cached.host) {
        case host_kind::vmware:
            cached.flags |= wire::hv_flag_vmware;
            break;
        case host_kind::hyperv:
            cached.flags |= wire::hv_flag_hyperv;
            break;
        default:
            break;
    }
    probe_capabilities(cached);
    return cached;
}

uint32_t flags() {
    return probe().flags;
}

bool preemption_timer_supported() {
    const auto& value = probe();
    // On bare metal the capability MSR is authoritative; when the nested host
    // does not report the timer, the hypervisor falls back to resynchronising
    // the TSC offset on every exit instead of on a timer.
    return value.preemption_timer;
}

bool vp_assist_supported() {
    return probe().vp_assist;
}

bool ept_ad_supported() {
    return probe().ept_ad;
}

bool vpid_supported() {
    const auto& value = probe();
    // A nested VM can report VPID but with flush semantics we do not model;
    // it is only a performance hint, so it is skipped there.
    return value.vpid && value.host == host_kind::none;
}

bool invpcid_supported() {
    return probe().invpcid;
}

bool xsaves_supported() {
    return probe().xsaves;
}

bool rdtscp_supported() {
    return probe().rdtscp;
}

bool mtf_supported() {
    const auto& value = probe();
    if (!value.nested)
        return true;  // reported by the CPU itself
    return value.mtf;
}

const char* host_name() {
    switch (probe().host) {
        case host_kind::none:
            return "bare-metal";
        case host_kind::vmware:
            return "vmware";
        case host_kind::hyperv:
            return "hyper-v";
        case host_kind::kvm:
            return "kvm";
        case host_kind::xen:
            return "xen";
        case host_kind::virtualbox:
            return "virtualbox";
        case host_kind::qemu:
            return "qemu";
        default:
            return "unknown";
    }
}
}  // namespace hv::nested
