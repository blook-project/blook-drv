#pragma once
#include "policy/integer.hpp"

// Pure CPUID presentation policy.
//
// The hypervisor has to answer CPUID consistently: a guest that sees the
// hypervisor bit clear but finds hypervisor vendor leaves (or readable VMX
// capability MSRs, see msr_policy.hpp) has detected it with one comparison.
// Keeping the decision here - instead of in the vm-exit handler - is what makes
// it testable on the host, and it is the single definition of "what a clean
// CPUID looks like" for the whole project.
namespace blook::policy {

struct cpuid_reply {
    uint32_t eax{};
    uint32_t ebx{};
    uint32_t ecx{};
    uint32_t edx{};
};

enum class host_kind : uint32_t {
    none = 0,  // bare metal
    vmware = 1,
    hyperv = 2,
    kvm = 3,
    xen = 4,
    virtualbox = 5,
    qemu = 6,
    unknown = 7,
};

struct cpuid_options {
    // Clear CPUID.1:ECX[31], the "a hypervisor is present" bit.
    bool hide_hypervisor_bit{true};
    // Clear CPUID.1:ECX[5] (VMX) and ECX[6] (SMX), and zero the SVM leaves, so
    // the feature view agrees with the filtered VMX MSRs.
    bool hide_virtualization_features{true};
    // Zero leaves 0x40000000..0x4FFFFFFF (the hypervisor vendor range).
    bool zero_hypervisor_leaves{true};
    host_kind host{host_kind::none};
};

inline constexpr uint32_t leaf_hypervisor_first = 0x40000000;
inline constexpr uint32_t leaf_hypervisor_last = 0x4FFFFFFF;
inline constexpr uint32_t leaf_extended_features = 0x80000001;
inline constexpr uint32_t leaf_svm_features = 0x8000000A;

// True for the leaves a hypervisor defines for itself.
inline constexpr bool is_hypervisor_leaf(uint32_t leaf) {
    return leaf >= leaf_hypervisor_first && leaf <= leaf_hypervisor_last;
}

// Applies the presentation policy to one CPUID result. `raw` is what the
// processor returned in root mode (which, when nested, already contains the
// outer hypervisor's answers).
inline cpuid_reply filter(const cpuid_reply& raw, uint32_t leaf, uint32_t,
                          const cpuid_options& options) {
    auto reply = raw;
    if (leaf == 1) {
        if (options.hide_hypervisor_bit)
            reply.ecx &= ~(1u << 31);
        if (options.hide_virtualization_features) {
            reply.ecx &= ~(1u << 5);  // VMX
            reply.ecx &= ~(1u << 6);  // SMX
        }
    } else if (leaf == leaf_extended_features) {
        if (options.hide_virtualization_features) {
            reply.ecx &= ~(1u << 2);  // SVM
        }
    } else if (leaf == leaf_svm_features) {
        // AMD-only leaves: on a hidden Intel VT-x machine they read as zero,
        // exactly like on a CPU without SVM.
        if (options.hide_virtualization_features)
            reply = {};
    }
    if (is_hypervisor_leaf(leaf) && options.zero_hypervisor_leaves)
        reply = {};
    return reply;
}

// The hypervisor vendor signature from a 0x40000000 reply, NUL padded.
struct vendor_signature {
    char text[13]{};
};

inline vendor_signature decode_vendor(const cpuid_reply& reply) {
    vendor_signature value;
    const uint32_t words[3] = {reply.ebx, reply.ecx, reply.edx};
    for (int word = 0; word < 3; ++word) {
        for (int byte = 0; byte < 4; ++byte)
            value.text[word * 4 + byte] =
                static_cast<char>((words[word] >> (byte * 8)) & 0xFF);
    }
    value.text[12] = 0;
    return value;
}

// Classifies a host from its 0x40000000 reply the way the driver does at
// bring-up. An empty reply means bare metal.
inline host_kind classify_host(const cpuid_reply& reply) {
    const auto vendor = decode_vendor(reply);
    if (reply.eax < leaf_hypervisor_first)
        return host_kind::none;
    struct known {
        const char* signature;
        host_kind kind;
    };
    static constexpr known table[] = {
        {"VMwareVMware", host_kind::vmware},
        {"Microsoft Hv", host_kind::hyperv},
        {"KVMKVMKVM", host_kind::kvm},
        {"XenVMMXenVMM", host_kind::xen},
        {"VBoxVBoxVBox", host_kind::virtualbox},
        {"TCGTCGTCGTCG", host_kind::qemu},
    };
    for (const auto& item : table) {
        bool match = true;
        for (int i = 0; i < 12; ++i) {
            if (item.signature[i] == 0)
                break;
            if (vendor.text[i] != item.signature[i]) {
                match = false;
                break;
            }
        }
        if (match)
            return item.kind;
    }
    return host_kind::unknown;
}

}  // namespace blook::policy