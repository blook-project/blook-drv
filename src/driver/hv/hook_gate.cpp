#include "hook_gate.hpp"

#include <intrin.h>
#include <stdint.h>

#include "policy/hook.hpp"
#include "vmx.h"

extern "C" char blook_hook_leave_site;

namespace hv::hook_gate {
namespace {
enum : LONG { empty = 0, prepared = 1, armed = 2 };
struct gate_record {
    volatile LONG state{};
    uint64_t target{};
    uint64_t shim{};
    uint64_t ret{};
    size_t covered{};
};

// Ordinary .data/.bss, never placed in a pageable/INIT section. Root only
// inspects armed records; their payload is immutable until all-CPU stop ACK.
gate_record gates[capacity]{};
alignas(8) volatile LONG64 inflight{};
volatile LONG closing{};
uint64_t ret_landing{};

LONG load_state(gate_record& gate) {
    return InterlockedCompareExchange(&gate.state, empty, empty);
}
bool kernel_address(uint64_t address) {
    return address >= 0xffff800000000000ull;
}
bool covers(uint64_t target, size_t covered, uint64_t address) {
    return address >= target && address - target < covered;
}
}  // namespace

NTSTATUS register_gate(void const* target_ptr, void const* shim_ptr,
                       void const* ret_ptr, size_t covered) {
    if (is_closing())
        return STATUS_DELETE_PENDING;
    auto const target = reinterpret_cast<uint64_t>(target_ptr);
    auto const shim = reinterpret_cast<uint64_t>(shim_ptr);
    auto const ret = reinterpret_cast<uint64_t>(ret_ptr);
    auto const leave = reinterpret_cast<uint64_t>(&blook_hook_leave_site);
    // Decode/image validation belongs to prepare (root must never dereference
    // these addresses). The architectural instruction maximum is also enforced
    // here, independently of the larger EPT patch-buffer capacity.
    if (!kernel_address(target) || !kernel_address(shim) ||
        !kernel_address(ret) || covered < 3 || covered > 15 ||
        !blook::valid_patch(target, covered) || target > UINT64_MAX - covered ||
        shim == target || shim == leave || ret == leave ||
        covers(target, covered, shim) || covers(target, covered, ret) ||
        covers(target, covered, leave))
        return STATUS_INVALID_PARAMETER;
    if (ret_landing && ret_landing != ret)
        return STATUS_INVALID_PARAMETER;

    gate_record* free_slot = nullptr;
    for (auto& gate : gates) {
        if (load_state(gate) == empty) {
            if (!free_slot)
                free_slot = &gate;
            continue;
        }
        if (gate.target == target)
            return STATUS_OBJECT_NAME_COLLISION;
        // Reject overlapping entry patches, and any entry that would patch
        // another gate's shim or the session-wide RET landing.
        if (covers(gate.target, gate.covered, target) ||
            covers(target, covered, gate.target) ||
            covers(gate.target, gate.covered, shim) ||
            covers(gate.target, gate.covered, ret) ||
            covers(target, covered, gate.shim) ||
            covers(target, covered, gate.ret))
            return STATUS_CONFLICTING_ADDRESSES;
    }
    if (!free_slot)
        return STATUS_INSUFFICIENT_RESOURCES;
    // Caller holds its management lifecycle lock. Publish state last; an
    // interlocked arm publication makes this payload visible to root readers.
    if (!ret_landing)
        ret_landing = ret;
    free_slot->target = target;
    free_slot->shim = shim;
    free_slot->ret = ret;
    free_slot->covered = covered;
    InterlockedExchange(&free_slot->state, prepared);
    return STATUS_SUCCESS;
}

NTSTATUS mark_armed(void const* target) {
    if (is_closing())
        return STATUS_DELETE_PENDING;
    for (auto& gate : gates) {
        auto const state = load_state(gate);
        if (state != empty &&
            gate.target == reinterpret_cast<uint64_t>(target)) {
            if (state == prepared)
                InterlockedExchange(&gate.state, armed);
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

NTSTATUS unregister_unarmed(void const* target) {
    for (auto& gate : gates) {
        auto const state = load_state(gate);
        if (state != empty &&
            gate.target == reinterpret_cast<uint64_t>(target)) {
            if (state != prepared)
                return STATUS_DEVICE_BUSY;
            // Root never reads the payload of prepared records. Only guest
            // management may reclaim these; armed records are never reclaimed.
            InterlockedExchange(&gate.state, empty);
            return STATUS_SUCCESS;
        }
    }
    return STATUS_NOT_FOUND;
}

void mark_closing() {
    InterlockedExchange(&closing, 1);
}
bool is_closing() {
    return InterlockedCompareExchange(&closing, 0, 0) != 0;
}
LONG64 inflight_count() {
    return InterlockedCompareExchange64(&inflight, 0, 0);
}
NTSTATUS reopen_after_drain() {
    if (inflight_count() != 0)
        return STATUS_DEVICE_BUSY;
    InterlockedExchange(&closing, 0);
    return STATUS_SUCCESS;
}
NTSTATUS reset_after_stop() {
    if (inflight_count() != 0)
        return STATUS_DEVICE_BUSY;
    for (auto& gate : gates) {
        InterlockedExchange(&gate.state, empty);
        gate.target = gate.shim = gate.ret = 0;
        gate.covered = 0;
    }
    ret_landing = 0;
    InterlockedExchange(&closing, 0);
    return STATUS_SUCCESS;
}

bool handle_gate_vmcall(vcpu* /*cpu*/) {
    if (current_guest_cpl() != 0)
        return false;
    auto const rip = vmx_vmread(VMCS_GUEST_RIP);
    if (rip == reinterpret_cast<uint64_t>(&blook_hook_leave_site)) {
        auto count = inflight_count();
        // A malformed/direct call must not underflow the global reference.
        // The shim has restored its original entry RSP before this VMCALL.
        // Resume at external C3 so hardware RET, including CET, does the
        // return. No driver instruction executes in non-root after this
        // decrement.
        if (!ret_landing || count <= 0) {
            inject_hw_exception(invalid_opcode);
            return true;
        }
        auto const landing = ret_landing;
        for (;;) {
            auto const observed =
                InterlockedCompareExchange64(&inflight, count - 1, count);
            if (observed == count)
                break;
            count = observed;
            if (count <= 0) {
                inject_hw_exception(invalid_opcode);
                return true;
            }
        }
        vmx_vmwrite(VMCS_GUEST_RIP, landing);
        return true;
    }
    for (auto& gate : gates) {
        if (load_state(gate) != armed || gate.target != rip)
            continue;
        // Keep accepting existing entry gates even when closing: all-CPU
        // unpatch is what stops acquisitions. Its per-CPU ACK serializes with
        // that CPU's root entry path before the caller tests the global count.
        InterlockedIncrement64(&inflight);
        vmx_vmwrite(VMCS_GUEST_RIP, gate.shim);
        return true;
    }
    return false;
}
}  // namespace hv::hook_gate
