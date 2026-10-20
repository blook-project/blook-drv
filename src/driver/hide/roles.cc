#include "roles.hpp"

#include "driver/resources.hpp"
#include "policy/role_rules.hpp"

namespace blook::roles {
namespace {
constexpr size_t max_pinned = 32;

struct pinned_entry {
    uint32_t pid{};
    role value{role::other};
    bool used{};
};

// Manual PID pins are runtime overrides, independent of configuration rules.
// No caller may acquire it outside PASSIVE_LEVEL.
EX_PUSH_LOCK pinned_lock{};
pinned_entry pinned[max_pinned]{};

uint32_t pid_of(HANDLE value) {
    return static_cast<uint32_t>(reinterpret_cast<uintptr_t>(value));
}

role lookup_pinned(uint32_t pid) {
    if (!pid || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return role::other;
    exclusive_lock lock{pinned_lock};
    for (const auto& entry : pinned)
        if (entry.used && entry.pid == pid)
            return entry.value;
    return role::other;
}

role classify_process(const features::policy_view& policy, PEPROCESS process) {
    if (!process || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return role::other;
    PUNICODE_STRING name{};
    if (!NT_SUCCESS(SeLocateProcessImageName(process, &name)) || !name)
        return role::other;
    role found = role::other;
    {
        exclusive_lock lock{pinned_lock};
        // Recheck after name resolution so a concurrently installed pin wins.
        const auto pid = pid_of(PsGetProcessId(process));
        for (const auto& entry : pinned)
            if (entry.used && entry.pid == pid) {
                found = entry.value;
                break;
            }
        if (found == role::other)
            found =
                policy.classify(name->Buffer, name->Length / sizeof(wchar_t));
    }
    ExFreePool(name);
    // Never fall back to compile-time names or a potentially truncated
    // EPROCESS short name: neither establishes an exact basename match.
    return found;
}
}  // namespace

role pinned_role(uint32_t pid) {
    return lookup_pinned(pid);
}

role of_process(const features::policy_view& policy, PEPROCESS process) {
    if (!process || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return role::other;
    const auto pinned_role = lookup_pinned(pid_of(PsGetProcessId(process)));
    if (pinned_role != role::other)
        return pinned_role;
    return classify_process(policy, process);
}

role of_pid(const features::policy_view& policy, uint32_t pid) {
    if (!pid || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return role::other;
    const auto pinned_role = lookup_pinned(pid);
    if (pinned_role != role::other)
        return pinned_role;
    PEPROCESS process{};
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(pid), &process)))
        return role::other;
    const auto found = classify_process(policy, process);
    ObDereferenceObject(process);
    return found;
}

role of_current(const features::policy_view& policy) {
    return of_process(policy, PsGetCurrentProcess());
}
role of_process(PEPROCESS process) {
    return of_process(features::policy_view{}, process);
}
role of_pid(uint32_t pid) {
    return of_pid(features::policy_view{}, pid);
}
role of_current() {
    return of_current(features::policy_view{});
}

bool pid_is_target(uint32_t pid) {
    return of_pid(pid) == role::target;
}
bool pid_is_tool(uint32_t pid) {
    return of_pid(pid) == role::tool;
}

void pin(uint32_t pid, role value) {
    if (!pid || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return;
    exclusive_lock lock{pinned_lock};
    pinned_entry* free_slot{};
    for (auto& entry : pinned) {
        if (entry.used && entry.pid == pid) {
            entry.value = value;
            return;
        }
        if (!entry.used && !free_slot)
            free_slot = &entry;
    }
    if (free_slot) {
        free_slot->used = true;
        free_slot->pid = pid;
        free_slot->value = value;
    }
}

void unpin(uint32_t pid) {
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return;
    exclusive_lock lock{pinned_lock};
    for (auto& entry : pinned)
        if (entry.used && entry.pid == pid)
            entry = {};
}

void reset() {
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return;
    exclusive_lock lock{pinned_lock};
    for (auto& entry : pinned)
        entry = {};
}
}  // namespace blook::roles
