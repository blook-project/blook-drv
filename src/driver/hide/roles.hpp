#pragma once
#include <ntifs.h>
#include "driver/features.hpp"

#include "policy/configuration.hpp"
#include "policy/integer.hpp"

// Runtime classification of the caller.
//
//   target : the image under analysis. Hook handlers only alter behaviour for
//            these callers, which is what keeps the sample from noticing the
//            debugger.
//   tool   : the analyst tools. They always see the real system.
//
// Name rules default to empty and are replaced atomically from configuration.
// A PID pin takes precedence so a renamed binary can still be classified.
// Classification is PASSIVE_LEVEL-only; higher IRQL returns role::other
// without taking a push lock or resolving a process name.
namespace blook::roles {
role of_process(const features::policy_view& policy, PEPROCESS process);
role of_pid(const features::policy_view& policy, uint32_t pid);
role of_current(const features::policy_view& policy);
inline bool is_target(const features::policy_view& policy) {
    return of_current(policy) == role::target;
}
inline bool is_tool(const features::policy_view& policy) {
    return of_current(policy) == role::tool;
}
inline bool pid_is_tool(const features::policy_view& policy, uint32_t pid) {
    return of_pid(policy, pid) == role::tool;
}
role of_process(PEPROCESS process);
role of_pid(uint32_t pid);
role of_current();

[[nodiscard]] inline bool is_target() {
    return of_current() == role::target;
}
[[nodiscard]] inline bool is_tool() {
    return of_current() == role::tool;
}

[[nodiscard]] bool pid_is_target(uint32_t pid);
[[nodiscard]] bool pid_is_tool(uint32_t pid);

// Pin table lookup only: no process reference or name resolution. At non-
// PASSIVE IRQL returns other without acquiring the push lock.
[[nodiscard]] role pinned_role(uint32_t pid);

// Mutations require PASSIVE_LEVEL and are ignored at higher IRQL. Rule
// publications do not clear manual PID pins; reset clears only manual pins.
void pin(uint32_t pid, role value);
void unpin(uint32_t pid);
void reset();
}  // namespace blook::roles
