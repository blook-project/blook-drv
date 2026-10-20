#pragma once
#include <ntifs.h>

#include "policy/hook.hpp"
#include "policy/hook_catalog.hpp"
#include "blook/drv/wire.hpp"

// Registry of EPT hooks.
//
// A hook is either global (domain = kernel, no owner) or owned by a process
// (domain = user). User hooks carry a per-process identity page - the target
// PEB - which is what the hypervisor compares at execute time, so a hook on a
// shared image page only fires for the process that owns it and a hook keeps
// working in every process the caller names, not just the current one.
namespace blook {
// Bring-up diagnostics: append one line to D:\blook-drv\.cache\driver.log.
void bringup_write(const char* label, uint32_t value, bool have_value);
NTSTATUS initialize_hooks();
// Only after the all-CPU unpatch/drain/stop barrier.
void shutdown_hooks();

// Hooks installed by the driver itself carry this token and are not reachable
// from the device ABI.
inline constexpr uint64_t system_token = ~uint64_t{};

// `patch` must fit inside the 64-byte patch buffer and inside the target page.
// `token` identifies the owner for later remove/refresh calls.
NTSTATUS install_hook(uint32_t pid, uint64_t token, void* target,
                      const uint8_t* patch, size_t length, uint64_t& id);

// Installing a hook has two phases, and the split is load bearing: a patch
// may only become executable after everything its handler reads is
// published. `prepare_hook` pins the target page, assigns the id and
// registers the hook (so remove/refresh/revoke already see it); `arm_hook`
// then makes the patch live, logical processor by logical processor. A
// handler starts running on each processor the moment it is armed - possibly
// before arm_hook() returns - so the caller must publish its own state (the
// immutable handler binding and original trampoline) between the two calls.
// Destination must be a counted known-ABI shim, not a bare C++ handler.
// `cancel_hook` drops a
// prepared hook that was never armed.
struct prepared_hook {
    uint64_t id{};
    hook_spec spec{};
    // Callable copy of the bytes the patch overwrites, followed by a jump
    // back into the original function. Handlers call this instead of the
    // patched entry (see hide::nt), so running the original does not require
    // changing any processor's page views.
    void* trampoline{};
};
NTSTATUS prepare_hook(
    uint32_t pid, uint64_t token, void* target, const uint8_t* patch,
    size_t length, prepared_hook& prepared, const void* destination = nullptr,
    hook_catalog::entry_id catalog = hook_catalog::entry_id::opaque);

NTSTATUS arm_hook(const prepared_hook& prepared);
void cancel_hook(const prepared_hook& prepared);

NTSTATUS remove_hook(uint64_t id);
NTSTATUS refresh_hook(uint64_t id);
// Token checked variants: a session can only drop the hooks it created.
NTSTATUS remove_owned_hook(uint64_t id, uint64_t token);
NTSTATUS refresh_owned_hook(uint64_t id, uint64_t token);
bool hook_present(uint64_t id);
bool hook_armed(uint64_t id);

// PASSIVE_LEVEL, feature+registry snapshot; no attach, pin, VA translation or
// hypercall. User rows/counts are token-filtered; kernel always counts-only.
// pid must already be resolved (nonzero user / zero kernel).
NTSTATUS query_page_hooks(uint32_t pid, uint64_t token, uint64_t address,
                          uint32_t domain, wire::QueryPageResponse& result);
namespace detail {
// Internal: feature writer lock must be held by query_page_hooks.
NTSTATUS query_page_hooks_snapshot(uint32_t pid, uint64_t token,
                                   uint64_t address, uint32_t domain,
                                   wire::QueryPageResponse& result,
                                   feature::mask effective);
}  // namespace detail

// Copy-on-write rebind. The VM hooks (NtProtectVirtualMemory,
// NtWriteVirtualMemory) call this after a successful operation: any hook the
// session layer placed inside [base, base + size) of `pid` may now sit on a
// stale physical page, because changing the protection of a shared image page
// (or writing it through another process) silently rebinds the virtual page to
// a fresh private page. For every such hook the current backing page is
// resolved again; when its PFN changed the hook moves to the new page -
// without this the EPT entry traps a page nobody executes any more and the
// patched copy runs unhooked.
// PASSIVE_LEVEL only (page probing + per-processor re-install).
NTSTATUS rebind_hooks_if_copied(uint32_t pid, const void* base, size_t size);
uint64_t rebind_count();
uint64_t rebind_failure_count();

// Deferred arming of dormant hooks. A user hook installed on a page that is
// committed but not yet executable (a JIT or shellcode allocation in its
// read-write stage) is registered dormant: it owns an id and its page pins,
// but nothing is published to the hypervisor and the instruction-boundary
// decode has not run - the bytes that matter are the ones the page holds when
// it becomes executable, not the ones it held at install time. The
// NtProtectVirtualMemory maintenance hook calls this after a successful
// protection change; every dormant hook of `pid` inside [base, base + size)
// whose page just became executable is finished (decode, patch, trampoline)
// and armed before the syscall returns, so no execution slips past unhooked.
// PASSIVE_LEVEL only (page probing + per-processor install).
void arm_dormant_hooks(uint32_t pid, const void* base, size_t size);

// Call-original window. Only valid on the logical processor that is currently
// executing the hook handler, which is exactly how the guest side handlers use
// it: begin, call the real function, end.
bool begin_hook_window(uint64_t id);
void end_hook_window(uint64_t id);

// Drop only the hooks created by this session, including remote targets.
// Closing an unrelated (even same-process) session must not affect them.
void revoke_session(uint64_t token);

// Target-process exit: drop every hook targeting this PID, across sessions.
// Session creators exiting are handled separately by revoke_session().
void revoke_process(uint32_t pid);

// Republish every hook after the hypervisor was restarted, e.g. across a
// system power transition.
NTSTATUS restore_all();
uint32_t active_hook_count();
uint32_t user_hook_count(uint32_t pid);
}  // namespace blook
