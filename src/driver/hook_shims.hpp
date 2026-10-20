#pragma once

#include "policy/integer.hpp"
#include "policy/hook_catalog.hpp"

// C linkage is shared with MASM and the root-side leave-site validator. These
// are addresses, NOT C-callable void() functions: each entry has its service's
// native Windows x64 ABI. In particular window_point receives POINT in RCX.
extern "C" {
extern void* blook_hook_handlers[15];
void blook_hook_shim_query_system();
void blook_hook_shim_query_process();
void blook_hook_shim_set_thread();
void blook_hook_shim_query_thread();
void blook_hook_shim_get_context();
void blook_hook_shim_open_process();
void blook_hook_shim_open_thread();
void blook_hook_shim_debug_attach();
void blook_hook_shim_write_memory();
void blook_hook_shim_protect_memory();
void blook_hook_shim_window_query();
void blook_hook_shim_window_find();
void blook_hook_shim_window_list();
void blook_hook_shim_window_foreground();
void blook_hook_shim_window_point();
void blook_hook_leave_site();
}

namespace blook {
// Fixed service identities, not dynamically allocated hook registry indices.
// Keep these values in sync with the handler offsets in hook_shims.asm.
using hook_shim_slot = hook_catalog::entry_id;
inline constexpr uint32_t hook_shim_count = 15;

// Publish the handler before returning the corresponding entry address. The
// caller must finish ALL other handler state publication before arming a root
// redirect. Invalid slots, null handlers and attempts to rebind an occupied
// slot to a different handler return nullptr. Repeating the same pair is OK.
// Bindings last for the image lifetime: do not clear them while any redirect,
// inflight invocation, original-call window or deferred root state can exist.
// No counters/gates are implemented here. Exceptional unwinding intentionally
// skips leave and retains the root-side inflight reference (fail-closed).
void* select_shim(uint32_t slot, void* handler) noexcept;
inline void* select_shim(hook_shim_slot slot, void* handler) noexcept {
    return select_shim(static_cast<uint32_t>(slot), handler);
}
}  // namespace blook
