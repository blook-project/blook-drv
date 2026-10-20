#include "hook_shims.hpp"

#include <intrin.h>

extern "C" {
alignas(8) void* blook_hook_handlers[15] = {};
}

namespace blook {
namespace {
using shim_entry = void (*)();
constexpr shim_entry entries[] = {
    blook_hook_shim_query_system, blook_hook_shim_query_process,
    blook_hook_shim_set_thread,   blook_hook_shim_query_thread,
    blook_hook_shim_get_context,  blook_hook_shim_open_process,
    blook_hook_shim_open_thread,  blook_hook_shim_debug_attach,
    blook_hook_shim_write_memory, blook_hook_shim_protect_memory,
    blook_hook_shim_window_query, blook_hook_shim_window_find,
    blook_hook_shim_window_list,  blook_hook_shim_window_foreground,
    blook_hook_shim_window_point,
};
static_assert(sizeof(entries) / sizeof(entries[0]) == hook_shim_count);
static_assert(sizeof(blook_hook_handlers) / sizeof(blook_hook_handlers[0]) ==
              hook_shim_count);
static_assert(static_cast<uint32_t>(hook_shim_slot::window_point) + 1 ==
              hook_shim_count);
}  // namespace

void* select_shim(uint32_t slot, void* handler) noexcept {
    if (slot >= hook_shim_count || handler == nullptr) {
        return nullptr;
    }
    // Full-barrier, atomic publication. Assembly reads an aligned pointer only
    // after the root redirect is armed, and the value never changes thereafter.
    void* previous = _InterlockedCompareExchangePointer(
        &blook_hook_handlers[slot], handler, nullptr);
    if (previous != nullptr && previous != handler) {
        return nullptr;
    }
    return reinterpret_cast<void*>(entries[slot]);
}
}  // namespace blook
