#pragma once
#include "policy/features.hpp"

namespace blook::hook_catalog {
// Fixed built-in physical entry identities. Values also index the MASM shims.
enum class entry_id : uint32_t {
    query_system,
    query_process,
    set_thread,
    query_thread,
    get_context,
    open_process,
    open_thread,
    debug_attach,
    write_memory,
    protect_memory,
    window_query,
    window_find,
    window_list,
    window_foreground,
    window_point,
    count,
    opaque = 0xffffffffu
};
struct descriptor {
    entry_id id;
    const char* name;
    feature::mask optional;
    uint32_t mandatory;
};
using feature::bit;
using feature::id;
inline constexpr descriptor entries[] = {
    {entry_id::query_system, "NtQuerySystemInformation",
     feature::system_query_mask | bit(id::first_contact), 0},
    {entry_id::query_process, "NtQueryInformationProcess",
     bit(id::query_process) | bit(id::first_contact), 0},
    {entry_id::set_thread, "NtSetInformationThread", bit(id::set_thread), 0},
    {entry_id::query_thread, "NtQueryInformationThread", bit(id::query_thread),
     0},
    {entry_id::get_context, "NtGetContextThread", bit(id::get_context), 0},
    {entry_id::open_process, "NtOpenProcess", bit(id::open_process), 0},
    {entry_id::open_thread, "NtOpenThread", bit(id::open_thread), 0},
    {entry_id::debug_attach, "NtDebugActiveProcess", bit(id::debug_attach), 0},
    {entry_id::write_memory, "NtWriteVirtualMemory", bit(id::write_memory), 1},
    {entry_id::protect_memory, "NtProtectVirtualMemory", 0, 1},
    {entry_id::window_query, "NtUserQueryWindow", bit(id::window_query), 0},
    {entry_id::window_find, "NtUserFindWindowEx", bit(id::window_find), 0},
    {entry_id::window_list, "NtUserBuildHwndList", bit(id::window_list), 0},
    {entry_id::window_foreground, "NtUserGetForegroundWindow",
     bit(id::window_foreground), 0},
    {entry_id::window_point, "NtUserWindowFromPoint", bit(id::window_point), 0},
};
static_assert(sizeof(entries) / sizeof(entries[0]) ==
              static_cast<uint32_t>(entry_id::count));
constexpr const descriptor* find(entry_id value) {
    const auto index = static_cast<uint32_t>(value);
    return index < static_cast<uint32_t>(entry_id::count) ? &entries[index]
                                                          : nullptr;
}
constexpr uint32_t count_bits(feature::mask value) {
    uint32_t count = 0;
    for (; value; value &= value - 1)
        ++count;
    return count;
}
}  // namespace blook::hook_catalog
