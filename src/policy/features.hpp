#pragma once
#include <stddef.h>
#include "policy/integer.hpp"

namespace blook::feature {
using mask = uint64_t;
// Stable wire bit positions: append only; never recycle an ID.
enum class id : uint8_t {
    first_contact,
    write_memory,
    system_process,
    system_module,
    kernel_debugger,
    query_process,
    set_thread,
    query_thread,
    get_context,
    open_process,
    open_thread,
    debug_attach,
    window_query,
    window_find,
    window_list,
    window_foreground,
    window_point,
    count
};
constexpr mask bit(id value) {
    return static_cast<uint8_t>(value) < 64
               ? mask{1} << static_cast<uint8_t>(value)
               : 0;
}
inline constexpr mask known_mask = (bit(id::count) - 1);
inline constexpr mask window_preset = known_mask & ~(bit(id::window_query) - 1);
inline constexpr mask nt_preset = known_mask & ~window_preset;
inline constexpr mask system_query_mask =
    bit(id::system_process) | bit(id::system_module) | bit(id::kernel_debugger);
struct descriptor {
    id value;
    const char* name;
    const char* purpose;
};
inline constexpr descriptor descriptors[] = {
    {id::first_contact, "scrub.first_contact",
     "Clear the debug flag when the target first touches the query entry."},
    {id::write_memory, "scrub.write_memory",
     "Temporarily neutralise the BeingDebugged byte while the tool writes to a non-tool process."},
    {id::system_process, "nt.query_system.process",
     "Hide the tool process from a non-tool caller system process list."},
    {id::system_module, "nt.query_system.module",
     "Hide matching modules from a non-tool caller system module list."},
    {id::kernel_debugger, "nt.query_system.kernel_debugger",
     "Report the kernel debugger as disabled to non-tool callers."},
    {id::query_process, "nt.query_process",
     "Hide the process debug port and debug object from a user-mode target caller."},
    {id::set_thread, "nt.set_thread", "Deny the target caller setting the thread hide-from-debugger flag."},
    {id::query_thread, "nt.query_thread",
     "Hide the thread hide-from-debugger flag from the target caller."},
    {id::get_context, "nt.get_context",
     "Hide hardware breakpoints in the thread context from the target caller."},
    {id::open_process, "nt.open_process", "Refuse the target caller opening the tool process."},
    {id::open_thread, "nt.open_thread", "Refuse the target caller opening tool threads."},
    {id::debug_attach, "scrub.debug_attach",
     "Clear the debug flags of the attached process after a successful attach."},
    {id::window_query, "window.query",
     "Hide the owning process id of tool windows from the target caller."},
    {id::window_find, "window.find", "Hide tool windows found by lookup from the target caller."},
    {id::window_list, "window.list",
     "Remove tool windows from a target caller window enumeration."},
    {id::window_foreground, "window.foreground",
     "Substitute the last visible window for the tool foreground window."},
    {id::window_point, "window.point", "Hide tool windows hit by point from the target caller."},
};
constexpr const descriptor* find(const char* name, size_t length) {
    if (!name)
        return nullptr;
    for (const auto& item : descriptors) {
        size_t i = 0;
        while (i < length && item.name[i] && item.name[i] == name[i])
            ++i;
        if (i == length && !item.name[i])
            return &item;
    }
    return nullptr;
}
constexpr bool valid(mask value) {
    return (value & ~known_mask) == 0;
}
}  // namespace blook::feature
