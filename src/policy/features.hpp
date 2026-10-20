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
     "在目标进程首次接触查询入口时清理调试标志。"},
    {id::write_memory, "scrub.write_memory",
     "在工具写入非工具进程时临时中和 BeingDebugged 字节。"},
    {id::system_process, "nt.query_system.process",
     "从非工具调用者的系统进程列表中隐藏工具进程。"},
    {id::system_module, "nt.query_system.module",
     "从非工具调用者的系统模块列表中隐藏匹配模块。"},
    {id::kernel_debugger, "nt.query_system.kernel_debugger",
     "向非工具调用者返回未启用内核调试器的状态。"},
    {id::query_process, "nt.query_process",
     "向用户态目标调用者隐藏进程调试端口和调试对象信息。"},
    {id::set_thread, "nt.set_thread", "阻止目标调用者设置线程脱离调试器标志。"},
    {id::query_thread, "nt.query_thread",
     "向目标调用者隐藏线程脱离调试器标志。"},
    {id::get_context, "nt.get_context",
     "向目标调用者隐藏线程上下文中的硬件断点。"},
    {id::open_process, "nt.open_process", "拒绝目标调用者打开工具进程。"},
    {id::open_thread, "nt.open_thread", "拒绝目标调用者打开工具线程。"},
    {id::debug_attach, "scrub.debug_attach",
     "在成功附加调试器后清理被附加进程的调试标志。"},
    {id::window_query, "window.query",
     "向目标调用者隐藏工具窗口的所属进程标识。"},
    {id::window_find, "window.find", "向目标调用者隐藏查找得到的工具窗口。"},
    {id::window_list, "window.list",
     "从目标调用者的窗口枚举结果中移除工具窗口。"},
    {id::window_foreground, "window.foreground",
     "向目标调用者用上次可见窗口替代工具前台窗口。"},
    {id::window_point, "window.point", "向目标调用者隐藏坐标命中的工具窗口。"},
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
