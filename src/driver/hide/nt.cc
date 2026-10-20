#include "nt.hpp"

#include <ntifs.h>
#include <intrin.h>

#include "driver/hooks.hpp"
#include "driver/hook_shims.hpp"
#include "driver/features.hpp"
#include "policy/dispatch.hpp"
#include "driver/resources.hpp"
#include "driver/watch.hpp"
#include "driver/hide/nt_types.hpp"
#include "driver/hide/peb.hpp"
#include "driver/hide/roles.hpp"
#include "policy/hook.hpp"
#include "ssdt/ssdt.hpp"

namespace blook::hide::nt {
namespace {
using query_system_information_t = NTSTATUS (*)(ULONG, PVOID, ULONG, PULONG);
using query_information_process_t = NTSTATUS (*)(HANDLE, PROCESSINFOCLASS,
                                                 PVOID, ULONG, PULONG);
using set_information_thread_t = NTSTATUS (*)(HANDLE, THREADINFOCLASS, PVOID,
                                              ULONG);
using query_information_thread_t = NTSTATUS (*)(HANDLE, THREADINFOCLASS, PVOID,
                                                ULONG, PULONG);
using get_context_thread_t = NTSTATUS (*)(HANDLE, PCONTEXT);
using open_process_t = NTSTATUS (*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                    PCLIENT_ID);
using open_thread_t = NTSTATUS (*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                   PCLIENT_ID);
using debug_active_process_t = NTSTATUS (*)(HANDLE, HANDLE);
using write_virtual_memory_t = NTSTATUS (*)(HANDLE, PVOID, PVOID, SIZE_T,
                                            PSIZE_T);
using protect_virtual_memory_t = NTSTATUS (*)(HANDLE, PVOID*, PSIZE_T, ULONG,
                                              PULONG);

// One physical entry and its immutable original trampoline.
template <class FunctionPointer>
struct service {
    uint64_t id{};
    FunctionPointer original{};
};

service<query_system_information_t> query_system_information;
service<query_information_process_t> query_information_process;
service<set_information_thread_t> set_information_thread;
service<query_information_thread_t> query_information_thread;
service<get_context_thread_t> get_context_thread;
service<open_process_t> open_process;
service<open_thread_t> open_thread;
service<debug_active_process_t> debug_active_process;
service<write_virtual_memory_t> write_virtual_memory;
service<protect_virtual_memory_t> protect_virtual_memory;

// Invoke the published trampoline under the root-acquired gate reference.
template <class FunctionPointer, class... Args>
NTSTATUS call_original(const service<FunctionPointer>& svc, Args... args) {
    const auto original = svc.original;
    if (!svc.id || !original)
        return STATUS_DEVICE_NOT_READY;
    // The entry gate owns the invocation lifetime. The trampoline replays a
    // single relocation-safe instruction; no per-CPU original window is used.
    return original(args...);
}

// A debugger that starts the sample with DEBUG_PROCESS has BeingDebugged set
// while the process is created, before any hook of ours can run. The first
// service the sample calls is therefore the moment to clear it, once per
// process.
EX_PUSH_LOCK scrub_lock{};
uint32_t scrubbed[16]{};

bool first_contact(uint32_t pid) {
    exclusive_lock lock{scrub_lock};
    const auto slot = pid % (sizeof(scrubbed) / sizeof(scrubbed[0]));
    if (scrubbed[slot] == pid)
        return false;
    scrubbed[slot] = pid;
    return true;
}

void scrub_on_first_contact(const features::policy_view& policy, bool enabled) {
    if (!enabled || !roles::is_target(policy))
        return;
    auto* process = PsGetCurrentProcess();
    const auto pid = static_cast<uint32_t>(
        reinterpret_cast<uintptr_t>(PsGetProcessId(process)));
    if (pid && first_contact(pid))
        peb::process(process, peb::scrub_flags);
}

// NtWriteVirtualMemory
//
// Clearing the flag once is not enough: a debugger that attaches later writes
// it again. The write is not refused outright - the flag byte is neutralised
// in the caller buffer for the duration of the call, so every other byte of a
// multi byte write still lands where the tool wanted it.
struct flag_patch {
    uint8_t* byte{};
    uint8_t saved{};
};

flag_patch neutralise_flag_byte(const features::policy_view& policy,
                                HANDLE process_handle, PVOID base, PVOID buffer,
                                SIZE_T size) {
    flag_patch result;
    if (!base || !buffer || !size)
        return result;
    PEPROCESS process{};
    if (!NT_SUCCESS(ObReferenceObjectByHandle(
            process_handle, 0, *PsProcessType, ExGetPreviousMode(),
            reinterpret_cast<PVOID*>(&process), nullptr)))
        return result;
    // Tools may write to themselves; only the sample is protected.
    if (roles::of_process(policy, process) == role::tool) {
        ObDereferenceObject(process);
        return result;
    }
    __try {
        const auto peb = reinterpret_cast<uint64_t>(PsGetProcessPeb(process));
        const auto address = reinterpret_cast<uint64_t>(base);
        const auto flag = peb + 2;
        if (peb && address <= flag && address + size > flag) {
            auto* byte = static_cast<uint8_t*>(buffer) + (flag - address);
            if (*byte) {
                result.byte = byte;
                result.saved = *byte;
                *byte = 0;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result = {};
    }
    ObDereferenceObject(process);
    return result;
}

// The memory hooks run for every process in the system, so resolving the
// process a handle names has to tolerate the pseudo-handle a process uses for
// itself along the real ones.
bool process_of_handle(HANDLE process_handle, PEPROCESS& process) {
    process = nullptr;
    if (process_handle == NtCurrentProcess()) {
        process = PsGetCurrentProcess();
        ObReferenceObject(process);
        return true;
    }
    return NT_SUCCESS(ObReferenceObjectByHandle(
        process_handle, 0, *PsProcessType, ExGetPreviousMode(),
        reinterpret_cast<PVOID*>(&process), nullptr));
}

uint32_t pid_of(PEPROCESS process) {
    return static_cast<uint32_t>(
        reinterpret_cast<uintptr_t>(PsGetProcessId(process)));
}

using write_chain =
    dispatch_chain<NTSTATUS(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T), 2>;
NTSTATUS write_original(HANDLE process, PVOID base, PVOID buffer, SIZE_T size,
                        PSIZE_T written) {
    return call_original(write_virtual_memory, process, base, buffer, size,
                         written);
}
NTSTATUS write_scrub_handler(void* context, write_chain::continuation next,
                             HANDLE process_handle, PVOID base, PVOID buffer,
                             SIZE_T size, PSIZE_T written) {
    const auto& policy = *static_cast<const features::policy_view*>(context);
    flag_patch patch;
    if (roles::is_tool(policy) && ExGetPreviousMode() == UserMode)
        patch =
            neutralise_flag_byte(policy, process_handle, base, buffer, size);
    const auto status = next(process_handle, base, buffer, size, written);
    if (patch.byte) {
        __try {
            *patch.byte = patch.saved;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }
    return status;
}
NTSTATUS write_maintenance_handler(void*, write_chain::continuation next,
                                   HANDLE process_handle, PVOID base,
                                   PVOID buffer, SIZE_T size, PSIZE_T written) {
    const auto status = next(process_handle, base, buffer, size, written);
    // Rebind copy-on-write backing independently of optional PEB scrubbing.
    if (NT_SUCCESS(status) && base && size) {
        PEPROCESS process{};
        if (process_of_handle(process_handle, process)) {
            const auto begin =
                reinterpret_cast<uint64_t>(base) & ~uint64_t{0xfff};
            (void)rebind_hooks_if_copied(pid_of(process), base, size);
            watch::rebind_if_copied(process, begin, begin + size);
            ObDereferenceObject(process);
        }
    }
    return status;
}
NTSTATUS hook_write_virtual_memory(HANDLE process_handle, PVOID base,
                                   PVOID buffer, SIZE_T size, PSIZE_T written) {
    features::policy_view policy;
    const auto mask = policy.mask();
    write_chain chain;
    chain.add({1, write_maintenance_handler, nullptr, 0});
    if (mask & feature::bit(feature::id::write_memory))
        chain.add({2, write_scrub_handler, &policy, 0});
    return chain.invoke(write_original, process_handle, base, buffer, size,
                        written);
}

// NtProtectVirtualMemory
//
// This is the main copy-on-write gate: image sections are shared until their
// protection becomes writable, and the VM privatizes them inside exactly this
// call (classic self-decrypting shells: VirtualProtect(RWX) -> decrypt ->
// jump). When the first instruction of the plain code runs, its virtual page
// no longer maps the physical page the hook armed.
//
// It is also the only gate that makes a committed page executable, so dormant
// hooks and watches (registered while their page was still read/write) are
// finished and armed here, before the syscall returns.
NTSTATUS hook_protect_virtual_memory(HANDLE process_handle, PVOID* base,
                                     PSIZE_T size, ULONG new_protection,
                                     PULONG old_protection) {
    const auto status =
        call_original(protect_virtual_memory, process_handle, base, size,
                      new_protection, old_protection);
    if (!NT_SUCCESS(status))
        return status;
    PEPROCESS process{};
    if (!process_of_handle(process_handle, process))
        return status;
    // On success the service reports the page-aligned range it changed.
    PVOID aligned_base{};
    SIZE_T aligned_size{};
    __try {
        aligned_base = *base;
        aligned_size = *size;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        aligned_base = nullptr;
        aligned_size = 0;
    }
    if (aligned_base && aligned_size) {
        const auto begin =
            reinterpret_cast<uint64_t>(aligned_base) & ~uint64_t{0xfff};
        (void)rebind_hooks_if_copied(pid_of(process), aligned_base,
                                     aligned_size);
        watch::rebind_if_copied(process, begin, begin + aligned_size);
        arm_dormant_hooks(pid_of(process), aligned_base, aligned_size);
        watch::arm_dormant_if_executable(process, begin, begin + aligned_size);
    }
    ObDereferenceObject(process);
    return status;
}

// User-mode outputs are written through a guard: the syscall validated them,
// but a handler must not be the reason an invalid pointer turns into a fault.
template <class T>
bool write_user(PVOID destination, T value) {
    if (!destination)
        return false;
    __try {
        *static_cast<T*>(destination) = value;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

void strip_processes(const features::policy_view& policy, PVOID buffer,
                     PULONG return_length) {
    if (!return_length)
        return;
    const auto used = *return_length;
    if (used < sizeof(system_process_entry))
        return;
    auto* base = static_cast<uint8_t*>(buffer);

    // One pass: move every surviving entry down over the holes the hidden ones
    // left, and relink the chain with the new distances as we go. The old code
    // relinked in a second pass that still walked with the *old* distances,
    // which after compaction lands on unrelated bytes and rewrites their
    // NextEntryOffset - the caller then walks a corrupted list.
    ULONG read = 0;
    ULONG write = 0;
    ULONG previous = 0;
    bool have_previous = false;
    __try {
        while (read + sizeof(system_process_entry) <= used) {
            auto* node = reinterpret_cast<system_process_entry*>(base + read);
            const ULONG offset = node->next_entry_offset;
            const ULONG size = offset ? offset : (used - read);
            if (size < sizeof(system_process_entry) || read + size > used)
                break;
            if (offset && (offset & 3))
                break;

            bool hidden = false;
            if (node->image_name.Buffer && node->image_name.Length) {
                const auto length = node->image_name.Length / sizeof(wchar_t);
                // The name pointer inside the entry is a user-mode pointer that
                // the service already validated; the length is not trusted
                // further than this bound before it is walked.
                if (length < 32768)
                    hidden = policy.classify(node->image_name.Buffer, length) ==
                             role::tool;
            }
            hidden = hidden || roles::pinned_role(static_cast<uint32_t>(
                                   reinterpret_cast<uintptr_t>(
                                       node->unique_process_id))) == role::tool;

            if (!hidden) {
                if (write != read)
                    memmove(base + write, node, size);
                if (have_previous)
                    reinterpret_cast<system_process_entry*>(base + previous)
                        ->next_entry_offset = write - previous;
                previous = write;
                have_previous = true;
                write += size;
            }
            if (!offset)
                break;
            read += size;
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Best effort: leave the list as the service produced it.
        return;
    }

    if (write == 0) {
        // Nothing survived: report a single anonymous entry rather than a chain
        // the caller would walk into stale bytes.
        auto* node = reinterpret_cast<system_process_entry*>(base);
        node->image_name.Length = 0;
        node->image_name.MaximumLength = 0;
        node->unique_process_id = nullptr;
        node->next_entry_offset = 0;
        return;
    }

    reinterpret_cast<system_process_entry*>(base + previous)
        ->next_entry_offset = 0;
    *return_length = write;
}

void strip_modules(PVOID buffer, ULONG length) {
    if (!buffer || length < sizeof(rtl_process_modules))
        return;
    auto* modules = static_cast<rtl_process_modules*>(buffer);
    const auto capacity =
        static_cast<ULONG>((length - offsetof(rtl_process_modules, modules)) /
                           sizeof(rtl_process_module_information));
    __try {
        ULONG index = 0;
        while (index < modules->number_of_modules && index < capacity) {
            const auto* path = reinterpret_cast<const char*>(
                modules->modules[index].full_path_name);
            size_t name_length = 0;
            while (name_length < 256 && path[name_length])
                ++name_length;
            if (!hidden_module(path, name_length)) {
                ++index;
                continue;
            }
            const auto remaining = modules->number_of_modules - index - 1;
            if (remaining)
                memmove(&modules->modules[index], &modules->modules[index + 1],
                        remaining * sizeof(rtl_process_module_information));
            --modules->number_of_modules;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // A malformed entry must never turn into a fault in the handler.
    }
}

void hide_kernel_debugger(PVOID buffer, ULONG length) {
    if (length < sizeof(system_kernel_debugger_information))
        return;
    auto* info = static_cast<system_kernel_debugger_information*>(buffer);
    info->enabled = FALSE;
    info->not_present = TRUE;
}

bool read_client_id(PCLIENT_ID client_id, uint32_t& pid, uint32_t& tid) {
    pid = tid = 0;
    if (!client_id)
        return false;
    __try {
        pid = static_cast<uint32_t>(
            reinterpret_cast<uintptr_t>(client_id->UniqueProcess));
        tid = static_cast<uint32_t>(
            reinterpret_cast<uintptr_t>(client_id->UniqueThread));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    return true;
}

bool tool_thread(const features::policy_view& policy, uint32_t tid) {
    if (!tid || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return false;
    PETHREAD thread{};
    if (!NT_SUCCESS(PsLookupThreadByThreadId(ULongToHandle(tid), &thread)))
        return false;
    bool tool = false;
    if (auto* process = PsGetThreadProcess(thread))
        tool = roles::of_process(policy, process) == role::tool;
    ObDereferenceObject(thread);
    return tool;
}

// Bring-up probe: what does the processor state look like at the moment the
// patch hands control to this handler? The entry jump is a ret, so [rsp] must
// hold the address the caller pushed; the arguments must look like
// (class, buffer, length, return_length). If they do not, the hook fired
// somewhere other than a call boundary - which is what puts service output on
// an unrelated kernel stack. Kept in the driver's own memory so a dump shows
// it (the array is deliberately named for that).
struct handler_probe_record {
    uint64_t sequence;
    uint64_t return_slot;
    uint64_t slot1;
    uint64_t slot2;
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;
    // Filled just before the handler returns: if these differ from the entry
    // sample, the call damaged its own return slot / frame.
    uint64_t return_slot_after;
    uint64_t slot1_after;
    uint64_t slot2_after;
    uint64_t rsp_after;
};
handler_probe_record handler_probes[32]{};
volatile uint64_t handler_probe_total{};

using system_chain = dispatch_chain<NTSTATUS(ULONG, PVOID, ULONG, PULONG), 4>;

NTSTATUS system_original(ULONG info_class, PVOID buffer, ULONG length,
                         PULONG return_length) {
    const auto status = call_original(query_system_information, info_class,
                                      buffer, length, return_length);
    return status;
}
NTSTATUS system_scrub_handler(void* context, system_chain::continuation next,
                              ULONG c, PVOID b, ULONG n, PULONG used) {
    const auto& policy = *static_cast<const features::policy_view*>(context);
    const auto status = next(c, b, n, used);
    scrub_on_first_contact(policy, true);
    return status;
}

bool rewrite_system(const features::policy_view& policy, NTSTATUS status,
                    PVOID buffer) {
    // Preserve the existing non-tool scope (NOT target-only).
    return NT_SUCCESS(status) && buffer && !roles::is_tool(policy);
}
NTSTATUS system_process_handler(void* context, system_chain::continuation next,
                                ULONG c, PVOID b, ULONG n, PULONG used) {
    const auto& policy = *static_cast<const features::policy_view*>(context);
    const auto status = next(c, b, n, used);
    if (c == static_cast<ULONG>(system_information_class::process) &&
        rewrite_system(policy, status, b))
        strip_processes(policy, b, used);
    return status;
}
NTSTATUS system_module_handler(void* context, system_chain::continuation next,
                               ULONG c, PVOID b, ULONG n, PULONG used) {
    const auto& policy = *static_cast<const features::policy_view*>(context);
    const auto status = next(c, b, n, used);
    if (c == static_cast<ULONG>(system_information_class::module) &&
        rewrite_system(policy, status, b))
        strip_modules(b, n);
    return status;
}
NTSTATUS system_debugger_handler(void* context, system_chain::continuation next,
                                 ULONG c, PVOID b, ULONG n, PULONG used) {
    const auto& policy = *static_cast<const features::policy_view*>(context);
    const auto status = next(c, b, n, used);
    if (c == static_cast<ULONG>(system_information_class::kernel_debugger) &&
        rewrite_system(policy, status, b))
        hide_kernel_debugger(b, n);
    return status;
}

NTSTATUS hook_query_system_information_impl(ULONG info_class, PVOID buffer,
                                            ULONG length,
                                            PULONG return_length) {
    {
        auto const total = ++handler_probe_total;
        if (total <= 32) {
            auto& probe = handler_probes[total - 1];
            auto* const return_slot =
                static_cast<uint64_t*>(_AddressOfReturnAddress());
            probe.sequence = total;
            probe.return_slot = return_slot ? return_slot[0] : 0;
            probe.slot1 = return_slot ? return_slot[1] : 0;
            probe.slot2 = return_slot ? return_slot[2] : 0;
            probe.arg0 = info_class;
            probe.arg1 = reinterpret_cast<uint64_t>(buffer);
            probe.arg2 = length;
            probe.arg3 = reinterpret_cast<uint64_t>(return_length);
        }
    }

    // Pin mask and role rules from the same immutable generation for the whole
    // call.
    features::policy_view policy;
    const auto mask = policy.mask();
    system_chain chain;
    if (mask & feature::bit(feature::id::system_process))
        chain.add({1, system_process_handler, &policy, 0});
    if (mask & feature::bit(feature::id::system_module))
        chain.add({2, system_module_handler, &policy, 0});
    if (mask & feature::bit(feature::id::kernel_debugger))
        chain.add({3, system_debugger_handler, &policy, 0});
    if (mask & feature::bit(feature::id::first_contact))
        chain.add({4, system_scrub_handler, &policy, 0});
    return chain.invoke(system_original, info_class, buffer, length,
                        return_length);
}

// Sampling wrapper: the same picture the entry probe takes, taken again right
// before the handler returns. A difference in the return slot is the direct
// evidence that this call path is eating its own way back to the caller.
// A nested entry is normal here: NtQuerySystemInformation and
// NtQuerySystemInformationEx call each other, so with a correct trampoline the
// nesting depth is exactly the depth the unhooked function has. Guarding it out
// broke the service (callers retried forever) - that was the last hang.
//
// What must never happen instead is the trampoline jumping back *into* the
// patched range: its target has to be the instruction boundary right after the
// bytes it replayed.
NTSTATUS hook_query_system_information(ULONG info_class, PVOID buffer,
                                       ULONG length, PULONG return_length) {
    auto* const return_slot = static_cast<uint64_t*>(_AddressOfReturnAddress());
    auto const before_0 = return_slot ? return_slot[0] : 0;
    auto const before_1 = return_slot ? return_slot[1] : 0;
    auto const before_2 = return_slot ? return_slot[2] : 0;
    auto const status = hook_query_system_information_impl(
        info_class, buffer, length, return_length);
    auto const after_0 = return_slot ? return_slot[0] : 0;
    auto const after_1 = return_slot ? return_slot[1] : 0;
    auto const after_2 = return_slot ? return_slot[2] : 0;
    for (uint64_t i = 0; i < 32; ++i) {
        auto& probe = handler_probes[i];
        if (probe.sequence != 0 && probe.return_slot == before_0 &&
            probe.arg0 == info_class && probe.arg2 == length &&
            probe.return_slot_after == 0) {
            probe.return_slot_after = after_0;
            probe.slot1_after = after_1;
            probe.slot2_after = after_2;
            probe.rsp_after = reinterpret_cast<uint64_t>(return_slot);
            break;
        }
    }
    return status;
}

NTSTATUS hook_query_information_process(HANDLE process_handle,
                                        PROCESSINFOCLASS info_class, PVOID info,
                                        ULONG length, PULONG return_length) {
    features::policy_view policy;
    const auto mask = policy.mask();
    const bool spoof = (mask & feature::bit(feature::id::query_process)) &&
                       roles::is_target(policy) &&
                       ExGetPreviousMode() == UserMode;
    scrub_on_first_contact(
        policy, (mask & feature::bit(feature::id::first_contact)) != 0);
    const auto status = call_original(query_information_process, process_handle,
                                      info_class, info, length, return_length);
    if (!spoof || !NT_SUCCESS(status))
        return status;

    switch (info_class) {
        case ProcessDebugPort:
            if (length >= sizeof(HANDLE)) {
                write_user<HANDLE>(info, nullptr);
                if (return_length)
                    write_user<ULONG>(return_length, sizeof(HANDLE));
            }
            break;
        case ProcessDebugObjectHandle:
            // The not-debugged answer is a failure, so the caller cannot be
            // told there is a debug object even if one exists.
            if (length >= sizeof(HANDLE))
                write_user<HANDLE>(info, nullptr);
            return STATUS_PORT_NOT_SET;
        case ProcessDebugFlags:
            if (length >= sizeof(ULONG)) {
                write_user<ULONG>(info, 1);
                if (return_length)
                    write_user<ULONG>(return_length, sizeof(ULONG));
            }
            break;
        default:
            break;
    }
    return status;
}

NTSTATUS hook_set_information_thread(HANDLE thread_handle,
                                     THREADINFOCLASS info_class, PVOID info,
                                     ULONG length) {
    features::policy_view policy;
    // Refusing the request keeps the thread visible to the debugger instead of
    // letting the sample hide the threads the analyst needs to inspect.
    if (policy.enabled(feature::id::set_thread) &&
        info_class == ThreadHideFromDebugger && roles::is_target(policy))
        return STATUS_SUCCESS;
    return call_original(set_information_thread, thread_handle, info_class,
                         info, length);
}

NTSTATUS hook_query_information_thread(HANDLE thread_handle,
                                       THREADINFOCLASS info_class, PVOID info,
                                       ULONG length, PULONG return_length) {
    features::policy_view policy;
    const auto status = call_original(query_information_thread, thread_handle,
                                      info_class, info, length, return_length);
    if (!policy.enabled(feature::id::query_thread) || !NT_SUCCESS(status) ||
        !roles::is_target(policy))
        return status;
    if (info_class == ThreadHideFromDebugger && length >= sizeof(ULONG))
        write_user<ULONG>(info, 0);
    return status;
}

NTSTATUS hook_get_context_thread(HANDLE thread_handle, PCONTEXT context) {
    features::policy_view policy;
    const auto status =
        call_original(get_context_thread, thread_handle, context);
    if (!policy.enabled(feature::id::get_context) || !NT_SUCCESS(status) ||
        !context || !roles::is_target(policy))
        return status;
    // Hardware breakpoints belong to the debugger. A sample that reads its own
    // thread context must not find them.
    __try {
        if (context->ContextFlags & 0x00100000 /* CONTEXT_DEBUG_REGISTERS */) {
            context->Dr0 = 0;
            context->Dr1 = 0;
            context->Dr2 = 0;
            context->Dr3 = 0;
            context->Dr6 = 0;
            context->Dr7 = 0;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }
    return status;
}

NTSTATUS hook_open_process(PHANDLE process_handle, ACCESS_MASK access,
                           POBJECT_ATTRIBUTES attributes,
                           PCLIENT_ID client_id) {
    features::policy_view policy;
    uint32_t pid{}, tid{};
    if (policy.enabled(feature::id::open_process) &&
        read_client_id(client_id, pid, tid) && roles::is_target(policy) &&
        pid && roles::pid_is_tool(policy, pid))
        return STATUS_ACCESS_DENIED;
    return call_original(open_process, process_handle, access, attributes,
                         client_id);
}

NTSTATUS hook_open_thread(PHANDLE thread_handle, ACCESS_MASK access,
                          POBJECT_ATTRIBUTES attributes, PCLIENT_ID client_id) {
    features::policy_view policy;
    uint32_t pid{}, tid{};
    if (policy.enabled(feature::id::open_thread) &&
        read_client_id(client_id, pid, tid) && roles::is_target(policy) &&
        tool_thread(policy, tid))
        return STATUS_ACCESS_DENIED;
    return call_original(open_thread, thread_handle, access, attributes,
                         client_id);
}

NTSTATUS hook_debug_active_process(HANDLE process_handle, HANDLE debug_object) {
    features::policy_view policy;
    const auto status =
        call_original(debug_active_process, process_handle, debug_object);
    // Attaching a debugger is exactly the moment Windows sets BeingDebugged and
    // the debug heap flags, so undo it right away.
    if (policy.enabled(feature::id::debug_attach) && NT_SUCCESS(status)) {
        PEPROCESS process{};
        if (NT_SUCCESS(ObReferenceObjectByHandle(
                process_handle, 0, *PsProcessType, ExGetPreviousMode(),
                reinterpret_cast<PVOID*>(&process), nullptr))) {
            peb::process(process, peb::scrub_flags);
            ObDereferenceObject(process);
        }
    }
    return status;
}

struct install_entry {
    uint64_t* id;
    void** original;
    const wchar_t* symbol;
    void* handler;
};

// The anti-anti-debug profile. These handlers adjust what the sample
// observes; nothing in them maintains the hook machinery itself.
install_entry profile_entries[] = {
    {&query_system_information.id,
     reinterpret_cast<void**>(&query_system_information.original),
     L"NtQuerySystemInformation",
     reinterpret_cast<void*>(&hook_query_system_information)},
    {&query_information_process.id,
     reinterpret_cast<void**>(&query_information_process.original),
     L"NtQueryInformationProcess",
     reinterpret_cast<void*>(&hook_query_information_process)},
    {&set_information_thread.id,
     reinterpret_cast<void**>(&set_information_thread.original),
     L"NtSetInformationThread",
     reinterpret_cast<void*>(&hook_set_information_thread)},
    {&query_information_thread.id,
     reinterpret_cast<void**>(&query_information_thread.original),
     L"NtQueryInformationThread",
     reinterpret_cast<void*>(&hook_query_information_thread)},
    {&get_context_thread.id,
     reinterpret_cast<void**>(&get_context_thread.original),
     L"NtGetContextThread", reinterpret_cast<void*>(&hook_get_context_thread)},
    {&open_process.id, reinterpret_cast<void**>(&open_process.original),
     L"NtOpenProcess", reinterpret_cast<void*>(&hook_open_process)},
    {&open_thread.id, reinterpret_cast<void**>(&open_thread.original),
     L"NtOpenThread", reinterpret_cast<void*>(&hook_open_thread)},
    {&debug_active_process.id,
     reinterpret_cast<void**>(&debug_active_process.original),
     L"NtDebugActiveProcess",
     reinterpret_cast<void*>(&hook_debug_active_process)},
};

// Core VM hooks: always on while the hypervisor runs, independent of the
// profile. Their handlers re-arm session hooks whose virtual pages were
// re-backed by copy-on-write (plus the write-side PEB scrub that has always
// lived on NtWriteVirtualMemory). Without them every hook on an image page
// dies silently the moment the page is made writable or written remotely.
install_entry core_entries[] = {
    {&protect_virtual_memory.id,
     reinterpret_cast<void**>(&protect_virtual_memory.original),
     L"NtProtectVirtualMemory",
     reinterpret_cast<void*>(&hook_protect_virtual_memory)},
    {&write_virtual_memory.id,
     reinterpret_cast<void**>(&write_virtual_memory.original),
     L"NtWriteVirtualMemory",
     reinterpret_cast<void*>(&hook_write_virtual_memory)},
};
}  // namespace

void forget_process(ULONG pid) {
    if (!pid)
        return;
    exclusive_lock lock{scrub_lock};
    for (auto& value : scrubbed)
        if (value == pid)
            value = 0;
}

bool installed() {
    for (const auto& entry : profile_entries)
        if (*entry.id)
            return true;
    return false;
}

bool core_installed() {
    for (const auto& entry : core_entries)
        if (*entry.id)
            return true;
    return false;
}

NTSTATUS install_table(install_entry* table, uint32_t entry_count,
                       uint32_t selected = ~uint32_t{0}) {
    uint32_t count = 0;
    for (uint32_t index = 0; index < entry_count; ++index) {
        auto& entry = table[index];
        if (!(selected & (uint32_t{1} << index)))
            continue;
        if (*entry.id) {
            if (hook_armed(*entry.id))
                ++count;
            continue;
        }
        // Current builds no longer export every service (24H2 has no
        // NtProtectVirtualMemory / NtWriteVirtualMemory), so resolution falls
        // back to the SSDT; a service that cannot be resolved at all is
        // skipped rather than guessed at.
        auto* address = ssdt::resolve_service(entry.symbol);
        if (!address) {
            blook::bringup_write("install: name unresolved, index", index,
                                 true);
            continue;
        }
        // prepare_hook validates and builds the counted VMCALL entry.
        uint8_t patch[max_patch]{};
        // Register and publish first, arm second. The handler needs both the
        // id and the original trampoline, and it can
        // be reached from another processor as soon as its own processor is
        // armed.
        prepared_hook prepared{};
        const auto shim_index =
            table == core_entries ? (index == 0 ? 9u : 8u) : index;
        auto* shim = select_shim(shim_index, entry.handler);
        const auto prepared_status =
            shim ? prepare_hook(0, system_token, address, patch, 3, prepared,
                                shim,
                                static_cast<hook_catalog::entry_id>(shim_index))
                 : STATUS_NOT_SUPPORTED;
        blook::bringup_write("install: prepare status",
                             static_cast<uint32_t>(prepared_status), true);
        if (!NT_SUCCESS(prepared_status))
            continue;

        // Without a trampoline the handler could only reach the original by
        // calling the patched entry, which re-enters the handler without
        // bound. Skip the hook instead.
        if (!prepared.trampoline) {
            blook::bringup_write("install: no trampoline, index", index, true);
            cancel_hook(prepared);
            continue;
        }
        *entry.id = prepared.id;
        // The trampoline is the copy of the overwritten bytes: reaching the
        // original means running those bytes and jumping back into the
        // function. No page view is touched for that.
        *entry.original = prepared.trampoline;
        if (NT_SUCCESS(arm_hook(prepared))) {
            ++count;
            continue;
        }
        // An earlier CPU may have entered the shim. Retain the published
        // original until global drain; report this service unavailable.
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    return count ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED;
}

NTSTATUS install_core() {
    (void)install_table(core_entries,
                        sizeof(core_entries) / sizeof(core_entries[0]));
    return hook_armed(protect_virtual_memory.id) &&
                   hook_armed(write_virtual_memory.id)
               ? STATUS_SUCCESS
               : STATUS_NOT_SUPPORTED;
}

void remove_core() {
    // No online removal: maintenance and trampolines live until global
    // teardown.
}

void reset_after_shutdown() {
    // Caller guarantees hooks are destroyed and all invocation readers drained.
    for (auto& entry : profile_entries) {
        *entry.id = 0;
        *entry.original = nullptr;
    }
    for (auto& entry : core_entries) {
        *entry.id = 0;
        *entry.original = nullptr;
    }
    for (auto& pid : scrubbed)
        pid = 0;
}

feature::mask ensure_features(feature::mask requested) {
    using feature::bit;
    using feature::id;
    // First-contact scrub uses QuerySystem as its independently installable
    // gate.
    const feature::mask needs[] = {
        feature::system_query_mask | bit(id::first_contact),
        bit(id::query_process),
        bit(id::set_thread),
        bit(id::query_thread),
        bit(id::get_context),
        bit(id::open_process),
        bit(id::open_thread),
        bit(id::debug_attach)};
    uint32_t selected = 0;
    for (uint32_t i = 0; i < sizeof(needs) / sizeof(needs[0]); ++i)
        if (requested & needs[i])
            selected |= uint32_t{1} << i;
    if (selected)
        (void)install_table(
            profile_entries,
            sizeof(profile_entries) / sizeof(profile_entries[0]), selected);
    if (requested & bit(id::write_memory))
        (void)install_table(core_entries, 2, 2);
    feature::mask supported = 0;
    for (uint32_t i = 0; i < sizeof(needs) / sizeof(needs[0]); ++i)
        if (hook_armed(*profile_entries[i].id))
            supported |= needs[i];
    if (hook_armed(write_virtual_memory.id))
        supported |= bit(id::write_memory);
    return supported & requested;
}

NTSTATUS install() {
    return features::update(feature::nt_preset, 0).status;
}

void remove() {
    // Logical disable only: published trampolines stay alive for in-flight
    // calls.
    (void)features::update(0, feature::nt_preset);
}
}  // namespace blook::hide::nt
