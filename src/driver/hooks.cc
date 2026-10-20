#include "hooks.hpp"

#include <ntifs.h>

#include "driver/hv/hv.h"
#include "driver/hv/hook_gate.hpp"
#include "driver/gate_landing.hpp"
#include "policy/gate_entry.hpp"
#include "policy/page_query.hpp"
#include "policy/x86_length.hpp"
#include "resources.hpp"

namespace blook {
namespace {
struct hook_entry {
    bool active{};
    // A dormant hook is fully registered (id, pins, token) but nothing is
    // published to the hypervisor: its page was not executable at install
    // time. The instruction-boundary decode is deferred until the page turns
    // executable (see arm_dormant_hooks), so spec.length/spec.patch are not
    // final while this is set.
    bool dormant{};
    bool armed{};  // publication result, not merely registry membership
    bool restore_requested{};  // survives a failed power-resume attempt
    uint64_t token{};
    hook_spec spec{};
    // The patch exactly as the caller requested it, kept for the deferred
    // decode: the bytes that matter are the ones the page holds when it
    // becomes executable, not the ones it held at install time.
    uint8_t pending_patch[max_patch]{};
    uint32_t pending_length{};
    page_lock page;  // mapping and PFN of the patched page
    page_lock
        identity;  // pinned per-process identity page (PEB), user hooks only
    PEPROCESS process{};  // referenced owner, user hooks only
    void* trampoline_pool{};
    PMDL trampoline_mdl{};
    void* trampoline_mapping{};
    bool gate{};
    bool published{};  // gate was exposed to root, even if all-CPU arm failed
    hook_catalog::entry_id catalog{hook_catalog::entry_id::opaque};
};

struct hook_store {
    EX_PUSH_LOCK lock{};
    hook_entry entries[max_hooks];
    uint64_t next_id{1};
};

hook_store* store{};

hook_entry* find_locked(uint64_t id) {
    for (auto& entry : store->entries)
        if (entry.active && entry.spec.id == id)
            return &entry;
    return nullptr;
}

void release(hook_entry& entry, bool remove_from_hypervisor) {
    // A dormant hook owns no hypervisor state: the id was never installed.
    if (entry.active && !entry.dormant && remove_from_hypervisor)
        hv::remove(entry.spec.id);
    entry.active = false;
    entry.dormant = false;
    entry.armed = false;
    entry.restore_requested = false;
    entry.pending_length = 0;
    if (entry.process) {
        ObDereferenceObject(entry.process);
        entry.process = nullptr;
    }
    if (entry.gate)
        (void)hv::hook_gate::unregister_unarmed(
            reinterpret_cast<void*>(entry.spec.target));
    entry.identity.reset();
    entry.page.reset();
    if (entry.trampoline_mapping && entry.trampoline_mdl)
        MmUnmapLockedPages(entry.trampoline_mapping, entry.trampoline_mdl);
    if (entry.trampoline_mdl) {
        if (entry.trampoline_mdl->MdlFlags & MDL_PAGES_LOCKED)
            MmUnlockPages(entry.trampoline_mdl);
        IoFreeMdl(entry.trampoline_mdl);
    }
    if (entry.trampoline_pool)
        ExFreePoolWithTag(entry.trampoline_pool, 'trkB');
    entry.trampoline_mapping = nullptr;
    entry.trampoline_mdl = nullptr;
    entry.trampoline_pool = nullptr;
    entry.gate = false;
    entry.published = false;
    entry.catalog = hook_catalog::entry_id::opaque;
    entry.spec = {};
}

// A user hook only makes sense on committed, readable memory: patching a page
// the target cannot read would be an unmapped PFN trap rather than a hook.
// Executability is *reported*, not required: a page that is not executable
// yet (a JIT or shellcode allocation in its read-write stage) registers the
// hook dormant, and the NtProtectVirtualMemory maintenance hook arms it the
// moment the page turns executable.
NTSTATUS check_user_page(void* target, bool& executable) {
    executable = false;
    MEMORY_BASIC_INFORMATION info{};
    SIZE_T returned{};
    auto status =
        ZwQueryVirtualMemory(ZwCurrentProcess(), target, MemoryBasicInformation,
                             &info, sizeof(info), &returned);
    if (!NT_SUCCESS(status))
        return status;
    if (info.State != MEM_COMMIT || (info.Protect & PAGE_GUARD))
        return STATUS_INVALID_PAGE_PROTECTION;
    constexpr auto readable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                              PAGE_EXECUTE | PAGE_EXECUTE_READ |
                              PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if (!(info.Protect & readable))
        return STATUS_INVALID_PAGE_PROTECTION;
    constexpr auto executable_mask = PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                     PAGE_EXECUTE_READWRITE |
                                     PAGE_EXECUTE_WRITECOPY;
    executable = (info.Protect & executable_mask) != 0;
    return STATUS_SUCCESS;
}
}  // namespace

// Bring-up log: a plain file the runner can read without a debugger and
// without the registry. Diagnostics only, PASSIVE_LEVEL only, one line per
// write.
void bringup_write(const char* label, uint32_t value, bool have_value) {
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return;
    UNICODE_STRING path;
    RtlInitUnicodeString(&path, L"\\??\\D:\\blook-drv\\.cache\\driver.log");
    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, &path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               nullptr, nullptr);
    HANDLE file{};
    IO_STATUS_BLOCK status{};
    if (!NT_SUCCESS(ZwCreateFile(
            &file, FILE_APPEND_DATA | SYNCHRONIZE, &attributes, &status,
            nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT | FILE_WRITE_THROUGH,
            nullptr, 0)))
        return;
    char line[96];
    size_t n = 0;
    while (label[n] && n < sizeof(line) - 24) {
        line[n] = label[n];
        ++n;
    }
    if (have_value) {
        static const char digits[] = "0123456789abcdef";
        char text[9];
        for (int i = 0; i < 8; ++i)
            text[i] = digits[(value >> ((7 - i) * 4)) & 0xf];
        line[n++] = ' ';
        line[n++] = '0';
        line[n++] = 'x';
        int first = 0;
        while (first < 7 && text[first] == '0')
            ++first;
        for (int i = first; i < 8; ++i)
            line[n++] = text[i];
    }
    line[n++] = '\r';
    line[n++] = '\n';
    ZwWriteFile(file, nullptr, nullptr, nullptr, &status, line, (ULONG)n,
                nullptr, nullptr);
    ZwClose(file);
}

NTSTATUS initialize_hooks() {
    store = allocate_object<hook_store>();
    return store ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}

void shutdown_hooks() {
    if (!store)
        return;
    {
        exclusive_lock lock{store->lock};
        for (auto& entry : store->entries)
            release(entry, true);
    }
    delete_object(store);
    store = nullptr;
}

namespace {
// Where the most recently prepared trampoline lives, so a dump can show its
// bytes without scanning the whole pool.
uint64_t last_trampoline_address{};
}  // namespace

namespace {
// Everything between "the page is pinned and its PFN known" and "the hook is
// registered": instruction-boundary decode on the bytes the page holds *now*,
// page-mate compatibility, patch construction, trampoline. prepare_hook runs
// it directly when the page is already executable; arm_dormant_hooks runs it
// when the page turns executable. Running it any earlier would decode bytes a
// JIT is still going to overwrite. On failure the caller decides what the
// entry becomes: prepare_hook releases it, the dormant path keeps it dormant
// so the next protection change retries.
NTSTATUS finish_preparation(hook_entry& slot, hook_spec& spec,
                            const uint8_t* patch, size_t length,
                            const void* destination, prepared_hook& prepared) {
    const auto address = spec.target;
    // Cover whole instructions: a patch whose length lands in the middle of one
    // makes the processor resume inside it, and a trampoline that replays half
    // an instruction jumps into nowhere (both were observed as a double fault
    // inside the handler). The requested length is the minimum - the jump
    // itself - and the real length is the instruction boundary at or after it.
    // A prologue that cannot be decoded skips the hook: a missing hook is
    // invisible, a corrupt one is a bugcheck.
    size_t covered = length;
    {
        const auto offset = address & 0xfff;
        const auto* page_code =
            static_cast<const uint8_t*>(slot.page.data()) + offset;
        const auto room = 4096 - offset;
        covered =
            destination ? x86::safe_gate_entry_length(page_code, room) : 0;
        if (destination && !covered)
            return STATUS_NOT_SUPPORTED;
        while (!destination && covered < length) {
            const auto step = blook::x86::instruction_length(
                page_code + covered, room - covered);
            if (!step)
                return STATUS_INVALID_PARAMETER;
            covered += step;
        }
        if (covered > max_patch || covered > room)
            return STATUS_INVALID_PARAMETER;
    }

    spec.length = static_cast<uint32_t>(covered);
    // Several hooks on one physical page merge into one shadow per scope, so
    // page mates are welcome as long as the merge is sound: same-scope hooks
    // must not overwrite each other's covered instructions, and a kernel
    // (global) hook never shares with a per-process one. Different processes
    // sharing the page each keep their own scope. The covered length is
    // final now, which is what makes the range comparison meaningful.
    for (const auto& entry : store->entries)
        if (entry.active && entry.spec.id != spec.id &&
            !blook::hooks_compatible(entry.spec, spec))
            return STATUS_OBJECT_NAME_COLLISION;
    if (destination) {
        // Acquire the lifetime reference in VM-exit before redirecting RIP:
        // no guest instruction can enter the driver before being counted.
        spec.patch[0] = 0x0f;
        spec.patch[1] = 0x01;
        spec.patch[2] = 0xc1;
        for (size_t i = 3; i < covered; ++i)
            spec.patch[i] = 0x90;
    } else {
        for (size_t i = 0; i < covered; ++i)
            spec.patch[i] = i < length ? patch[i] : 0x90;
    }

    // Raw user patches do not request an original callable. Avoid allocating
    // inaccessible kernel trampolines for them.
    if (!destination) {
        prepared.id = spec.id;
        prepared.spec = spec;
        return STATUS_SUCCESS;
    }

    // Trampoline: the overwritten bytes followed by a jump back to the rest of
    // the function. The handler calls this to reach the original, which is how
    // the call-original window is avoided: no EPT view of kernel code has to be
    // turned executable, on any processor, for a call to the real service.
    {
        constexpr size_t back_jump_size = jump_patch_length + 8;
        const auto size = covered + back_jump_size;
        // MmProtectMdlSystemAddress changes the protection of whole pages, so
        // the trampoline may not share its page with other pool blocks: the
        // small pool allocation used to live in a shared page, the protection
        // call failed, no trampoline was published and the handler ended up
        // calling the patched entry (unbounded recursion, 0x7f double fault).
        // The raw allocation is intentionally kept alive with the hook so the
        // page-aligned slice inside it stays valid.
        const auto raw_size = size + PAGE_SIZE;
        auto* raw = static_cast<uint8_t*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, raw_size, 'trkB'));
        slot.trampoline_pool = raw;
        auto* trampoline =
            raw ? reinterpret_cast<uint8_t*>(
                      (reinterpret_cast<unsigned long long>(raw) + PAGE_SIZE -
                       1) &
                      ~(static_cast<unsigned long long>(PAGE_SIZE) - 1))
                : nullptr;
        bringup_write("trampoline: pool", trampoline ? 1u : 0u, true);
        if (trampoline) {
            // Everything is written through ONE mapping. The MDL system
            // address is what the entry patch's literal points at and what the
            // handler executes, and on this machine it is not the pool address
            // the allocation returned: writing to the pool address left the
            // published page holding something else entirely (a dump showed
            // permission-looking bytes where the prologue should have been,
            // so the service resumed at target+covered with its prologue never
            // executed and faulted at +0x3e).
            auto* mdl = IoAllocateMdl(trampoline, static_cast<ULONG>(size),
                                      FALSE, FALSE, nullptr);
            slot.trampoline_mdl = mdl;
            bringup_write("trampoline: mdl", mdl ? 1u : 0u, true);
            uint8_t* code = nullptr;
            if (mdl) {
                // MmProtectMdlSystemAddress wants a locked MDL; the flags that
                // MmBuildMdlForNonPagedPool sets were not enough here (log:
                // pool 1, mdl 1, mapped-protected 0). MmProbeAndLockPages is
                // the documented way to lock a non-paged buffer, and it can
                // raise, so guard it.
                // Verified order: MmProtectMdlSystemAddress only accepts MDLs
                // whose pages carry a *system* mapping, and it answers
                // STATUS_NOT_SUPPORTED (0xC00000BB) otherwise - which is
                // exactly what the log showed. So map first, protect second,
                // and run the trampoline through that executable mapping.
                __try {
                    MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    bringup_write("trampoline: probe raised",
                                  static_cast<uint32_t>(GetExceptionCode()),
                                  true);
                }
                if (!(mdl->MdlFlags & MDL_PAGES_LOCKED))
                    return STATUS_INSUFFICIENT_RESOURCES;
                auto* mapped =
                    static_cast<uint8_t*>(MmMapLockedPagesSpecifyCache(
                        mdl, KernelMode, MmCached, nullptr, FALSE,
                        NormalPagePriority));
                slot.trampoline_mapping = mapped;
                if (mapped) {
                    const auto protect =
                        MmProtectMdlSystemAddress(mdl, PAGE_EXECUTE_READWRITE);
                    bringup_write("trampoline: protect status",
                                  static_cast<uint32_t>(protect), true);
                    if (NT_SUCCESS(protect))
                        code = mapped;
                }
            }
            bringup_write("trampoline: mapped-protected", code ? 1u : 0u, true);
            if (code) {
                // Same source as the shadow: the locked page mapping plus the
                // in-page offset. Reading the live target address instead only
                // works while that address space is the current one - which a
                // user hook is no longer by this point, prepare_hook has
                // detached - and it can fault where the locked mapping cannot.
                memcpy(code, spec.original + (address & 0xfff), covered);
                const auto back = address + covered;
                auto* const literal = reinterpret_cast<uint64_t*>(
                    code + covered + jump_patch_length);
                *literal = back;
                uint8_t back_patch[max_patch]{};
                // The literal sits jump_patch_length bytes past the patch, so
                // the displacement always fits; the check cannot fail here.
                (void)build_jump_patch(
                    back_patch, reinterpret_cast<uint64_t>(code + covered),
                    reinterpret_cast<uint64_t>(literal));
                for (size_t i = 0; i < jump_patch_length; ++i)
                    code[covered + i] = back_patch[i];
                prepared.trampoline = code;
                last_trampoline_address = reinterpret_cast<uint64_t>(code);
            }
        }
    }

    if (!prepared.trampoline)
        return STATUS_INSUFFICIENT_RESOURCES;
    auto* landing = system_return_landing();
    if (!landing)
        return STATUS_NOT_SUPPORTED;
    const auto registered = hv::hook_gate::register_gate(
        reinterpret_cast<void*>(address), destination, landing, covered);
    if (!NT_SUCCESS(registered))
        return registered;
    slot.gate = true;
    prepared.id = spec.id;
    prepared.spec = spec;
    return STATUS_SUCCESS;
}
}  // namespace

NTSTATUS prepare_hook(uint32_t pid, uint64_t token, void* target,
                      const uint8_t* patch, size_t length,
                      prepared_hook& prepared, const void* destination,
                      hook_catalog::entry_id catalog) {
    if (hv::hook_gate::is_closing())
        return STATUS_DEVICE_BUSY;
    if (!store || KeGetCurrentIrql() != PASSIVE_LEVEL || !target || !patch)
        return STATUS_INVALID_PARAMETER;
    const auto address = reinterpret_cast<uint64_t>(target);
    if (!valid_patch(address, length))
        return STATUS_INVALID_PARAMETER;
    if (!hv::ghv.running)
        return STATUS_DEVICE_NOT_READY;

    // Everything that consumes hook_spec::original - the hypervisor shadow
    // copy above all - expects a mapping of the whole page with the in-page
    // offset preserved: shadow[i] must hold the byte at page offset i, and the
    // patch belongs at shadow[target & 0xfff]. Locking the *target* instead
    // returns a mapping whose first byte *is* the target, so the shadow came
    // out holding the code from the target onward, shifted by the target page
    // offset. The entry patch still landed correctly (the EPT preserves the
    // in-page offset), which is why the hook fired and looked healthy while
    // every other entry point on that page - the other services sharing the
    // 4 KiB page, and the body of the hooked function itself whenever it was
    // reached from anywhere but offset zero - executed bytes from the wrong
    // offset and ended in a return to zero. Lock the page, not the target.
    auto* const page = reinterpret_cast<void*>(address & ~uint64_t{0xfff});

    hook_spec spec{};
    hook_entry* slot{};
    exclusive_lock lock{store->lock};
    for (auto& entry : store->entries)
        if (!entry.active) {
            slot = &entry;
            break;
        }
    if (!slot)
        return STATUS_QUOTA_EXCEEDED;

    NTSTATUS status = STATUS_SUCCESS;
    bool executable = true;
    if (pid) {
        if (!user_address(address))
            return STATUS_INVALID_ADDRESS;
        PEPROCESS process{};
        status = PsLookupProcessByProcessId(ULongToHandle(pid), &process);
        if (!NT_SUCCESS(status))
            return status;
        PVOID peb = PsGetProcessPeb(process);
        if (!peb) {
            ObDereferenceObject(process);
            return STATUS_INVALID_ADDRESS;
        }
        KAPC_STATE apc{};
        KeStackAttachProcess(process, &apc);
        status = check_user_page(target, executable);
        if (NT_SUCCESS(status))
            status = slot->page.acquire(page, UserMode, IoReadAccess);
        if (NT_SUCCESS(status) &&
            (reinterpret_cast<uint64_t>(slot->page.data()) & 0xfff))
            status = STATUS_INVALID_PARAMETER;
        // Pinning the identity page keeps the root mode translation of that
        // address valid for as long as the hook lives.
        if (NT_SUCCESS(status))
            status = slot->identity.acquire(peb, UserMode, IoReadAccess);
        KeUnstackDetachProcess(&apc);
        if (!NT_SUCCESS(status)) {
            slot->identity.reset();
            slot->page.reset();
            ObDereferenceObject(process);
            return status;
        }
        spec.domain = hook_domain::user;
        spec.owner_pid = pid;
        spec.address_space = slot->identity.pfn();
        spec.identity_address = reinterpret_cast<uint64_t>(peb);
        slot->process = process;
    } else {
        if (address < reinterpret_cast<uint64_t>(MmSystemRangeStart))
            return STATUS_INVALID_ADDRESS;
        spec.domain = hook_domain::kernel;
        status = slot->page.acquire(page, KernelMode, IoReadAccess);
        if (!NT_SUCCESS(status))
            return status;
        if (reinterpret_cast<uint64_t>(slot->page.data()) & 0xfff) {
            slot->page.reset();
            return STATUS_INVALID_PARAMETER;
        }
    }

    const auto pfn = slot->page.pfn();
    if (store->next_id == 0) {
        release(*slot, false);
        return STATUS_INTEGER_OVERFLOW;
    }

    slot->catalog = catalog;
    spec.id = store->next_id++;
    spec.pfn = pfn;
    spec.target = address;
    spec.original = slot->page.data();

    if (!executable) {
        // A page that cannot execute yet cannot be hooked yet either - but it
        // cannot be *executed* either, so nothing is missed by registering
        // now and arming when the page turns executable. Driver-internal
        // patches are built around a literal slot that nothing would keep
        // alive meanwhile; they only ever target kernel code, which is
        // executable, so refusing them here is a no-op in practice.
        if (destination) {
            release(*slot, false);
            return STATUS_INVALID_PAGE_PROTECTION;
        }
        memcpy(slot->pending_patch, patch, length);
        slot->pending_length = static_cast<uint32_t>(length);
        slot->dormant = true;
        slot->token = token;
        slot->spec = spec;
        slot->active = true;
        prepared.id = spec.id;
        prepared.spec = spec;
        return STATUS_SUCCESS;
    }

    status =
        finish_preparation(*slot, spec, patch, length, destination, prepared);
    if (!NT_SUCCESS(status)) {
        release(*slot, false);
        return status;
    }

    // Publish the record before anything can execute the patch: the handler
    // the patch jumps to has nothing but this registry to rely on.
    slot->token = token;
    slot->spec = spec;
    slot->active = true;
    return STATUS_SUCCESS;
}

NTSTATUS arm_hook(const prepared_hook& prepared) {
    if (!store || !prepared.id)
        return STATUS_INVALID_PARAMETER;
    if (!hv::ghv.running)
        return STATUS_DEVICE_NOT_READY;
    exclusive_lock lock{store->lock};
    auto* entry = find_locked(prepared.id);
    if (!entry)
        return STATUS_NOT_FOUND;
    // A dormant hook has nothing to publish yet; it arms itself when its page
    // turns executable (arm_dormant_hooks).
    if (entry->dormant)
        return STATUS_SUCCESS;
    if (entry->gate) {
        const auto status = hv::hook_gate::mark_armed(
            reinterpret_cast<void*>(entry->spec.target));
        if (!NT_SUCCESS(status))
            return status;
        entry->published = true;
    }
    if (!hv::install(prepared.spec)) {
        // Some CPUs may already have invoked this gate. Keep its original,
        // metadata and trampoline alive until global drain, even on failure.
        if (!entry->gate)
            release(*entry, false);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    entry->armed = true;
    entry->restore_requested = true;
    return STATUS_SUCCESS;
}

void cancel_hook(const prepared_hook& prepared) {
    if (!store || !prepared.id)
        return;
    exclusive_lock lock{store->lock};
    if (auto* entry = find_locked(prepared.id);
        entry && !entry->published && !entry->armed)
        release(*entry, false);
}

NTSTATUS install_hook(uint32_t pid, uint64_t token, void* target,
                      const uint8_t* patch, size_t length, uint64_t& id) {
    prepared_hook prepared{};
    auto status = prepare_hook(pid, token, target, patch, length, prepared);
    if (!NT_SUCCESS(status))
        return status;
    status = arm_hook(prepared);
    if (!NT_SUCCESS(status))
        return status;
    id = prepared.id;
    return STATUS_SUCCESS;
}

NTSTATUS remove_hook(uint64_t id) {
    if (!store || !id)
        return STATUS_INVALID_PARAMETER;
    exclusive_lock lock{store->lock};
    auto* entry = find_locked(id);
    if (!entry)
        return STATUS_NOT_FOUND;
    if (entry->published)
        return STATUS_DEVICE_BUSY;
    release(*entry, true);
    return STATUS_SUCCESS;
}

NTSTATUS refresh_hook(uint64_t id) {
    if (!store || KeGetCurrentIrql() != PASSIVE_LEVEL || !id)
        return STATUS_INVALID_PARAMETER;
    if (!hv::ghv.running)
        return STATUS_DEVICE_NOT_READY;
    exclusive_lock lock{store->lock};
    if (!find_locked(id))
        return STATUS_NOT_FOUND;
    hv::refresh(id);
    return STATUS_SUCCESS;
}

NTSTATUS remove_owned_hook(uint64_t id, uint64_t token) {
    if (!store || !id)
        return STATUS_INVALID_PARAMETER;
    exclusive_lock lock{store->lock};
    auto* entry = find_locked(id);
    if (!entry)
        return STATUS_NOT_FOUND;
    if (entry->token != token)
        return STATUS_ACCESS_DENIED;
    if (entry->published)
        return STATUS_DEVICE_BUSY;
    release(*entry, true);
    return STATUS_SUCCESS;
}

NTSTATUS refresh_owned_hook(uint64_t id, uint64_t token) {
    if (!store || !id)
        return STATUS_INVALID_PARAMETER;
    if (!hv::ghv.running)
        return STATUS_DEVICE_NOT_READY;
    exclusive_lock lock{store->lock};
    auto* entry = find_locked(id);
    if (!entry)
        return STATUS_NOT_FOUND;
    if (entry->token != token)
        return STATUS_ACCESS_DENIED;
    hv::refresh(id);
    return STATUS_SUCCESS;
}

bool hook_present(uint64_t id) {
    if (!store || !id)
        return false;
    exclusive_lock lock{store->lock};
    return find_locked(id) != nullptr;
}

bool hook_armed(uint64_t id) {
    if (!store || !id)
        return false;
    exclusive_lock lock{store->lock};
    const auto* entry = find_locked(id);
    return entry && entry->armed && !entry->dormant && hv::ghv.running &&
           !hv::hook_gate::is_closing();
}

namespace {
volatile uint64_t rebinds{};
volatile uint64_t rebind_failures{};
}  // namespace

uint64_t rebind_count() {
    return rebinds;
}
uint64_t rebind_failure_count() {
    return rebind_failures;
}

NTSTATUS rebind_hooks_if_copied(uint32_t pid, const void* base, size_t size) {
    if (!store || KeGetCurrentIrql() != PASSIVE_LEVEL || !pid || !base || !size)
        return STATUS_INVALID_PARAMETER;
    if (!hv::ghv.running)
        return STATUS_DEVICE_NOT_READY;
    const auto begin = reinterpret_cast<uint64_t>(base) & ~uint64_t{0xfff};
    const auto end = begin + size;
    if (end < begin)
        return STATUS_INVALID_PARAMETER;

    exclusive_lock lock{store->lock};
    // Candidates: active user hooks of this process inside the range. A
    // kernel hook is not a candidate - its page is not a per-process
    // copy-on-write page. All candidates share the owner, so resolving the
    // process once is enough; without a candidate there is nothing to do
    // (this is the common case for the flood of unrelated VM calls).
    PEPROCESS process{};
    for (const auto& entry : store->entries) {
        if (entry.active && entry.spec.domain == hook_domain::user &&
            entry.spec.owner_pid == pid && entry.spec.target >= begin &&
            entry.spec.target < end) {
            process = entry.process;
            break;
        }
    }
    if (!process)
        return STATUS_SUCCESS;

    KAPC_STATE apc{};
    KeStackAttachProcess(process, &apc);
    for (auto& entry : store->entries) {
        if (!entry.active || entry.spec.domain != hook_domain::user ||
            entry.spec.owner_pid != pid || entry.spec.target < begin ||
            entry.spec.target >= end)
            continue;
        // What does the virtual page map NOW? The copy made by the VM is
        // already in place: this call is a post-hook.
        auto* const page =
            reinterpret_cast<void*>(entry.spec.target & ~uint64_t{0xfff});
        page_lock fresh;
        const auto status = fresh.acquire(page, UserMode, IoReadAccess);
        if (!NT_SUCCESS(status)) {
            // The range can be partially freed: leave the hook on its old
            // page, it cannot run there either way.
            continue;
        }
        const auto pfn = fresh.pfn();
        if (!pfn || pfn == entry.spec.pfn)
            continue;
        // The page the hook armed is no longer the page the process
        // executes. Move: same id, same patch, new backing page. A dormant
        // hook owns no hypervisor state yet, so it just follows the page.
        if (!entry.dormant)
            hv::remove(entry.spec.id);
        entry.page.reset();
        entry.page = static_cast<page_lock&&>(fresh);
        entry.spec.pfn = pfn;
        entry.spec.original = entry.page.data();
        if (entry.dormant)
            continue;
        const auto rebound = hv::install(entry.spec);
        entry.armed = rebound;
        if (rebound)
            ++rebinds;
        else
            ++rebind_failures;
    }
    KeUnstackDetachProcess(&apc);
    return STATUS_SUCCESS;
}

// Deferred arming. The NtProtectVirtualMemory maintenance hook calls this
// after every successful protection change: a dormant hook whose page just
// became executable is finished (the deferred instruction decode runs on the
// final bytes) and armed before the syscall returns, so no execution of the
// page can slip past unhooked. Same event-driven shape as the execute watch:
// nothing polls, the protection change is the trigger.
void arm_dormant_hooks(uint32_t pid, const void* base, size_t size) {
    if (!store || KeGetCurrentIrql() != PASSIVE_LEVEL || !pid || !base || !size)
        return;
    if (!hv::ghv.running)
        return;
    const auto begin = reinterpret_cast<uint64_t>(base) & ~uint64_t{0xfff};
    const auto end = begin + size;
    if (end < begin)
        return;

    exclusive_lock lock{store->lock};
    // Candidates: dormant user hooks of this process inside the range. Same
    // shortcut as rebind_hooks_if_copied: no candidate, no attach.
    PEPROCESS process{};
    for (const auto& entry : store->entries) {
        if (entry.active && entry.dormant && entry.spec.owner_pid == pid &&
            entry.spec.target >= begin && entry.spec.target < end) {
            process = entry.process;
            break;
        }
    }
    if (!process)
        return;

    KAPC_STATE apc{};
    KeStackAttachProcess(process, &apc);
    for (auto& entry : store->entries) {
        if (!entry.active || !entry.dormant ||
            entry.spec.domain != hook_domain::user ||
            entry.spec.owner_pid != pid || entry.spec.target < begin ||
            entry.spec.target >= end)
            continue;
        bool executable = false;
        if (!NT_SUCCESS(check_user_page(
                reinterpret_cast<void*>(entry.spec.target), executable)) ||
            !executable)
            continue;
        // The backing page may have moved (copy-on-write) while the hook was
        // dormant: re-resolve it before the decode reads a stale mapping.
        auto* const page =
            reinterpret_cast<void*>(entry.spec.target & ~uint64_t{0xfff});
        page_lock fresh;
        if (!NT_SUCCESS(fresh.acquire(page, UserMode, IoReadAccess)))
            continue;
        entry.page = static_cast<page_lock&&>(fresh);
        entry.spec.pfn = entry.page.pfn();
        entry.spec.original = entry.page.data();
        prepared_hook prepared{};
        // A failure leaves the hook dormant: the bytes may simply not be
        // final yet (or a page mate conflicts), and the next protection
        // change retries.
        if (!NT_SUCCESS(
                finish_preparation(entry, entry.spec, entry.pending_patch,
                                   entry.pending_length, nullptr, prepared))) {
            entry.spec.length = 0;
            continue;
        }
        entry.dormant = false;
        entry.pending_length = 0;
        entry.armed = hv::install(entry.spec);
        entry.restore_requested = entry.armed;
        if (!entry.armed)
            release(entry, false);
    }
    KeUnstackDetachProcess(&apc);
}

bool begin_hook_window(uint64_t id) {
    if (!store || !id)
        return false;
    return hv::begin_window(id);
}

void end_hook_window(uint64_t id) {
    if (store && id)
        hv::end_window(id);
}

void revoke_session(uint64_t token) {
    if (!store || !token || token == system_token ||
        KeGetCurrentIrql() != PASSIVE_LEVEL)
        return;
    exclusive_lock lock{store->lock};
    for (auto& entry : store->entries)
        if (entry.active && entry.token == token)
            release(entry, true);
}

void revoke_process(uint32_t pid) {
    if (!store || !pid || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return;
    exclusive_lock lock{store->lock};
    for (auto& entry : store->entries)
        if (entry.active && entry.spec.owner_pid == pid)
            release(entry, true);
}

NTSTATUS restore_all() {
    if (!store || !hv::ghv.running)
        return STATUS_DEVICE_NOT_READY;
    exclusive_lock lock{store->lock};
    bool success = true;
    // Only previously armed entries are restored, never failed preparations.
    for (auto& entry : store->entries) {
        if (!entry.active || entry.dormant || !entry.restore_requested)
            continue;
        entry.armed = hv::install(entry.spec);
        success = success && entry.armed;
    }
    return success ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
}

NTSTATUS detail::query_page_hooks_snapshot(uint32_t pid, uint64_t token,
                                           uint64_t address, uint32_t domain,
                                           wire::QueryPageResponse& result,
                                           feature::mask effective) {
    if (!store || KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_DEVICE_NOT_READY;
    const bool user = domain == wire::page_domain_user;
    if ((!user && domain != wire::page_domain_kernel) ||
        (user && (!pid || !token || token == system_token)) || (!user && pid))
        return STATUS_INVALID_PARAMETER;
    if ((user && !user_address(address)) ||
        (!user && address < reinterpret_cast<uint64_t>(MmSystemRangeStart)))
        return STATUS_INVALID_ADDRESS;
    static_assert(max_hooks <= wire::page_hook_capacity);
    exclusive_lock lock{store->lock};
    page_query::initialize(result, pid, address, domain);
    const bool running = hv::ghv.running && !hv::hook_gate::is_closing();
    for (const auto& entry : store->entries) {
        if (!entry.active)
            continue;
        page_query::append(result,
                           {entry.spec.id, entry.spec.target, entry.token,
                            entry.spec.owner_pid, entry.spec.domain,
                            entry.armed, entry.dormant, entry.catalog},
                           pid, token, address, effective, running);
    }
    return STATUS_SUCCESS;
}

uint32_t active_hook_count() {
    if (!store)
        return 0;
    exclusive_lock lock{store->lock};
    uint32_t count{};
    for (const auto& entry : store->entries)
        if (entry.active)
            ++count;
    return count;
}

uint32_t user_hook_count(uint32_t pid) {
    if (!store)
        return 0;
    exclusive_lock lock{store->lock};
    uint32_t count{};
    for (const auto& entry : store->entries)
        if (entry.active && entry.spec.domain == hook_domain::user &&
            entry.spec.owner_pid == pid)
            ++count;
    return count;
}
}  // namespace blook
