// Session lifecycle (see session.hpp). Derived from the pre-hardening
// device-session layer: the ownership token, revocation and power/processor
// handling are unchanged; the transport that creates sessions is now
// blook-kchannel instead of a file object.
#include "session.hpp"

#include <intrin.h>

#include "driver/configuration_state.hpp"
#include "driver/control.hpp"
#include "driver/features.hpp"
#include "driver/hide/hide.hpp"
#include "driver/hide/self.hpp"
#include "driver/hooks.hpp"
#include "driver/hv/detect.h"
#include "driver/hv/hv.h"
#include "driver/hv/hook_gate.hpp"
#include "driver/resources.hpp"
#include "driver/watch.hpp"

// The token APIs are exported by ntoskrnl but not declared by every WDK header
// set; the declarations are stable and documented by the token model.
extern "C" {
NTSYSAPI PACCESS_TOKEN NTAPI PsReferencePrimaryToken(PEPROCESS process);
NTSYSAPI void NTAPI PsDereferencePrimaryToken(PACCESS_TOKEN token);
NTSYSAPI BOOLEAN NTAPI SeTokenIsAdmin(PACCESS_TOKEN token);
}

namespace blook {
namespace {
struct peer_state {
    bool live{};
    uint32_t pid{};
    uint64_t token{};
    bool administrator{};
    bool enabled{};
};

struct state {
    EX_PUSH_LOCK lock{};
    EX_PUSH_LOCK power_lock{};
    peer_state peer{};
    void* power_callback{};
    void* processor_callback{};
    bool process_callback{}, suspended{}, stopping{};
    uint64_t next_token{1};
};

state* manager{};

void revoke(peer_state& peer) {
    peer.enabled = false;
    revoke_session(peer.token);
    watch::revoke_session(peer.token);
}

void process_notify(PEPROCESS process, HANDLE, PPS_CREATE_NOTIFY_INFO info) {
    if (info)
        return;
    const auto pid = static_cast<uint32_t>(
        reinterpret_cast<uintptr_t>(PsGetProcessId(process)));
    {
        exclusive_lock lock{manager->lock};
        if (manager->peer.live && manager->peer.pid == pid)
            revoke(manager->peer);
    }
    // A dead PID must not stay pinned to a role or keep its hooks alive.
    revoke_process(pid);
    watch::revoke_process(pid);
    hide::unpin(pid);
    hide::forget_process(pid);
}

void processor_notify(void*, PKE_PROCESSOR_CHANGE_NOTIFY_CONTEXT context,
                      PNTSTATUS status) {
    // Do not silently allow an unvirtualized hot-added CPU to execute hooked
    // pages.
    if (context->State == KeProcessorAddStartNotify)
        *status = STATUS_NOT_SUPPORTED;
}

void power_notify(void*, void* argument1, void* argument2) {
    if (argument1 != reinterpret_cast<void*>(PO_CB_SYSTEM_STATE_LOCK))
        return;
    // Only other power callbacks take this lock; hook handlers never do.
    exclusive_lock power{manager->power_lock};
    {
        exclusive_lock lock{manager->lock};
        if (manager->stopping)
            return;
        if (argument2 && !manager->suspended)
            return;
        manager->suspended = true;
    }
    // A counted original can require manager/store locks. Never hold them here.
    if (!argument2) {
        hv::stop();
        return;
    }
    auto status = hv::start();
    if (NT_SUCCESS(status)) {
        const auto hooks = restore_all();
        const auto watches = watch::restore_all();
        if (!NT_SUCCESS(hooks) || !NT_SUCCESS(watches)) {
            status = STATUS_UNSUCCESSFUL;
            hv::stop();  // rollback through the same unpatch/drain barrier
        }
    }
    exclusive_lock lock{manager->lock};
    manager->suspended = !NT_SUCCESS(status);
}
}  // namespace

bool process_is_administrator(uint32_t pid) {
    PEPROCESS process{};
    if (!NT_SUCCESS(PsLookupProcessByProcessId(ULongToHandle(pid), &process)))
        return false;
    bool admin{};
    auto* token = PsReferencePrimaryToken(process);
    if (token) {
        admin = SeTokenIsAdmin(token) != FALSE;
        PsDereferencePrimaryToken(token);
    }
    ObDereferenceObject(process);
    return admin;
}

NTSTATUS initialize_sessions() {
    manager = allocate_object<state>();
    if (!manager)
        return STATUS_INSUFFICIENT_RESOURCES;
    auto status = initialize_hooks();
    if (!NT_SUCCESS(status)) {
        shutdown_sessions();
        return status;
    }
    status = watch::initialize();
    if (!NT_SUCCESS(status)) {
        shutdown_sessions();
        return status;
    }
    status = PsSetCreateProcessNotifyRoutineEx(process_notify, FALSE);
    if (!NT_SUCCESS(status)) {
        shutdown_sessions();
        return status;
    }
    manager->process_callback = true;
    manager->processor_callback =
        KeRegisterProcessorChangeCallback(processor_notify, nullptr, 0);
    if (!manager->processor_callback) {
        shutdown_sessions();
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    UNICODE_STRING name = RTL_CONSTANT_STRING(L"\\Callback\\PowerState");
    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, &name,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               nullptr, nullptr);
    PCALLBACK_OBJECT object{};
    status = ExCreateCallback(&object, &attributes, FALSE, TRUE);
    if (!NT_SUCCESS(status)) {
        shutdown_sessions();
        return status;
    }
    manager->power_callback = ExRegisterCallback(object, power_notify, nullptr);
    ObDereferenceObject(object);
    if (!manager->power_callback) {
        shutdown_sessions();
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // The hypervisor starts with the driver: every logical processor is
    // virtualized before the first request arrives, and the anti-detection
    // state (CPUID spoofing, MSR filtering) is in effect from that point on.
    hv::detect::initialize();
    status = hv::start();
    if (NT_SUCCESS(status)) {
        // Mandatory VM maintenance is not an optional feature. Refuse startup
        // rather than silently promising COW/dormant support without its hooks.
        status = hide::activate_maintenance();
    }
    if (!NT_SUCCESS(status))
        shutdown_sessions();
    return status;
}

void shutdown_sessions() {
    if (!manager)
        return;
    {
        exclusive_lock lock{manager->lock};
        manager->stopping = true;
        manager->peer.live = false;
    }
    // Disable optional behavior first; physical entries survive until drain.
    hide::deactivate();
    hide::deactivate_maintenance();
    if (manager->power_callback)
        ExUnregisterCallback(manager->power_callback);
    if (manager->process_callback)
        PsSetCreateProcessNotifyRoutineEx(process_notify, TRUE);
    // Callback unregisters above finish before store destruction. Do NOT hold
    // manager/store locks while waiting for hook originals to return.
    hv::stop();
    if (!NT_SUCCESS(hv::hook_gate::reset_after_stop()))
        KeBugCheckEx(DRIVER_CORRUPTED_EXPOOL, 0x4252, 0, 0, 0);
    {
        exclusive_lock lock{manager->lock};
        shutdown_hooks();
        hide::reset_after_shutdown();
        watch::shutdown();
    }
    if (manager->processor_callback)
        KeDeregisterProcessorChangeCallback(manager->processor_callback);
    // The image is about to be unmapped: the module list must not point into it
    // any more. Hiding was opt-in, un-hiding is mandatory for a clean unload.
    hide::self::restore_module_list();
    delete_object(manager);
    manager = nullptr;
}

NTSTATUS attach_peer(uint32_t pid, bool administrator, uint64_t& token) {
    token = 0;
    if (!manager)
        return STATUS_DEVICE_NOT_READY;
    exclusive_lock lock{manager->lock};
    if (manager->stopping || manager->suspended || manager->peer.live)
        return STATUS_DEVICE_BUSY;
    if (!manager->next_token)
        return STATUS_INTEGER_OVERFLOW;
    manager->peer.live = true;
    manager->peer.pid = pid;
    manager->peer.token = manager->next_token++;
    manager->peer.administrator = administrator;
    manager->peer.enabled = hv::ghv.running;
    token = manager->peer.token;
    return STATUS_SUCCESS;
}

void detach_peer(uint64_t token) {
    if (!manager)
        return;
    exclusive_lock lock{manager->lock};
    if (!manager->peer.live || manager->peer.token != token)
        return;
    revoke(manager->peer);
    manager->peer = {};
}

void peer_gone() {
    if (!manager)
        return;
    exclusive_lock lock{manager->lock};
    if (!manager->peer.live)
        return;
    revoke(manager->peer);
    manager->peer = {};
}

bool peer_live() {
    return manager && manager->peer.live;
}

uint32_t peer_pid() {
    return manager ? manager->peer.pid : 0;
}

NTSTATUS dispatch_peer(uint64_t token, uint16_t op, const void* in,
                       uint32_t in_len, void* out, uint32_t* out_cap,
                       uint32_t* out_len) {
    if (!manager)
        return STATUS_DEVICE_NOT_READY;
    // The context is a copy: control handlers may block for milliseconds (EPT
    // broadcast) and must not hold the session lock while they do.
    control::context caller{};
    {
        exclusive_lock lock{manager->lock};
        if (manager->stopping || manager->suspended || !manager->peer.live ||
            manager->peer.token != token)
            return STATUS_DEVICE_NOT_READY;
        caller.pid = manager->peer.pid;
        caller.token = manager->peer.token;
        caller.administrator = manager->peer.administrator;
        caller.enabled = manager->peer.enabled;
    }
    const auto status =
        control::dispatch(caller, op, in, in_len, out, out_cap, out_len);
    // `enable` is the one command whose effect must be visible to the next
    // request: write it back.
    if (caller.enabled) {
        exclusive_lock lock{manager->lock};
        if (manager->peer.live && manager->peer.token == token)
            manager->peer.enabled = true;
    }
    return status;
}
}  // namespace blook