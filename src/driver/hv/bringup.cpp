#include "bringup.hpp"

#include "driver/pool.hpp"

namespace hv::bringup {
exit_storm last_storm{};
volatile uint32_t storm_count{};
volatile uint32_t stage_serial{};
volatile uint32_t stage_cpu{};
volatile uint64_t launch_error{};
volatile uint64_t vmwrite_error{};
volatile uint32_t armed{};
volatile uint32_t first_exit_reason{};
volatile uint64_t entry_controls{};
volatile uint64_t entry_efer{};
volatile uint64_t entry_cr0{};
volatile uint64_t entry_cr4{};
volatile uint64_t entry_activity{};
volatile uint64_t entry_gdtr_limit{};
volatile uint64_t entry_idtr_limit{};
volatile uint64_t entry_interruptibility{};
volatile uint64_t entry_pending_debug{};
volatile uint64_t entry_link_pointer{};
volatile uint64_t entry_eptp{};
volatile uint64_t host_cr0{};
volatile uint64_t host_cr4{};
volatile uint64_t host_rsp{};
volatile uint64_t host_rip{};
volatile uint64_t host_efer{};
volatile uint32_t first_launch_error{};
volatile uint64_t entry_ctls_allowed0{};
volatile uint64_t entry_ctls_allowed1{};
volatile uint64_t first_exit_rip{};
namespace {
UNICODE_STRING parameters{};
bool ready{};
volatile uint32_t last_stage_cpu{};
PVOID stage_thread{};
void write_dword(const wchar_t* name, uint32_t value);
}  // namespace

void stage(const char* name, uint32_t cpu) {
    stage_cpu = cpu;
    last_stage_cpu = cpu;
    ++stage_serial;
    // The guest is configured with a serial debug port; without a debugger
    // attached DbgPrint is cheap and lands in the serial log.
    DbgPrint("[blook] stage=%s cpu=%u\n", name, cpu);
}

void record_storm(uint32_t cpu, uint32_t reason, uint64_t rip, uint32_t count) {
    // Root-mode-safe: plain stores only.
    last_storm.cpu = cpu;
    last_storm.reason = reason;
    last_storm.rip = rip;
    last_storm.count = count;
    last_storm.active = 1;
    ++storm_count;
}

void remember_service_path(PCUNICODE_STRING path) {
    // Deliberately ignore the driver's own service key: the self-hide path
    // deletes that key (including its Parameters subkey) when the hypervisor
    // stops, which would erase exactly the evidence we are trying to keep. The
    // bring-up record lives in its own key and survives a start failure, a
    // self-hide and a host-side VM reset.
    (void)path;
    static constexpr wchar_t target[] =
        L"\\Registry\\Machine\\Software\\BlookBringup";
    const auto bytes = sizeof(target);
    auto* buffer = static_cast<PWCH>(
        ExAllocatePool2(POOL_FLAG_PAGED, bytes, blook::pool_tag));
    if (!buffer)
        return;
    RtlCopyMemory(buffer, target, bytes);
    parameters.Buffer = buffer;
    parameters.Length = static_cast<USHORT>(bytes - sizeof(WCHAR));
    parameters.MaximumLength = static_cast<USHORT>(bytes);
    ready = true;
}

namespace {
void write_dword(const wchar_t* name, uint32_t value) {
    if (!ready)
        return;
    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, &parameters,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               nullptr, nullptr);
    HANDLE key{};
    if (!NT_SUCCESS(ZwOpenKey(&key, KEY_SET_VALUE, &attributes))) {
        if (!NT_SUCCESS(ZwCreateKey(&key, KEY_SET_VALUE, &attributes, 0,
                                    nullptr, REG_OPTION_NON_VOLATILE, nullptr)))
            return;
    }
    UNICODE_STRING value_name;
    RtlInitUnicodeString(&value_name, name);
    ZwSetValueKey(key, &value_name, 0, REG_DWORD, &value, sizeof(value));
    // A hard VM power-off (the only way to recover a wedged guest) loses
    // registry writes that have not reached the hive, so flush explicitly.
    ZwFlushKey(key);
    ZwClose(key);
}

void stage_worker(PVOID) {
    LARGE_INTEGER interval{};
    interval.QuadPart = -10000;  // 1 ms poll
    uint32_t written{};
    while (armed) {
        if (stage_serial != written) {
            written = stage_serial;
            write_dword(L"WatchStage", written);
            write_dword(L"WatchCpu", last_stage_cpu);
        }
        if (entry_controls) {
            write_dword(L"EntryCtls", static_cast<uint32_t>(entry_controls));
            write_dword(L"EntryEfer", static_cast<uint32_t>(entry_efer));
            write_dword(L"EntryCr0", static_cast<uint32_t>(entry_cr0));
            write_dword(L"EntryCr4", static_cast<uint32_t>(entry_cr4));
            write_dword(L"EntryActivity", static_cast<uint32_t>(entry_activity));
            write_dword(L"EntryGdtrLimit",
                        static_cast<uint32_t>(entry_gdtr_limit));
            write_dword(L"EntryIdtrLimit",
                        static_cast<uint32_t>(entry_idtr_limit));
            write_dword(L"EntryIntr", static_cast<uint32_t>(entry_interruptibility));
            write_dword(L"EntryPendDbg", static_cast<uint32_t>(entry_pending_debug));
            write_dword(L"EntryLinkPtr", static_cast<uint32_t>(entry_link_pointer));
            write_dword(L"EntryEptp", static_cast<uint32_t>(entry_eptp));
            write_dword(L"HostCr0Low", static_cast<uint32_t>(host_cr0));
            write_dword(L"HostCr4Low", static_cast<uint32_t>(host_cr4));
            write_dword(L"HostRspLow", static_cast<uint32_t>(host_rsp));
            write_dword(L"HostRipLow", static_cast<uint32_t>(host_rip));
            write_dword(L"HostEfer", static_cast<uint32_t>(host_efer));
            write_dword(L"EntryCtlsAllowed0",
                        static_cast<uint32_t>(entry_ctls_allowed0));
            write_dword(L"EntryCtlsAllowed1",
                        static_cast<uint32_t>(entry_ctls_allowed1));
            write_dword(L"FirstLaunchErr", first_launch_error);
        }
        if (first_exit_reason) {
            write_dword(L"FirstExitReason", first_exit_reason);
            write_dword(L"FirstExitRipLow",
                        static_cast<uint32_t>(first_exit_rip));
            write_dword(L"FirstExitRipHigh",
                        static_cast<uint32_t>(first_exit_rip >> 32));
        }
        KeDelayExecutionThread(KernelMode, FALSE, &interval);
    }
    PsTerminateSystemThread(STATUS_SUCCESS);
}
}  // namespace

void start_stage_thread() {
    if (!ready || armed)
        return;
    armed = 1;
    HANDLE handle{};
    if (!NT_SUCCESS(PsCreateSystemThread(&handle, THREAD_ALL_ACCESS, nullptr,
                                         nullptr, nullptr, stage_worker,
                                         nullptr))) {
        armed = 0;
        return;
    }
    ObReferenceObjectByHandle(handle, THREAD_ALL_ACCESS, nullptr, KernelMode,
                              &stage_thread, nullptr);
    ZwClose(handle);
}

void disarm_stage_thread() {
    armed = 0;
}

void publish_probe(uint32_t code, uint32_t extra) {
    write_dword(L"Probe", code);
    write_dword(L"ProbeExtra", extra);
}

void publish_stage() {
    write_dword(L"LaunchErrorLow", static_cast<uint32_t>(launch_error));
    write_dword(L"LaunchErrorHigh", static_cast<uint32_t>(launch_error >> 32));
    write_dword(L"VmwriteFieldLow", static_cast<uint32_t>(vmwrite_error));
    write_dword(L"VmwriteFieldHigh",
                static_cast<uint32_t>(vmwrite_error >> 32));
    write_dword(L"StageSerial", stage_serial);
    write_dword(L"StageCpu", stage_cpu);
}

void publish_storm() {
    if (!last_storm.active)
        return;
    write_dword(L"StormReason", last_storm.reason);
    write_dword(L"StormCount", last_storm.count);
    write_dword(L"StormCpu", last_storm.cpu);
    write_dword(L"StormRipLow", static_cast<uint32_t>(last_storm.rip));
    write_dword(L"StormRipHigh", static_cast<uint32_t>(last_storm.rip >> 32));
    write_dword(L"StormTotal", storm_count);
}

void record_vmwrite_failure(uint64_t field) {
    if (!vmwrite_error)
        vmwrite_error = field ? field : 1;
}

void record_launch_error(uint64_t error) {
    launch_error = error;
}
}  // namespace hv::bringup