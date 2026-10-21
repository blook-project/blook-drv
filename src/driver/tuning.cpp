#include "tuning.hpp"

#include "driver/pool.hpp"

namespace blook::tuning {
namespace {
UNICODE_STRING parameters{};
PWCH parameters_buffer{};
bool initialized{};
uint32_t intercept_debug_value{default_intercept_debug};
uint32_t intercept_rdtscp_value{default_intercept_rdtscp};
bool trace_value{};
bool skip_timing_value{};
bool minimal_value{};
uint32_t start_stage_value{};
bool no_hypervisor_value{};
uint32_t max_cpus_value{};
bool no_ept_value{};
bool host_page_tables_value{true};
bool probe_exits_value{};
uint32_t raw_entry_ctls_value{};
uint32_t raw_pin_ctls_value{};
uint32_t raw_exit_ctls_value{};
bool bare_entry_value{};

bool read_dword(const wchar_t* name, uint32_t& value) {
    if (!parameters.Buffer)
        return false;
    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, &parameters,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               nullptr, nullptr);
    HANDLE key{};
    if (!NT_SUCCESS(ZwOpenKey(&key, KEY_READ, &attributes)))
        return false;
    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 64]{};
    UNICODE_STRING value_name;
    RtlInitUnicodeString(&value_name, name);
    ULONG length{};
    const auto status =
        ZwQueryValueKey(key, &value_name, KeyValuePartialInformation, buffer,
                        sizeof(buffer), &length);
    ZwClose(key);
    if (!NT_SUCCESS(status))
        return false;
    auto* info = reinterpret_cast<PKEY_VALUE_PARTIAL_INFORMATION>(buffer);
    if (info->Type != REG_DWORD || info->DataLength < sizeof(uint32_t))
        return false;
    value = *reinterpret_cast<const uint32_t*>(info->Data);
    return true;
}

void write_dword(const wchar_t* name, uint32_t value) {
    if (!parameters.Buffer)
        return;
    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, &parameters,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               nullptr, nullptr);
    HANDLE key{};
    if (!NT_SUCCESS(ZwOpenKey(&key, KEY_SET_VALUE, &attributes)))
        return;
    UNICODE_STRING value_name;
    RtlInitUnicodeString(&value_name, name);
    ZwSetValueKey(key, &value_name, 0, REG_DWORD, &value, sizeof(value));
    ZwClose(key);
}
}  // namespace

void initialize(PCUNICODE_STRING service_path) {
    if (initialized || !service_path || !service_path->Buffer)
        return;
    initialized = true;
    const auto bytes =
        service_path->Length + sizeof(L"\\Parameters") + sizeof(WCHAR);
    parameters_buffer = static_cast<PWCH>(
        ExAllocatePool2(POOL_FLAG_PAGED, bytes, blook::pool_tag));
    if (!parameters_buffer)
        return;
    RtlCopyMemory(parameters_buffer, service_path->Buffer,
                  service_path->Length);
    auto* cursor =
        reinterpret_cast<UCHAR*>(parameters_buffer) + service_path->Length;
    const wchar_t suffix[] = L"\\Parameters";
    RtlCopyMemory(cursor, suffix, sizeof(suffix));
    parameters.Buffer = parameters_buffer;
    parameters.Length = static_cast<USHORT>(service_path->Length +
                                            sizeof(suffix) - sizeof(WCHAR));
    parameters.MaximumLength = static_cast<USHORT>(bytes);

    read_dword(L"InterceptDebug", intercept_debug_value);
    read_dword(L"InterceptRdtscp", intercept_rdtscp_value);
    uint32_t trace{};
    if (read_dword(L"TraceMarkers", trace))
        trace_value = trace != 0;
    uint32_t skip_timing{};
    if (read_dword(L"SkipTimingCalibration", skip_timing))
        skip_timing_value = skip_timing != 0;
    uint32_t max_cpus_dword{};
    if (read_dword(L"MaxCpus", max_cpus_dword))
        max_cpus_value = max_cpus_dword;
    uint32_t bare{};
    if (read_dword(L"BareEntry", bare))
        bare_entry_value = bare != 0;
    uint32_t raw_pin{};
    if (read_dword(L"RawPinCtls", raw_pin))
        raw_pin_ctls_value = raw_pin;
    uint32_t raw_exit{};
    if (read_dword(L"RawExitCtls", raw_exit))
        raw_exit_ctls_value = raw_exit;
    uint32_t raw_entry{};
    if (read_dword(L"RawEntryCtls", raw_entry))
        raw_entry_ctls_value = raw_entry;
    uint32_t probe{};
    if (read_dword(L"ProbeExits", probe))
        probe_exits_value = probe != 0;
    uint32_t host_pt{};
    if (read_dword(L"HostPageTables", host_pt))
        host_page_tables_value = host_pt != 0;
    uint32_t no_ept{};
    if (read_dword(L"BringupNoEpt", no_ept))
        no_ept_value = no_ept != 0;
    uint32_t no_hv{};
    if (read_dword(L"NoHypervisor", no_hv))
        no_hypervisor_value = no_hv != 0;
    uint32_t stage{};
    if (read_dword(L"StartStage", stage))
        start_stage_value = stage;
    uint32_t minimal{};
    if (read_dword(L"BringupMinimal", minimal))
        minimal_value = minimal != 0;
}

bool intercept_debug() {
    return intercept_debug_value != 0;
}

bool intercept_rdtscp() {
    return intercept_rdtscp_value != 0;
}

bool trace_markers() {
    return trace_value;
}

bool skip_timing_calibration() {
    return skip_timing_value || minimal_value;
}

uint32_t start_stage() {
    return start_stage_value;
}

bool no_hypervisor() {
    return no_hypervisor_value;
}

uint32_t max_cpus() {
    return max_cpus_value;
}

bool probe_exits() {
    return probe_exits_value;
}

uint32_t raw_entry_ctls() {
    return raw_entry_ctls_value;
}

uint32_t raw_pin_ctls() {
    return raw_pin_ctls_value;
}

bool bare_entry() {
    return bare_entry_value;
}

uint32_t raw_exit_ctls() {
    return raw_exit_ctls_value;
}

bool host_page_tables() {
    return host_page_tables_value;
}

bool bringup_no_ept() {
    return no_ept_value;
}

bool bringup_minimal() {
    return minimal_value;
}

void mark(uint32_t phase, uint32_t extra) {
    if (!trace_value)
        return;
    write_dword(L"TraceLast", phase);
    write_dword(L"TraceExtra", extra);
    uint32_t count{};
    read_dword(L"TraceCount", count);
    write_dword(L"TraceCount", count + 1);
}
}  // namespace blook::tuning