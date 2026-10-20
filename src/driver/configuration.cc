#include "driver/configuration.hpp"

namespace blook::configuration {
namespace {
constexpr ULONG pool_tag = 'CfLB';
constexpr ULONG max_path_chars = 1024;
constexpr ULONG registry_bytes =
    sizeof(KEY_VALUE_PARTIAL_INFORMATION) + max_path_chars * sizeof(WCHAR);
struct handle_guard {
    HANDLE value{};
    ~handle_guard() {
        if (value)
            ZwClose(value);
    }
};
struct buffer_guard {
    void* value{};
    ~buffer_guard() {
        if (value)
            ExFreePoolWithTag(value, pool_tag);
    }
};
NTSTATUS done(load_error& e, NTSTATUS status) noexcept {
    e.status = status;
    return status;
}
bool missing(NTSTATUS status) noexcept {
    return status == STATUS_OBJECT_NAME_NOT_FOUND ||
           status == STATUS_OBJECT_PATH_NOT_FOUND;
}
bool safe_path(const WCHAR* p, size_t count) noexcept {
    // Exactly a DOS drive rooted NT path, not UNC/GLOBALROOT/device aliases.
    if (count < 8 || p[0] != L'\\' || p[1] != L'?' || p[2] != L'?' ||
        p[3] != L'\\' ||
        !((p[4] >= L'A' && p[4] <= L'Z') || (p[4] >= L'a' && p[4] <= L'z')) ||
        p[5] != L':' || p[6] != L'\\')
        return false;
    size_t component = 7;
    for (size_t i = 7; i <= count; ++i) {
        const WCHAR c = i == count ? L'\\' : p[i];
        if (c == L'\\') {
            const size_t n = i - component;
            if (!n || (n == 1 && p[component] == L'.') ||
                (n == 2 && p[component] == L'.' && p[component + 1] == L'.') ||
                p[i - 1] == L'.' || p[i - 1] == L' ')
                return false;
            component = i + 1;
        } else if (c < 32 || c == L':' || c == L'/' || c == L'*' || c == L'?' ||
                   c == L'"' || c == L'<' || c == L'>' || c == L'|')
            return false;
        if (c >= 0xd800 && c <= 0xdbff) {
            if (i + 1 >= count || p[i + 1] < 0xdc00 || p[i + 1] > 0xdfff)
                return false;
            ++i;
        } else if (c >= 0xdc00 && c <= 0xdfff)
            return false;
    }
    return true;
}
NTSTATUS parse_status(error_code code) noexcept {
    switch (code) {
        case error_code::file_too_large:
            return STATUS_FILE_TOO_LARGE;
        case error_code::too_many_roles:
        case error_code::name_too_long:
            return STATUS_BUFFER_OVERFLOW;
        case error_code::migration_required:
        case error_code::unsupported_name:
            return STATUS_NOT_SUPPORTED;
        case error_code::invalid_utf8:
        case error_code::embedded_nul:
            return STATUS_DATA_ERROR;
        default:
            return STATUS_INVALID_PARAMETER;
    }
}
}  // namespace

NTSTATUS load_candidate(PCUNICODE_STRING registry_path, snapshot& output,
                        load_error& error) noexcept {
    error = {};
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return done(error, STATUS_INVALID_DEVICE_STATE);
    if (!registry_path || !registry_path->Buffer || !registry_path->Length ||
        registry_path->Length % sizeof(WCHAR) ||
        registry_path->Length > registry_path->MaximumLength)
        return done(error, STATUS_INVALID_PARAMETER);
    OBJECT_ATTRIBUTES attributes;
    InitializeObjectAttributes(
        &attributes, const_cast<PUNICODE_STRING>(registry_path),
        OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr, nullptr);
    handle_guard service;
    NTSTATUS status = ZwOpenKey(&service.value, KEY_READ, &attributes);
    if (!NT_SUCCESS(status))
        return done(error, status);
    UNICODE_STRING parameters = RTL_CONSTANT_STRING(L"Parameters");
    InitializeObjectAttributes(&attributes, &parameters,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               service.value, nullptr);
    handle_guard key;
    status = ZwOpenKey(&key.value, KEY_QUERY_VALUE, &attributes);
    if (missing(status)) {
        reset(output);
        return done(error, STATUS_SUCCESS);
    }
    if (!NT_SUCCESS(status))
        return done(error, status);
    buffer_guard registry{
        ExAllocatePool2(POOL_FLAG_PAGED, registry_bytes, pool_tag)};
    if (!registry.value)
        return done(error, STATUS_INSUFFICIENT_RESOURCES);
    UNICODE_STRING value_name = RTL_CONSTANT_STRING(L"ConfigPath");
    ULONG required = 0;
    status = ZwQueryValueKey(key.value, &value_name, KeyValuePartialInformation,
                             registry.value, registry_bytes, &required);
    if (missing(status)) {
        reset(output);
        return done(error, STATUS_SUCCESS);
    }
    error.path_configured = true;
    if (!NT_SUCCESS(status))
        return done(error, status);
    auto* value = static_cast<PKEY_VALUE_PARTIAL_INFORMATION>(registry.value);
    if (value->Type != REG_SZ)
        return done(error, STATUS_OBJECT_TYPE_MISMATCH);
    if (value->DataLength < 2 * sizeof(WCHAR) ||
        value->DataLength % sizeof(WCHAR) ||
        value->DataLength > max_path_chars * sizeof(WCHAR))
        return done(error, STATUS_OBJECT_PATH_SYNTAX_BAD);
    auto* path_chars = reinterpret_cast<WCHAR*>(value->Data);
    const size_t count = value->DataLength / sizeof(WCHAR) - 1;
    if (path_chars[count] != L'\0' || !safe_path(path_chars, count))
        return done(error, STATUS_OBJECT_PATH_SYNTAX_BAD);
    UNICODE_STRING path;
    path.Buffer = path_chars;
    path.Length = static_cast<USHORT>(count * sizeof(WCHAR));
    path.MaximumLength = static_cast<USHORT>(value->DataLength);
    InitializeObjectAttributes(&attributes, &path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE |
                                   OBJ_DONT_REPARSE | OBJ_FORCE_ACCESS_CHECK,
                               nullptr, nullptr);
    IO_STATUS_BLOCK ios{};
    handle_guard file;
    // No write sharing: a successful candidate cannot be assembled from a file
    // that a concurrent ordinary writer is changing in place.
    status = ZwCreateFile(
        &file.value, FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &attributes, &ios, nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT |
            FILE_OPEN_REPARSE_POINT,
        nullptr, 0);
    if (!NT_SUCCESS(status))
        return done(error, status);
    FILE_FS_DEVICE_INFORMATION device{};
    status = ZwQueryVolumeInformationFile(
        file.value, &ios, &device, sizeof(device), FileFsDeviceInformation);
    if (!NT_SUCCESS(status))
        return done(error, status);
    if ((device.Characteristics & FILE_REMOTE_DEVICE) ||
        device.DeviceType != FILE_DEVICE_DISK)
        return done(error, STATUS_NOT_SUPPORTED);
    FILE_ATTRIBUTE_TAG_INFORMATION tag{};
    status = ZwQueryInformationFile(file.value, &ios, &tag, sizeof(tag),
                                    FileAttributeTagInformation);
    if (!NT_SUCCESS(status))
        return done(error, status);
    if (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
        return done(error, STATUS_REPARSE_POINT_ENCOUNTERED);
    FILE_STANDARD_INFORMATION info{};
    status = ZwQueryInformationFile(file.value, &ios, &info, sizeof(info),
                                    FileStandardInformation);
    if (!NT_SUCCESS(status))
        return done(error, status);
    if (info.Directory || info.EndOfFile.QuadPart < 0)
        return done(error, STATUS_INVALID_PARAMETER);
    if (info.EndOfFile.QuadPart > static_cast<LONGLONG>(max_file_bytes))
        return done(error, STATUS_FILE_TOO_LARGE);
    const auto size = static_cast<ULONG>(info.EndOfFile.QuadPart);
    buffer_guard contents{
        ExAllocatePool2(POOL_FLAG_PAGED, max_file_bytes + 1, pool_tag)};
    if (!contents.value)
        return done(error, STATUS_INSUFFICIENT_RESOURCES);
    LARGE_INTEGER offset{};
    status =
        ZwReadFile(file.value, nullptr, nullptr, nullptr, &ios, contents.value,
                   static_cast<ULONG>(max_file_bytes + 1), &offset, nullptr);
    if (status == STATUS_END_OF_FILE && size == 0) {
        status = STATUS_SUCCESS;
        ios.Information = 0;
    }
    if (!NT_SUCCESS(status))
        return done(error, status);
    if (ios.Information > max_file_bytes)
        return done(error, STATUS_FILE_TOO_LARGE);
    if (ios.Information != size)
        return done(error, STATUS_DATA_ERROR);
    buffer_guard workspace{
        ExAllocatePool2(POOL_FLAG_PAGED, sizeof(snapshot), pool_tag)};
    if (!workspace.value)
        return done(error, STATUS_INSUFFICIENT_RESOURCES);
    if (!parse_with_workspace(static_cast<const char*>(contents.value), size,
                              output, error.parse,
                              *static_cast<snapshot*>(workspace.value)))
        return done(error, parse_status(error.parse.code));
    return done(error, STATUS_SUCCESS);
}
}  // namespace blook::configuration
