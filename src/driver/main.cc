// Driver entry point.
//
// Two load paths, one initialisation:
//
//   manual map (production)  the loader maps the image, creates the blook-kchannel
//                            region and passes a kernel copy of kc_bootstrap in
//                            the DriverObject slot. Nothing else about the load
//                            is observable: no device, no registry, no service.
//   service load (dev/e2e)   `sc create/start`. The bootstrap blob is read from
//                            the service key's Parameters\KcBootstrap value, which
//                            blook-loader wrote before starting the service. With
//                            Parameters\Solo=1 the driver starts the hypervisor
//                            with no peer at all (used by the e2e "driver runs"
//                            cases and by bring-up on a bare machine).
//
// The driver never calls IoCreateDevice/IoCreateSymbolicLink and never exports a
// symbol: the only kernel<->user path is blook-kchannel.
#include <ntifs.h>

#include "blook/drv/wire.hpp"
#include "driver/configuration_state.hpp"
#include "driver/hide/hide.hpp"
#include "driver/hide/self.hpp"
#include "driver/pool.hpp"
#include "driver/session.hpp"
#include "ipc/kchannel.hpp"
#include "policy/integer.hpp"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver,
                                PUNICODE_STRING registry_path);

namespace {
// 'KCB1' from include/blook/kchannel.h. The bootstrap struct is only read
// through a probe: the mapped path hands us a kernel copy, but a wrong pointer
// must not bugcheck the machine during load.
constexpr uint32_t bootstrap_magic = 0x3142434Bu;
constexpr uint32_t bootstrap_size = 0x90u;

bool looks_like_bootstrap(const void* candidate) {
    if (!candidate)
        return false;
    __try {
        const auto* bytes = static_cast<const uint8_t*>(candidate);
        const auto magic = *reinterpret_cast<const uint32_t*>(bytes);
        const auto size = *reinterpret_cast<const uint32_t*>(bytes + 8);
        return magic == bootstrap_magic && size == bootstrap_size;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

const UNICODE_STRING* concatenate(const UNICODE_STRING* base,
                                  const WCHAR* suffix, PWCH scratch,
                                  size_t capacity, UNICODE_STRING& out) {
    const auto suffix_bytes =
        static_cast<USHORT>(wcslen(suffix) * sizeof(WCHAR));
    if (base->Length + suffix_bytes + sizeof(WCHAR) > capacity)
        return nullptr;
    RtlCopyMemory(scratch, base->Buffer, base->Length);
    RtlCopyMemory(reinterpret_cast<UCHAR*>(scratch) + base->Length, suffix,
                  suffix_bytes + sizeof(WCHAR));
    out.Buffer = scratch;
    out.Length = static_cast<USHORT>(base->Length + suffix_bytes);
    out.MaximumLength =
        static_cast<USHORT>(base->Length + suffix_bytes + sizeof(WCHAR));
    return &out;
}

// Reads Parameters\KcBootstrap (REG_BINARY) and Parameters\Solo (REG_DWORD).
NTSTATUS read_service_bootstrap(PUNICODE_STRING registry_path, void*& blob,
                                ULONG& blob_size, bool& solo) {
    blob = nullptr;
    blob_size = 0;
    solo = false;
    if (!registry_path || !registry_path->Buffer || !registry_path->Length)
        return STATUS_OBJECT_NAME_NOT_FOUND;

    WCHAR path_buffer[512]{};
    UNICODE_STRING path{};
    if (!concatenate(registry_path, L"\\Parameters", path_buffer,
                     sizeof(path_buffer) - sizeof(WCHAR), path))
        return STATUS_NAME_TOO_LONG;

    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, &path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, nullptr,
                               nullptr);
    HANDLE key{};
    auto status = ZwOpenKey(&key, KEY_READ, &attributes);
    if (!NT_SUCCESS(status))
        return status;

    constexpr ULONG query_size =
        sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 0x100;
    auto* buffer = static_cast<UCHAR*>(
        ExAllocatePool2(POOL_FLAG_PAGED, query_size, blook::pool_tag));
    if (!buffer) {
        ZwClose(key);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    UNICODE_STRING value_name;
    RtlInitUnicodeString(&value_name, L"KcBootstrap");
    ULONG length{};
    status = ZwQueryValueKey(key, &value_name, KeyValuePartialInformation,
                             buffer, query_size, &length);
    if (NT_SUCCESS(status)) {
        auto* info = reinterpret_cast<PKEY_VALUE_PARTIAL_INFORMATION>(buffer);
        if (info->Type == REG_BINARY && info->DataLength) {
            blob = ExAllocatePool2(POOL_FLAG_NON_PAGED, info->DataLength,
                                   blook::pool_tag);
            if (blob) {
                RtlCopyMemory(blob, info->Data, info->DataLength);
                blob_size = info->DataLength;
            }
        }
    }

    RtlInitUnicodeString(&value_name, L"Solo");
    length = 0;
    if (NT_SUCCESS(ZwQueryValueKey(key, &value_name, KeyValuePartialInformation,
                                   buffer, query_size, &length))) {
        auto* info = reinterpret_cast<PKEY_VALUE_PARTIAL_INFORMATION>(buffer);
        if (info->Type == REG_DWORD && info->DataLength >= sizeof(ULONG))
            solo = *reinterpret_cast<const ULONG*>(info->Data) != 0;
    }
    ExFreePoolWithTag(buffer, blook::pool_tag);
    ZwClose(key);
    return blob ? STATUS_SUCCESS : STATUS_OBJECT_NAME_NOT_FOUND;
}

void unload(PDRIVER_OBJECT) {
    blook::ipc::adapter_stop();
    blook::hide::deactivate();
    blook::shutdown_sessions();
}

NTSTATUS run(PUNICODE_STRING registry_path, const void* bootstrap) {
    auto status = blook::configuration_state::initialize(registry_path);
    if (!NT_SUCCESS(status))
        return status;
    status = blook::initialize_sessions();
    if (!NT_SUCCESS(status)) {
        blook::shutdown_sessions();
        blook::configuration_state::shutdown();
        return status;
    }
    if (blook::ipc::adapter_start(bootstrap) != 0 && !blook::ipc::adapter_solo()) {
        // A client expected the channel to answer and it did not: fail the load
        // instead of pretending to be ready.
        blook::shutdown_sessions();
        blook::configuration_state::shutdown();
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}
}  // namespace

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver,
                                PUNICODE_STRING registry_path) {
    // Manual map: the DriverObject slot carries a kernel copy of kc_bootstrap.
    if (looks_like_bootstrap(reinterpret_cast<const void*>(driver))) {
        blook::hide::self::remember_driver_object(nullptr);
        return run(nullptr, reinterpret_cast<const void*>(driver));
    }

    auto* driver_object = reinterpret_cast<PDRIVER_OBJECT>(driver);
    driver_object->DriverUnload = unload;
    blook::hide::self::remember_driver_object(driver_object);
    blook::hide::self::remember_service_path(registry_path);

    void* blob{};
    ULONG blob_size{};
    bool solo{};
    const auto read =
        read_service_bootstrap(registry_path, blob, blob_size, solo);
    blook::ipc::set_solo_mode(solo || !NT_SUCCESS(read));
    auto status = run(registry_path, NT_SUCCESS(read) ? blob : nullptr);
    if (blob)
        ExFreePoolWithTag(blob, blook::pool_tag);
    return status;
}
