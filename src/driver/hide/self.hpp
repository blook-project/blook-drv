#pragma once
#include <ntifs.h>

#include "blook/drv/wire.hpp"

// Self-hiding: making the driver and its load path invisible to user-mode and
// kernel-mode scanners that are not already looking at raw physical memory.
//
// What "hidden" means here, precisely:
//   - not present in PsLoadedModuleList in any of its three link chains, so
//     EnumDeviceDrivers / SystemModuleInformation / a stack-walk symbolisation
//     do not see it (the module is still mapped; a scanner that finds the image
//     by scanning the whole kernel address space for PE headers is not defeated
//     by list unlinking, and this project does not claim that);
//   - the DRIVER_OBJECT has no name in the object manager namespace
//     (ObMakeTemporaryObject), so \Driver\<name> enumeration is empty;
//   - there is no device object and no symbolic link by construction: the
//     driver never calls IoCreateDevice, the transport is blook-kchannel;
//   - the service registry key and its Parameters subkey are gone, including
//     the dev-mode bootstrap blob;
//   - pool allocations carry a benign, Windows-looking tag from the first
//     allocation instead of a project-identifying one (a post-hoc rewrite of
//     pool headers is racy and detectable; using the tag from boot is strictly
//     better, and trace_scan reports what a poolmon scan would see).
namespace blook::hide::self {

struct outcome {
    uint32_t module_list_found{};
    uint32_t module_list_unlinked{};
    uint32_t driver_object_found{};
    uint32_t driver_object_unlinked{};
    uint32_t device_found{};
    uint32_t device_unlinked{};
    uint32_t registry_found{};
    uint32_t registry_removed{};
    uint32_t pool_tags_rewritten{};
};

// Remembers the service name (from DriverEntry's registry path) so the registry
// cleanup addresses the real key when the service was installed under another
// name.
void remember_service_path(PCUNICODE_STRING registry_path);

// Remembers the DRIVER_OBJECT so the object-manager name can be dropped. Called
// from DriverEntry; the pointer is valid for the driver's lifetime.
void remember_driver_object(PDRIVER_OBJECT driver);

// Hides everything `flags` (wire::selfhide_*) asks for. PASSIVE_LEVEL. Safe to
// call twice (second call reports what is left to do and is a no-op for the
// parts already hidden).
NTSTATUS hide(uint32_t flags, outcome& result);

// True once the module was unlinked from PsLoadedModuleList. The image must not
// be unmapped while this is true *and* another component holds a pointer into
// it; on the unload path the driver relinks first so the list never contains a
// dangling entry.
bool module_list_hidden();

// Relinks the module list entry. Must run before the image is unmapped (unload
// path) to avoid leaving the system with a list that points at freed memory.
void restore_module_list();
bool driver_object_hidden();

// What a detector enumerating the usual places would still find
// (wire::trace_* bits). PASSIVE_LEVEL, allocates nothing.
NTSTATUS scan(wire::TraceScanResponse& out);

// Image base/size of this driver (size 0 when the load entry was not found).
void image_range(uint64_t& base, uint64_t& size);

}  // namespace blook::hide::self
