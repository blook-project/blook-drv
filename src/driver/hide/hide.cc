#include "hide.hpp"

#include "driver/hooks.hpp"
#include "driver/features.hpp"
#include "driver/resources.hpp"
#include "driver/hide/nt.hpp"
#include "driver/hide/peb.hpp"
#include "driver/hide/roles.hpp"
#include "driver/hide/win32k.hpp"

namespace blook::hide {
NTSTATUS activate() {
    return features::update(feature::nt_preset, 0).status;
}

NTSTATUS activate_maintenance() {
    return nt::install_core();
}
void deactivate_maintenance() {
    // Maintenance remains installed until global teardown has drained readers.
}

void reset_after_shutdown() {
    (void)features::set_desired(0);
    nt::reset_after_shutdown();
    win32k::reset_after_shutdown();
}

void deactivate() {
    (void)features::set_desired(0);
}

NTSTATUS enable_windows(bool enable) {
    return features::update(enable ? feature::window_preset : 0,
                            enable ? 0 : feature::window_preset)
        .status;
}

bool windows_active() {
    return (features::effective_mask() & feature::window_preset) != 0;
}
ULONG window_hook_count() {
    return win32k::hook_count();
}
bool active() {
    return (features::effective_mask() & feature::nt_preset) != 0;
}

void forget_process(uint32_t pid) {
    nt::forget_process(pid);
}

void pin(uint32_t pid, role value) {
    roles::pin(pid, value);
}
void unpin(uint32_t pid) {
    roles::unpin(pid);
}

NTSTATUS scrub(uint32_t pid, uint32_t flags) {
    return peb::process(pid, flags);
}
}  // namespace blook::hide
