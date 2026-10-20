#pragma once
#include <ntifs.h>
#include "blook/drv/wire.hpp"
namespace blook::configuration_state {
NTSTATUS initialize(PCUNICODE_STRING service_path);
NTSTATUS activate();
bool allow_users();
bool hide_timing();
uint32_t page_fault_trace();
wire::ConfigurationResponse query();
wire::ConfigurationResponse reload();
void shutdown();
}  // namespace blook::configuration_state
