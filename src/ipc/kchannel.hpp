#pragma once
#include <stdint.h>

#include "blook/drv/wire.hpp"

// Kernel side of the blook-kchannel integration.
//
// This is the only kernel file allowed to include a kchannel header: it creates
// the kernel instance from the bootstrap, registers one handler per wire::op and
// forwards every request to blook::dispatch_peer, which is the transport-neutral
// command layer. Nothing else in the driver (and nothing in the SDK) may define
// a second IPC path.
namespace blook::ipc {

// Set by the entry point when the driver was started without a client
// (Parameters\Solo=1 or a service load with no bootstrap blob). In solo mode a
// missing transport is not a load failure: the hypervisor runs and the driver
// can only be stopped by unloading it.
void set_solo_mode(bool solo);
bool adapter_solo();

// Starts the kchannel session. `bootstrap` is a kernel-memory copy of
// kc_bootstrap when the driver was manual-mapped, and NULL for a service load
// (in which case there is no channel and the adapter reports unavailable).
// Returns 0 on success, otherwise a kchannel status value.
int adapter_start(const void* bootstrap);

// Stops the session, joins the worker and releases the adapter buffers. Safe to
// call when no session is live.
int adapter_stop();

bool adapter_live();
int adapter_last_error();

}  // namespace blook::ipc
