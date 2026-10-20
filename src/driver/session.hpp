#pragma once
#include <ntifs.h>

#include "blook/drv/wire.hpp"

// Session lifecycle: the parts of the old device-file session layer that still
// make sense when the peer is a blook-kchannel client.
//
// A session is created by the transport adapter when a peer completes the
// kchannel handshake, and destroyed when the peer detaches or dies (kchannel
// watchdog). It owns the hook/watch ownership token, the peer's identity and
// the privilege decision; the command bodies themselves live in control.cc.
namespace blook {

// Installs the process/power/processor notifications, brings up the hypervisor
// and the mandatory VM maintenance hooks. PASSIVE_LEVEL, once.
NTSTATUS initialize_sessions();

// Unpatches every CPU, drains, stops virtualization, drops the notifications
// and relinks the driver into PsLoadedModuleList (so an unload never leaves a
// dangling module-list entry behind).
void shutdown_sessions();

// One peer at a time (blook-kchannel is single-peer by contract). `pid` is the
// client process, `administrator` its elevation at attach time.
NTSTATUS attach_peer(uint32_t pid, bool administrator, uint64_t& token);

// True when the process token is a member of Administrators. Used to decide
// whether the peer may change hypervisor state; a failed lookup is "not admin",
// never "allowed".
bool process_is_administrator(uint32_t pid);

// Drops the session and every hook/watch it owns. No-op when `token` is not the
// live session.
void detach_peer(uint64_t token);

bool peer_live();
uint32_t peer_pid();

// Routes one wire request to control::dispatch under this session's identity.
NTSTATUS dispatch_peer(uint64_t token, uint16_t op, const void* in,
                       uint32_t in_len, void* out, uint32_t* out_cap,
                       uint32_t* out_len);

// Called when the transport reports a dead peer: revokes the session but keeps
// the hypervisor running so a new client can attach.
void peer_gone();

}  // namespace blook
