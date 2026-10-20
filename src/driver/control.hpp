#pragma once
#include <ntifs.h>

#include "blook/drv/wire.hpp"

// Transport-independent command layer.
//
// Every request that used to be a device IOCTL is one entry in this switch. The
// only things the transport (blook-kchannel adapter) does around it are:
//   - validating the kc_msg_header and the payload length,
//   - handing over the caller's identity (peer pid + admin flag + ownership
//     token) in a `context`,
//   - copying the reply into the response ring.
// Keeping the command bodies here is what makes the "no custom IPC" rule
// checkable: the adapter contains no policy, and this file contains no
// transport.
namespace blook::control {

// Identity of the peer that is allowed to issue commands. The transport fills
// it once at attach time; it never changes for the lifetime of a session.
struct context {
    uint32_t pid{};        // peer process id (hooks default to this process)
    uint64_t token{};      // hook ownership token, unique per session
    bool administrator{};  // peer token is a member of Administrators
    bool enabled{};        // session may modify hypervisor state
};

// Handles one request. `in` may be NULL when in_len == 0. `out_cap` is the
// writable capacity of `out`; on success *out_len is the reply size. Returns an
// NTSTATUS; the transport maps it to a kc_status.
NTSTATUS dispatch(context& caller, uint16_t op, const void* in, uint32_t in_len,
                  void* out, uint32_t* out_cap, uint32_t* out_len);

// Applies the hide-self request (also used by the solo/dev path).
NTSTATUS dispatch_hide_self(context& caller,
                            const wire::HideSelfRequest& request,
                            wire::HideSelfResponse& reply);

// Nested-virtualisation / degradation report, also used by the driver startup
// path for logging.
void fill_hv_info(wire::HvInfoResponse& reply);

}  // namespace blook::control
