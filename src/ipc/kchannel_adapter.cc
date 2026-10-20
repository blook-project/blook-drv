// Kernel side of the blook-kchannel adapter.
//
// One handler per wire::op, one shared reply buffer, one session token. All the
// policy lives in driver/control.cc; this file only knows how to unpack a
// kchannel request, hand it to the command layer and pack the reply.
#include "ipc/kchannel.hpp"

#include <ntifs.h>

#include "blook/kchannel_km.h"
#include "driver/pool.hpp"
#include "driver/resources.hpp"
#include "driver/session.hpp"

namespace blook::ipc {
namespace {
kc_kernel* instance{};
uint8_t* reply_buffer{};
uint64_t session_token{};
int last_error{};
bool solo{};
bool live{};
bool peer_gone_pending{};

// Backpressure in the response ring is handled by kchannel; our buffer only has
// to be big enough for the largest reply (StatsResponse/QueryPageResponse), plus
// the dump chunk.
constexpr uint32_t reply_capacity = 0x10000;

kc_status to_status(NTSTATUS status) {
    if (NT_SUCCESS(status))
        return KC_OK;
    switch (status) {
        case STATUS_INVALID_PARAMETER:
        case STATUS_INFO_LENGTH_MISMATCH:
        case STATUS_REVISION_MISMATCH:
        case STATUS_BUFFER_TOO_SMALL:
        case STATUS_INVALID_ADDRESS:
        case STATUS_DATATYPE_MISALIGNMENT:
            return KC_ERR_PARAM;
        case STATUS_ACCESS_DENIED:
            return KC_ERR_AUTH;
        case STATUS_DEVICE_NOT_READY:
        case STATUS_INVALID_DEVICE_STATE:
            return KC_ERR_STATE;
        case STATUS_NOT_FOUND:
        case STATUS_OBJECT_NAME_NOT_FOUND:
            return KC_ERR_NOT_FOUND;
        case STATUS_ALREADY_REGISTERED:
            return KC_ERR_ALREADY;
        case STATUS_INSUFFICIENT_RESOURCES:
            return KC_ERR_NOMEM;
        case STATUS_NOT_SUPPORTED:
            return KC_ERR_UNSUPPORTED;
        default:
            return KC_ERR_INTERNAL;
    }
}

void on_peer_gone(void*) {
    peer_gone_pending = true;
    live = false;
    blook::peer_gone();
}

// The worker thread is the only caller, so a single reply buffer is safe and
// avoids a per-request allocation on the command path.
kc_status dispatch(void* ctx, uint16_t op, const void* in, uint32_t in_len,
                   void* out, uint32_t* out_cap, uint32_t* out_len) {
    if (!out || !out_cap || !out_len)
        return KC_ERR_PARAM;
    // kchannel promises the outcome of the wire header/length checks before the
    // handler runs; a short output buffer is still possible when the caller's
    // ring is smaller than the reply, and the command layer reports it.
    auto capacity = *out_cap;
    if (capacity > reply_capacity)
        capacity = reply_capacity;
    uint32_t written{};
    const auto token = *static_cast<const uint64_t*>(ctx);
    const auto status = blook::dispatch_peer(token, op, in, in_len,
                                             reply_buffer, &capacity, &written);
    if (!NT_SUCCESS(status))
        return to_status(status);
    if (written > *out_cap)
        return KC_ERR_INTERNAL;
    RtlCopyMemory(out, reply_buffer, written);
    *out_len = written;
    return KC_OK;
}

struct registration {
    uint16_t op;
};
constexpr registration registrations[] = {
    {wire::opcode(wire::op::ping)},
    {wire::opcode(wire::op::get_version)},
    {wire::opcode(wire::op::enable)},
    {wire::opcode(wire::op::query)},
    {wire::opcode(wire::op::install)},
    {wire::opcode(wire::op::remove)},
    {wire::opcode(wire::op::refresh)},
    {wire::opcode(wire::op::stats)},
    {wire::opcode(wire::op::probe)},
    {wire::opcode(wire::op::hide)},
    {wire::opcode(wire::op::scrub)},
    {wire::opcode(wire::op::watch)},
    {wire::opcode(wire::op::dump)},
    {wire::opcode(wire::op::query_page)},
    {wire::opcode(wire::op::configuration)},
    {wire::opcode(wire::op::features)},
    {wire::opcode(wire::op::hide_self)},
    {wire::opcode(wire::op::swbreak_arm)},
    {wire::opcode(wire::op::swbreak_disarm)},
    {wire::opcode(wire::op::swbreak_query)},
    {wire::opcode(wire::op::hwbreak_arm)},
    {wire::opcode(wire::op::hwbreak_disarm)},
    {wire::opcode(wire::op::hwbreak_query)},
    {wire::opcode(wire::op::detect_probe)},
    {wire::opcode(wire::op::hv_info)},
    {wire::opcode(wire::op::trace_scan)},
};
}  // namespace

void set_solo_mode(bool value) {
    solo = value;
}

bool adapter_solo() {
    return solo;
}

int adapter_start(const void* bootstrap) {
    last_error = 0;
    if (instance)
        return KC_ERR_ALREADY;
    if (!bootstrap) {
        // No channel can be created without a bootstrap descriptor. In solo
        // mode that is expected (the entry point decided to) and the driver
        // keeps running; otherwise it is a load failure.
        last_error = KC_ERR_PARAM;
        return last_error;
    }

    if (!reply_buffer) {
        reply_buffer = static_cast<uint8_t*>(ExAllocatePool2(
            POOL_FLAG_NON_PAGED, reply_capacity, blook::pool_tag));
        if (!reply_buffer) {
            last_error = KC_ERR_NOMEM;
            return last_error;
        }
    }

    kc_kernel_config config{};
    config.max_payload = KC_MAX_PAYLOAD;
    config.poll_spin_us = KC_DEFAULT_POLL_SPIN_US;
    config.poll_idle_us = KC_DEFAULT_POLL_IDLE_US;
    config.poll_idle_max_us = KC_DEFAULT_POLL_IDLE_MAX_US;
    config.watchdog_ms = KC_DEFAULT_WATCHDOG_MS;
    config.flags = KC_KFLAG_EVENTS;

    kc_kernel* kernel{};
    auto status = kc_kernel_create(static_cast<const kc_bootstrap*>(bootstrap),
                                   &config, &kernel);
    if (status != KC_OK) {
        last_error = status;
        return last_error;
    }

    const auto pid = kc_kernel_peer_pid(kernel);
    uint64_t token{};
    const auto attach = blook::attach_peer(
        pid, blook::process_is_administrator(pid), token);
    if (!NT_SUCCESS(attach)) {
        kc_kernel_destroy(kernel);
        last_error = to_status(attach);
        return last_error;
    }
    session_token = token;

    for (const auto& item : registrations) {
        status = kc_kernel_register(kernel, item.op, dispatch, &session_token);
        if (status != KC_OK) {
            blook::detach_peer(session_token);
            kc_kernel_destroy(kernel);
            last_error = status;
            return last_error;
        }
    }
    kc_kernel_set_peer_gone(kernel, on_peer_gone, nullptr);

    status = kc_kernel_start(kernel);
    if (status != KC_OK) {
        blook::detach_peer(session_token);
        session_token = 0;
        kc_kernel_destroy(kernel);
        last_error = status;
        return last_error;
    }

    instance = kernel;
    live = true;
    peer_gone_pending = false;
    return 0;
}

int adapter_stop() {
    if (instance) {
        kc_kernel_stop(instance);
        kc_kernel_destroy(instance);
        instance = nullptr;
    }
    if (session_token) {
        blook::detach_peer(session_token);
        session_token = 0;
    }
    live = false;
    if (reply_buffer) {
        ExFreePoolWithTag(reply_buffer, blook::pool_tag);
        reply_buffer = nullptr;
    }
    return 0;
}

bool adapter_live() {
    return live && instance && kc_kernel_state(instance) == KC_STATE_ACTIVE;
}

int adapter_last_error() {
    return last_error;
}
}  // namespace blook::ipc
