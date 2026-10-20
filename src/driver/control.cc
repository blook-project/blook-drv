// Command layer: the wire ABI, one case per opcode (see control.hpp).
#include "control.hpp"

#include <intrin.h>

#include "driver/configuration_state.hpp"
#include "driver/features.hpp"
#include "driver/hide/hide.hpp"
#include "driver/hide/self.hpp"
#include "driver/hooks.hpp"
#include "driver/resources.hpp"
#include "driver/hv/hwbreak.hpp"
#include "driver/hv/detect.h"
#include "driver/hv/hv.h"
#include "driver/hv/nested.h"
#include "driver/hv/swbreak.hpp"
#include "driver/watch.hpp"

namespace blook::control {
namespace {
// Copies a fixed-size request only after the length and the embedded header
// both match the type, so a mismatched payload can never be reinterpreted as a
// different message.
template <class Request>
bool parse(const void* in, uint32_t in_len, Request& request) {
    if (!in || in_len != sizeof(Request))
        return false;
    RtlCopyMemory(&request, in, sizeof(Request));
    return wire::valid_header(request);
}

// Not every reply carries the generic header (the small ones never did), so the
// stamping is conditional on the member existing.
template <class T>
struct has_header {
    template <class U>
    static auto test(decltype(&U::header)) -> char;
    template <class U>
    static long test(...);
    static constexpr bool value = sizeof(test<T>(nullptr)) == sizeof(char);
};

template <class Reply>
Reply* prepare(void* out, uint32_t* out_cap, uint32_t* out_len) {
    if (!out || !out_cap || *out_cap < sizeof(Reply))
        return nullptr;
    auto* reply = static_cast<Reply*>(out);
    RtlZeroMemory(reply, sizeof(Reply));
    if constexpr (has_header<Reply>::value) {
        reply->header.version = wire::abi_version;
        reply->header.size = sizeof(Reply);
    }
    *out_len = sizeof(Reply);
    return reply;
}

NTSTATUS allow(bool condition) {
    return condition ? STATUS_SUCCESS : STATUS_ACCESS_DENIED;
}

// The session must have been enabled (read-write attach) before it may change
// hypervisor state; a read-only attach is deliberately able to observe only.
NTSTATUS gate(const context& caller) {
    return allow(caller.enabled);
}

NTSTATUS require_admin(const context& caller) {
    return allow(caller.administrator);
}

NTSTATUS ping(const context&, const wire::PingRequest& request,
              wire::PingResponse& reply) {
    if (request.magic != wire::PingRequest::kMagic)
        return STATUS_INVALID_PARAMETER;
    reply.magic = wire::PingResponse::kMagic;
    reply.status = wire::PingResponse::kStatusOk;
    return STATUS_SUCCESS;
}

void enable(context& caller) {
    caller.enabled = hv::ghv.running;
}

NTSTATUS query(uint32_t version, wire::QueryResponse& reply) {
    reply.version = version;
    reply.running = hv::ghv.running ? 1u : 0u;
    reply.enabled = 1;
    reply.hooks = active_hook_count();
    reply.hidden = hide::active() ? 1u : 0u;
    reply.abi = wire::abi_version;
    reply.backend_status = STATUS_SUCCESS;
    reply.window_hooks = hide::window_hook_count();
    reply.hv_flags =
        hv::nested::flags() | (hv::ghv.running ? wire::hv_flag_running : 0u);
    reply.swbreak_count = hv::swbreak::count();
    reply.hwbreak_count = hv::hwbreak::count();
    reply.self_hidden = hide::self::module_list_hidden() ? 1u : 0u;
    return STATUS_SUCCESS;
}

NTSTATUS query_page(const context& caller,
                    const wire::QueryPageRequest& request,
                    wire::QueryPageResponse& reply) {
    if (request.reserved || request.reserved2)
        return STATUS_INVALID_PARAMETER;
    uint32_t pid = request.pid;
    if (request.domain == wire::page_domain_user)
        pid = request.pid ? request.pid : caller.pid;
    else if (request.domain == wire::page_domain_kernel)
        pid = 0;
    else
        return STATUS_INVALID_PARAMETER;
    return query_page_hooks(pid, caller.token, request.address, request.domain,
                            reply);
}
}  // namespace

void fill_hv_info(wire::HvInfoResponse& reply) {
    const auto& nested = hv::nested::probe();
    reply.flags = nested.flags | (hv::ghv.running ? wire::hv_flag_running : 0u);
    reply.vcpu_count = hv::ghv.vcpu_count;
    reply.nested_vendor_leaf_max = nested.leaf_max;
    for (int i = 0; i < 4; ++i)
        reply.nested_vendor[i] = nested.vendor_leaf[i];
    reply.vmx_basic = nested.vmx_basic;
    reply.nested_cr4_fixed0 = nested.cr4_fixed0;
    reply.nested_cr4_fixed1 = nested.cr4_fixed1;
    reply.capabilities =
        (nested.vmx_msr_readable ? 1ull : 0ull) |
        (nested.vp_assist ? 2ull : 0ull) |
        (nested.preemption_timer ? 4ull : 0ull) |
        (nested.ept_ad ? 8ull : 0ull) | (nested.vpid ? 16ull : 0ull) |
        (nested.invpcid ? 32ull : 0ull) | (nested.xsaves ? 64ull : 0ull) |
        (nested.rdtscp ? 128ull : 0ull) | (nested.mtf ? 256ull : 0ull);
    reply.degradation_reasons = nested.flags;
}

NTSTATUS dispatch_hide_self(context& caller,
                            const wire::HideSelfRequest& request,
                            wire::HideSelfResponse& reply) {
    if (!caller.enabled || !caller.administrator)
        return STATUS_ACCESS_DENIED;
    hide::self::outcome outcome{};
    const auto status = hide::self::hide(request.flags, outcome);
    reply.module_list_found = outcome.module_list_found;
    reply.module_list_unlinked = outcome.module_list_unlinked;
    reply.device_found = outcome.device_found;
    reply.device_unlinked = outcome.device_unlinked;
    reply.registry_found = outcome.registry_found;
    reply.registry_removed = outcome.registry_removed;
    reply.pool_tags_rewritten = outcome.pool_tags_rewritten;
    return status;
}

NTSTATUS dispatch(context& caller, uint16_t op, const void* in, uint32_t in_len,
                  void* out, uint32_t* out_cap, uint32_t* out_len) {
    if (!out_cap || !out_len)
        return STATUS_INVALID_PARAMETER;
    *out_len = 0;

    switch (static_cast<wire::op>(op)) {
        case wire::op::ping: {
            wire::PingRequest request{};
            if (!parse(in, in_len, request))
                return STATUS_INVALID_PARAMETER;
            auto* reply = prepare<wire::PingResponse>(out, out_cap, out_len);
            return reply ? ping(caller, request, *reply)
                         : STATUS_BUFFER_TOO_SMALL;
        }
        case wire::op::get_version: {
            if (in_len)
                return STATUS_INVALID_PARAMETER;
            auto* reply = prepare<wire::VersionInfo>(out, out_cap, out_len);
            if (!reply)
                return STATUS_BUFFER_TOO_SMALL;
            *reply = wire::kDriverVersion;
            return STATUS_SUCCESS;
        }
        case wire::op::enable: {
            wire::EnableRequest request{};
            if (!parse(in, in_len, request))
                return STATUS_INVALID_PARAMETER;
            enable(caller);
            return caller.enabled ? STATUS_SUCCESS : STATUS_DEVICE_NOT_READY;
        }
        case wire::op::query: {
            auto* reply = prepare<wire::QueryResponse>(out, out_cap, out_len);
            if (!reply)
                return STATUS_BUFFER_TOO_SMALL;
            return query(wire::kDriverVersion.major, *reply);
        }
        case wire::op::install: {
            wire::InstallRequest request{};
            if (!parse(in, in_len, request))
                return STATUS_INVALID_PARAMETER;
            if (const auto status = gate(caller); !NT_SUCCESS(status))
                return status;
            if (!request.length || request.length > sizeof(request.bytes) ||
                request.reserved)
                return STATUS_INVALID_PARAMETER;
            auto* reply = prepare<wire::InstallResponse>(out, out_cap, out_len);
            if (!reply)
                return STATUS_BUFFER_TOO_SMALL;
            const auto pid = request.pid ? request.pid : caller.pid;
            uint64_t id{};
            const auto status = install_hook(
                pid, caller.token, reinterpret_cast<void*>(request.target),
                request.bytes, request.length, id);
            if (NT_SUCCESS(status))
                reply->id = id;
            return status;
        }
        case wire::op::remove:
        case wire::op::refresh: {
            wire::HookRequest request{};
            if (!parse(in, in_len, request))
                return STATUS_INVALID_PARAMETER;
            if (const auto status = gate(caller); !NT_SUCCESS(status))
                return status;
            if (!request.id)
                return STATUS_INVALID_PARAMETER;
            return static_cast<wire::op>(op) == wire::op::remove
                       ? remove_owned_hook(request.id, caller.token)
                       : refresh_owned_hook(request.id, caller.token);
        }
        case wire::op::stats: {
            auto* reply = prepare<wire::StatsResponse>(out, out_cap, out_len);
            if (!reply)
                return STATUS_BUFFER_TOO_SMALL;
            if (const auto status = require_admin(caller); !NT_SUCCESS(status))
                return status;
            reply->execute_violations = hv::g_stats.execute_violations;
            reply->data_violations = hv::g_stats.data_violations;
            reply->window_open = hv::g_stats.window_open;
            reply->identity_ok = hv::g_stats.identity_ok;
            reply->identity_mismatch = hv::g_stats.identity_mismatch;
            reply->identity_failed = hv::g_stats.identity_failed;
            reply->internal_entry = hv::g_stats.internal_entry;
            reply->shadow_mapped = hv::g_stats.shadow_mapped;
            reply->original_step = hv::g_stats.original_step;
            reply->unowned_group = hv::g_stats.unowned_group;
            for (unsigned i = 0; i < wire::stats_exit_reason_slots; ++i)
                reply->exit_reasons[i] =
                    static_cast<uint64_t>(hv::g_stats.exit_reasons[i]);
            reply->vcpu_count = hv::g_stats.vcpu_count;
            reply->invept_calls = hv::g_stats.invept_calls;
            reply->invept_error = hv::g_stats.invept_error;
            reply->ept_misconfig = hv::g_stats.ept_misconfig;
            reply->install_rounds = hv::g_stats.install_rounds;
            reply->install_ok_cpus = hv::g_stats.install_ok_cpus;
            reply->install_fail_cpus = hv::g_stats.install_fail_cpus;
            for (unsigned i = 0; i < wire::stats_cpu_mask_words; ++i) {
                reply->install_ok_mask[i] =
                    static_cast<uint64_t>(hv::g_stats.install_ok_mask[i]);
                reply->install_fail_mask[i] =
                    static_cast<uint64_t>(hv::g_stats.install_fail_mask[i]);
            }
            reply->armed_entries_verified = hv::g_stats.armed_entries_verified;
            reply->armed_entries_wrong = hv::g_stats.armed_entries_wrong;
            for (unsigned i = 0; i < wire::stats_hook_rows; ++i) {
                const auto& row = hv::g_hook_diag[i];
                reply->hooks[i].id = static_cast<uint32_t>(row.id);
                reply->hooks[i].target = static_cast<uint64_t>(row.target);
                reply->hooks[i].pfn = static_cast<uint64_t>(row.pfn);
                reply->hooks[i].address_space =
                    static_cast<uint64_t>(row.address_space);
                reply->hooks[i].domain = static_cast<uint32_t>(row.domain);
                reply->hooks[i].active = static_cast<uint32_t>(row.active);
                reply->hooks[i].execute_hits =
                    static_cast<uint64_t>(row.execute_hits);
                reply->hooks[i].shadow_mapped =
                    static_cast<uint64_t>(row.shadow_mapped);
                reply->hooks[i].identity_mismatches =
                    static_cast<uint64_t>(row.identity_mismatches);
                if (reply->hooks[i].active)
                    ++reply->hook_rows;
            }
            return STATUS_SUCCESS;
        }
        case wire::op::probe: {
            wire::ProbeRequest request{};
            if (!parse(in, in_len, request))
                return STATUS_INVALID_PARAMETER;
            if (const auto status = require_admin(caller); !NT_SUCCESS(status))
                return status;
            auto* reply = prepare<wire::ProbeResponse>(out, out_cap, out_len);
            if (!reply)
                return STATUS_BUFFER_TOO_SMALL;
            reply->cr3 = __readcr3();
            reply->physical =
                MmGetPhysicalAddress(reinterpret_cast<void*>(request.address))
                    .QuadPart;
            reply->pid = caller.pid;
            reply->kernel_physical =
                MmGetPhysicalAddress(&hv::g_stats).QuadPart;
            {
                blook::page_lock lock;
                const auto status =
                    lock.acquire(reinterpret_cast<void*>(request.address),
                                 UserMode, IoReadAccess);
                reply->locked_status =
                    static_cast<uint64_t>(static_cast<uint32_t>(status));
                reply->locked_pfn = NT_SUCCESS(status) ? lock.pfn() : 0;
            }
            return STATUS_SUCCESS;
        }
        case wire::op::hide: {
            wire::HideRequest request{};
            if (!parse(in, in_len, request))
                return STATUS_REVISION_MISMATCH;
            if (const auto status = gate(caller); !NT_SUCCESS(status))
                return status;
            if (request.enable_hide != 2 && request.enable_hide != 3 &&
                !caller.administrator)
                return STATUS_ACCESS_DENIED;
            switch (request.enable_hide) {
                case 0:
                    hide::deactivate();
                    return STATUS_SUCCESS;
                case 1:
                    return hide::activate();
                case 2:
                    if (request.role != wire::hide_role_tool &&
                        request.role != wire::hide_role_target)
                        return STATUS_INVALID_PARAMETER;
                    hide::pin(request.pid ? request.pid : caller.pid,
                              request.role == wire::hide_role_tool
                                  ? role::tool
                                  : role::target);
                    return STATUS_SUCCESS;
                case 3:
                    hide::unpin(request.pid ? request.pid : caller.pid);
                    return STATUS_SUCCESS;
                case wire::hide_windows_on:
                    return hide::enable_windows(true);
                case wire::hide_windows_off:
                    return hide::enable_windows(false);
                default:
                    return STATUS_INVALID_PARAMETER;
            }
        }
        case wire::op::scrub: {
            wire::ScrubRequest request{};
            if (!parse(in, in_len, request))
                return STATUS_REVISION_MISMATCH;
            if (const auto status = gate(caller); !NT_SUCCESS(status))
                return status;
            return hide::scrub(request.pid ? request.pid : caller.pid,
                               request.flags ? request.flags : wire::scrub_all);
        }
        case wire::op::watch: {
            wire::WatchRequest request{};
            if (!parse(in, in_len, request))
                return STATUS_REVISION_MISMATCH;
            if (const auto status = gate(caller); !NT_SUCCESS(status))
                return status;
            if (request.action == wire::watch_disarm)
                return watch::disarm(request.id, caller.token);
            if (request.action != wire::watch_arm)
                return STATUS_INVALID_PARAMETER;
            auto* reply = prepare<wire::WatchResponse>(out, out_cap, out_len);
            if (!reply)
                return STATUS_BUFFER_TOO_SMALL;
            const auto address = request.base + request.address;
            const auto dump_base = request.base + request.dump_base;
            const auto target_pid = request.pid ? request.pid : caller.pid;
            uint64_t id{};
            const auto status = watch::arm(target_pid, caller.token, address,
                                           dump_base, request.dump_size, id);
            if (NT_SUCCESS(status))
                reply->id = id;
            return status;
        }
        case wire::op::dump: {
            wire::DumpRequest request{};
            if (!parse(in, in_len, request))
                return STATUS_INVALID_PARAMETER;
            if (const auto status = gate(caller); !NT_SUCCESS(status))
                return status;
            if (request.reserved || request.length > wire::dump_chunk_size)
                return STATUS_INVALID_PARAMETER;
            auto* reply = prepare<wire::DumpResponse>(out, out_cap, out_len);
            if (!reply)
                return STATUS_BUFFER_TOO_SMALL;
            watch::fetch_result fetched{};
            const auto status =
                watch::fetch(request.id, caller.token, request.offset,
                             reply->data, request.length, fetched);
            if (!NT_SUCCESS(status))
                return status;
            reply->state = fetched.state;
            reply->copied = fetched.copied;
            reply->total = fetched.total;
            reply->hit_rip = fetched.hit_rip;
            reply->hit_cr3 = fetched.hit_cr3;
            return STATUS_SUCCESS;
        }
        case wire::op::query_page: {
            wire::QueryPageRequest request{};
            if (!parse(in, in_len, request))
                return STATUS_REVISION_MISMATCH;
            auto* reply =
                prepare<wire::QueryPageResponse>(out, out_cap, out_len);
            if (!reply)
                return STATUS_BUFFER_TOO_SMALL;
            return query_page(caller, request, *reply);
        }
        case wire::op::configuration: {
            wire::ConfigurationRequest request{};
            if (!parse(in, in_len, request))
                return STATUS_REVISION_MISMATCH;
            if (request.reserved || request.reload > 1)
                return STATUS_INVALID_PARAMETER;
            if (request.reload && !caller.administrator)
                return STATUS_ACCESS_DENIED;
            auto* reply =
                prepare<wire::ConfigurationResponse>(out, out_cap, out_len);
            if (!reply)
                return STATUS_BUFFER_TOO_SMALL;
            *reply = request.reload ? configuration_state::reload()
                                    : configuration_state::query();
            return STATUS_SUCCESS;
        }
        case wire::op::features: {
            wire::FeaturesRequest request{};
            if (!parse(in, in_len, request))
                return STATUS_REVISION_MISMATCH;
            if (request.reserved || request.action > 1 || request.enabled > 1 ||
                (!request.action && (request.id || request.enabled)))
                return STATUS_INVALID_PARAMETER;
            if (request.action && !caller.administrator)
                return STATUS_ACCESS_DENIED;
            if (request.action && request.id >= 64)
                return STATUS_INVALID_PARAMETER;
            auto* reply =
                prepare<wire::FeaturesResponse>(out, out_cap, out_len);
            if (!reply)
                return STATUS_BUFFER_TOO_SMALL;
            const auto state =
                request.action
                    ? features::set_one(static_cast<feature::id>(request.id),
                                        request.enabled != 0)
                    : features::query();
            reply->desired = state.desired;
            reply->effective = state.effective;
            reply->unsupported = state.unsupported;
            reply->last_status = state.status;
            return STATUS_SUCCESS;
        }
        case wire::op::hide_self: {
            wire::HideSelfRequest request{};
            if (!parse(in, in_len, request))
                return STATUS_REVISION_MISMATCH;
            auto* reply =
                prepare<wire::HideSelfResponse>(out, out_cap, out_len);
            if (!reply)
                return STATUS_BUFFER_TOO_SMALL;
            return dispatch_hide_self(caller, request, *reply);
        }
        case wire::op::swbreak_arm: {
            wire::SwBreakArmRequest request{};
            if (!parse(in, in_len, request))
                return STATUS_INVALID_PARAMETER;
            if (const auto status = gate(caller); !NT_SUCCESS(status))
                return status;
            auto* reply = prepare<wire::SwBreakResponse>(out, out_cap, out_len);
            if (!reply)
                return STATUS_BUFFER_TOO_SMALL;
            hv::swbreak::info info{};
            const auto pid = request.pid ? request.pid : caller.pid;
            const auto status = hv::swbreak::arm(
                {pid, request.flags, request.address, caller.token}, info);
            reply->id = info.id;
            reply->hit_count = info.hits;
            reply->state = info.state;
            return status;
        }
        case wire::op::swbreak_disarm: {
            wire::SwBreakArmRequest request{};
            if (!parse(in, in_len, request))
                return STATUS_INVALID_PARAMETER;
            if (const auto status = gate(caller); !NT_SUCCESS(status))
                return status;
            auto* reply = prepare<wire::SwBreakResponse>(out, out_cap, out_len);
            if (!reply)
                return STATUS_BUFFER_TOO_SMALL;
            hv::swbreak::info info{};
            const auto status =
                request.id
                    ? hv::swbreak::disarm_id(request.id, caller.token, info)
                    : hv::swbreak::disarm(
                          {request.pid ? request.pid : caller.pid,
                           request.flags, request.address, caller.token},
                          info);
            reply->id = info.id;
            reply->hit_count = info.hits;
            reply->state = info.state;
            return status;
        }
        case wire::op::swbreak_query: {
            wire::SwBreakArmRequest request{};
            if (!parse(in, in_len, request))
                return STATUS_INVALID_PARAMETER;
            auto* reply = prepare<wire::SwBreakResponse>(out, out_cap, out_len);
            if (!reply)
                return STATUS_BUFFER_TOO_SMALL;
            hv::swbreak::info info{};
            const auto status = hv::swbreak::query(
                {request.pid ? request.pid : caller.pid, request.flags,
                 request.address, caller.token},
                info);
            reply->id = info.id;
            reply->hit_count = info.hits;
            reply->state = info.state;
            return status;
        }
        case wire::op::hwbreak_arm: {
            wire::HwBreakArmRequest request{};
            if (!parse(in, in_len, request))
                return STATUS_INVALID_PARAMETER;
            if (const auto status = gate(caller); !NT_SUCCESS(status))
                return status;
            if (!caller.administrator)
                return STATUS_ACCESS_DENIED;
            auto* reply = prepare<wire::HwBreakResponse>(out, out_cap, out_len);
            if (!reply)
                return STATUS_BUFFER_TOO_SMALL;
            hv::hwbreak::info info{};
            const auto status = hv::hwbreak::arm(
                {request.pid ? request.pid : caller.pid, request.tid,
                 request.dr_index, request.access, request.length,
                 request.flags, request.address, caller.token},
                info);
            reply->id = info.id;
            reply->dr_index = info.dr_index;
            reply->hit_count = info.hits;
            reply->state = info.state;
            reply->hidden = info.hidden;
            return status;
        }
        case wire::op::hwbreak_disarm: {
            wire::HwBreakArmRequest request{};
            if (!parse(in, in_len, request))
                return STATUS_INVALID_PARAMETER;
            if (const auto status = gate(caller); !NT_SUCCESS(status))
                return status;
            if (!caller.administrator)
                return STATUS_ACCESS_DENIED;
            auto* reply = prepare<wire::HwBreakResponse>(out, out_cap, out_len);
            if (!reply)
                return STATUS_BUFFER_TOO_SMALL;
            hv::hwbreak::info info{};
            hv::hwbreak::arm_request key{};
            key.pid = request.pid ? request.pid : caller.pid;
            key.tid = request.tid;
            key.dr_index = request.dr_index;
            key.token = caller.token;
            const auto status = request.id ? hv::hwbreak::disarm_id(
                                                 request.id, caller.token, info)
                                           : hv::hwbreak::disarm(key, info);
            reply->id = info.id;
            reply->dr_index = info.dr_index;
            reply->hit_count = info.hits;
            reply->state = info.state;
            reply->hidden = info.hidden;
            return status;
        }
        case wire::op::hwbreak_query: {
            wire::HwBreakQueryRequest request{};
            if (!parse(in, in_len, request))
                return STATUS_INVALID_PARAMETER;
            if (!caller.administrator)
                return STATUS_ACCESS_DENIED;
            auto* reply =
                prepare<wire::HwBreakQueryResponse>(out, out_cap, out_len);
            if (!reply)
                return STATUS_BUFFER_TOO_SMALL;
            hv::hwbreak::sanitized view{};
            const auto status = hv::hwbreak::query_view(
                request.pid ? request.pid : caller.pid, request.tid, view);
            reply->dr0 = view.dr[0];
            reply->dr1 = view.dr[1];
            reply->dr2 = view.dr[2];
            reply->dr3 = view.dr[3];
            reply->dr6 = view.dr6;
            reply->dr7 = view.dr7;
            reply->armed = view.armed;
            reply->hits = view.hits;
            reply->leaks_blocked = view.leaks_blocked;
            return status;
        }
        case wire::op::detect_probe: {
            wire::DetectProbeRequest request{};
            if (!parse(in, in_len, request))
                return STATUS_INVALID_PARAMETER;
            auto* reply =
                prepare<wire::DetectProbeResponse>(out, out_cap, out_len);
            if (!reply)
                return STATUS_BUFFER_TOO_SMALL;
            return hv::detect::probe(request, *reply);
        }
        case wire::op::hv_info: {
            auto* reply = prepare<wire::HvInfoResponse>(out, out_cap, out_len);
            if (!reply)
                return STATUS_BUFFER_TOO_SMALL;
            fill_hv_info(*reply);
            return STATUS_SUCCESS;
        }
        case wire::op::trace_scan: {
            wire::TraceScanRequest request{};
            if (!parse(in, in_len, request))
                return STATUS_INVALID_PARAMETER;
            auto* reply =
                prepare<wire::TraceScanResponse>(out, out_cap, out_len);
            if (!reply)
                return STATUS_BUFFER_TOO_SMALL;
            return hide::self::scan(*reply);
        }
        default:
            return STATUS_INVALID_DEVICE_REQUEST;
    }
}
}  // namespace blook::control
