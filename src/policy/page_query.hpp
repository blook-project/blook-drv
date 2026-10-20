#pragma once
#include "blook/drv/wire.hpp"
#include "policy/hook.hpp"
#include "policy/hook_catalog.hpp"

namespace blook::page_query {
struct record {
    uint64_t id{}, target{}, token{};
    uint32_t pid{};
    hook_domain domain{};
    bool armed{}, dormant{};
    hook_catalog::entry_id catalog{hook_catalog::entry_id::opaque};
};
// Caller validates the request and serializes the registry and feature
// snapshot.
inline void initialize(wire::QueryPageResponse& out, uint32_t pid,
                       uint64_t address, uint32_t domain) {
    out = {};
    out.header = {wire::abi_version, sizeof(out)};
    out.domain = domain;
    if (domain == wire::page_domain_user) {
        out.pid = pid;
        out.page_base = address & ~uint64_t{0xfff};
    } else
        out.flags = wire::page_query_counts_only;
}
inline void append(wire::QueryPageResponse& out, const record& entry,
                   uint32_t pid, uint64_t token, uint64_t address,
                   feature::mask effective, bool running) {
    const bool user = out.domain == wire::page_domain_user;
    if ((entry.target & ~uint64_t{0xfff}) != (address & ~uint64_t{0xfff}) ||
        (user ? (entry.domain != hook_domain::user || entry.pid != pid ||
                 entry.token != token)
              : entry.domain != hook_domain::kernel))
        return;
    const bool armed = entry.armed && !entry.dormant && running;
    ++out.registered_count;
    out.armed_count += armed ? 1u : 0u;
    out.dormant_count += entry.dormant ? 1u : 0u;
    if (const auto* binding = hook_catalog::find(entry.catalog)) {
        out.logical_count +=
            binding->mandatory + hook_catalog::count_bits(binding->optional);
        if (armed)
            out.enabled_logical_count +=
                binding->mandatory +
                hook_catalog::count_bits(binding->optional & effective);
    } else
        ++out.opaque_count;
    if (user && out.entry_count < wire::page_hook_capacity) {
        out.entries[out.entry_count++] = {entry.id,
                                          entry.target,
                                          pid,
                                          out.domain,
                                          entry.dormant ? 1u : 0u,
                                          armed ? 1u : 0u};
    }
}
}  // namespace blook::page_query
