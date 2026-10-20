#pragma once
#include <ntifs.h>
#include "policy/features.hpp"
#include "policy/configuration.hpp"

namespace blook::features {
struct snapshot {
    feature::mask desired{};
    feature::mask effective{};
    feature::mask unsupported{};
    NTSTATUS status{STATUS_SUCCESS};
};
struct policy_object;
// A pointer-sized generation reference. Only acquisition briefly takes a lock;
// no lock/critical region is held across original calls or name resolution.
// Above PASSIVE_LEVEL an empty (disabled) view is returned.
class policy_view final {
    policy_object* value_{};

   public:
    policy_view();
    ~policy_view();
    policy_view(const policy_view&) = delete;
    policy_view& operator=(const policy_view&) = delete;
    feature::mask mask() const;
    bool enabled(feature::id id) const {
        return (mask() & feature::bit(id)) != 0;
    }
    role classify(const wchar_t* name, size_t length) const;
};
snapshot set_policy(const configuration::snapshot& policy);
// Call after hook rundown, while driver code is still resident.
void shutdown();
// PASSIVE_LEVEL, serialized all-or-nothing logical publication. Failure retains
// previous desired/effective; unsupported describes the latest failed request.
snapshot set_desired(feature::mask desired);
snapshot query();
snapshot set_one(feature::id value, bool enabled);
// Atomically modify a group without query/set lost updates (legacy presets).
snapshot update(feature::mask set, feature::mask clear);
// Compatibility single-value queries. Multi-step hook decisions must instead
// retain one policy_view and use its mask/roles for the complete invocation.
feature::mask effective_mask();
bool enabled(feature::id value);
}  // namespace blook::features
