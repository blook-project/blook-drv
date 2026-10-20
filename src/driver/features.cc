#include "features.hpp"
#include "driver/hooks.hpp"
#include "driver/hv/hook_gate.hpp"
#include "driver/resources.hpp"
#include "driver/hide/nt.hpp"
#include "driver/hide/win32k.hpp"
#include "policy/role_rules.hpp"

namespace blook::features {
struct policy_object {
    volatile LONG references{1};  // Publication owns one reference.
    feature::mask mask{};
    uint32_t role_count{};
    configuration::role_rule roles[configuration::max_roles]{};
};
namespace {
EX_PUSH_LOCK writer_lock{};
EX_PUSH_LOCK publication_lock{};
policy_object* current{};
snapshot state{};
void release(policy_object* value) {
    if (value && InterlockedDecrement(&value->references) == 0)
        delete_object(value);
}
void publish(policy_object* value) {
    policy_object* previous{};
    {
        exclusive_lock guard{publication_lock};
        previous = current;
        current = value;
    }
    // Never wait for readers: nested originals can acquire the new generation.
    release(previous);
}
snapshot apply(feature::mask requested,
               const configuration::snapshot* rules = nullptr) {
    if (rules && rules->role_count > configuration::max_roles) {
        state.status = STATUS_INVALID_PARAMETER;
        state.unsupported = 0;
        return state;
    }
    if (hv::hook_gate::is_closing()) {
        state.status = STATUS_DEVICE_BUSY;
        return state;
    }
    auto unsupported = requested & ~feature::known_mask;
    if (!unsupported) {
        const auto nt = hide::nt::ensure_features(requested);
        const auto windows = hide::win32k::ensure_features(requested);
        unsupported = requested & ~(nt | windows);
    }
    state.unsupported = unsupported;
    state.status = unsupported ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
    if (unsupported)
        return state;
    auto* next = allocate_object<policy_object>();
    if (!next) {
        state.status = STATUS_INSUFFICIENT_RESOURCES;
        return state;
    }
    next->mask = requested;
    // All publications own writer_lock; current cannot change while copying.
    if (rules) {
        next->role_count = rules->role_count <= configuration::max_roles
                               ? rules->role_count
                               : 0;
        for (uint32_t i = 0; i < next->role_count; ++i)
            next->roles[i] = rules->roles[i];
    } else if (current) {
        next->role_count = current->role_count;
        for (uint32_t i = 0; i < next->role_count; ++i)
            next->roles[i] = current->roles[i];
    }
    publish(next);
    state.desired = requested;
    state.effective = requested;
    return state;
}
}  // namespace
policy_view::policy_view() {
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return;
    KeEnterCriticalRegion();
    ExAcquirePushLockShared(&publication_lock);
    value_ = current;
    if (value_)
        InterlockedIncrement(&value_->references);
    ExReleasePushLockShared(&publication_lock);
    KeLeaveCriticalRegion();
}
policy_view::~policy_view() {
    release(value_);
}
feature::mask policy_view::mask() const {
    return value_ ? value_->mask : 0;
}
role policy_view::classify(const wchar_t* name, size_t length) const {
    return value_ ? role_rules::classify(name, length, value_->roles,
                                         value_->role_count)
                  : role::other;
}
snapshot set_policy(const configuration::snapshot& policy) {
    exclusive_lock guard{writer_lock};
    return apply(policy.feature_mask, &policy);
}
snapshot set_desired(feature::mask requested) {
    exclusive_lock guard{writer_lock};
    return apply(requested);
}
snapshot update(feature::mask set, feature::mask clear) {
    exclusive_lock guard{writer_lock};
    return apply((state.desired | set) & ~clear);
}
snapshot set_one(feature::id value, bool enable) {
    if (static_cast<uint8_t>(value) >=
        static_cast<uint8_t>(feature::id::count)) {
        exclusive_lock guard{writer_lock};
        state.status = STATUS_INVALID_PARAMETER;
        state.unsupported = 0;
        return state;
    }
    const auto bit = feature::bit(value);
    return update(enable ? bit : 0, enable ? 0 : bit);
}
snapshot query() {
    exclusive_lock guard{writer_lock};
    return state;
}
NTSTATUS query_page(uint32_t pid, uint64_t token, uint64_t address,
                    uint32_t domain, wire::QueryPageResponse& result) {
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return STATUS_INVALID_DEVICE_STATE;
    exclusive_lock guard{writer_lock};
    return blook::detail::query_page_hooks_snapshot(pid, token, address, domain,
                                                    result, state.effective);
}
feature::mask effective_mask() {
    return policy_view{}.mask();
}
bool enabled(feature::id value) {
    return policy_view{}.enabled(value);
}
void shutdown() {
    exclusive_lock guard{writer_lock};
    publish(nullptr);
    state = {};
}
}  // namespace blook::features

namespace blook {
NTSTATUS query_page_hooks(uint32_t pid, uint64_t token, uint64_t address,
                          uint32_t domain, wire::QueryPageResponse& result) {
    return features::query_page(pid, token, address, domain, result);
}
}  // namespace blook
