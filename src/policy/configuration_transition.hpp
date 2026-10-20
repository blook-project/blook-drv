#pragma once
#include "policy/configuration.hpp"
namespace blook::configuration {
enum class transition {
    applied,
    restart_required,
    rejected,
    generation_exhausted
};
// Candidate is already parsed. Caller serializes publication; apply must commit
// features+roles together or retain the old policy. Snapshot/generation only
// change after apply succeeds. No filesystem or registry writes occur here.
template <class Apply>
transition commit(snapshot& current, uint64_t& generation,
                  const snapshot& candidate, Apply apply) {
    if (candidate.allow_users != current.allow_users ||
        candidate.hide_timing != current.hide_timing ||
        candidate.page_fault_trace != current.page_fault_trace)
        return transition::restart_required;
    if (generation == ~uint64_t{})
        return transition::generation_exhausted;
    if (!apply(candidate))
        return transition::rejected;
    current = candidate;
    ++generation;
    return transition::applied;
}
}  // namespace blook::configuration
