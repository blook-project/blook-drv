#pragma once
#include <stddef.h>

#include "policy/integer.hpp"

namespace blook {
// A typed, allocation-free invocation snapshot. One physical entry patch calls
// a dispatcher; logical handlers call `next` rather than patching the entry
// again. The owner publishes/copies snapshots under its own synchronization and
// keeps handler code/context and the original alive until readers have drained.
// Never mutate a snapshot while it is being invoked.
template <class Signature, size_t Capacity = 32>
class dispatch_chain;

template <size_t Capacity, class Result, class... Args>
class dispatch_chain<Result(Args...), Capacity> {
   public:
    using original_type = Result (*)(Args...);
    class continuation;
    using handler_type = Result (*)(void*, continuation, Args...);
    struct entry {
        uint64_t id{};
        handler_type handler{};
        void* context{};
        int32_t priority{};
        bool enabled{true};
        const char* name{};
        const char* purpose{};
    };
    class continuation {
        friend class dispatch_chain;
        const dispatch_chain* chain_;
        size_t index_;
        original_type original_;
        continuation(const dispatch_chain* chain, size_t index,
                     original_type original)
            : chain_(chain), index_(index), original_(original) {}

       public:
        Result operator()(Args... args) const {
            size_t index = index_;
            while (index < chain_->count_ && !chain_->entries_[index].enabled)
                ++index;
            if (index == chain_->count_)
                return original_(static_cast<Args&&>(args)...);
            const auto& item = chain_->entries_[index];
            return item.handler(item.context,
                                continuation{chain_, index + 1, original_},
                                static_cast<Args&&>(args)...);
        }
    };

    // Ascending priority, then registration order. Duplicate logical IDs are
    // rejected; multiple different IDs may use the same handler function.
    bool add(entry value) {
        if (!value.id || !value.handler || count_ == Capacity)
            return false;
        for (size_t i = 0; i < count_; ++i)
            if (entries_[i].id == value.id)
                return false;
        size_t index = count_;
        while (index && entries_[index - 1].priority > value.priority) {
            entries_[index] = entries_[index - 1];
            --index;
        }
        entries_[index] = value;
        ++count_;
        return true;
    }
    bool remove(uint64_t id) {
        for (size_t i = 0; i < count_; ++i) {
            if (entries_[i].id != id)
                continue;
            for (size_t j = i + 1; j < count_; ++j)
                entries_[j - 1] = entries_[j];
            entries_[--count_] = {};
            return true;
        }
        return false;
    }
    bool set_enabled(uint64_t id, bool enabled) {
        for (size_t i = 0; i < count_; ++i) {
            if (entries_[i].id == id) {
                entries_[i].enabled = enabled;
                return true;
            }
        }
        return false;
    }
    size_t size() const { return count_; }
    size_t enabled_count() const {
        size_t count = 0;
        for (size_t i = 0; i < count_; ++i)
            if (entries_[i].enabled)
                ++count;
        return count;
    }
    // Read-only enumeration in execution order; pointers belong to this
    // snapshot.
    const entry* at(size_t index) const {
        return index < count_ ? &entries_[index] : nullptr;
    }
    // original must be a valid callable with exactly this signature. Handlers
    // must call next at most once, or short circuit by not calling next; the
    // framework never guesses an ABI.
    Result invoke(original_type original, Args... args) const {
        return continuation{this, 0, original}(static_cast<Args&&>(args)...);
    }

   private:
    entry entries_[Capacity]{};
    size_t count_{};
};
}  // namespace blook
