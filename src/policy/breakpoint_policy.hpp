#pragma once
#include "policy/integer.hpp"

// Pure state machine for the software-breakpoint (#BP) hook and the hardware
// breakpoint (#DB) hook.
//
// The kernel side owns the hard parts (EPT shadow pages, VMCS fields, single
// stepping), but *which* transitions are legal - hit, single-step once,
// restore, re-arm, disarm under a running target - is decided here so it can be
// tested on the host against a simulated exit stream. The invariant the tests
// encode is the one the target can observe: the original instruction executes
// exactly once, and while the breakpoint is armed the target's own reads of the
// patched page keep showing the original bytes.
namespace blook::policy {

enum class breakpoint_state : uint32_t {
    free = 0,
    armed = 1,
    stepping = 2,
};

struct breakpoint_entry {
    uint64_t id{};
    uint64_t address{};
    breakpoint_state state{breakpoint_state::free};
    uint32_t hits{};
};

// What the caller must do with the guest after a #BP or a #DB.
struct breakpoint_action {
    bool handled{};
    uint64_t id{};
    // #BP only: rewind the guest RIP to this address and execute the original
    // instruction under the trap flag / MTF.
    bool rewind{};
    uint64_t rewind_to{};
    // #DB only: the single step that just completed.
    uint64_t completed{};
};

// Canonical user-mode address that can hold code. A #BP outside this range can
// never fault and must be rejected instead of pinning a bogus page.
inline constexpr bool usable_code_address(uint64_t address) {
    return address >= 0x10000 && address <= 0x00007FFFFFFFFFFFull;
}

class breakpoint_table {
   public:
    static constexpr size_t capacity = 32;

    // Installs a new entry. Returns 0 when the address is unusable, the table
    // is full, or the address is already armed.
    uint64_t arm(uint64_t address) {
        if (!usable_code_address(address))
            return 0;
        if (find(address))
            return 0;
        for (auto& slot : entries_) {
            if (slot.state != breakpoint_state::free)
                continue;
            slot.id = next_id_++;
            slot.address = address;
            slot.hits = 0;
            slot.state = breakpoint_state::armed;
            return slot.id;
        }
        return 0;
    }

    // Removes an entry. A breakpoint that is being single-stepped cannot be
    // removed from under the processor: the caller must finish the step first.
    bool disarm(uint64_t id) {
        auto* entry = find_id(id);
        if (!entry || entry->state == breakpoint_state::stepping)
            return false;
        *entry = {};
        return true;
    }

    // #BP arrived at `int3_address` (the guest RIP minus one). Rewinds the
    // entry into the stepping state; a second #BP for the same address while
    // stepping is a re-entrant hit on a different processor and is reported as
    // unhandled so the caller can reflect it instead of corrupting the step.
    breakpoint_action on_breakpoint(uint64_t int3_address) {
        breakpoint_action action;
        // While one breakpoint is single-stepping, the processor is executing a
        // traced instruction; a second #BP cannot start another step (the
        // processor has one trap flag). The caller reflects it instead.
        if (stepping())
            return action;
        auto* entry = find(int3_address);
        if (!entry || entry->state != breakpoint_state::armed)
            return action;
        entry->state = breakpoint_state::stepping;
        ++entry->hits;
        action.handled = true;
        action.id = entry->id;
        action.rewind = true;
        action.rewind_to = int3_address;
        return action;
    }

    // The single step of the original instruction completed.
    breakpoint_action on_single_step() {
        breakpoint_action action;
        for (auto& entry : entries_) {
            if (entry.state != breakpoint_state::stepping)
                continue;
            entry.state = breakpoint_state::armed;
            action.handled = true;
            action.id = entry.id;
            action.completed = entry.address;
            return action;
        }
        return action;
    }

    breakpoint_state state(uint64_t id) const {
        const auto* entry = find_id(id);
        return entry ? entry->state : breakpoint_state::free;
    }

    uint32_t hits(uint64_t id) const {
        const auto* entry = find_id(id);
        return entry ? entry->hits : 0;
    }

    bool stepping() const {
        for (const auto& entry : entries_)
            if (entry.state == breakpoint_state::stepping)
                return true;
        return false;
    }

    size_t size() const {
        size_t count{};
        for (const auto& entry : entries_)
            if (entry.state != breakpoint_state::free)
                ++count;
        return count;
    }

   private:
    breakpoint_entry* find(uint64_t address) {
        for (auto& entry : entries_)
            if (entry.state != breakpoint_state::free &&
                entry.address == address)
                return &entry;
        return nullptr;
    }
    breakpoint_entry* find_id(uint64_t id) {
        for (auto& entry : entries_)
            if (entry.state != breakpoint_state::free && entry.id == id)
                return &entry;
        return nullptr;
    }
    const breakpoint_entry* find_id(uint64_t id) const {
        for (const auto& entry : entries_)
            if (entry.state != breakpoint_state::free && entry.id == id)
                return &entry;
        return nullptr;
    }

    breakpoint_entry entries_[capacity]{};
    uint64_t next_id_{1};
};

// Per-processor single-step bookkeeping: exactly what the vm-exit handler keeps
// while the original instruction of a #BP is executed under the trap flag. Two
// processors can step at the same time (they each have their own trap flag), so
// this state is per-processor, not global.
struct step_state {
    uint64_t id{};
    uint64_t saved_rflags{};
    bool active{};
};

inline bool begin_step(const breakpoint_action& action, step_state& state) {
    if (!action.handled || !action.rewind || state.active)
        return false;
    state.id = action.id;
    state.active = true;
    return true;
}

inline bool end_step(step_state& state, uint64_t& id) {
    if (!state.active)
        return false;
    id = state.id;
    state.active = false;
    state.id = 0;
    return true;
}

// Debug-register presentation policy for the hardware-breakpoint hook. Mirrors
// what hwbreak.cpp does with the live DRs: the driver's own breakpoints are
// never visible, writes that would disable them are swallowed, and everything
// else behaves like the bare-metal register.
struct debug_register_state {
    uint64_t dr[4]{};
    uint64_t dr6{};
    uint64_t dr7{};
};

inline constexpr uint64_t dr7_enable_bit(uint32_t index) {
    return uint64_t{1} << (index * 2);
}

inline constexpr uint64_t dr7_control_mask(uint32_t index) {
    return uint64_t{0xF} << (16 + index * 4);
}

struct dr_read_result {
    bool handled{};  // false: the caller must reproduce the architectural #GP
    uint64_t value{};
};

struct dr_write_result {
    bool handled{};    // false: let the guest write the register
    bool swallowed{};  // handled and the write was dropped
    uint64_t value{};
};

// `live` is the register value in the CPU (equal to the guest's write path for
// non-driver registers, the driver's own address for its breakpoints).
inline dr_read_result read_debug_register(const uint64_t* owned, uint32_t index,
                                          uint64_t live) {
    dr_read_result result;
    if (index < 4) {
        result.handled = true;
        // An address the driver owns is never reported; a register the driver
        // does not own passes through unchanged.
        result.value = owned && owned[index] == live ? 0 : live;
        return result;
    }
    if (index == 6 || index == 7) {
        result.handled = true;
        result.value = live;
        return result;
    }
    return result;
}

// Returns whether the write must be swallowed. `owned` describes the driver's
// addresses per DR index (0 = not owned).
inline dr_write_result write_debug_register(const uint64_t* owned,
                                            uint32_t index, uint64_t live,
                                            uint64_t value) {
    dr_write_result result;
    result.value = value;
    if (index >= 4) {
        result.handled = index == 6 || index == 7;
        return result;
    }
    result.handled = true;
    if (owned && owned[index] != 0 && value != owned[index]) {
        // The guest is trying to move or clear a driver breakpoint.
        result.swallowed = true;
        return result;
    }
    return result;
}

}  // namespace blook::policy