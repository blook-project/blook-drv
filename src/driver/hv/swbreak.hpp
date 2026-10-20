#pragma once
#include <ntifs.h>

#include "blook/drv/wire.hpp"

namespace hv {
struct vcpu;
}

// External-process EPT software-breakpoint hooks.
//
// The hook itself is the existing EPT shadow-page mechanism: the target process
// executes a page whose shadow copy has 0xCC at the breakpoint address while
// every guest *read* of that page still returns the original bytes (so the
// target cannot discover the hook by comparing its own memory). What this module
// adds is the breakpoint semantic on top:
//
//   1. the shadow page holds 0xCC at the breakpoint; the CPU raises #BP (#BP is
//      a trap, so the RIP the processor reports is already one byte past it);
//   2. the #BP VM-exit finds the entry for RIP-1, counts the hit and rewinds
//      the guest RIP to the breakpoint address;
//   3. exit-handlers switches this logical processor to the *original* view of
//      the page (the same call-original window the EPT hooks use) and sets the
//      trap flag, so the original instruction executes exactly once from the
//      real bytes;
//   4. the single-step #DB VM-exit drops the original view again and resumes at
//      RIP + instruction length, where the shadow page is back in effect.
//
// Step 3/4 is MTF (monitor trap flag) when the processor exposes it and
// trap-flag emulation otherwise (a nested host frequently masks MTF). Both are
// transparent to the guest: TF is restored to its previous value, and the #DB
// never reaches the target's exception handlers.
namespace hv::swbreak {

struct arm_request {
    uint32_t pid{};
    uint32_t flags{wire::swbreak_execute};
    uint64_t address{};
    uint64_t token{};
};

struct info {
    uint64_t id{};
    uint32_t hits{};
    uint32_t state{};  // 0 = gone, 1 = armed
};

// Installs the shadow page with 0xCC at `address` for `pid`. PASSIVE_LEVEL.
NTSTATUS arm(const arm_request& request, info& out);
// Removes the entry that belongs to `token` at (`pid`, `address`).
NTSTATUS disarm(const arm_request& request, info& out);
// Removes by id, only when the caller owns it.
NTSTATUS disarm_id(uint64_t id, uint64_t token, info& out);
NTSTATUS query(const arm_request& request, info& out);
uint32_t count();

// VM-exit side (root mode: no allocation, no kernel API calls, bounded work).
// `guest_rip` is the RIP the processor left in the VMCS (one past 0xCC). On a
// hit fills `address` (the breakpoint address the caller must rewind RIP to)
// and `id`, and returns true.
bool breakpoint_hit(uint64_t guest_rip, uint64_t& address, uint64_t& id);

}  // namespace hv::swbreak
