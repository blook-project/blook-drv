#pragma once
#include <ntifs.h>

#include "blook/drv/wire.hpp"

namespace hv {
struct vcpu;
}

// External-process hardware-breakpoint hooks and debug-register hiding.
//
// A hardware breakpoint is a per-thread property: DR0-DR3 hold the addresses
// and DR7 the control bits. The driver cannot silently write another thread's
// DRs from kernel mode (no such kernel API exists), so arming is done the same
// way a debugger does it - the *client* calls SetThreadContext on the target
// thread. The kernel then owns everything a scanner would look at:
//
//   - `arm` records the breakpoint as belonging to this driver and to the
//     session that asked for it, so a #DB can be attributed without trusting
//     guest state;
//   - `mov_dr_exiting` intercepts every `MOV DRn`: reads of DR0-DR7 are
//     answered from the driver's shadow of what the guest should see (our
//     breakpoints are simply not there), and writes that would disable one of
//     our breakpoints are swallowed;
//   - exception bitmap bit 1 turns #DB into a VM-exit, so the hit is counted
//   and
//     the exception never reaches the target's own debugger/fault handlers;
//   - the thread-context path (`NtGetContextThread`/`NtSetContextThread`) is
//     sanitised by hide/nt.cc on top of this module, because that is the path
//     every user-mode scanner actually uses.
namespace hv::hwbreak {

struct arm_request {
    uint32_t pid{};
    uint32_t tid{};
    uint32_t dr_index{};
    uint32_t access{};
    uint32_t length{};
    uint32_t flags{};
    uint64_t address{};
    uint64_t token{};
};

struct info {
    uint64_t id{};
    uint32_t dr_index{};
    uint32_t hits{};
    uint32_t state{};
    uint32_t hidden{};
};

struct sanitized {
    uint64_t dr[4]{};
    uint64_t dr6{};
    uint64_t dr7{};
    uint32_t armed{};
    uint32_t hits{};
    uint32_t leaks_blocked{};
};

NTSTATUS arm(const arm_request& request, info& out);
NTSTATUS disarm(const arm_request& request, info& out);
NTSTATUS disarm_id(uint64_t id, uint64_t token, info& out);
NTSTATUS query(uint64_t id, uint64_t token, info& out);
// The sanitised view the guest can see (nothing while hiding is on).
NTSTATUS query_view(uint32_t pid, uint32_t tid, sanitized& out);
uint32_t count();

// Enables the VMX controls this module needs (mov_dr_exiting + #DB bitmap bit).
// Called once from hv::start() before the first VMCS is written.
void prepare_controls();

// VM-exit side. `dr_index` is 0..7 for DR0-DR7.
// Returns true when the access was handled here and the guest must not read the
// real register; `value` carries the sanitised result for reads.
bool dr_read(vcpu* cpu, uint32_t dr_index, uint64_t& value);
// Returns true when the write must not reach the guest's DR registers.
bool dr_write(vcpu* cpu, uint32_t dr_index, uint64_t value);
// #DB was raised. Returns true when it belongs to a driver breakpoint; `id`
// names the entry.
bool debug_hit(uint64_t dr6, uint64_t& id);
// Called after a handled #DB so the status bits we consumed are cleared before
// the guest can see them again.
void consume_status(vcpu* cpu, uint64_t id);

}  // namespace hv::hwbreak
