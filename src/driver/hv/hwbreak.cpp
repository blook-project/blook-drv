// External-process hardware-breakpoint hooks and debug-register hiding
// (see hwbreak.hpp for the design).
#include "hwbreak.hpp"

#include <intrin.h>

#include "driver/resources.hpp"
#include "vcpu.h"

namespace hv::hwbreak {
namespace {
constexpr size_t capacity = 32;

struct entry {
    volatile uint64_t id{};
    uint64_t token{};
    uint64_t address{};
    uint32_t pid{};
    uint32_t tid{};
    uint32_t dr_index{};
    uint32_t access{};
    uint32_t length{};
    uint32_t flags{};
    volatile uint32_t hits{};
    volatile uint32_t hidden{};
};
entry entries[capacity];
KSPIN_LOCK lock{};
uint32_t next_id{1};
volatile uint32_t blocked_reads{};
volatile uint32_t blocked_writes{};

entry* find_by_id(uint64_t id) {
    for (auto& item : entries) {
        if (item.id == id)
            return &item;
    }
    return nullptr;
}

// True when this DR index holds one of the driver's breakpoints. The
// comparison is against the live register value, which is what the guest would
// read if the access were not intercepted - that is what makes the value
// "ours" no matter which thread is currently running.
bool register_is_ours(uint32_t dr_index, uint64_t live) {
    if (dr_index > 3)
        return false;
    for (const auto& item : entries) {
        if (item.id && item.dr_index == dr_index && item.address == live)
            return true;
    }
    return false;
}

uint64_t dr7_hidden_bits() {
    uint64_t mask{};
    for (const auto& item : entries) {
        if (!item.id)
            continue;
        const auto index = item.dr_index;
        // L0/L1/L2/L3 enable bits live at 0,2,4,6; the RW/LEN fields for each
        // register follow. Hiding the enable bit is what stops a scanner from
        // even asking the CPU about the address.
        mask |= 1ull << (index * 2);
        mask |= 0xFull << (16 + index * 4);
    }
    return mask;
}

uint64_t read_dr(uint32_t index) {
    switch (index) {
        case 0:
            return __readdr(0);
        case 1:
            return __readdr(1);
        case 2:
            return __readdr(2);
        case 3:
            return __readdr(3);
        case 6:
            return __readdr(6);
        case 7:
            return __readdr(7);
        default:
            return 0;
    }
}

void write_dr(uint32_t index, uint64_t value) {
    switch (index) {
        case 0:
            __writedr(0, value);
            break;
        case 1:
            __writedr(1, value);
            break;
        case 2:
            __writedr(2, value);
            break;
        case 3:
            __writedr(3, value);
            break;
        case 6:
            __writedr(6, value);
            break;
        case 7:
            __writedr(7, value);
            break;
        default:
            break;
    }
}

uint32_t interrupt_flag() {
    return static_cast<uint32_t>(__readeflags() & 0x200);
}
}  // namespace

NTSTATUS arm(const arm_request& request, info& out) {
    out = {};
    if (!request.pid || !request.address || request.dr_index > 3)
        return STATUS_INVALID_PARAMETER;
    if (request.access > wire::hwbreak_read_write ||
        request.length > wire::hwbreak_len_4 ||
        (request.access == wire::hwbreak_io))
        return STATUS_NOT_SUPPORTED;
    // The hardware rejects unaligned addresses for data breakpoints and any
    // access to a register width it cannot watch.
    const uint64_t width = request.length == wire::hwbreak_len_8   ? 8
                           : request.length == wire::hwbreak_len_4 ? 4
                           : request.length == wire::hwbreak_len_2 ? 2
                                                                   : 1;
    if (request.access != wire::hwbreak_execute &&
        (request.address % width) != 0)
        return STATUS_DATATYPE_MISALIGNMENT;
    if (request.access == wire::hwbreak_execute && width != 1)
        return STATUS_INVALID_PARAMETER;

    KIRQL old_irql{};
    KeAcquireSpinLock(&lock, &old_irql);
    entry* slot{};
    for (auto& item : entries) {
        if (item.id && item.pid == request.pid && item.tid == request.tid &&
            item.dr_index == request.dr_index) {
            KeReleaseSpinLock(&lock, old_irql);
            return STATUS_ALREADY_REGISTERED;
        }
        if (!item.id && !slot)
            slot = &item;
    }
    if (!slot) {
        KeReleaseSpinLock(&lock, old_irql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    slot->token = request.token;
    slot->pid = request.pid;
    slot->tid = request.tid;
    slot->dr_index = request.dr_index;
    slot->access = request.access;
    slot->length = request.length;
    slot->flags = request.flags;
    slot->address = request.address;
    slot->hits = 0;
    slot->hidden = 0;
    const auto id = (static_cast<uint64_t>(request.pid) << 32) | next_id++;
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&slot->id),
                          static_cast<LONG64>(id));
    KeReleaseSpinLock(&lock, old_irql);

    out.id = id;
    out.dr_index = request.dr_index;
    out.state = 1;
    return STATUS_SUCCESS;
}

NTSTATUS disarm_id(uint64_t id, uint64_t token, info& out) {
    out = {};
    KIRQL old_irql{};
    KeAcquireSpinLock(&lock, &old_irql);
    auto* item = find_by_id(id);
    if (!item || item->token != token) {
        KeReleaseSpinLock(&lock, old_irql);
        return STATUS_NOT_FOUND;
    }
    const auto index = item->dr_index;
    const auto hits = item->hits;
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&item->id), 0);
    item->token = 0;
    item->address = 0;
    KeReleaseSpinLock(&lock, old_irql);

    // Put the guest's own view of the register back: the driver must not leave
    // a stale breakpoint address behind after a disarm.
    write_dr(index, 0);
    const auto dr7 = read_dr(7) & ~(1ull << (index * 2));
    write_dr(7, dr7);

    out.id = id;
    out.dr_index = index;
    out.hits = hits;
    out.state = 0;
    return STATUS_SUCCESS;
}

NTSTATUS disarm(const arm_request& request, info& out) {
    out = {};
    uint64_t id{};
    for (const auto& item : entries) {
        if (item.id && item.pid == request.pid && item.tid == request.tid &&
            item.dr_index == request.dr_index) {
            id = item.id;
            break;
        }
    }
    if (!id)
        return STATUS_NOT_FOUND;
    return disarm_id(id, request.token, out);
}

NTSTATUS query(uint64_t id, uint64_t token, info& out) {
    out = {};
    KIRQL old_irql{};
    KeAcquireSpinLock(&lock, &old_irql);
    auto* item = find_by_id(id);
    if (!item || item->token != token) {
        KeReleaseSpinLock(&lock, old_irql);
        return STATUS_NOT_FOUND;
    }
    out.id = item->id;
    out.dr_index = item->dr_index;
    out.hits = item->hits;
    out.state = 1;
    out.hidden = item->hidden;
    KeReleaseSpinLock(&lock, old_irql);
    return STATUS_SUCCESS;
}

NTSTATUS query_view(uint32_t pid, uint32_t tid, sanitized& out) {
    out = {};
    KIRQL old_irql{};
    KeAcquireSpinLock(&lock, &old_irql);
    for (const auto& item : entries) {
        if (!item.id || item.pid != pid || (tid && item.tid != tid))
            continue;
        out.armed |= 1u << item.dr_index;
        out.hits += item.hits;
    }
    KeReleaseSpinLock(&lock, old_irql);
    // The registers themselves are exactly what a detector must not see: the
    // sanitised view is all zeroes even for the session that armed them, and
    // the session reads the real state through this structure instead.
    out.leaks_blocked = blocked_reads;
    return STATUS_SUCCESS;
}

uint32_t count() {
    uint32_t total{};
    for (const auto& item : entries) {
        if (item.id)
            ++total;
    }
    return total;
}

bool dr_read(vcpu* cpu, uint32_t dr_index, uint64_t& value) {
    const auto live = read_dr(dr_index);
    switch (dr_index) {
        case 0:
        case 1:
        case 2:
        case 3:
            if (register_is_ours(dr_index, live)) {
                // Our address never leaves the hypervisor.
                value = 0;
                InterlockedIncrement(
                    reinterpret_cast<volatile LONG*>(&blocked_reads));
                return true;
            }
            // Not ours: the guest gets what it actually set.
            cpu->guest_dr[dr_index] = live;
            value = live;
            return true;
        case 6: {
            value = cpu->guest_dr6;
            return true;
        }
        case 7: {
            value = live & ~dr7_hidden_bits();
            cpu->guest_dr7 = value;
            if (value != live)
                InterlockedIncrement(
                    reinterpret_cast<volatile LONG*>(&blocked_reads));
            return true;
        }
        default:
            return false;
    }
}

bool dr_write(vcpu* cpu, uint32_t dr_index, uint64_t value) {
    switch (dr_index) {
        case 0:
        case 1:
        case 2:
        case 3: {
            const auto live = read_dr(dr_index);
            if (register_is_ours(dr_index, live) && value != live) {
                // A write that would move or clear a driver breakpoint is a
                // detection attempt (or a debugger trying to win); swallow it.
                cpu->guest_dr[dr_index] = value;
                InterlockedIncrement(
                    reinterpret_cast<volatile LONG*>(&blocked_writes));
                return true;
            }
            cpu->guest_dr[dr_index] = value;
            write_dr(dr_index, value);
            return true;
        }
        case 6: {
            cpu->guest_dr6 = value;
            write_dr(6, value);
            return true;
        }
        case 7: {
            cpu->guest_dr7 = value;
            // Keep our enables alive: the guest may write DR7 to disable
            // everything, which must not disarm the hypervisor's breakpoints.
            const auto hidden = dr7_hidden_bits();
            const auto live = read_dr(7);
            write_dr(7, (value & ~hidden) | (live & hidden));
            return true;
        }
        default:
            return false;
    }
}

bool debug_hit(uint64_t dr6, uint64_t& id) {
    // A software breakpoint single-step is handled by exit-handlers and never
    // gets here.
    for (uint32_t index = 0; index < 4; ++index) {
        if ((dr6 & (1ull << index)) == 0)
            continue;
        const auto live = read_dr(index);
        for (const auto& item : entries) {
            if (item.id && item.dr_index == index && item.address == live) {
                id = item.id;
                return true;
            }
        }
    }
    return false;
}

void consume_status(vcpu* cpu, uint64_t id) {
    (void)id;
    // Clear the status bits we consumed; DR6 is only meaningful to the guest
    // for breakpoints it owns.
    const auto dr6 = __readdr(6);
    __writedr(6, dr6 & 0xFFF0ull);
    cpu->guest_dr6 = 0;
}

void prepare_controls() {
    // The VMCS control fields are written in vmcs.cpp: `mov_dr_exiting` in the
    // primary processor-based controls and #DB in the exception bitmap. This
    // hook exists so hv::start() has one place to call that documents the
    // dependency, and so a future degraded mode can clear them here.
    (void)interrupt_flag();
}
}  // namespace hv::hwbreak
