// External-process software-breakpoint hooks (see swbreak.hpp).
#include "swbreak.hpp"

#include "driver/hooks.hpp"
#include "hv.h"

namespace hv::swbreak {
namespace {
constexpr size_t capacity = 32;

// Read from vm-exit context (no locks, no allocation), written from PASSIVE.
// `id` is published last with an interlocked store and cleared first, which is
// enough for a single writer: a reader either sees a fully populated entry or
// none. The fields other than `id`/`hits` never change while `id` is non-zero.
struct entry {
    volatile uint64_t id{};
    uint64_t token{};
    uint64_t address{};
    uint32_t pid{};
    uint32_t flags{};
    volatile uint32_t hits{};
};
entry entries[capacity];
KSPIN_LOCK lock{};
uint32_t next_id{1};

entry* find_by_address(uint64_t address) {
    for (auto& item : entries) {
        if (item.id && item.address == address)
            return &item;
    }
    return nullptr;
}

entry* find_by_id(uint64_t id) {
    for (auto& item : entries) {
        if (item.id == id)
            return &item;
    }
    return nullptr;
}
}  // namespace

NTSTATUS arm(const arm_request& request, info& out) {
    out = {};
    if (!request.address || !request.pid)
        return STATUS_INVALID_PARAMETER;
    if (request.flags != wire::swbreak_execute &&
        request.flags != wire::swbreak_write)
        return STATUS_INVALID_PARAMETER;
    // A breakpoint has to be reachable by an instruction fetch; a non-canonical
    // address can never fault, and installing it would pin a bogus page.
    if (request.address > 0x00007FFFFFFFFFFFull &&
        request.address < 0xFFFF800000000000ull)
        return STATUS_INVALID_ADDRESS;

    KIRQL old_irql{};
    KeAcquireSpinLock(&lock, &old_irql);
    if (find_by_address(request.address)) {
        KeReleaseSpinLock(&lock, old_irql);
        return STATUS_ALREADY_REGISTERED;
    }
    entry* slot{};
    for (auto& item : entries) {
        if (!item.id) {
            slot = &item;
            break;
        }
    }
    KeReleaseSpinLock(&lock, old_irql);
    if (!slot)
        return STATUS_INSUFFICIENT_RESOURCES;

    // The shadow page is the normal EPT hook machinery with a one-byte patch:
    // the host page copy gets 0xCC, the guest's own view of the page keeps the
    // original bytes.
    uint8_t patch[1] = {0xCC};
    uint64_t hook_id{};
    const auto status = blook::install_hook(
        request.pid, request.token, reinterpret_cast<void*>(request.address),
        patch, sizeof(patch), hook_id);
    if (!NT_SUCCESS(status))
        return status;

    slot->token = request.token;
    slot->address = request.address;
    slot->pid = request.pid;
    slot->flags = request.flags;
    slot->hits = 0;
    const auto id = (static_cast<uint64_t>(request.pid) << 32) | next_id++;
    InterlockedExchange64(
        reinterpret_cast<volatile LONG64*>(&slot->id),
        static_cast<LONG64>(id));

    out.id = id;
    out.hits = 0;
    out.state = 1;
    return STATUS_SUCCESS;
}

NTSTATUS disarm(const arm_request& request, info& out) {
    out = {};
    if (!request.address || !request.pid)
        return STATUS_INVALID_PARAMETER;
    KIRQL old_irql{};
    KeAcquireSpinLock(&lock, &old_irql);
    auto* item = find_by_address(request.address);
    if (!item || item->token != request.token || item->pid != request.pid) {
        KeReleaseSpinLock(&lock, old_irql);
        return STATUS_NOT_FOUND;
    }
    const auto id = item->id;
    const auto hits = item->hits;
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&item->id), 0);
    item->token = 0;
    item->address = 0;
    item->pid = 0;
    KeReleaseSpinLock(&lock, old_irql);

    blook::remove_owned_hook(id, request.token);
    out.id = id;
    out.hits = hits;
    out.state = 0;
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
    const auto hits = item->hits;
    InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&item->id), 0);
    item->token = 0;
    item->address = 0;
    item->pid = 0;
    KeReleaseSpinLock(&lock, old_irql);

    blook::remove_owned_hook(id, token);
    out.id = id;
    out.hits = hits;
    out.state = 0;
    return STATUS_SUCCESS;
}

NTSTATUS query(const arm_request& request, info& out) {
    out = {};
    KIRQL old_irql{};
    KeAcquireSpinLock(&lock, &old_irql);
    auto* item = find_by_address(request.address);
    if (!item || item->token != request.token) {
        KeReleaseSpinLock(&lock, old_irql);
        return STATUS_NOT_FOUND;
    }
    out.id = item->id;
    out.hits = item->hits;
    out.state = 1;
    KeReleaseSpinLock(&lock, old_irql);
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

bool breakpoint_hit(uint64_t int3_address, uint64_t& address, uint64_t& id) {
    for (auto& item : entries) {
        if (item.id && item.address == int3_address) {
            id = item.id;
            address = item.address;
            InterlockedIncrement(
                reinterpret_cast<volatile LONG*>(&item.hits));
            return true;
        }
    }
    return false;
}
}  // namespace hv::swbreak
