#pragma once
#include <stddef.h>

#include "policy/integer.hpp"

// Fixed-width, pointer-free payload ABI carried over blook-kchannel.
//
// There is no device object and no IOCTL path: every request below is the
// payload of one kchannel CALL, its opcode is the kchannel application opcode
// listed next to it, and every reply is the payload of the matching kchannel
// REPLY. The only adapter between this ABI and kchannel lives in
// src/ipc/kchannel_adapter.cc (kernel) and src/ipc/kchannel_client.cc (user);
// nothing else in the project touches a kchannel API directly.
//
// Page queries accept virtual addresses as numeric lookup keys, never pointers
// to dereference; physical addresses/PFNs cannot be supplied for installation.
namespace wire {

// Application opcode range reserved by blook-kchannel for its clients
// (kc_msg_header.opcode >= 0x8000). One opcode per message type.
enum class op : uint16_t {
    ping = 0x8001,
    get_version = 0x8002,
    enable = 0x8003,
    install = 0x8004,
    remove = 0x8005,
    refresh = 0x8006,
    query = 0x8007,
    hide = 0x8008,
    scrub = 0x8009,
    stats = 0x800A,
    probe = 0x800B,
    watch = 0x800C,
    dump = 0x800D,
    query_page = 0x800E,
    configuration = 0x800F,
    features = 0x8010,
    // Hides the driver itself: PsLoadedModuleList unlink, object-directory
    // unlink of the device, registry service trace cleanup, and reports what
    // remained visible before/after.
    hide_self = 0x8011,
    // External-process software-breakpoint hook (int3 shadow + #BP VM-exit).
    swbreak_arm = 0x8012,
    swbreak_disarm = 0x8013,
    swbreak_query = 0x8014,
    // External-process hardware-breakpoint hook (DR0-DR3 + #DB / MOV DR).
    hwbreak_arm = 0x8015,
    hwbreak_disarm = 0x8016,
    hwbreak_query = 0x8017,
    // Anti-detection state and per-check results (VMAware-style).
    detect_probe = 0x8018,
    // Nested-virtualisation capability report (VMware guest adaptation).
    hv_info = 0x8019,
    // Artifact scan: enumerates whatever traces a detector would look for.
    trace_scan = 0x801A,

    // Events emitted by the kernel (kchannel EVENT direction, not CALLs).
    event_hook_hit = 0x8101,
    event_break_hit = 0x8102,
};

inline constexpr uint16_t opcode(op value) noexcept {
    return static_cast<uint16_t>(value);
}

inline constexpr uint32_t abi_version = 7;

struct Header {
    uint32_t version{abi_version};
    uint32_t size{};
};

struct PingRequest {
    Header header{};
    uint32_t magic{};
    static constexpr uint32_t kMagic = 0x424c4f4b;
};
struct PingResponse {
    uint32_t magic{}, status{};
    static constexpr uint32_t kMagic = 0x4b4f4c42, kStatusOk = 0;
};
struct VersionInfo {
    uint16_t major, minor, patch, reserved;
};
inline constexpr VersionInfo kDriverVersion{4, 0, 0, 0};

// Diagnostic counters for the user-mode hook path. Purely observational: the
// numbers say which branch a page access took, which is the only way to tell
// "the hook never fired" apart from "the page was never fetched".
struct StatsRequest {
    Header header{};
};
// A hook that never fires has two completely different explanations and only
// the driver can tell them apart:
//  * exit_reasons[48] (EPT violation) stays zero -> the fetch never left guest
//    mode, so no EPT entry was consulted at all;
//  * the per-processor install masks say whether the entry was published on
//    every processor in the first place;
//  * armed_entries_verified counts the EPT entries that were read back as
//    "present, writable, not executable" right after they were written.
inline constexpr unsigned stats_exit_reason_slots = 80;
inline constexpr unsigned stats_cpu_mask_words = 4;
inline constexpr unsigned stats_hook_rows = 16;

struct StatsHookRow {
    uint64_t target{};
    uint64_t pfn{};
    uint64_t address_space{};
    uint64_t execute_hits{};
    uint64_t shadow_mapped{};
    uint64_t identity_mismatches{};
    uint32_t id{};
    uint32_t domain{};
    uint32_t active{};
    uint32_t reserved{};
};

struct StatsResponse {
    Header header{};
    uint64_t execute_violations{};
    uint64_t data_violations{};
    uint64_t window_open{};
    uint64_t identity_ok{};
    uint64_t identity_mismatch{};
    uint64_t identity_failed{};
    uint64_t internal_entry{};
    uint64_t shadow_mapped{};
    uint64_t original_step{};
    uint64_t unowned_group{};

    uint64_t exit_reasons[stats_exit_reason_slots]{};
    uint64_t vcpu_count{};
    uint64_t invept_calls{};
    uint64_t invept_error{};
    uint64_t ept_misconfig{};
    uint64_t install_rounds{};
    uint64_t install_ok_cpus{};
    uint64_t install_fail_cpus{};
    uint64_t install_ok_mask[stats_cpu_mask_words]{};
    uint64_t install_fail_mask[stats_cpu_mask_words]{};
    uint64_t armed_entries_verified{};
    uint64_t armed_entries_wrong{};
    uint64_t hook_rows{};
    StatsHookRow hooks[stats_hook_rows]{};
};
static_assert(sizeof(StatsResponse) < 4096);

struct ProbeRequest {
    Header header{};
    uint64_t address{};
};
struct ProbeResponse {
    Header header{};
    uint64_t cr3{};
    uint64_t physical{};  // MmGetPhysicalAddress(address)
    uint64_t pid{};
    uint64_t peb{};
    uint64_t locked_pfn{};  // the way prepare_hook resolves the page
    uint64_t locked_status{};
    uint64_t kernel_physical{};  // MmGetPhysicalAddress(&g_stats): does it work
                                 // here at all
};

struct EnableRequest {
    Header header{};
};
// `flags` selects what happens on a hook hit:
//   install_flag_read_hooked    - reserved: the driver keeps the original bytes
//                                 visible to reads by design (so a target
//                                 cannot find a hook by comparing its own
//                                 memory) and rejects this flag with
//                                 KC_ERR_UNSUPPORTED
//   install_flag_once          - disarm after the first hit
//   install_flag_swbreak       - install as an int3 software breakpoint: the
//                                 shadow page holds 0xCC instead of `bytes`,
//                                 the #BP VM-exit calls the kernel handler,
//                                 and the original instruction is
//                                 single-stepped (MTF) with the original byte
//                                 restored
inline constexpr uint32_t install_flag_read_hooked = 1;
inline constexpr uint32_t install_flag_once = 2;
inline constexpr uint32_t install_flag_swbreak = 4;
struct InstallRequest {
    Header header{};
    uint32_t pid{};
    uint32_t flags{};
    uint64_t target{};
    uint32_t length{};
    uint32_t reserved{};
    uint8_t bytes[64]{};
};
struct InstallResponse {
    uint64_t id{};
};
struct HookRequest {
    Header header{};
    uint64_t id{};
};
// enable_hide: 0 = deactivate, 1 = activate, 2 = pin the given pid to a role,
// 3 = unpin it. Roles are the same ones the image-name policy uses.
inline constexpr uint32_t hide_role_tool = 1;
inline constexpr uint32_t hide_role_target = 2;
// Window hides are a separate switch because they patch win32k: on a build
// where the win32kfull export table cannot be resolved they are simply left
// off instead of guessing.
inline constexpr uint32_t hide_windows_on = 4;
inline constexpr uint32_t hide_windows_off = 5;
struct HideRequest {
    Header header{};
    uint32_t enable_hide{};
    uint32_t pid{};
    uint32_t role{};
    uint32_t reserved{};
};
// scrub flags: bit 0 = PEB flags, bit 1 = heap flags. Hardware breakpoints are
// covered by the NtGetContextThread hook rather than by rewriting a context.
inline constexpr uint32_t scrub_peb = 1;
inline constexpr uint32_t scrub_heap = 2;
inline constexpr uint32_t scrub_all = scrub_peb | scrub_heap;
struct ScrubRequest {
    Header header{};
    uint32_t pid{};
    uint32_t flags{};
};

// `address`, `dump_base` and `dump_size` describe the watched address and the
// range copied out on a hit. `base` is added to the first two, so a caller
// can think in (module base, RVA) instead of absolute addresses. Watches are
// one-shot; a hit leaves the dump fetchable until the watch is disarmed (or
// the session dies).
inline constexpr uint32_t watch_arm = 1;
inline constexpr uint32_t watch_disarm = 2;
struct WatchRequest {
    Header header{};
    uint64_t address{};
    uint64_t base{};
    uint64_t dump_base{};
    uint64_t dump_size{};  // capped by blook::max_dump (16 MiB)
    uint64_t id{};         // disarm input
    uint32_t pid{};        // 0 = the calling process
    uint32_t action{};     // watch_arm / watch_disarm
};
struct WatchResponse {
    uint64_t id{};
};
// Chunks per fetch: the same request is repeated with a growing `offset`
// until `total` bytes have been read.
inline constexpr uint32_t dump_chunk_size = 40960;
struct DumpRequest {
    Header header{};
    uint64_t id{};
    uint64_t offset{};
    uint32_t length{};  // <= dump_chunk_size
    uint32_t reserved{};
};
struct DumpResponse {
    Header header{};
    uint32_t state{};  // blook::watch_pending / blook::watch_hit
    uint32_t copied{};
    uint64_t total{};
    uint64_t hit_rip{};
    uint64_t hit_cr3{};
    uint8_t data[dump_chunk_size]{};
};
// ABI v7 query. Logical 4 KiB virtual pages, never physical pages.
// User counts and rows include ONLY hooks owned by the calling session, even
// for another PID. Kernel queries are counts-only: no ids or addresses leave
// the registry. pid=0 means caller for user, and is required for kernel.
inline constexpr uint32_t page_hook_capacity = 64;
inline constexpr uint32_t page_domain_user = 1;
inline constexpr uint32_t page_domain_kernel = 2;
inline constexpr uint32_t page_query_counts_only = 1;
struct QueryPageRequest {
    Header header{};
    uint64_t address{};  // any byte in the virtual page; never dereferenced
    uint32_t pid{};
    uint32_t domain{};  // explicit page_domain_user / page_domain_kernel
    uint32_t reserved{};
    uint32_t reserved2{};
};
struct PageHookRow {
    uint64_t id{};
    uint64_t target{};
    uint32_t pid{};
    uint32_t domain{};
    uint32_t dormant{};
    uint32_t armed{};  // last successful publication AND backend running
};
struct QueryPageResponse {
    Header header{};
    uint64_t page_base{};  // zero for counts-only kernel queries
    uint32_t pid{};
    uint32_t domain{};
    uint32_t registered_count{};  // includes prepared and dormant hooks
    uint32_t armed_count{};
    uint32_t dormant_count{};
    uint32_t entry_count{};
    uint32_t flags{};
    uint32_t reserved{};
    uint32_t
        logical_count{};  // known built-in handler bindings, including disabled
    uint32_t enabled_logical_count{};  // effective bindings on armed entries
    uint32_t
        opaque_count{};  // raw patches: their process-local chains are unknown
    uint32_t reserved2{};
    PageHookRow entries[page_hook_capacity]{};
};
static_assert(sizeof(QueryPageRequest) == 32 && alignof(QueryPageRequest) == 8);
static_assert(offsetof(QueryPageRequest, address) == 8);
static_assert(offsetof(QueryPageRequest, pid) == 16);
static_assert(offsetof(QueryPageRequest, domain) == 20);
static_assert(offsetof(QueryPageRequest, reserved) == 24);
static_assert(offsetof(QueryPageRequest, reserved2) == 28);
static_assert(sizeof(PageHookRow) == 32 && alignof(PageHookRow) == 8);
static_assert(offsetof(PageHookRow, target) == 8);
static_assert(offsetof(PageHookRow, pid) == 16);
static_assert(offsetof(PageHookRow, domain) == 20);
static_assert(offsetof(PageHookRow, dormant) == 24);
static_assert(offsetof(PageHookRow, armed) == 28);
static_assert(sizeof(QueryPageResponse) == 2112);
static_assert(offsetof(QueryPageResponse, page_base) == 8);
static_assert(offsetof(QueryPageResponse, registered_count) == 24);
static_assert(offsetof(QueryPageResponse, entries) == 64);
static_assert(offsetof(QueryPageResponse, logical_count) == 48);
static_assert(offsetof(QueryPageResponse, enabled_logical_count) == 52);
static_assert(offsetof(QueryPageResponse, opaque_count) == 56);
static_assert(offsetof(QueryPageResponse, reserved2) == 60);

struct ConfigurationRequest {
    Header header{};
    uint32_t
        reload{};  // 0=query, 1=reload registered path (administrators only)
    uint32_t reserved{};
};
struct ConfigurationResponse {
    Header header{};
    uint64_t generation{};
    uint64_t features{};
    uint32_t allow_users{};
    uint32_t restart_required{};
    int32_t last_status{};
    uint32_t error_line{};
};
struct FeaturesRequest {
    Header header{};
    uint32_t action{};  // 0=query, 1=set one logical feature
    uint32_t id{};
    uint32_t enabled{};
    uint32_t reserved{};
};
struct FeaturesResponse {
    Header header{};
    uint64_t desired{}, effective{}, unsupported{};
    int32_t last_status{};
    uint32_t reserved{};
};
static_assert(sizeof(ConfigurationRequest) == 16);
static_assert(sizeof(ConfigurationResponse) == 40);
static_assert(sizeof(FeaturesRequest) == 24);
static_assert(sizeof(FeaturesResponse) == 40);

struct QueryResponse {
    uint32_t version{}, running{}, enabled{}, hooks{};
    uint32_t hidden{};
    uint32_t abi{};
    int32_t backend_status{};
    // Number of win32k window hooks that are actually installed, so a machine
    // where the win32kfull exports could not be resolved is visible instead of
    // silently hiding nothing.
    uint32_t window_hooks{};
    // Nested-virtualisation and artefact state: see hv_flag below.
    uint32_t hv_flags{};
    uint32_t swbreak_count{};
    uint32_t hwbreak_count{};
    uint32_t self_hidden{};
};

// hv_flags bits reported by QueryResponse and HvInfoResponse.
inline constexpr uint32_t hv_flag_running = 1u << 0;
inline constexpr uint32_t hv_flag_nested = 1u
                                           << 1;  // running under a hypervisor
inline constexpr uint32_t hv_flag_vmware = 1u << 2;  // nested host is VMware
inline constexpr uint32_t hv_flag_hyperv = 1u << 3;  // nested host is Hyper-V
inline constexpr uint32_t hv_flag_no_vp_assist = 1u << 4;
inline constexpr uint32_t hv_flag_no_preemption_timer = 1u << 5;
inline constexpr uint32_t hv_flag_no_ept_ad = 1u << 6;
inline constexpr uint32_t hv_flag_no_vpid = 1u << 7;
inline constexpr uint32_t hv_flag_no_invpcid = 1u << 8;
inline constexpr uint32_t hv_flag_no_xsaves = 1u << 9;
inline constexpr uint32_t hv_flag_no_rdtscp = 1u << 10;
inline constexpr uint32_t hv_flag_tsc_scaling = 1u << 11;

// HideSelfRequest flags: what to clean up. All flags are on by default; the
// response reports what was actually visible before the cleanup ran.
inline constexpr uint32_t selfhide_module_list = 1;
inline constexpr uint32_t selfhide_device = 2;
inline constexpr uint32_t selfhide_registry = 4;
inline constexpr uint32_t selfhide_pool_tag = 8;
inline constexpr uint32_t selfhide_all = 0xF;
struct HideSelfRequest {
    Header header{};
    uint32_t flags{selfhide_all};
    uint32_t reserved{};
};
struct HideSelfResponse {
    Header header{};
    uint32_t module_list_found{};     // before
    uint32_t module_list_unlinked{};  // after
    uint32_t device_found{};
    uint32_t device_unlinked{};
    uint32_t registry_found{};
    uint32_t registry_removed{};
    uint32_t pool_tags_rewritten{};
    uint32_t reserved{};
};

// External-process software-breakpoint hook.
inline constexpr uint32_t swbreak_execute = 1;  // int3 on execute
inline constexpr uint32_t swbreak_write = 2;    // trap on write (watchpoint)
struct SwBreakArmRequest {
    Header header{};
    uint32_t pid{};
    uint32_t flags{swbreak_execute};
    uint64_t address{};
    uint32_t id{};  // disarm input (0 for arm)
    uint32_t reserved{};
};
struct SwBreakResponse {
    Header header{};
    uint64_t id{};
    uint32_t hit_count{};
    uint32_t state{};
};

// External-process hardware-breakpoint hook: DR0-DR3 armed for one thread.
// `dr_index` is 0..3, `access` is the DR7 RW encoding, `length` the LEN
// encoding.
inline constexpr uint32_t hwbreak_execute = 0;     // DR7 RW=00
inline constexpr uint32_t hwbreak_write = 1;       // DR7 RW=01
inline constexpr uint32_t hwbreak_io = 2;          // DR7 RW=10
inline constexpr uint32_t hwbreak_read_write = 3;  // DR7 RW=11
inline constexpr uint32_t hwbreak_len_1 = 0;
inline constexpr uint32_t hwbreak_len_2 = 1;
inline constexpr uint32_t hwbreak_len_8 = 2;
inline constexpr uint32_t hwbreak_len_4 = 3;
struct HwBreakArmRequest {
    Header header{};
    uint32_t pid{};
    uint32_t tid{};
    uint32_t dr_index{};
    uint32_t access{};
    uint32_t length{};
    uint32_t flags{};
    uint64_t address{};
    uint32_t id{};
    uint32_t reserved{};
};
struct HwBreakResponse {
    Header header{};
    uint64_t id{};
    uint32_t dr_index{};
    uint32_t hit_count{};
    uint32_t state{};
    uint32_t hidden{};
};
// Sanitised debug-register view: what the guest is told about DR6/DR7 when it
// reads them through MOV DR, GetThreadContext or XSAVE.
struct HwBreakQueryRequest {
    Header header{};
    uint32_t pid{};
    uint32_t tid{};
};
struct HwBreakQueryResponse {
    Header header{};
    uint64_t dr0{}, dr1{}, dr2{}, dr3{};
    uint64_t dr6{}, dr7{};
    uint32_t armed{};
    uint32_t hits{};
    uint32_t leaks_blocked{};
    uint32_t reserved{};
};

// Anti-detection probe. Each bit in `checks` asks for one VMAware-style test;
// the driver answers with its own state (and whether the check can be answered
// at all on this CPU / nested host).
inline constexpr uint32_t detect_check_cpuid_hypervisor_bit = 1u << 0;
inline constexpr uint32_t detect_check_cpuid_vendor = 1u << 1;
inline constexpr uint32_t detect_check_cpuid_features = 1u << 2;
inline constexpr uint32_t detect_check_cpuid_leaf_max = 1u << 3;
inline constexpr uint32_t detect_check_msr_vmx = 1u << 4;
inline constexpr uint32_t detect_check_tsc = 1u << 5;
inline constexpr uint32_t detect_check_rdtscp = 1u << 6;
inline constexpr uint32_t detect_check_aperf_mperf = 1u << 7;
inline constexpr uint32_t detect_check_exception = 1u << 8;
inline constexpr uint32_t detect_check_memory_latency = 1u << 9;
inline constexpr uint32_t detect_check_all = 0x3FF;
struct DetectProbeRequest {
    Header header{};
    uint32_t checks{detect_check_all};
    uint32_t rounds{};   // timing loops; 0 = default
    uint64_t address{};  // optional memory-latency probe address
};
struct DetectProbeResponse {
    Header header{};
    uint32_t checks_run{};
    uint32_t checks_failed{};
    uint64_t flags{};  // per-check failure bits, same encoding as `checks`
    uint64_t nested_host_vendor{};  // raw CPUID 0x40000000 EBX/ECX/EDX
    uint64_t tsc_offset_ticks{};
    uint64_t exit_latency_ticks{};
    uint32_t masked_msrs{};
    uint32_t vmx_msr_reads_blocked{};
};

struct HvInfoRequest {
    Header header{};
};
struct HvInfoResponse {
    Header header{};
    uint32_t flags{};
    uint32_t vcpu_count{};
    uint32_t nested_vendor_leaf_max{};
    uint32_t nested_vendor[4]{};  // CPUID 0x40000000 as seen inside the guest
    uint64_t vmx_basic{};         // IA32_VMX_BASIC as seen by root mode
    uint64_t nested_cr4_fixed0{};
    uint64_t nested_cr4_fixed1{};
    uint64_t capabilities{};  // per-feature support as probed at bring-up
    uint32_t degradation_reasons{};
    uint32_t reserved{};
};

// Artifact scan: names of the objects a detector enumerates.
inline constexpr uint32_t trace_device = 1u << 0;
inline constexpr uint32_t trace_symlink = 1u << 1;
inline constexpr uint32_t trace_service_key = 1u << 2;
inline constexpr uint32_t trace_module_list = 1u << 3;
inline constexpr uint32_t trace_pool_tag = 1u << 4;
inline constexpr uint32_t trace_imports = 1u << 5;
inline constexpr uint32_t trace_all = 0x3F;
struct TraceScanRequest {
    Header header{};
    uint32_t what{trace_all};
    uint32_t reserved{};
};
struct TraceScanResponse {
    Header header{};
    uint32_t found{};  // trace_* bits still visible
    uint32_t checked{};
    uint64_t module_base{};
    uint64_t module_size{};
    uint32_t pool_tag[8]{};  // the tag currently used by the driver's pool
    uint32_t reserved{};
};

static_assert(sizeof(WatchRequest) == 56 && alignof(WatchRequest) == 8);
static_assert(offsetof(WatchRequest, header) == 0);
static_assert(offsetof(WatchRequest, address) == 8);
static_assert(offsetof(WatchRequest, base) == 16);
static_assert(offsetof(WatchRequest, dump_base) == 24);
static_assert(offsetof(WatchRequest, dump_size) == 32);
static_assert(offsetof(WatchRequest, id) == 40);
static_assert(offsetof(WatchRequest, pid) == 48);
static_assert(offsetof(WatchRequest, action) == 52);

static_assert(sizeof(WatchResponse) == 8 && alignof(WatchResponse) == 8);
static_assert(offsetof(WatchResponse, id) == 0);

static_assert(sizeof(DumpRequest) == 32 && alignof(DumpRequest) == 8);
static_assert(offsetof(DumpRequest, header) == 0);
static_assert(offsetof(DumpRequest, id) == 8);
static_assert(offsetof(DumpRequest, offset) == 16);
static_assert(offsetof(DumpRequest, length) == 24);
static_assert(offsetof(DumpRequest, reserved) == 28);

static_assert(sizeof(DumpResponse) == 8 + 4 + 4 + 8 + 8 + 8 + dump_chunk_size &&
              alignof(DumpResponse) == 8);
static_assert(offsetof(DumpResponse, header) == 0);
static_assert(offsetof(DumpResponse, state) == 8);
static_assert(offsetof(DumpResponse, copied) == 12);
static_assert(offsetof(DumpResponse, total) == 16);
static_assert(offsetof(DumpResponse, hit_rip) == 24);
static_assert(offsetof(DumpResponse, hit_cr3) == 32);
static_assert(offsetof(DumpResponse, data) == 40);

// ABI v7 layout: fail compilation rather than silently changing the wire
// format.
static_assert(sizeof(Header) == 8 && alignof(Header) == 4);
static_assert(offsetof(Header, version) == 0);
static_assert(offsetof(Header, size) == 4);

static_assert(sizeof(PingRequest) == 12 && alignof(PingRequest) == 4);
static_assert(offsetof(PingRequest, header) == 0);
static_assert(offsetof(PingRequest, magic) == 8);

static_assert(sizeof(PingResponse) == 8 && alignof(PingResponse) == 4);
static_assert(offsetof(PingResponse, magic) == 0);
static_assert(offsetof(PingResponse, status) == 4);

static_assert(sizeof(VersionInfo) == 8 && alignof(VersionInfo) == 2);
static_assert(offsetof(VersionInfo, major) == 0);
static_assert(offsetof(VersionInfo, minor) == 2);
static_assert(offsetof(VersionInfo, patch) == 4);
static_assert(offsetof(VersionInfo, reserved) == 6);

static_assert(sizeof(EnableRequest) == 8 && alignof(EnableRequest) == 4);
static_assert(offsetof(EnableRequest, header) == 0);

static_assert(sizeof(InstallRequest) == 96 && alignof(InstallRequest) == 8);
static_assert(offsetof(InstallRequest, header) == 0);
static_assert(offsetof(InstallRequest, pid) == 8);
static_assert(offsetof(InstallRequest, flags) == 12);
static_assert(offsetof(InstallRequest, target) == 16);
static_assert(offsetof(InstallRequest, length) == 24);
static_assert(offsetof(InstallRequest, reserved) == 28);
static_assert(offsetof(InstallRequest, bytes) == 32);

static_assert(sizeof(InstallResponse) == 8 && alignof(InstallResponse) == 8);
static_assert(offsetof(InstallResponse, id) == 0);

static_assert(sizeof(HookRequest) == 16 && alignof(HookRequest) == 8);
static_assert(offsetof(HookRequest, header) == 0);
static_assert(offsetof(HookRequest, id) == 8);

static_assert(sizeof(HideRequest) == 24 && alignof(HideRequest) == 4);
static_assert(offsetof(HideRequest, header) == 0);
static_assert(offsetof(HideRequest, enable_hide) == 8);
static_assert(offsetof(HideRequest, pid) == 12);
static_assert(offsetof(HideRequest, role) == 16);
static_assert(offsetof(HideRequest, reserved) == 20);

static_assert(sizeof(ScrubRequest) == 16 && alignof(ScrubRequest) == 4);
static_assert(offsetof(ScrubRequest, header) == 0);
static_assert(offsetof(ScrubRequest, pid) == 8);
static_assert(offsetof(ScrubRequest, flags) == 12);

static_assert(sizeof(QueryResponse) == 48 && alignof(QueryResponse) == 4);
static_assert(offsetof(QueryResponse, version) == 0);
static_assert(offsetof(QueryResponse, running) == 4);
static_assert(offsetof(QueryResponse, enabled) == 8);
static_assert(offsetof(QueryResponse, hooks) == 12);
static_assert(offsetof(QueryResponse, hidden) == 16);
static_assert(offsetof(QueryResponse, abi) == 20);
static_assert(offsetof(QueryResponse, backend_status) == 24);
static_assert(offsetof(QueryResponse, window_hooks) == 28);
static_assert(offsetof(QueryResponse, hv_flags) == 32);
static_assert(offsetof(QueryResponse, swbreak_count) == 36);
static_assert(offsetof(QueryResponse, hwbreak_count) == 40);
static_assert(offsetof(QueryResponse, self_hidden) == 44);

static_assert(sizeof(HideSelfRequest) == 16);
static_assert(sizeof(HideSelfResponse) == 40);
static_assert(sizeof(SwBreakArmRequest) == 32);
static_assert(sizeof(SwBreakResponse) == 24);
static_assert(sizeof(HwBreakArmRequest) == 48);
static_assert(sizeof(HwBreakResponse) == 32);
static_assert(sizeof(HwBreakQueryRequest) == 16);
static_assert(sizeof(HwBreakQueryResponse) == 72);
static_assert(sizeof(DetectProbeRequest) == 24);
static_assert(sizeof(DetectProbeResponse) == 56);
static_assert(sizeof(HvInfoRequest) == 8);
static_assert(sizeof(HvInfoResponse) == 80);
static_assert(sizeof(TraceScanRequest) == 16);
static_assert(sizeof(TraceScanResponse) == 72);

namespace detail {
template <class T, class U>
inline constexpr bool same_type = false;
template <class T>
inline constexpr bool same_type<T, T> = true;
}  // namespace detail

// Compile-time check that a type is one of the wire messages. Used by the
// adapter and by the SDK to reject accidental framing of an internal type.
template <class T>
inline constexpr bool is_wire_message =
    detail::same_type<T, PingRequest> || detail::same_type<T, ProbeRequest> ||
    detail::same_type<T, EnableRequest> ||
    detail::same_type<T, InstallRequest> || detail::same_type<T, HookRequest> ||
    detail::same_type<T, HideRequest> || detail::same_type<T, ScrubRequest> ||
    detail::same_type<T, WatchRequest> || detail::same_type<T, DumpRequest> ||
    detail::same_type<T, QueryPageRequest> ||
    detail::same_type<T, ConfigurationRequest> ||
    detail::same_type<T, FeaturesRequest> ||
    detail::same_type<T, HideSelfRequest> ||
    detail::same_type<T, SwBreakArmRequest> ||
    detail::same_type<T, HwBreakArmRequest> ||
    detail::same_type<T, HwBreakQueryRequest> ||
    detail::same_type<T, DetectProbeRequest> ||
    detail::same_type<T, HvInfoRequest> ||
    detail::same_type<T, TraceScanRequest>;

// Exact request types only: a look-alike header does not establish a wire ABI.
// The constraint is a substitution failure rather than a C++20 concept because
// this header is also compiled as C++17 inside the kernel.
template <bool Condition, class T = void>
struct enable_if {};
template <class T>
struct enable_if<true, T> {
    using type = T;
};
template <class T>
using wire_requirement = typename enable_if<is_wire_message<T>>::type;

template <class T, class = wire_requirement<T>>
[[nodiscard]] constexpr T request() noexcept {
    T value{};
    value.header.version = abi_version;
    value.header.size = sizeof(T);
    return value;
}

template <class T, class = wire_requirement<T>>
[[nodiscard]] constexpr bool valid_header(const T& value) noexcept {
    return value.header.version == abi_version &&
           value.header.size == sizeof(T);
}

#if defined(__cplusplus) && __cplusplus >= 202002L
// Host-side tests use the concept form.
template <class T>
concept WireRequest = is_wire_message<T>;
#endif

// Kernel replies are fixed-layout too; the adapter refuses to copy a reply
// whose header does not match its own type (a mismatched reply means the
// adapter and the handler disagree about the wire, and the copy would leak
// uninitialised stack bytes).
template <class T>
[[nodiscard]] constexpr bool valid_reply(const T& value) noexcept {
    return value.header.version == abi_version &&
           value.header.size == sizeof(T);
}
}  // namespace wire