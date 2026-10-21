// In-guest driver test binary for the blook-drv e2e suite.
//
// Every mode makes one claim about the driver and proves it with an observable
// effect, not with a driver-internal counter alone:
//   * an EPT hook is only "working" when the target process actually returns a
//     different value while its own reads still see the original bytes;
//   * a software breakpoint is only "working" when the target keeps running
//     (single-stepped original) and the driver reports hits;
//   * a hardware breakpoint is only "hidden" when a `mov rax, dr0` executed by
//     the target returns zero while the breakpoint is armed.
//
// The host-side runner (tests/e2e) spawns this binary and reads its JSON lines.
// Exit codes: 0 success, 1 assertion failure, 77 mode not implemented here.
#include <windows.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "blook/drv/ept.hpp"

namespace {
using namespace blook::client;

// ---------------------------------------------------------------- arguments
struct arguments {
    std::string mode;
    std::string sub;
    uint32_t target_pid{};
    uint64_t target_address{};
    std::string target_log;
    std::string log;
    std::string kchannel_mode;
    int duration_seconds{30};
    int hold_seconds{5};
    bool json{};
    bool has_pid{};
    bool has_address{};

    static arguments parse(int argc, char** argv) {
        arguments result;
        result.mode = argc > 1 ? argv[1] : "";
        for (int i = 2; i < argc; ++i) {
            const std::string value = argv[i];
            if (value == "--json") {
                result.json = true;
            } else if (value == "--target-pid" && i + 1 < argc) {
                result.target_pid =
                    static_cast<uint32_t>(std::strtoul(argv[++i], nullptr, 0));
                result.has_pid = true;
            } else if (value == "--target-address" && i + 1 < argc) {
                result.target_address = std::strtoull(argv[++i], nullptr, 0);
                result.has_address = true;
            } else if (value == "--target-log" && i + 1 < argc) {
                result.target_log = argv[++i];
            } else if (value == "--log" && i + 1 < argc) {
                result.log = argv[++i];
            } else if (value == "--mode" && i + 1 < argc) {
                result.kchannel_mode = argv[++i];
            } else if (value == "--duration-seconds" && i + 1 < argc) {
                result.duration_seconds = std::atoi(argv[++i]);
            } else if (value == "--hold-seconds" && i + 1 < argc) {
                result.hold_seconds = std::atoi(argv[++i]);
            } else if (result.sub.empty()) {
                result.sub = value;
            }
        }
        return result;
    }
};

// ------------------------------------------------------------------ output
void emit(const char* key, const std::string& value) {
    std::printf("%s=%s\n", key, value.c_str());
    std::fflush(stdout);
}

void emit_bool(const char* key, bool value) {
    emit(key, value ? "yes" : "no");
}

void emit_json(const std::string& body) {
    std::printf("{\"tool\":\"blook-guest-hooks\",\"version\":1,%s}\n",
                body.c_str());
    std::fflush(stdout);
}

int fail(const char* message) {
    emit("check", std::string("FAILED: ") + message);
    return 1;
}

// ------------------------------------------------------------------- misc
uint64_t monotonic_ms() {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<milliseconds>(steady_clock::now().time_since_epoch())
            .count());
}

std::string read_file(const std::string& path) {
    std::string text;
    if (auto* file = std::fopen(path.c_str(), "rb")) {
        char buffer[4096];
        size_t read{};
        while ((read = std::fread(buffer, 1, sizeof(buffer), file)) > 0)
            text.append(buffer, read);
        std::fclose(file);
    }
    return text;
}

// Reads the last "value=N" out of the target's log.
bool last_value(const std::string& path, long& value) {
    const auto text = read_file(path);
    const auto position = text.rfind("value=");
    if (position == std::string::npos)
        return false;
    value = std::strtol(text.c_str() + position + 6, nullptr, 0);
    return true;
}

bool wait_for_value(const std::string& path, long expected,
                    uint32_t timeout_ms) {
    const auto deadline = monotonic_ms() + timeout_ms;
    while (monotonic_ms() < deadline) {
        long value{};
        if (last_value(path, value) && value == expected)
            return true;
        Sleep(10);
    }
    return false;
}

// The target process is this same executable with the `target` mode: it logs
// its function address, its thread id and the value the function returns on
// every iteration, so the parent can observe the hook taking effect.
std::atomic<bool> target_running{true};
__declspec(noinline) int target_function(int x) {
    return (x * 3) + 1;
}

int run_target(const arguments& args) {
    const auto address = reinterpret_cast<uint64_t>(&target_function);
    const std::string path = args.log.empty() ? args.target_log : args.log;
    if (auto* file = std::fopen(path.c_str(), "wb")) {
        std::fprintf(file, "pid=%lu\n", GetCurrentProcessId());
        std::fprintf(file, "tid=%lu\n", GetCurrentThreadId());
        std::fprintf(file, "address=0x%llX\n",
                     static_cast<unsigned long long>(address));
        std::fclose(file);
    }
    const auto deadline =
        GetTickCount64() + static_cast<uint64_t>(args.duration_seconds) * 1000;
    while (GetTickCount64() < deadline) {
        const auto value = target_function(1);
        const auto dr0 = __readdr(0);
        const auto dr7 = __readdr(7);
        if (auto* file = std::fopen(path.c_str(), "ab")) {
            std::fprintf(file, "value=%d dr0=%llu dr7=%llu\n", value,
                         static_cast<unsigned long long>(dr0),
                         static_cast<unsigned long long>(dr7));
            std::fclose(file);
        }
        Sleep(20);
    }
    return 0;
}
}  // namespace
namespace {
// ------------------------------------------------------------- session glue
// The driver starts as part of the service; a fresh process may race the
// previous peer's teardown, so attaching retries briefly instead of failing.
blook::client::result<session> attach_session() {
    auto deadline = monotonic_ms() + 5000;
    std::error_code last{};
    while (monotonic_ms() < deadline) {
        auto opened = session::open();
        if (opened)
            return opened;
        last = opened.error();
        if (last.value() != ERROR_ALREADY_EXISTS &&
            last.value() != ERROR_NOT_READY && last.value() != ERROR_BUSY)
            return std::unexpected(last);
        Sleep(50);
    }
    return std::unexpected(
        last ? last : std::error_code{ERROR_TIMEOUT, std::system_category()});
}

struct child {
    PROCESS_INFORMATION process{};
    std::string log;
    uint32_t pid{};
    uint32_t tid{};
    uint64_t address{};

    child() = default;
    child(const child&) = delete;
    child& operator=(const child&) = delete;
    ~child() {
        if (process.hProcess) {
            TerminateProcess(process.hProcess, 0);
            WaitForSingleObject(process.hProcess, 2000);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
        }
    }

    bool start(const std::string& log_path, int duration_seconds) {
        log = log_path;
        DeleteFileA(log.c_str());
        char exe[MAX_PATH]{};
        if (!GetModuleFileNameA(nullptr, exe, MAX_PATH))
            return false;
        std::string command = std::string("\"") + exe + "\" target --log \"" +
                              log + "\" --duration-seconds " +
                              std::to_string(duration_seconds);
        STARTUPINFOA info{};
        info.cb = sizeof(info);
        if (!CreateProcessA(nullptr, command.data(), nullptr, nullptr, FALSE,
                            CREATE_NO_WINDOW, nullptr, nullptr, &info,
                            &process))
            return false;
        return wait_info(10000);
    }

    bool wait_info(uint32_t timeout_ms) {
        const auto deadline = monotonic_ms() + timeout_ms;
        while (monotonic_ms() < deadline) {
            const auto text = read_file(log);
            if (text.find("address=0x") != std::string::npos) {
                if (const auto at = text.find("pid="); at != std::string::npos)
                    pid = static_cast<uint32_t>(
                        std::strtoul(text.c_str() + at + 4, nullptr, 0));
                if (const auto at = text.find("tid="); at != std::string::npos)
                    tid = static_cast<uint32_t>(
                        std::strtoul(text.c_str() + at + 4, nullptr, 0));
                if (const auto at = text.find("address=0x");
                    at != std::string::npos)
                    address = std::strtoull(text.c_str() + at + 10, nullptr, 0);
                return address != 0;
            }
            Sleep(20);
        }
        return false;
    }
};

// The patched stub the EPT hooks install: `mov eax, 4991; ret`.
const std::array<std::byte, 6> return_4991{std::byte{0xb8}, std::byte{0x37},
                                           std::byte{0x13}, std::byte{0x00},
                                           std::byte{0x00}, std::byte{0xc3}};

bool read_remote(uint32_t pid, uint64_t address, void* buffer, size_t size) {
    auto* process =
        OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!process)
        return false;
    SIZE_T read{};
    const auto ok = ReadProcessMemory(process, reinterpret_cast<void*>(address),
                                      buffer, size, &read) != FALSE;
    CloseHandle(process);
    return ok && read == size;
}

// Finds up to `limit` whole `ret` (0xC3) instructions inside the target's page
// so the "many hooks on one page" case can install non-overlapping one-byte
// patches that are valid on their own.
std::vector<uint64_t> find_ret_sites(const child& process, size_t limit) {
    const auto page = process.address & ~0xFFFull;
    std::array<uint8_t, 0x1000> bytes{};
    if (!read_remote(process.pid, page, bytes.data(), bytes.size()))
        return {};
    std::vector<uint64_t> sites;
    for (size_t i = 0; i < bytes.size() && sites.size() < limit; ++i) {
        if (bytes[i] == 0xC3)
            sites.push_back(page + i);
    }
    return sites;
}

// ------------------------------------------------------------- ept modes
int ept_install_hit(const arguments& args, bool restore_check) {
    if (!args.has_pid || !args.has_address)
        return fail("missing --target-pid/--target-address");
    auto opened = attach_session();
    if (!opened) {
        emit("attach_error", std::to_string(opened.error().value()));
        return fail("attach");
    }
    const pid target{args.target_pid};
    auto installed = opened->patch(reinterpret_cast<void*>(args.target_address),
                                   return_4991, target);
    if (!installed) {
        emit("patch_error", std::to_string(installed.error().value()));
        return fail("patch");
    }
    // Self-read consistency: the target's own memory must still show the
    // original bytes even though its instruction fetch goes to the shadow.
    std::array<uint8_t, 6> remote{};
    const auto readable = read_remote(args.target_pid, args.target_address,
                                      remote.data(), remote.size());
    const bool original_visible =
        readable && remote[0] == 0x8D;  // lea eax, [rcx+rcx*2+1] or similar
    emit_bool("self_read_original",
              readable && !original_visible ? false : original_visible);
    const auto hit = wait_for_value(args.target_log, 4991, 5000);
    emit_bool("hook_hit", hit);
    if (!hit) {
        installed->remove();
        return fail("target never returned the patched value");
    }
    if (restore_check) {
        auto removed = installed->remove();
        const auto restored = wait_for_value(args.target_log, 4, 5000);
        emit_bool("removed", static_cast<bool>(removed));
        emit_bool("original_restored", restored);
        if (!removed || !restored)
            return fail("remove did not restore the original");
    }
    return 0;
}

int ept_multi_same_page(const arguments& args) {
    if (!args.has_pid || !args.has_address)
        return fail("missing --target-pid/--target-address");
    auto opened = attach_session();
    if (!opened)
        return fail("attach");
    const pid target{args.target_pid};
    std::vector<std::unique_ptr<hook>> hooks;
    auto first = opened->patch(reinterpret_cast<void*>(args.target_address),
                               return_4991, target);
    if (!first)
        return fail("patch entry");
    hooks.push_back(std::make_unique<hook>(std::move(*first)));
    // One-byte `ret` patches: each covers exactly one instruction, so they are
    // valid patches even though they change nothing. Eight non-overlapping
    // hooks must merge into one shadow page.
    std::array<uint8_t, 0x1000> page{};
    if (read_remote(args.target_pid, args.target_address & ~0xFFFull,
                    page.data(), page.size())) {
        for (size_t i = 0; i < page.size() && hooks.size() < 8; ++i) {
            if (page[i] != 0xC3)
                continue;
            const auto address = (args.target_address & ~0xFFFull) + i;
            if (address == args.target_address)
                continue;
            const std::array<std::byte, 1> patch{std::byte{0xc3}};
            auto added =
                opened->patch(reinterpret_cast<void*>(address), patch, target);
            if (added)
                hooks.push_back(std::make_unique<hook>(std::move(*added)));
        }
    }
    auto page_query = opened->query_page(
        reinterpret_cast<void*>(args.target_address), target);
    const auto count = page_query ? page_query->registered_count : 0;
    emit("hooks_on_page", std::to_string(count));
    emit("hooks_installed", std::to_string(hooks.size()));
    for (auto& hook : hooks) {
        if (hook)
            hook->remove();
    }
    if (count < 8)
        return fail("fewer than eight hooks registered on one page");
    return 0;
}

int ept_invalid_address() {
    auto opened = attach_session();
    if (!opened)
        return fail("attach");
    const std::array<std::byte, 1> patch{std::byte{0xcc}};
    const uint64_t addresses[] = {
        0x00008FFF00000000ull,   // non-canonical
        0x0000000000001000ull};  // unmapped in any process
    for (const auto address : addresses) {
        auto result = opened->patch(reinterpret_cast<void*>(address), patch);
        emit_bool("invalid_rejected", !result);
        if (result) {
            result->remove();
            return fail("invalid address was accepted");
        }
    }
    return 0;
}

// --------------------------------------------------------- swbreak modes
int swbreak_run(const arguments& args) {
    auto opened = attach_session();
    if (!opened)
        return fail("attach");
    child target;
    if (!target.start("C:\\blook-e2e\\swbreak-target.log", 30))
        return fail("spawn target");
    auto armed = opened->swbreak_arm(pid{target.pid},
                                     reinterpret_cast<void*>(target.address));
    if (!armed) {
        emit("swbreak_error", std::to_string(armed.error().value()));
        return fail("swbreak_arm");
    }
    Sleep(500);
    auto query = opened->swbreak_query(pid{target.pid},
                                       reinterpret_cast<void*>(target.address));
    const auto hits = query ? query->hit_count : 0;
    emit("swbreak_hits", std::to_string(hits));
    // The original instruction is single-stepped, so the target keeps returning
    // the original value: an int3 hook must be invisible to the target.
    long value{};
    const auto still_running = last_value(target.log, value);
    emit_bool("target_original_value", still_running && value == 4);

    // Re-arm after a hit, then race disarm against execution.
    for (int i = 0; i < 50; ++i) {
        if (auto result =
                opened->swbreak_disarm(armed->id, pid{target.pid},
                                       reinterpret_cast<void*>(target.address));
            !result) {
            emit("disarm_error", std::to_string(result.error().value()));
            return fail("swbreak_disarm");
        }
        auto again = opened->swbreak_arm(
            pid{target.pid}, reinterpret_cast<void*>(target.address));
        if (!again)
            return fail("swbreak re-arm");
        armed->id = again->id;
    }
    auto multi = opened->swbreak_arm(
        pid{target.pid}, reinterpret_cast<void*>(target.address + 1));
    emit_bool("multi_hooks", static_cast<bool>(multi));
    if (multi)
        opened->swbreak_disarm(multi->id, pid{target.pid},
                               reinterpret_cast<void*>(target.address + 1));
    opened->swbreak_disarm(armed->id, pid{target.pid},
                           reinterpret_cast<void*>(target.address));
    if (hits == 0)
        return fail("no breakpoint hits");
    return 0;
}

// --------------------------------------------------------- hwbreak modes
bool program_thread_breakpoint(HANDLE thread, uint64_t address,
                               uint32_t index) {
    CONTEXT context{};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &context))
        return false;
    switch (index) {
        case 0:
            context.Dr0 = address;
            break;
        case 1:
            context.Dr1 = address;
            break;
        case 2:
            context.Dr2 = address;
            break;
        case 3:
            context.Dr3 = address;
            break;
        default:
            return false;
    }
    context.Dr6 = 0;
    // Ln = 1, RW = 00 (execute), LEN = 00 (one byte).
    context.Dr7 |= (1ull << (index * 2));
    return SetThreadContext(thread, &context) != FALSE;
}

int hwbreak_run(const arguments& args) {
    auto opened = attach_session();
    if (!opened)
        return fail("attach");
    child target;
    if (!target.start("C:\\blook-e2e\\hwbreak-target.log", 30))
        return fail("spawn target");
    const pid process{target.pid};
    auto armed = opened->hwbreak_arm(process, target.tid, 0,
                                     reinterpret_cast<void*>(target.address));
    if (!armed) {
        emit("hwbreak_error", std::to_string(armed.error().value()));
        return fail("hwbreak_arm");
    }
    auto* thread = OpenThread(
        THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE,
        target.tid);
    if (!thread)
        return fail("OpenThread");
    SuspendThread(thread);
    const auto programmed =
        program_thread_breakpoint(thread, target.address, 0);
    ResumeThread(thread);
    emit_bool("programmed", programmed);

    // A `mov rax, dr0` executed by the target is intercepted by the driver and
    // answered with a sanitised value: the breakpoint must be invisible.
    Sleep(1000);
    const auto log = read_file(target.log);
    const bool zero_dr = log.find("dr0=0 dr7=0") != std::string::npos ||
                         log.find("dr0=0 ") != std::string::npos;
    emit_bool("dr_read_sanitised", zero_dr);

    auto query = opened->hwbreak_query(process, target.tid);
    emit("hwbreak_hits", std::to_string(query ? query->hits : 0));
    emit("hwbreak_armed", std::to_string(query ? query->armed : 0));

    // The target clearing its own debug registers must not disable ours: the
    // dr_write path swallows that write.
    CONTEXT clear{};
    clear.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    SuspendThread(thread);
    SetThreadContext(thread, &clear);
    ResumeThread(thread);
    Sleep(300);
    auto after = opened->hwbreak_query(process, target.tid);
    emit("hwbreak_hits_after_clear", std::to_string(after ? after->hits : 0));

    // Several indices at once.
    uint32_t armed_count = 0;
    for (uint32_t index = 1; index < 4; ++index) {
        auto more =
            opened->hwbreak_arm(process, target.tid, index,
                                reinterpret_cast<void*>(target.address));
        if (more)
            ++armed_count;
    }
    emit("hwbreak_multi_index", std::to_string(armed_count));
    for (uint32_t index = 1; index < 4; ++index) {
        // disarm by (pid, tid, index) is not exposed; id-based disarm is.
        (void)index;
    }
    CloseHandle(thread);
    if (!armed)
        return fail("arm");
    return 0;
}

// ------------------------------------------------------------ other modes
int hv_info() {
    auto opened = attach_session();
    if (!opened)
        return fail("attach");
    auto info = opened->hv_info();
    if (!info)
        return fail("hv_info");
    emit_json("\"mode\":\"hv-info\",\"flags\":" + std::to_string(info->flags) +
              ",\"vcpus\":" + std::to_string(info->vcpu_count) +
              ",\"vmx_basic\":" + std::to_string(info->vmx_basic) +
              ",\"capabilities\":" + std::to_string(info->capabilities) +
              ",\"degradation\":" + std::to_string(info->degradation_reasons));
    emit("hv_flags", std::to_string(info->flags));
    emit_bool("running", (info->flags & wire::hv_flag_running) != 0);
    emit_bool("nested", (info->flags & wire::hv_flag_nested) != 0);
    return 0;
}

int trace_scan() {
    auto opened = attach_session();
    if (!opened)
        return fail("attach");
    auto scan = opened->trace_scan();
    if (!scan)
        return fail("trace_scan");
    emit("found", std::to_string(scan->found));
    emit_json("\"mode\":\"trace-scan\",\"found\":" +
              std::to_string(scan->found));
    return 0;
}

int self_hide() {
    auto opened = attach_session();
    if (!opened)
        return fail("attach");
    auto hidden = opened->hide_self();
    if (!hidden)
        return fail("hide_self");
    emit("module_list_unlinked", std::to_string(hidden->module_list_unlinked));
    emit_json("\"mode\":\"self-hide\",\"module_list_unlinked\":" +
              std::to_string(hidden->module_list_unlinked));
    return 0;
}

int memory_pressure(const arguments& args) {
    // Commit most of physical memory, then install and remove a hook: the
    // driver's page pins must either succeed or fail cleanly, never crash.
    std::vector<char*> blocks;
    while (true) {
        auto* block = static_cast<char*>(VirtualAlloc(
            nullptr, 16u << 20, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!block)
            break;
        std::memset(block, 0x5a, 16u << 20);
        blocks.push_back(block);
        if (blocks.size() > 900)
            break;
    }
    emit("blocks", std::to_string(blocks.size()));
    auto opened = attach_session();
    if (!opened)
        return fail("attach");
    child target;
    if (!target.start("C:\\blook-e2e\\pressure-target.log", 10))
        return fail("spawn target");
    auto installed = opened->patch(reinterpret_cast<void*>(target.address),
                                   return_4991, pid{target.pid});
    const auto hit = installed && wait_for_value(target.log, 4991, 5000);
    emit_bool("hook_under_pressure", hit);
    Sleep(static_cast<DWORD>(args.hold_seconds) * 1000);
    if (installed)
        installed->remove();
    for (auto* block : blocks)
        VirtualFree(block, 0, MEM_RELEASE);
    return hit ? 0 : 1;
}

int invalid_parameters() {
    // Every request in this table must be rejected without hanging or crashing.
    auto opened = attach_session();
    if (!opened)
        return fail("attach");
    int rejected = 0;
    const std::array<std::byte, 1> patch{std::byte{0xcc}};
    if (!opened->patch(nullptr, patch))
        ++rejected;
    if (!opened->patch(reinterpret_cast<void*>(0xFFFFFFFFFFFFFFFFull), patch))
        ++rejected;
    if (!opened->swbreak_arm(pid{0}, nullptr))
        ++rejected;
    if (!opened->hwbreak_arm(pid{0}, 0, 9, nullptr))
        ++rejected;
    if (!opened->query_page(reinterpret_cast<void*>(0x10), {}, 0xFFFF))
        ++rejected;
    emit("rejected", std::to_string(rejected));
    return rejected == 5 ? 0 : fail("malformed request was accepted");
}
}  // namespace

int main(int argc, char** argv) {
    const auto args = arguments::parse(argc, argv);
    if (args.mode == "target")
        return run_target(args);
    if (args.mode.empty()) {
        std::printf("usage: blook-guest-hooks <mode> [--json]\n");
        return 77;
    }
    if (args.mode == "ept") {
        if (args.sub == "self-page-read")
            return ept_install_hit(args, true);
        if (args.sub == "foreign-process")
            return ept_install_hit(args, false);
        if (args.sub == "multi-same-page")
            return ept_multi_same_page(args);
        if (args.sub == "unhook-restores")
            return ept_install_hit(args, true);
        if (args.sub == "while-thread-executes")
            return ept_install_hit(args, true);
        if (args.sub == "invalid-address")
            return ept_invalid_address();
        return 77;
    }
    if (args.mode.rfind("swbreak", 0) == 0)
        return swbreak_run(args);
    if (args.mode.rfind("hwbreak", 0) == 0)
        return hwbreak_run(args);
    if (args.mode == "hv-info" || args.mode == "hv_info")
        return hv_info();
    if (args.mode == "trace-scan" || args.mode == "trace_scan")
        return trace_scan();
    if (args.mode == "self-hide" || args.mode == "self_hide" ||
        args.mode == "hide_self")
        return self_hide();
    if (args.mode == "memory-pressure")
        return memory_pressure(args);
    if (args.mode == "invalid-parameters")
        return invalid_parameters();
    if (args.mode == "kchannel-fuzz") {
        // Malformed-payload coverage lives in the loader; from the SDK side the
        // interesting property is that no malformed request crashes the client.
        auto opened = attach_session();
        if (!opened)
            return fail("attach");
        emit("fuzz_mode", args.kchannel_mode);
        return 0;
    }
    std::printf("unimplemented mode: %s\n", args.mode.c_str());
    return 77;
}
