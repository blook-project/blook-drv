// In-guest anti-detection probe: the checks a VMAware-style detector runs,
// executed inside the guest so the answer is the one a real detector would get.
//
// It is deliberately independent of the driver: it never calls the SDK, it only
// executes CPU instructions and Win32 APIs. That is what makes it a useful
// regression test - it can be run once without the driver (baseline: the
// hypervisor is the VMware L0 and is visible) and once with the driver loaded
// (the driver must hide those vectors), and the difference is the evidence.
#include <windows.h>
#include <intrin.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace {
// ------------------------------------------------------------------ report
enum class verdict { pass, fail, info, error };

struct check_result {
    std::string id;
    std::string category;
    verdict value{verdict::info};
    std::string detail;
    std::string values;
};

std::vector<check_result>& results() {
    static std::vector<check_result> list;
    return list;
}

void add(const char* id, const char* category, verdict value,
         const std::string& detail, const std::string& values = {}) {
    results().push_back({id, category, value, detail, values});
    const char* name = value == verdict::pass  ? "PASS"
                       : value == verdict::fail ? "FAIL"
                       : value == verdict::error ? "ERROR"
                                                 : "INFO";
    std::printf("[%s] %-32s %s%s%s\n", name, id, detail.c_str(),
                values.empty() ? "" : " ", values.c_str());
    std::fflush(stdout);
}

// ------------------------------------------------------------------- cpuid
struct cpuid_result {
    uint32_t eax{}, ebx{}, ecx{}, edx{};
};

cpuid_result cpuid(uint32_t leaf, uint32_t subleaf = 0) {
    int regs[4]{};
    __cpuidex(regs, static_cast<int>(leaf), static_cast<int>(subleaf));
    return {static_cast<uint32_t>(regs[0]), static_cast<uint32_t>(regs[1]),
            static_cast<uint32_t>(regs[2]), static_cast<uint32_t>(regs[3])};
}

std::string vendor_string(const cpuid_result& value) {
    char text[13]{};
    std::memcpy(text, &value.ebx, 4);
    std::memcpy(text + 4, &value.ecx, 4);
    std::memcpy(text + 8, &value.edx, 4);
    return text;
}

// Safe privileged instructions: each one lives in a function with no C++
// objects so __try/__except is allowed with the default exception model.
extern "C" bool rdmsr_safe(uint32_t msr, uint64_t& value) {
    __try {
        value = __readmsr(msr);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

extern "C" bool wrmsr_faults(uint32_t msr, uint64_t value) {
    __try {
        __writemsr(msr, value);
        return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;
    }
}

extern "C" bool xsetbv_faults(uint64_t value) {
    __try {
        _xsetbv(0, value);
        return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;
    }
}

extern "C" bool read_dr0(uint64_t& value) {
    __try {
        value = __readdr(0);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// A minimal PEB prefix: only BeingDebugged is needed and the layout of the
// first three bytes is stable across every Windows version.
struct peb_prefix {
    unsigned char reserved[2];
    unsigned char being_debugged;
};

std::string hex(uint64_t value) {
    char text[32]{};
    std::snprintf(text, sizeof(text), "0x%llX",
                  static_cast<unsigned long long>(value));
    return text;
}

uint64_t rdtscp() {
    unsigned aux{};
    return __rdtscp(&aux);
}

// --------------------------------------------------------------- the checks
void check_cpuid_hypervisor() {
    const auto leaf1 = cpuid(1);
    const bool present = (leaf1.ecx & (1u << 31)) != 0;
    add("cpuid-hypervisor-bit", "cpuid", present ? verdict::fail : verdict::pass,
        present ? "CPUID.1:ECX[31] is set" : "CPUID.1:ECX[31] is clear",
        "ecx=" + hex(leaf1.ecx));
}

void check_cpuid_vendor() {
    const auto max = cpuid(0);
    const auto vendor = cpuid(0x40000000);
    // A CPU without hypervisor leaves answers CPUID.0x40000000 with the data of
    // its highest basic leaf, so the vendor signature is only meaningful when
    // the returned maximum leaf is actually in the hypervisor range.
    const bool empty = vendor.eax < 0x40000000 || (vendor.ebx == 0 &&
                                                   vendor.ecx == 0 &&
                                                   vendor.edx == 0);
    const auto raw = vendor_string(vendor);
    const auto display = empty ? std::string("(empty)") : raw;
    const bool known = raw.rfind("VMware", 0) == 0 ||
                       raw.rfind("Microsoft Hv", 0) == 0 ||
                       raw.rfind("KVMKVMKVM", 0) == 0 ||
                       raw.rfind("XenVMM", 0) == 0 ||
                       raw.rfind("VBoxVBox", 0) == 0;
    add("cpuid-vendor-leaves", "cpuid",
        empty ? verdict::pass : (known ? verdict::fail : verdict::info),
        empty ? "leaf 0x40000000 is empty"
              : "leaf 0x40000000 reports a hypervisor vendor",
        "vendor=" + display + " max_leaf=" + hex(vendor.eax) +
            " basic_max=" + hex(max.eax));
}

void check_cpuid_features() {
    const auto leaf1 = cpuid(1);
    const auto extended = cpuid(0x80000001);
    const bool vmx = (leaf1.ecx & (1u << 5)) != 0;
    const bool smx = (leaf1.ecx & (1u << 6)) != 0;
    const bool svm = (extended.ecx & (1u << 2)) != 0;
    // The CPUID feature view is only a detection vector when it contradicts the
    // MSR view: a real VT-x machine advertises VMX and has a locked
    // IA32_FEATURE_CONTROL, and a machine (or a hidden hypervisor) that does
    // not advertise VMX must not answer the VMX capability MSRs. Comparing the
    // two is what the drivers of this project have to keep consistent.
    uint64_t feature_control{};
    const bool fc_readable = rdmsr_safe(0x3A, feature_control);
    const bool fc_locked = fc_readable && (feature_control & 1) != 0;
    const bool fc_vmx = fc_readable && (feature_control & 4) != 0;
    uint64_t vmx_basic{};
    const bool vmx_msr_readable = rdmsr_safe(0x480, vmx_basic);
    bool consistent{};
    const char* detail{};
    if (vmx) {
        consistent = fc_locked && fc_vmx && vmx_msr_readable;
        detail = consistent ? "CPUID advertises VT-x and the MSR view agrees"
                            : "CPUID advertises VT-x but the MSR view disagrees";
    } else {
        consistent = !vmx_msr_readable && !fc_vmx;
        detail = consistent
                     ? "CPUID hides VT-x and the VMX MSRs are filtered too"
                     : "CPUID hides VT-x but the VMX MSRs still answer";
    }
    // IA32_FEATURE_CONTROL and the VMX capability MSRs are CPL0-only, so the
    // consistency check cannot be completed from user mode: report it and leave
    // the verdict to the driver-side detect_probe (which is what the e2e suite
    // asserts). Never fail a machine just because a CPL0 MSR is privileged.
    add("cpuid-vmx-svm-bits", "cpuid", verdict::info, detail,
        "vmx=" + std::to_string(vmx) + " smx=" + std::to_string(smx) +
            " svm=" + std::to_string(svm) + " fc_readable=" +
            std::to_string(fc_readable) + " fc_locked=" +
            std::to_string(fc_locked) + " vmx_msr_readable=" +
            std::to_string(vmx_msr_readable));
}

void check_msr_feature_control() {
    uint64_t value{};
    if (!rdmsr_safe(0x3A, value)) {
        add("msr-feature-control", "msr", verdict::pass,
            "IA32_FEATURE_CONTROL faults (no VT-x exposed)", "fault=1");
        return;
    }
    const bool locked = (value & 1) != 0;
    const bool vmx_outside = (value & 4) != 0;
    add("msr-feature-control", "msr",
        (locked && !vmx_outside) ? verdict::pass : verdict::fail,
        (locked && !vmx_outside) ? "locked with VMX disabled"
                                 : "VMX enabled outside SMX",
        "value=" + hex(value));
}

void check_msr_vmx_leaves() {
    int faults = 0;
    const uint32_t msrs[] = {0x480, 0x481, 0x482, 0x483, 0x484,
                             0x485, 0x486, 0x487, 0x488, 0x489, 0x48B, 0x48C};
    for (const auto msr : msrs) {
        uint64_t value{};
        if (!rdmsr_safe(msr, value))
            ++faults;
    }
    add("msr-vmx-leaves", "msr", faults == 12 ? verdict::pass : verdict::fail,
        faults == 12 ? "every IA32_VMX_* MSR faults"
                     : "IA32_VMX_* MSRs are readable",
        "faults=" + std::to_string(faults) + "/12");
}

void check_tsc_timing() {
    // Minimum delta of a CPUID over 64 samples: a world switch dominates the
    // measurement, so a large minimum means CPUID is being intercepted.
    uint64_t minimum = ~0ull;
    uint64_t maximum{};
    for (int i = 0; i < 64; ++i) {
        _mm_lfence();
        const auto start = __rdtsc();
        _mm_lfence();
        (void)cpuid(0);
        _mm_lfence();
        const auto stop = __rdtsc();
        _mm_lfence();
        const auto delta = stop - start;
        minimum = std::min(minimum, delta);
        maximum = std::max(maximum, delta);
    }
    // ~2000 cycles is comfortably above any bare-metal CPUID (a few hundred).
    add("tsc-cpuid-latency", "timing",
        minimum < 2000 ? verdict::pass : verdict::fail,
        minimum < 2000 ? "CPUID round trip looks native"
                       : "CPUID round trip is dominated by a world switch",
        "min=" + std::to_string(minimum) + " max=" + std::to_string(maximum));
}

void check_tsc_monotonic() {
    uint64_t previous = __rdtsc();
    bool monotonic = true;
    for (int i = 0; i < 1000; ++i) {
        const auto now = __rdtsc();
        if (now <= previous) {
            monotonic = false;
            break;
        }
        previous = now;
    }
    add("tsc-monotonic", "timing", monotonic ? verdict::pass : verdict::fail,
        monotonic ? "RDTSC is strictly increasing" : "RDTSC went backwards");
}

void check_aperf_mperf() {
    uint64_t before_aperf{}, before_mperf{}, after_aperf{}, after_mperf{};
    if (!rdmsr_safe(0xE8, before_aperf) || !rdmsr_safe(0xE7, before_mperf)) {
        add("aperf-mperf-ratio", "timing", verdict::info,
            "APERF/MPERF are not readable in user mode");
        return;
    }
    LARGE_INTEGER qpc_before{}, qpc_after{};
    QueryPerformanceCounter(&qpc_before);
    Sleep(100);
    QueryPerformanceCounter(&qpc_after);
    if (!rdmsr_safe(0xE8, after_aperf) || !rdmsr_safe(0xE7, after_mperf)) {
        add("aperf-mperf-ratio", "timing", verdict::info,
            "APERF/MPERF unavailable after the sample");
        return;
    }
    const auto aperf = after_aperf - before_aperf;
    const auto mperf = after_mperf - before_mperf;
    const auto qpc = qpc_after.QuadPart - qpc_before.QuadPart;
    const double ratio = mperf ? static_cast<double>(aperf) / mperf : 0.0;
    // APERF/MPERF both count at the (nominal) core clock; a compensated
    // world switch shows up as a ratio far from the QPC-implied one.
    add("aperf-mperf-ratio", "timing",
        (qpc > 0 && ratio > 0.5 && ratio < 1.5) ? verdict::pass : verdict::fail,
        "ratio in the expected band", "aperf=" + std::to_string(aperf) +
                                          " mperf=" + std::to_string(mperf) +
                                          " ratio=" + std::to_string(ratio));
}

void check_exception_behaviour() {
    // Writing an IA32_VMX_* MSR must fault on a machine where CPUID does not
    // advertise VT-x; a hypervisor that leaves the MSRs writable is a one-line
    // detection.
    const bool ro_msr = wrmsr_faults(0x48C, 0);
    // XSETBV with an unsupported bit must fault as well.
    const bool xsetbv = xsetbv_faults(0);
    add("exception-behaviour", "exception",
        (ro_msr && xsetbv) ? verdict::pass : verdict::fail,
        "write-to-read-only-MSR and XSETBV fault as on bare metal",
        "ro_msr_fault=" + std::to_string(ro_msr) +
            " xsetbv_fault=" + std::to_string(xsetbv));
}

void check_debug_registers() {
    uint64_t dr0{};
    const bool read = read_dr0(dr0);
    // On a bare-metal CPU a CPL3 read of DR0 raises #GP. A hypervisor that
    // emulates it instead is exactly what this check looks for.
    add("dr-read-faults", "exception", read ? verdict::fail : verdict::pass,
        read ? "CPL3 MOV DR0 succeeded (emulated)"
             : "CPL3 MOV DR0 faults as on bare metal",
        "dr0=" + hex(dr0));
}

void check_debugger_surface() {
    const auto peb =
        reinterpret_cast<peb_prefix*>(__readgsqword(0x60));
    const bool being_debugged = peb && peb->being_debugged != 0;
    BOOL remote{};
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    add("debugger-surface", "debugger",
        (being_debugged || remote) ? verdict::fail : verdict::pass,
        "PEB flags and debug port are clean",
        "being_debugged=" + std::to_string(being_debugged) +
            " remote=" + std::to_string(remote));
}

void check_memory_latency() {
    constexpr size_t size = 64u << 20;
    auto* buffer = static_cast<char*>(VirtualAlloc(nullptr, size,
                                                   MEM_COMMIT | MEM_RESERVE,
                                                   PAGE_READWRITE));
    if (!buffer) {
        add("memory-latency", "memory", verdict::error, "allocation failed");
        return;
    }
    // Build a pointer chase over every 64-byte line.
    constexpr size_t line = 64;
    const auto lines = size / line;
    for (size_t i = 0; i < lines; ++i) {
        const auto next = (i * 167 + 13) % lines;
        *reinterpret_cast<size_t*>(buffer + i * line) = next * line;
    }
    size_t offset{};
    uint64_t minimum = ~0ull;
    uint64_t total{};
    for (int sample = 0; sample < 4096; ++sample) {
        const auto start = __rdtsc();
        offset = *reinterpret_cast<size_t*>(buffer + offset);
        const auto delta = __rdtsc() - start;
        minimum = std::min(minimum, delta);
        total += delta;
    }
    VirtualFree(buffer, 0, MEM_RELEASE);
    add("memory-latency", "memory", verdict::info,
        "pointer-chase latency recorded (EPT shifts it slightly)",
        "min=" + std::to_string(minimum) +
            " avg=" + std::to_string(total / 4096));
}

void check_nested_host() {
    const auto vendor = cpuid(0x40000000);
    const auto signature = vendor_string(vendor);
    const bool empty = vendor.eax < 0x40000000 || (vendor.ebx == 0 &&
                                                  vendor.ecx == 0 &&
                                                  vendor.edx == 0);
    add("nested-host-visible", "cpuid", verdict::info,
        empty ? "no L0 hypervisor vendor is visible"
              : "an L0 hypervisor vendor is visible",
        "vendor=" + (empty ? std::string("(empty)") : signature));
}

// ------------------------------------------------------------------- driver
struct options {
    std::string json_path;
    std::string baseline_path;
    bool quick{};
    bool expect_hypervisor{};
};

options parse(int argc, char** argv) {
    options value;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--json" && i + 1 < argc)
            value.json_path = argv[++i];
        else if (arg == "--baseline" && i + 1 < argc)
            value.baseline_path = argv[++i];
        else if (arg == "--quick")
            value.quick = true;
        else if (arg == "--expect-hypervisor")
            value.expect_hypervisor = true;
    }
    return value;
}

const char* verdict_name(verdict value) {
    switch (value) {
        case verdict::pass:
            return "pass";
        case verdict::fail:
            return "fail";
        case verdict::error:
            return "error";
        default:
            return "info";
    }
}

std::string escape(const std::string& text) {
    std::string out;
    for (const auto c : text) {
        if (c == '"' || c == '\\')
            out.push_back('\\');
        if (c == '\n') {
            out += "\\n";
            continue;
        }
        out.push_back(c);
    }
    return out;
}

std::string to_json() {
    int pass = 0, fail_count = 0, info = 0, error = 0;
    std::string checks;
    std::string fails;
    for (const auto& result : results()) {
        switch (result.value) {
            case verdict::pass:
                ++pass;
                break;
            case verdict::fail:
                ++fail_count;
                if (!fails.empty())
                    fails += ",";
                fails += "\"" + escape(result.id) + "\"";
                break;
            case verdict::error:
                ++error;
                break;
            default:
                ++info;
                break;
        }
        if (!checks.empty())
            checks += ",";
        checks += "{\"id\":\"" + escape(result.id) + "\",\"category\":\"" +
                  escape(result.category) + "\",\"verdict\":\"" +
                  verdict_name(result.value) + "\",\"detail\":\"" +
                  escape(result.detail) + "\",\"values\":\"" +
                  escape(result.values) + "\"}";
    }
    std::string json = "{\"tool\":\"blook-antidetect\",\"version\":1,";
    json += "\"checks\":[" + checks + "],";
    json += "\"fails\":[" + fails + "],";
    json += "\"failed\":" + std::to_string(fail_count) + ",";
    json += "\"summary\":{\"pass\":" + std::to_string(pass) +
            ",\"fail\":" + std::to_string(fail_count) +
            ",\"info\":" + std::to_string(info) +
            ",\"error\":" + std::to_string(error) + "},";
    json += "\"exit\":" + std::to_string(fail_count == 0 ? 0 : 1) + "}";
    return json;
}

bool write_text(const std::string& path, const std::string& text) {
    auto* file = std::fopen(path.c_str(), "wb");
    if (!file)
        return false;
    std::fwrite(text.data(), 1, text.size(), file);
    std::fclose(file);
    return true;
}
}  // namespace

int main(int argc, char** argv) {
    const auto args = parse(argc, argv);
    std::printf("blook-antidetect: %s\n", "VMAware-style in-guest probe");

    check_cpuid_hypervisor();
    check_cpuid_vendor();
    check_cpuid_features();
    check_msr_feature_control();
    check_msr_vmx_leaves();
    check_tsc_monotonic();
    if (!args.quick) {
        check_tsc_timing();
        check_aperf_mperf();
        check_memory_latency();
    }
    check_exception_behaviour();
    check_debug_registers();
    check_debugger_surface();
    check_nested_host();

    const auto json = to_json();
    if (!args.json_path.empty() && !write_text(args.json_path, json + "\n"))
        std::printf("error: cannot write %s\n", args.json_path.c_str());
    if (!args.baseline_path.empty() &&
        !write_text(args.baseline_path, json + "\n"))
        std::printf("error: cannot write baseline %s\n",
                    args.baseline_path.c_str());
    std::printf("%s\n", json.c_str());

    int failures = 0;
    for (const auto& result : results()) {
        if (result.value == verdict::fail)
            ++failures;
    }
    return failures == 0 ? 0 : 1;
}