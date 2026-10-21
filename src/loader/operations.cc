#include "operations.hpp"

#include <windows.h>

#include <array>
#include <cstdio>
#include <memory>
#include <system_error>
#include <utility>

#include "blook/drv/ept.hpp"
#include "blook/drv/handle.hpp"
#include "config.hpp"

namespace blook::loader {
namespace {
template <class T, auto Close>
class owned_handle final {
    T value_{};

   public:
    explicit owned_handle(T value = {}) noexcept : value_(value) {}
    ~owned_handle() {
        if (value_) {
            const auto error = GetLastError();
            Close(value_);
            SetLastError(error);
        }
    }
    owned_handle(const owned_handle&) = delete;
    owned_handle& operator=(const owned_handle&) = delete;
    owned_handle(owned_handle&& other) noexcept
        : value_(std::exchange(other.value_, {})) {}
    owned_handle& operator=(owned_handle&&) = delete;
    [[nodiscard]] T get() const noexcept { return value_; }
    explicit operator bool() const noexcept { return value_ != nullptr; }
};
using service_handle = owned_handle<SC_HANDLE, CloseServiceHandle>;
using registry_handle = owned_handle<HKEY, RegCloseKey>;
using result = std::expected<operation_result, failure>;

std::unexpected<failure> failed(std::string action, DWORD code = GetLastError(),
                                std::string detail = {},
                                std::string hint = {}) {
    if (hint.empty()) {
        if (code == ERROR_ACCESS_DENIED)
            hint =
                "Check access permissions and use an elevated terminal if "
                "required.";
        else if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND ||
                 code == ERROR_SERVICE_DOES_NOT_EXIST)
            hint =
                "Check that the signed driver is installed and running; no "
                "automatic changes were made.";
        else if (code == ERROR_INVALID_IMAGE_HASH)
            hint =
                "Use a driver signed and trusted under this machine's normal "
                "Windows policy.";
    }
    return std::unexpected(
        failure{std::move(action), code, std::move(detail), std::move(hint)});
}
std::unexpected<failure> failed(std::string action, std::error_code code,
                                std::string detail = {},
                                std::string hint = {}) {
    return failed(std::move(action), static_cast<DWORD>(code.value()),
                  std::move(detail), std::move(hint));
}

namespace {
// A kernel driver must never be loaded outside a bvmenv VMware guest: a broken
// hypervisor takes the host machine down with it. The guard is structural - the
// e2e harness is the only thing that sets the two marker variables, on a
// command line it executes through bvmenv - and there is deliberately no
// environment variable or switch that bypasses it.
bool inside_virtual_machine() {
    // Structural guard, no escape hatch: only the bvmenv e2e harness sets these
    // variables, on a command line that runs inside the VM. A host shell never
    // has them, so a driver can never be loaded on the physical machine.
    if (std::getenv("BLOOK_VM_GUEST") == nullptr ||
        std::getenv("BLOOK_ALLOW_KERNEL_LOAD") == nullptr) {
        return false;
    }
    int regs[4]{};
    __cpuid(regs, 1);
    if ((static_cast<unsigned>(regs[2]) & 0x80000000u) != 0) {
        return true;
    }
    HKEY key{};
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"HARDWARE\\DESCRIPTION\\System\\BIOS", 0, KEY_READ,
                      &key) != ERROR_SUCCESS) {
        return false;
    }
    wchar_t model[256]{};
    DWORD size = sizeof(model);
    DWORD type{};
    const auto status =
        RegQueryValueExW(key, L"SystemProductName", nullptr, &type,
                         reinterpret_cast<LPBYTE>(model), &size);
    RegCloseKey(key);
    if (status != ERROR_SUCCESS || type != REG_SZ) {
        return false;
    }
    const std::wstring text{model};
    return text.find(L"VMware") != std::wstring::npos ||
           text.find(L"VirtualBox") != std::wstring::npos ||
           text.find(L"KVM") != std::wstring::npos ||
           text.find(L"QEMU") != std::wstring::npos ||
           text.find(L"Hyper-V") != std::wstring::npos ||
           text.find(L"Microsoft Hv") != std::wstring::npos;
}
}  // namespace

result service_command(const cli::command& command, output_sink& output) {
    using enum cli::kind;
    std::wstring image_path;
    if (command.action == install) {
        std::array<wchar_t, 32768> absolute{};
        const auto length = GetFullPathNameW(
            command.path.c_str(), static_cast<DWORD>(absolute.size()),
            absolute.data(), nullptr);
        if (!length)
            return failed("Resolve driver path");
        if (length >= absolute.size())
            return failed("Resolve driver path", ERROR_FILENAME_EXCED_RANGE);
        const auto attributes = GetFileAttributesW(absolute.data());
        if (attributes == INVALID_FILE_ATTRIBUTES)
            return failed("Read driver path");
        if (attributes & FILE_ATTRIBUTE_DIRECTORY)
            return failed("Read driver path", ERROR_DIRECTORY,
                          "Expected a driver file, not a directory.");
        // Preserve the existing NT-form service image path, without changing
        // signing policy.
        image_path = L"\\??\\" + std::wstring{absolute.data()};
    }
    service_handle scm{OpenSCManagerW(
        nullptr, nullptr,
        SC_MANAGER_CONNECT |
            (command.action == install ? SC_MANAGER_CREATE_SERVICE : 0))};
    if (!scm)
        return failed("Open service manager");
    if (command.action == install) {
        service_handle service{CreateServiceW(
            scm.get(), L"BlookDrv", L"Blook Intel EPT analysis driver",
            SERVICE_QUERY_STATUS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL, image_path.c_str(), nullptr, nullptr, nullptr,
            nullptr, nullptr)};
        if (!service)
            return failed("Install service", GetLastError(),
                          "An existing service is not overwritten.");
        output.message("Installed, NOT started.");
        return operation_result{};
    }
    const DWORD access = command.action == start ? SERVICE_START
                         : command.action == stop
                             ? SERVICE_STOP | SERVICE_QUERY_STATUS
                             : DELETE | SERVICE_QUERY_STATUS;
    service_handle service{OpenServiceW(scm.get(), L"BlookDrv", access)};
    if (!service)
        return failed("Open service");
    if (command.action == start) {
        if (!inside_virtual_machine()) {
            return failed(
                "Start service", ERROR_ACCESS_DENIED,
                "Refusing to load a kernel driver on a physical host: this "
                "machine does not look virtualised and a broken hypervisor "
                "takes the host down. Run the driver inside a bvmenv VMware "
                "guest (scripts/E2E.ps1 sets the required markers).");
        }
        // Start through the channel bootstrap: create the anonymous shared
        // region, hand the descriptor to the driver through its service key,
        // start the service and complete the handshake. A plain StartServiceW
        // would boot the driver with no control channel at all (solo mode).
        auto opened = blook::client::session::open();
        if (opened) {
            output.message("Started with a control channel (kchannel ready).");
            return operation_result{};
        }
        // Fall back to a solo start for bring-up: the hypervisor runs, and
        // `stop` is the only way to reach it.
        if (!StartServiceW(service.get(), 0, nullptr) &&
            GetLastError() != ERROR_SERVICE_ALREADY_RUNNING)
            return failed("Start service");
        output.message("Started in solo mode (no control channel).");
        return operation_result{};
    }
    SERVICE_STATUS service_status{};
    if (command.action == stop) {
        if (!ControlService(service.get(), SERVICE_CONTROL_STOP,
                            &service_status) &&
            GetLastError() != ERROR_SERVICE_NOT_ACTIVE)
            return failed("Stop service");
        const auto deadline = GetTickCount64() + 30000;
        do {
            if (!QueryServiceStatus(service.get(), &service_status))
                return failed("Query service");
            if (service_status.dwCurrentState == SERVICE_STOPPED) {
                output.message("Stopped.");
                return operation_result{};
            }
            Sleep(100);
        } while (GetTickCount64() < deadline);
        return failed(
            "Stop service", ERROR_TIMEOUT,
            "Timed out after 30 seconds; the service was not deleted.");
    }
    if (!QueryServiceStatus(service.get(), &service_status))
        return failed("Query service");
    if (service_status.dwCurrentState != SERVICE_STOPPED)
        return failed("Uninstall service", ERROR_SERVICE_CANNOT_ACCEPT_CTRL,
                      "Stop the driver before uninstalling.");
    if (!DeleteService(service.get()))
        return failed("Uninstall service");
    output.message("Service removed; the driver file is left untouched.");
    return operation_result{};
}

std::expected<cli::configuration, failure> read_config(
    const std::wstring& path) {
    using file_ptr = std::unique_ptr<FILE, decltype(&std::fclose)>;
    FILE* raw_file{};
    const auto open_error = _wfopen_s(&raw_file, path.c_str(), L"rb");
    file_ptr file{raw_file, &std::fclose};
    if (open_error || !file)
        return failed(
            "Read configuration", 0, "Cannot open the configuration file.",
            "Check the path and file permissions; no settings were applied.");
    std::string bytes;
    std::array<char, 4096> buffer{};
    while (const auto count =
               std::fread(buffer.data(), 1, buffer.size(), file.get())) {
        bytes.append(buffer.data(), count);
        if (bytes.size() > blook::configuration::max_file_bytes)
            return failed("Read configuration", ERROR_FILE_TOO_LARGE);
    }
    if (std::ferror(file.get()))
        return failed("Read configuration", ERROR_READ_FAULT);
    auto parsed = cli::parse_config(bytes);
    if (!parsed)
        return failed("Validate configuration", 0,
                      "Line " + std::to_string(parsed.error().line) + ": " +
                          parsed.error().message,
                      "Correct the configuration; no settings were applied.");
    return std::move(*parsed);
}

std::expected<std::wstring, failure> local_config_path(
    const std::wstring& path) {
    std::array<wchar_t, 32768> absolute{};
    const auto length =
        GetFullPathNameW(path.c_str(), static_cast<DWORD>(absolute.size()),
                         absolute.data(), nullptr);
    if (!length)
        return failed("Resolve configuration path");
    if (length >= absolute.size())
        return failed("Resolve configuration path", ERROR_FILENAME_EXCED_RANGE);
    std::wstring resolved{absolute.data(), length};
    if (resolved.size() < 3 ||
        !((resolved[0] >= L'A' && resolved[0] <= L'Z') ||
          (resolved[0] >= L'a' && resolved[0] <= L'z')) ||
        resolved[1] != L':' || resolved[2] != L'\\' ||
        resolved.find(L':', 2) != std::wstring::npos)
        return failed("Resolve configuration path", ERROR_BAD_PATHNAME,
                      "Only local drive paths are supported; no UNC, device "
                      "paths or alternate streams.");
    const auto root = resolved.substr(0, 3);
    const auto drive = GetDriveTypeW(root.c_str());
    if (drive != DRIVE_FIXED && drive != DRIVE_REMOVABLE)
        return failed(
            "Resolve configuration path", ERROR_BAD_PATHNAME,
            "Configuration must reside on a local disk, not a network drive.");
    return resolved;
}

result register_config_path(const std::wstring& path, output_sink& output) {
    auto absolute = local_config_path(path);
    if (!absolute)
        return std::unexpected(absolute.error());
    auto config = read_config(*absolute);
    if (!config)
        return std::unexpected(config.error());
    // Do not synthesize a service entry when the driver has not been installed.
    HKEY raw_service{};
    const auto opened = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\BlookDrv", 0,
        KEY_CREATE_SUB_KEY, &raw_service);
    if (opened != ERROR_SUCCESS)
        return failed("Open installed service settings", opened);
    registry_handle service{raw_service};
    HKEY raw{};
    const auto created =
        RegCreateKeyExW(service.get(), L"Parameters", 0, nullptr, 0,
                        KEY_SET_VALUE, nullptr, &raw, nullptr);
    if (created != ERROR_SUCCESS)
        return failed("Open configuration settings", created);
    registry_handle key{raw};
    const auto nt_path = L"\\??\\" + *absolute;
    const auto written = RegSetValueExW(
        key.get(), L"ConfigPath", 0, REG_SZ,
        reinterpret_cast<const BYTE*>(nt_path.c_str()),
        static_cast<DWORD>((nt_path.size() + 1) * sizeof(wchar_t)));
    if (written != ERROR_SUCCESS)
        return failed("Persist configuration path", written);
    output.message(
        "ConfigPath persisted. This does not apply runtime settings.");
    output.message(
        "Security requirement: only Administrators/SYSTEM may write the file "
        "and its parent directories.");
    return operation_result{};
}

result reload_command(output_sink& output, bool persisted = false) {
    const std::string detail =
        persisted ? "ConfigPath was persisted successfully, but runtime reload "
                    "failed. The saved path has not been rolled back."
                  : "Runtime reload failed; no configuration path was changed.";
    auto session =
        blook::client::session::open(blook::client::open_mode::read_only);
    if (!session)
        return failed("Open driver for reload", session.error(), detail);
    auto response = session->reload_configuration();
    if (!response)
        return failed("Reload configuration", response.error(), detail);
    if (response->last_status < 0) {
        char status[16]{};
        std::snprintf(status, sizeof(status), "0x%08lX",
                      static_cast<unsigned long>(response->last_status));
        return failed(
            "Reload configuration", 0,
            detail + " NTSTATUS " + status + "; line " +
                std::to_string(response->error_line) + "." +
                (response->restart_required
                     ? " Restart required; no runtime settings were applied."
                     : ""));
    }
    output.message("Configuration reloaded; generation " +
                   std::to_string(response->generation) + ".");
    if (response->restart_required)
        output.message(
            "Driver restart required for startup-only settings (device access "
            "policy, hide_timing or page_fault_trace); runtime reload does not "
            "apply these settings.");
    return operation_result{};
}
}  // namespace

std::uint32_t client_abi() noexcept {
    return wire::abi_version;
}

std::expected<operation_result, failure> execute(const cli::command& command,
                                                 output_sink& output) {
    using enum cli::kind;
    switch (command.action) {
        case help:
            return operation_result{};
        case install:
        case start:
        case stop:
        case uninstall:
            return service_command(command, output);
        case config_path:
            return register_config_path(command.path, output);
        case apply: {
            auto persisted = register_config_path(command.path, output);
            if (!persisted)
                return persisted;
            return reload_command(output, true);
        }
        case reload:
            return reload_command(output);
        default:
            break;
    }
    // Information commands must not enable VMX as a side effect of opening a
    // session.
    const bool information =
        command.action == ping || command.action == version ||
        command.action == status || command.action == features ||
        command.action == feature || command.action == page;
    auto session =
        information
            ? blook::client::session::open(blook::client::open_mode::read_only)
            : blook::client::session::open();
    if (!session)
        return failed("Open driver", session.error());
    switch (command.action) {
        case features:
        case feature: {
            auto response =
                command.action == features
                    ? session->query_features()
                    : session->set_feature(
                          static_cast<std::uint32_t>(command.feature_id),
                          command.enable);
            if (!response)
                return failed("Feature configuration", response.error());
            for (const auto& descriptor : blook::feature::descriptors) {
                const auto bit = blook::feature::bit(descriptor.value);
                output.message(
                    std::string{descriptor.name} + " desired=" +
                    ((response->desired & bit) ? "on" : "off") + " effective=" +
                    ((response->effective & bit) ? "on" : "off") +
                    ((response->unsupported & bit) ? " unsupported" : "") +
                    " -- " + descriptor.purpose);
            }
            if (response->last_status < 0) {
                char status[16]{};
                std::snprintf(
                    status, sizeof(status), "0x%08lX",
                    static_cast<unsigned long>(response->last_status));
                return failed(
                    "Feature configuration", 0,
                    std::string{"Backend NTSTATUS "} + status +
                        "; desired and effective states are shown above.");
            }
            if (command.action == feature)
                output.message(
                    "Runtime feature request completed; the configuration file "
                    "was not changed. Reload/start restores file settings.");
            break;
        }
        case page: {
            auto response = session->query_page(
                reinterpret_cast<const void*>(command.address),
                blook::client::pid{command.pid},
                command.kernel ? wire::page_domain_kernel
                               : wire::page_domain_user);
            if (!response)
                return failed("Query page hooks", response.error());
            output.message(
                "physical registered=" +
                std::to_string(response->registered_count) +
                " armed=" + std::to_string(response->armed_count) +
                " dormant=" + std::to_string(response->dormant_count));
            output.message(
                "known logical bindings=" +
                std::to_string(response->logical_count) +
                " enabled=" + std::to_string(response->enabled_logical_count) +
                " opaque physical entries=" +
                std::to_string(response->opaque_count));
            output.message(
                command.kernel
                    ? "Kernel counts only; no kernel hook IDs or addresses are "
                      "returned."
                    : "Current-session ownership only. A fresh CLI session "
                      "does not enumerate another session's hooks; use the "
                      "installing SDK session. Process-local handler chains "
                      "are opaque to the driver.");
            break;
        }
        case hide: {
            auto changed = command.windows
                               ? session->hide_windows(command.enable)
                               : session->hide(command.enable);
            if (!changed)
                return failed("Hide profile", changed.error());
            output.message(std::string{"Hide profile "} +
                           (command.windows ? "windows " : "") +
                           (command.enable ? "active." : "inactive."));
            break;
        }
        case pin: {
            auto changed =
                session->pin(blook::client::pid{command.pid},
                             command.process_role == cli::role::tool
                                 ? blook::client::process_role::tool
                                 : blook::client::process_role::target);
            if (!changed)
                return failed("Pin process", changed.error());
            output.message("Pinned " + std::to_string(command.pid) +
                           (command.process_role == cli::role::tool
                                ? " as tool."
                                : " as target."));
            break;
        }
        case unpin: {
            auto changed = session->unpin(blook::client::pid{command.pid});
            if (!changed)
                return failed("Unpin process", changed.error());
            output.message("Unpinned.");
            break;
        }
        case scrub: {
            auto changed = session->scrub(blook::client::pid{command.pid});
            if (!changed)
                return failed("Scrub process", changed.error());
            output.message("Scrubbed " + std::to_string(command.pid) + ".");
            break;
        }
        case hook: {
            auto installed =
                session->patch(reinterpret_cast<void*>(command.address),
                               command.bytes, blook::client::pid{command.pid});
            if (!installed)
                return failed("Install EPT hook", installed.error());
            output.message("Hook " + std::to_string(installed->id()) +
                           (command.pid ? " installed in the target process."
                                        : " installed in this process."));
            output.wait_for_enter();
            break;
        }
        default: {
            auto queried = session->query();
            if (!queried)
                return failed("Query driver", queried.error());
            dashboard view{wire::abi_version,
                           queried->abi,
                           queried->hooks,
                           queried->window_hooks,
                           static_cast<std::uint32_t>(queried->backend_status),
                           queried->running,
                           queried->enabled,
                           queried->hidden};
            return operation_result{queried->running ? 0 : 2, view};
        }
    }
    return operation_result{};
}
}  // namespace blook::loader
