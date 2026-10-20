// blook-kchannel user-side adapter: the only SDK translation unit that includes
// a kchannel header.
#include "blook/drv/transport.hpp"

#include <winreg.h>

#include <cstring>

#include "blook/kchannel.h"

namespace blook::transport {
namespace {
std::error_code make_error(unsigned long code) {
    return {static_cast<int>(code), std::system_category()};
}

std::error_code from_status(kc_status status) {
    if (status == KC_OK)
        return {};
    // KC_ERR_* values are not Win32 codes; map the ones a caller acts on and
    // keep the rest distinguishable.
    switch (status) {
        case KC_ERR_PARAM:
            return make_error(ERROR_INVALID_PARAMETER);
        case KC_ERR_NOMEM:
            return make_error(ERROR_NOT_ENOUGH_MEMORY);
        case KC_ERR_AUTH:
            return make_error(ERROR_ACCESS_DENIED);
        case KC_ERR_TIMEOUT:
            return make_error(ERROR_TIMEOUT);
        case KC_ERR_BUSY:
            return make_error(ERROR_BUSY);
        case KC_ERR_ALREADY:
            return make_error(ERROR_ALREADY_EXISTS);
        case KC_ERR_NOT_FOUND:
            return make_error(ERROR_NOT_FOUND);
        case KC_ERR_UNSUPPORTED:
            return make_error(ERROR_NOT_SUPPORTED);
        case KC_ERR_PEER_GONE:
            return make_error(ERROR_CONNECTION_ABORTED);
        case KC_ERR_STATE:
            return make_error(ERROR_INVALID_STATE);
        default:
            return make_error(ERROR_GEN_FAILURE);
    }
}

kc_client* client(const attachment& value) {
    return static_cast<kc_client*>(value.handle());
}
}  // namespace

attachment::attachment(attachment&& other) noexcept
    : impl_(std::exchange(other.impl_, nullptr)) {}

attachment& attachment::operator=(attachment&& other) noexcept {
    if (this != &other) {
        reset();
        impl_ = std::exchange(other.impl_, nullptr);
    }
    return *this;
}

attachment::~attachment() {
    reset();
}

void attachment::reset() {
    if (impl_) {
        kc_detach(static_cast<kc_client*>(impl_));
        impl_ = nullptr;
    }
}

std::unique_ptr<attachment> begin(const attach_options& options,
                                  std::error_code& error) {
    error = {};
    kc_attach_opts opts{};
    opts.region_size =
        options.region_size ? options.region_size : default_region_size;
    opts.mode = options.mode;
    opts.cipher = KC_CIPHER_CHACHA20;
    opts.peer_pid = options.peer_pid;
    opts.flags = KC_ATTACH_FLAG_REQUIRE_CHACHA20;
    opts.debug_tag = options.debug_tag;

    kc_client* value{};
    const auto status = kc_attach(&opts, &value);
    if (status != KC_OK) {
        error = from_status(status);
        return nullptr;
    }
    auto result = std::make_unique<attachment>();
    result->impl_ = value;
    return result;
}

std::span<const std::byte> bootstrap(const attachment& value) {
    if (!value)
        return {};
    kc_bootstrap descriptor{};
    if (kc_get_bootstrap(client(value), &descriptor) != KC_OK)
        return {};
    // The descriptor is filled by the library; hand back the raw bytes so the
    // mapper can copy them into kernel memory.
    static thread_local kc_bootstrap copy;
    copy = descriptor;
    return {reinterpret_cast<const std::byte*>(&copy), sizeof(copy)};
}

uint32_t peer_pid(const attachment& value) {
    if (!value)
        return 0;
    kc_bootstrap descriptor{};
    if (kc_get_bootstrap(client(value), &descriptor) != KC_OK)
        return 0;
    return descriptor.peer_pid ? descriptor.peer_pid : GetCurrentProcessId();
}

std::error_code finish(attachment& value, uint32_t timeout_ms) {
    if (!value)
        return make_error(ERROR_INVALID_HANDLE);
    return from_status(kc_attach_finish(client(value), timeout_ms));
}

int call(attachment& value, uint16_t op, const void* in, uint32_t in_len,
         void* out, uint32_t out_cap, uint32_t* out_len, uint32_t timeout_ms) {
    if (!value)
        return KC_ERR_STATE;
    return static_cast<int>(
        kc_call(client(value), op, in, in_len, out, out_cap, out_len,
                timeout_ms ? timeout_ms : KC_DEFAULT_TIMEOUT_MS));
}

void detach(std::unique_ptr<attachment> value) {
    value.reset();
}

std::error_code write_service_bootstrap(const std::wstring& service_name,
                                        const attachment& value) {
    if (!value)
        return make_error(ERROR_INVALID_HANDLE);
    const auto bytes = bootstrap(value);
    if (bytes.empty())
        return make_error(ERROR_INVALID_DATA);

    const auto path = L"SYSTEM\\CurrentControlSet\\Services\\" + service_name +
                      L"\\Parameters";
    HKEY key{};
    auto result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, nullptr,
                                  0, KEY_SET_VALUE, nullptr, &key, nullptr);
    if (result != ERROR_SUCCESS)
        return make_error(result);
    result = RegSetValueExW(key, L"KcBootstrap", 0, REG_BINARY,
                            reinterpret_cast<const BYTE*>(bytes.data()),
                            static_cast<DWORD>(bytes.size()));
    RegCloseKey(key);
    return result == ERROR_SUCCESS ? std::error_code{} : make_error(result);
}

std::error_code set_service_dword(const std::wstring& service_name,
                                  const std::wstring& name, uint32_t value) {
    const auto path = L"SYSTEM\\CurrentControlSet\\Services\\" + service_name +
                      L"\\Parameters";
    HKEY key{};
    auto result = RegCreateKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, nullptr,
                                  0, KEY_SET_VALUE, nullptr, &key, nullptr);
    if (result != ERROR_SUCCESS)
        return make_error(result);
    result =
        RegSetValueExW(key, name.c_str(), 0, REG_DWORD,
                       reinterpret_cast<const BYTE*>(&value), sizeof(value));
    RegCloseKey(key);
    return result == ERROR_SUCCESS ? std::error_code{} : make_error(result);
}

std::error_code install_service(const std::wstring& service_name,
                                const std::wstring& image_path) {
    SC_HANDLE manager =
        OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!manager)
        return make_error(GetLastError());
    SC_HANDLE service = CreateServiceW(
        manager, service_name.c_str(), service_name.c_str(), SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        image_path.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    auto result = GetLastError();
    if (service)
        CloseServiceHandle(service);
    CloseServiceHandle(manager);
    if (!service && result == ERROR_SERVICE_EXISTS)
        return {};
    return service ? std::error_code{} : make_error(result);
}

std::error_code start_service(const std::wstring& service_name) {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager)
        return make_error(GetLastError());
    SC_HANDLE service =
        OpenServiceW(manager, service_name.c_str(), SERVICE_START);
    if (!service) {
        const auto error = GetLastError();
        CloseServiceHandle(manager);
        return make_error(error);
    }
    const auto ok = StartServiceW(service, 0, nullptr);
    const auto error = GetLastError();
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    // A service that is already running is exactly the state the caller wants;
    // the handshake against the live peer happens in finish().
    if (!ok && error == ERROR_SERVICE_ALREADY_RUNNING)
        return {};
    return ok ? std::error_code{} : make_error(error);
}

std::error_code stop_service(const std::wstring& service_name) {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager)
        return make_error(GetLastError());
    SC_HANDLE service =
        OpenServiceW(manager, service_name.c_str(), SERVICE_STOP);
    if (!service) {
        const auto error = GetLastError();
        CloseServiceHandle(manager);
        return make_error(error);
    }
    SERVICE_STATUS status{};
    const auto ok = ControlService(service, SERVICE_CONTROL_STOP, &status);
    const auto error = GetLastError();
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return ok ? std::error_code{} : make_error(error);
}

std::error_code delete_service(const std::wstring& service_name) {
    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!manager)
        return make_error(GetLastError());
    SC_HANDLE service = OpenServiceW(manager, service_name.c_str(), DELETE);
    if (!service) {
        const auto error = GetLastError();
        CloseServiceHandle(manager);
        return make_error(error);
    }
    const auto ok = DeleteService(service);
    const auto error = GetLastError();
    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    return ok ? std::error_code{} : make_error(error);
}
}  // namespace blook::transport
