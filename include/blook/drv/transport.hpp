#pragma once
#include <windows.h>

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <system_error>

// blook-kchannel transport (user side), deliberately reduced to the few
// operations the SDK needs. The public SDK headers never include a kchannel
// header; the implementation lives in src/ipc/kchannel_client.cc and is linked
// into blook-sdk.
namespace blook::transport {

inline constexpr uint32_t bootstrap_size = 0x90;
// 256 KiB region => 128 KiB rings, which is what the 40 KiB dump replies need.
inline constexpr uint32_t default_region_size = 0x40000;

struct attach_options {
    uint32_t region_size{default_region_size};
    uint32_t mode{0};  // 0 = mapped (default), 1 = copy
    uint32_t peer_pid{0};
    const char* debug_tag{nullptr};
};

// Owns a kchannel client. Move-only; destroying it detaches (BYE + unmap).
class attachment final {
   public:
    attachment() = default;
    attachment(const attachment&) = delete;
    attachment& operator=(const attachment&) = delete;
    attachment(attachment&&) noexcept;
    attachment& operator=(attachment&&) noexcept;
    ~attachment();

    [[nodiscard]] void* handle() const noexcept { return impl_; }
    [[nodiscard]] explicit operator bool() const noexcept { return impl_ != nullptr; }

   private:
    friend std::unique_ptr<attachment> begin(const attach_options&,
                                             std::error_code&);
    friend void detach(std::unique_ptr<attachment> value);
    void reset();
    void* impl_{};
};

// Creates the anonymous section, fills the bootstrap descriptor and generates
// the session key. Nothing is visible to the kernel yet.
std::unique_ptr<attachment> begin(const attach_options& options,
                                  std::error_code& error);

// The bootstrap descriptor to hand to the manual-map loader (0x90 bytes).
std::span<const std::byte> bootstrap(const attachment& value);
uint32_t peer_pid(const attachment& value);

// Waits for the driver to publish READY and completes the HELLO handshake.
std::error_code finish(attachment& value, uint32_t timeout_ms);

// Synchronous CALL/REPLY. `status` is the handler's status (KC_OK == success).
int call(attachment& value, uint16_t op, const void* in, uint32_t in_len,
         void* out, uint32_t out_cap, uint32_t* out_len, uint32_t timeout_ms);

// Best effort BYE + resource release.
void detach(std::unique_ptr<attachment> value);

// Registry/SCM helpers for the service-load development path (sc create/start).
// They are what the loader CLI and the e2e runner use; a manual-map client never
// calls them.
std::error_code write_service_bootstrap(const std::wstring& service_name,
                                        const attachment& value);
std::error_code install_service(const std::wstring& service_name,
                                const std::wstring& image_path);
std::error_code start_service(const std::wstring& service_name);
std::error_code stop_service(const std::wstring& service_name);
std::error_code delete_service(const std::wstring& service_name);
std::error_code set_service_dword(const std::wstring& service_name,
                                  const std::wstring& name, uint32_t value);

}  // namespace blook::transport
