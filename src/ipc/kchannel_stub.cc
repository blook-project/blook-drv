// Link-time stand-in for the blook-kchannel user library, used only while the
// transport repository has not published its sources (its headers are already
// enough to compile this adapter, but the kc_* entry points live in that
// repository).
//
// The build defines BLOOK_KCHANNEL_STUB only when <kchannel_dir>/src/user does
// not exist. Every call reports "unsupported": no test can accidentally pass by
// talking to this file, because the host SDK tests inject the fake transport
// through detail::connection::test_call and never reach the real attachment.
#include <cstring>

#include "blook/kchannel.h"

extern "C" {

kc_status kc_attach(const kc_attach_opts*, kc_client**) {
    return KC_ERR_UNSUPPORTED;
}

kc_status kc_get_bootstrap(kc_client*, kc_bootstrap* out) {
    if (out)
        std::memset(out, 0, sizeof(*out));
    return KC_ERR_UNSUPPORTED;
}

kc_status kc_attach_finish(kc_client*, uint32_t) {
    return KC_ERR_UNSUPPORTED;
}

void kc_detach(kc_client*) {}

kc_status kc_call(kc_client*, uint16_t, const void*, uint32_t, void*, uint32_t,
                  uint32_t* out_len, uint32_t) {
    if (out_len)
        *out_len = 0;
    return KC_ERR_UNSUPPORTED;
}

kc_status kc_ping(kc_client*, uint32_t) {
    return KC_ERR_UNSUPPORTED;
}

uint32_t kc_state(kc_client*) {
    return KC_STATE_DEAD;
}

const char* kc_status_str(kc_status) {
    return "KC_ERR_UNSUPPORTED";
}

uint32_t kc_state_error(kc_client*) {
    return KC_ERR_UNSUPPORTED;
}

uint64_t kc_attach_id(kc_client*) {
    return 0;
}

kc_status kc_tick(kc_client*) {
    return KC_ERR_UNSUPPORTED;
}

void kc_set_event_handler(kc_client*, kc_event_fn, void*) {}

void kc_get_stats(kc_client*, kc_client_stats* out) {
    if (out)
        std::memset(out, 0, sizeof(*out));
}

}  // extern "C"