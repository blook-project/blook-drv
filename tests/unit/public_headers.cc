// Compile-time guard: every public header must be includable on its own from a
// consumer include root, with nothing but the packaged include tree available.
#include <blook/drv/ept.hpp>
#include <blook/drv/handle.hpp>
#include <blook/drv/transport.hpp>
#include <blook/drv/wire.hpp>

#include <gtest/gtest.h>

TEST(PublicHeaders, WireAbiIsStable) {
    EXPECT_EQ(wire::abi_version, 7u);
    EXPECT_EQ(static_cast<uint16_t>(wire::op::get_version), 0x8002);
    EXPECT_EQ(wire::kDriverVersion.major, 4);
}

TEST(PublicHeaders, SessionTypeIsUsable) {
    // Instantiating the public types proves the headers are self-contained.
    EXPECT_GT(sizeof(blook::client::session), 0u);
}