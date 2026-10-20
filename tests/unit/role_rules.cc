#include <gtest/gtest.h>

#include "policy/configuration.hpp"
#include "policy/role_rules.hpp"

namespace {
using blook::role;
using blook::configuration::snapshot;

template <class Char, size_t N>
role classify(const snapshot& state, const Char (&path)[N]) {
    return blook::role_rules::classify(path, N - 1, state.roles,
                                       state.role_count);
}

TEST(RoleRules, EmptyRulesDoNotUseLegacyNames) {
    const snapshot state{};
    EXPECT_EQ(classify(state, L"C:\\tools\\x64dbg.exe"), role::other);
    EXPECT_EQ(classify(state, L"test_app.exe"), role::other);
}

TEST(RoleRules, MatchesAsciiBasenameExactlyIgnoringCase) {
    snapshot state{};
    state.role_count = 1;
    state.roles[0] = {role::target, "sample.exe"};
    EXPECT_EQ(classify(state, L"C:\\folder\\SaMpLe.ExE"), role::target);
    EXPECT_EQ(classify(state, "/folder/SAMPLE.EXE"), role::target);
    EXPECT_EQ(classify(state, "sample.exe"), role::target);
    EXPECT_EQ(classify(state, "prefix-sample.exe"), role::other);
    EXPECT_EQ(classify(state, "sample.exe.bak"), role::other);
    EXPECT_EQ(classify(state, "C:\\sample.exe\\other.exe"), role::other);
    EXPECT_EQ(classify(state, "C:\\sample.exe\\"), role::other);
    EXPECT_EQ(classify(state, L"s\u00e1mple.exe"), role::other);
    EXPECT_EQ(classify(state, "sample.exe\0suffix"), role::other);
}

TEST(RoleRules, ReplacementAndCountDoNotRetainOldRules) {
    snapshot state{};
    state.role_count = 2;
    state.roles[0] = {role::tool, "debugger.exe"};
    state.roles[1] = {role::watched, "monitor.exe"};
    EXPECT_EQ(classify(state, "debugger.exe"), role::tool);
    EXPECT_EQ(classify(state, "monitor.exe"), role::watched);
    snapshot replacement{};
    replacement.role_count = 1;
    replacement.roles[0] = {role::target, "new.exe"};
    state = replacement;
    EXPECT_EQ(classify(state, "debugger.exe"), role::other);
    EXPECT_EQ(classify(state, "monitor.exe"), role::other);
    EXPECT_EQ(classify(state, "new.exe"), role::target);
    state.role_count = 0;
    EXPECT_EQ(classify(state, "new.exe"), role::other);
}

TEST(RoleRules, InvalidRulesAndCountsFailClosed) {
    snapshot state{};
    state.role_count = 1;
    state.roles[0] = {role::target, ""};
    EXPECT_EQ(classify(state, ""), role::other);
    state.roles[0] = {role::target, "folder/sample.exe"};
    EXPECT_EQ(classify(state, "folder/sample.exe"), role::other);
    state.roles[0] = {role::target, "s\xe1mple.exe"};
    EXPECT_EQ(classify(state, "s\xe1mple.exe"), role::other);
    for (auto& c : state.roles[0].name)
        c = 'x';
    EXPECT_FALSE(blook::role_rules::matches("x", 1, state.roles[0].name));
    state.roles[0] = {static_cast<role>(255), "sample.exe"};
    EXPECT_EQ(classify(state, "sample.exe"), role::other);
    state.roles[0] = {role::tool, "sample.exe"};
    state.role_count = 33;
    EXPECT_EQ(classify(state, "sample.exe"), role::other);
}

TEST(RoleRules, ParsedSnapshotFeedsExactNameRules) {
    constexpr char ini[] =
        "[roles]\ntarget=sample.exe\ntool=debugger.exe\nwatched=monitor.exe\n";
    snapshot state{};
    blook::configuration::parse_error error{};
    ASSERT_TRUE(
        blook::configuration::parse(ini, sizeof(ini) - 1, state, error));
    EXPECT_EQ(classify(state, L"C:\\folder\\SAMPLE.EXE"), role::target);
    EXPECT_EQ(classify(state, "debugger.exe"), role::tool);
    EXPECT_EQ(classify(state, "monitor.exe"), role::watched);
    EXPECT_EQ(classify(state, "debugger.exe.bak"), role::other);
}

TEST(RoleRules, MaximumLengthNameRequiresFullExactMatch) {
    snapshot state{};
    state.role_count = 1;
    state.roles[0].value = role::target;
    char path[64]{};
    for (size_t i = 0; i < 63; ++i) {
        state.roles[0].name[i] = 'a';
        path[i] = 'A';
    }
    EXPECT_EQ(classify(state, path), role::target);
    EXPECT_EQ(
        blook::role_rules::classify(path, 15, state.roles, state.role_count),
        role::other);
    EXPECT_EQ(blook::role_rules::classify(static_cast<const char*>(nullptr), 63,
                                          state.roles, state.role_count),
              role::other);
}

TEST(RoleRules, LastSlotAndDeclarationOrderAreDeterministic) {
    snapshot state{};
    state.role_count = 32;
    state.roles[31] = {role::watched, "last.exe"};
    EXPECT_EQ(classify(state, "last.exe"), role::watched);
    state.roles[0] = {role::target, "LAST.EXE"};
    EXPECT_EQ(classify(state, "last.exe"), role::target);
    state.role_count = 31;
    state.roles[0] = {};
    EXPECT_EQ(classify(state, "last.exe"), role::other);
}
}  // namespace
