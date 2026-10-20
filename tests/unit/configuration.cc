#include <gtest/gtest.h>
#include <cstring>
#include <string>

#include "policy/configuration.hpp"

namespace {
using namespace blook::configuration;
bool parse_text(const std::string& text, snapshot& out, parse_error& error) {
    return parse(text.data(), text.size(), out, error);
}
void rejects(const std::string& text, error_code code, uint32_t line) {
    snapshot out{};
    out.allow_users = true;
    out.feature_mask = 0x1234;
    out.role_count = 1;
    out.roles[0].value = blook::role::tool;
    std::strcpy(out.roles[0].name, "sentinel.exe");
    parse_error error{};
    ASSERT_FALSE(parse_text(text, out, error));
    EXPECT_EQ(error.code, code);
    EXPECT_EQ(error.line, line);
    EXPECT_TRUE(out.allow_users);
    EXPECT_EQ(out.feature_mask, 0x1234u);
    EXPECT_EQ(out.role_count, 1u);
    EXPECT_STREQ(out.roles[0].name, "sentinel.exe");
}
}  // namespace
TEST(Configuration, EmptyIsSafeFullReplacement) {
    snapshot out{};
    out.allow_users = true;
    out.feature_mask = ~uint64_t{};
    out.role_count = 12;
    parse_error error{};
    ASSERT_TRUE(parse(nullptr, 0, out, error));
    EXPECT_FALSE(out.allow_users);
    EXPECT_EQ(out.feature_mask, 0u);
    EXPECT_EQ(out.role_count, 0u);
    EXPECT_EQ(error.code, error_code::none);
}
TEST(Configuration, ValidBomCrlfFeaturesAndRoles) {
    snapshot out{};
    parse_error error{};
    ASSERT_TRUE(parse_text(
        "\xef\xbb\xbf# UTF8 comment: \xe4\xb8\xad\xe6\x96\x87\r\n[device]\r\n "
        "allow_users = true \r\n"
        "[features]\r\nnt.query_process=true\r\nwindow.find=false\r\n[roles]"
        "\r\ntarget=Sample.EXE\r\n"
        "tool=x64dbg.exe\r\nwatched=taskmgr.exe",
        out, error));
    EXPECT_TRUE(out.allow_users);
    EXPECT_EQ(out.feature_mask,
              blook::feature::bit(blook::feature::id::query_process));
    ASSERT_EQ(out.role_count, 3u);
    EXPECT_STREQ(out.roles[0].name, "sample.exe");
    EXPECT_EQ(out.roles[0].value, blook::role::target);
    EXPECT_EQ(out.roles[1].value, blook::role::tool);
    EXPECT_EQ(out.roles[2].value, blook::role::watched);
}
TEST(Configuration, RestartOnlySettings) {
    snapshot out{};
    parse_error error{};
    ASSERT_TRUE(parse(nullptr, 0, out, error));
    EXPECT_TRUE(out.hide_timing);
    EXPECT_EQ(out.page_fault_trace, 0u);
    ASSERT_TRUE(parse_text(
        "[hypervisor]\nhide_timing=false\n[diagnostics]\npage_fault_trace=2",
        out, error));
    EXPECT_FALSE(out.hide_timing);
    EXPECT_EQ(out.page_fault_trace, 2u);
    rejects("[hypervisor]\nhide_timing=1", error_code::invalid_boolean, 2);
    rejects("[hypervisor]\nhide_timing=true\nhide_timing=false",
            error_code::duplicate_key, 3);
    rejects("[diagnostics]\npage_fault_trace=3", error_code::invalid_value, 2);
    rejects("[diagnostics]\npage_fault_trace=-1", error_code::invalid_value, 2);
    rejects("[diagnostics]\npage_fault_trace=01", error_code::invalid_value, 2);
    rejects("[diagnostics]\npage_fault_trace=0\npage_fault_trace=1",
            error_code::duplicate_key, 3);
    snapshot workspace{};
    ASSERT_TRUE(parse_with_workspace("", 0, out, error, workspace));
    ASSERT_FALSE(parse_with_workspace("", 0, out, error, out));
    EXPECT_EQ(error.code, error_code::invalid_argument);
}
TEST(Configuration, EveryFeatureUsesStableName) {
    for (const auto& feature : blook::feature::descriptors) {
        snapshot out{};
        parse_error error{};
        ASSERT_TRUE(parse_text(
            std::string("[features]\n") + feature.name + "=true", out, error));
        EXPECT_EQ(out.feature_mask, blook::feature::bit(feature.value));
    }
}
TEST(Configuration, ErrorsArePreciseAndTransactional) {
    rejects("[device]\nallow_users=1", error_code::invalid_boolean, 2);
    rejects("[features]\nunknown=true", error_code::unknown_key, 2);
    rejects("[roles]\npid=1234", error_code::unknown_key, 2);
    rejects("[device]\nallow_users=true\nallow_users=false",
            error_code::duplicate_key, 3);
    rejects("[features]\nwindow.find=false\nwindow.find=true",
            error_code::duplicate_key, 3);
    rejects("[roles]\ntarget=FOO.exe\ntool=foo.exe", error_code::duplicate_name,
            3);
    rejects("[invalid]", error_code::unknown_section, 1);
    rejects("[device", error_code::syntax, 1);
    rejects("[device]\nallow_users=true # inline", error_code::invalid_boolean,
            2);
    rejects("[hooks]\nmask=3", error_code::migration_required, 1);
    rejects("hooks.mask=3", error_code::migration_required, 1);
    rejects("hooks=3", error_code::migration_required, 1);
    rejects("[roles]\ntarget=42", error_code::migration_required, 2);
    rejects("[roles]\ntool=00042", error_code::migration_required, 2);
    rejects("[roles]\nwatched=0", error_code::migration_required, 2);
    rejects("[roles]\ntarget=\xe4\xb8\xad.exe", error_code::unsupported_name,
            2);
    rejects("[roles]\ntarget=C:\\foo.exe", error_code::unsupported_name, 2);
    rejects("[roles]\ntarget=*.exe", error_code::unsupported_name, 2);
    rejects("[roles]\ntarget=..", error_code::unsupported_name, 2);
    rejects("[roles]\ntarget=", error_code::unsupported_name, 2);
}
TEST(Configuration, StrictUtf8EvenInComments) {
    const std::string invalid[] = {"\x80",
                                   "\xc0\xaf",
                                   "\xe0\x80\x80",
                                   "\xed\xa0\x80",
                                   "\xf0\x80\x80\x80",
                                   "\xf4\x90\x80\x80",
                                   "\xf5\x80\x80\x80",
                                   "\xe4\xb8",
                                   "\xc2x"};
    for (const auto& s : invalid)
        rejects("#valid\n#" + s, error_code::invalid_utf8, 2);
    rejects(std::string("#\0ignored", 9), error_code::embedded_nul, 1);
    rejects("#ok\r#\x80", error_code::invalid_utf8, 2);
    rejects("#ok\r\n#\x80", error_code::invalid_utf8, 2);
}
TEST(Configuration, AllCapacityBoundaries) {
    snapshot out{};
    parse_error error{};
    ASSERT_TRUE(parse_text(
        "[roles]\ntarget=" + std::string(max_name_bytes, 'a'), out, error));
    rejects("[roles]\ntarget=" + std::string(max_name_bytes + 1, 'a'),
            error_code::name_too_long, 2);
    std::string roles = "[roles]\n";
    for (size_t i = 0; i < max_roles; ++i)
        roles += "target=sample" + std::to_string(i) + ".exe\n";
    ASSERT_TRUE(parse_text(roles, out, error));
    EXPECT_EQ(out.role_count, max_roles);
    rejects(roles + "target=overflow.exe", error_code::too_many_roles,
            static_cast<uint32_t>(max_roles + 2));
    ASSERT_TRUE(
        parse_text("#" + std::string(max_file_bytes - 1, 'a'), out, error));
    rejects(std::string(max_file_bytes + 1, 'a'), error_code::file_too_large,
            0);
    ASSERT_FALSE(parse(nullptr, 1, out, error));
    EXPECT_EQ(error.code, error_code::invalid_argument);
}

#include "policy/configuration_transition.hpp"

TEST(ConfigurationTransition,
     RestartFieldsRejectWholeCandidateBeforeApplyingAnything) {
    using namespace blook::configuration;
    for (int setting = 0; setting < 3; ++setting) {
        snapshot current;
        current.feature_mask = 1;
        auto candidate = current;
        candidate.feature_mask = 2;
        if (setting == 0)
            candidate.allow_users = true;
        if (setting == 1)
            candidate.hide_timing = false;
        if (setting == 2)
            candidate.page_fault_trace = 1;
        uint64_t generation = 7;
        bool called = false;
        EXPECT_EQ(commit(current, generation, candidate,
                         [&](const snapshot&) {
                             called = true;
                             return true;
                         }),
                  transition::restart_required);
        EXPECT_FALSE(called);
        EXPECT_EQ(generation, 7u);
        EXPECT_EQ(current.feature_mask, 1u);
    }
}
TEST(ConfigurationTransition, RejectedBackendKeepsSnapshotAndGeneration) {
    using namespace blook::configuration;
    snapshot current;
    current.feature_mask = 1;
    auto candidate = current;
    candidate.feature_mask = 2;
    candidate.role_count = 1;
    candidate.roles[0].value = blook::role::tool;
    candidate.roles[0].name[0] = 'x';
    uint64_t generation = 7;
    EXPECT_EQ(commit(current, generation, candidate,
                     [](const snapshot&) { return false; }),
              transition::rejected);
    EXPECT_EQ(generation, 7u);
    EXPECT_EQ(current.feature_mask, 1u);
    EXPECT_EQ(current.role_count, 0u);
    EXPECT_EQ(commit(current, generation, candidate,
                     [](const snapshot&) { return true; }),
              transition::applied);
    EXPECT_EQ(generation, 8u);
    EXPECT_EQ(current.feature_mask, 2u);
    EXPECT_EQ(current.role_count, 1u);
    EXPECT_EQ(current.roles[0].name[0], 'x');
}
TEST(ConfigurationTransition, GenerationNeverWrapsOrAppliesAtExhaustion) {
    using namespace blook::configuration;
    snapshot current, candidate;
    candidate.feature_mask = 2;
    uint64_t generation = ~uint64_t{};
    bool called = false;
    EXPECT_EQ(commit(current, generation, candidate,
                     [&](const snapshot&) {
                         called = true;
                         return true;
                     }),
              transition::generation_exhausted);
    EXPECT_FALSE(called);
    EXPECT_EQ(current.feature_mask, 0u);
    EXPECT_EQ(generation, ~uint64_t{});
}
