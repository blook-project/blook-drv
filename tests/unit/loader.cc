#include <gtest/gtest.h>

#include <array>
#include <initializer_list>
#include <string>
#include <string_view>

#include "loader/cli.hpp"
#include "loader/config.hpp"

namespace cli = blook::loader::cli;
namespace {
auto parse(std::initializer_list<std::wstring_view> args) {
    return cli::parse({args.begin(), args.size()});
}
void rejects(std::initializer_list<std::wstring_view> args) {
    const auto result = parse(args);
    ASSERT_TRUE((!result)) << "malformed command rejected";
    ASSERT_TRUE(
        (!result.error().message.empty() && !result.error().usage.empty()))
        << "parse failure includes explanation and usage";
}
}  // namespace

TEST(LoaderTest, EmptyArgumentsAndHelpAliasesShowHelp) {
    const auto empty = parse({});
    ASSERT_TRUE(empty.has_value());
    EXPECT_EQ(empty->action, cli::kind::help) << "no arguments shows help";
    for (const auto name : {L"help", L"--help"}) {
        const auto result = parse({name});
        ASSERT_TRUE(result.has_value());
        EXPECT_EQ(result->action, cli::kind::help) << "help aliases";
    }
}

TEST(LoaderTest, SingleCommandsAcceptNoArgumentsAndSupportHelp) {
    for (const auto name : {L"start", L"stop", L"uninstall", L"ping",
                            L"version", L"status", L"reload", L"features"}) {
        ASSERT_TRUE((parse({name}).has_value())) << "single command accepted";
        rejects({name, L"extra"});
        const auto help = parse({name, L"--help"});
        ASSERT_TRUE(help.has_value());
        EXPECT_EQ(help->action, cli::kind::help)
            << "command help has no action";
    }
}

TEST(LoaderTest, MalformedCommandsIncludeExplanationAndUsage) {
    rejects({L"unknown"});
    rejects({L"unknown", L"--help"});
    rejects({L"help", L"extra"});
    rejects({L"install"});
    rejects({L"install", L""});
    rejects({L"apply", L"a", L"b"});
}

TEST(LoaderTest, InstallPreservesQuotedPath) {
    const auto result = parse({L"install", LR"(D:\test folder\driver.sys)"});
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->path, LR"(D:\test folder\driver.sys)")
        << "quoted path preserved";
}

TEST(LoaderTest, ApplyUsesDefaultAndPreservesUnicodePath) {
    const auto defaults = parse({L"apply"});
    ASSERT_TRUE(defaults.has_value());
    EXPECT_EQ(defaults->path, L"blook.ini") << "default configuration path";
    const auto unicode = parse({L"apply", L"配置.ini"});
    ASSERT_TRUE(unicode.has_value());
    EXPECT_EQ(unicode->path, L"配置.ini") << "Unicode path preserved";
}

TEST(LoaderTest, InstallRejectsEmbeddedNul) {
    // Construct an actual embedded NUL rather than an escaped path separator.
    std::wstring nul_path = L"bad";
    nul_path.push_back(L'\0');
    nul_path += L"path";
    rejects({L"install", nul_path});
}

TEST(LoaderTest, PidRejectsInvalidInputsAndAcceptsMaximum) {
    for (const auto text : {L"0", L"-1", L"+1", L"1junk", L" 1", L"1 ",
                            L"4294967296", L"0x10", L""}) {
        ASSERT_TRUE((!cli::parse_pid(text))) << "invalid PID rejected";
        rejects({L"unpin", text});
    }
    const auto maximum = cli::parse_pid(L"4294967295");
    ASSERT_TRUE(maximum.has_value());
    EXPECT_EQ(*maximum, 0xffffffffu) << "maximum PID";
}

TEST(LoaderTest, PinParsesTypedRoleAndRejectsInvalidRole) {
    const auto result = parse({L"pin", L"target", L"42"});
    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->process_role, cli::role::target) << "typed role";
    rejects({L"pin", L"invalid", L"42"});
}

TEST(LoaderTest, ScrubRequiresArguments) {
    rejects({L"scrub"});
}

TEST(LoaderTest, HideValidatesArgumentsAndParsesModes) {
    rejects({L"hide", L"yes"});
    rejects({L"hide", L"other", L"on"});
    const auto windows = parse({L"hide", L"windows", L"off"});
    ASSERT_TRUE(windows.has_value());
    EXPECT_TRUE(windows->windows) << "window mode parsed";
    const auto off = parse({L"hide", L"off"});
    ASSERT_TRUE(off.has_value());
    EXPECT_FALSE(off->enable) << "off mode parsed";
}

TEST(LoaderTest, BytesRejectMalformedAndOversizedInputs) {
    for (const auto text : {L"", L"0", L"0x", L"GG", L"+1", L" 1", L"C3 90"})
        ASSERT_TRUE((!cli::parse_bytes(text))) << "malformed bytes rejected";
    const auto maximum = cli::parse_bytes(std::wstring(128, L'f'));
    ASSERT_TRUE(maximum.has_value());
    EXPECT_EQ(maximum->size(), 64u) << "maximum bytes accepted";
    ASSERT_TRUE((!cli::parse_bytes(std::wstring(130, L'f'))))
        << "oversize bytes rejected";
}

TEST(LoaderTest, EveryHexadecimalBytePairRoundTrips) {
    for (unsigned value = 0; value < 256; ++value) {
        constexpr std::wstring_view digits = L"0123456789abcdef";
        const std::array text{digits[value >> 4], digits[value & 15]};
        const auto bytes = cli::parse_bytes({text.data(), text.size()});
        ASSERT_TRUE((bytes && bytes->size() == 1 && (*bytes)[0] == value))
            << "all hexadecimal byte pairs roundtrip";
    }
}

TEST(LoaderTest, HookValidatesAddressAndParsesTypedFields) {
    rejects({L"hook", L"self", L"0", L"C3"});
    rejects({L"hook", L"self", L"10000000000000000", L"C3"});
    const auto hook = parse({L"hook", L"self", L"0X10000", L"C3"});
    ASSERT_TRUE((hook && hook->pid == 0 && hook->address == 0x10000 &&
                 hook->bytes[0] == 0xc3))
        << "typed command fields";
}

TEST(LoaderTest, ConfigPathRequiresOneNonemptyPath) {
    rejects({L"config-path"});
    rejects({L"config-path", L""});
    rejects({L"config-path", L"a", L"b"});
    const auto command = parse({L"config-path", L"配置.ini"});
    ASSERT_TRUE(command.has_value());
    EXPECT_EQ(command->action, cli::kind::config_path);
    EXPECT_EQ(command->path, L"配置.ini");
    std::wstring nul = L"a";
    nul.push_back(L'\0');
    rejects({L"config-path", nul});
    rejects({L"apply", nul});
}

TEST(LoaderTest, FeatureCommandsValidateNamesAndModes) {
    rejects({L"feature"});
    rejects({L"feature", L"unknown", L"on"});
    rejects({L"feature", L"window.query", L"yes"});
    rejects({L"feature", L"window.query", L"off", L"extra"});
    for (const auto& descriptor : blook::feature::descriptors) {
        const std::string_view name{descriptor.name};
        const std::wstring wide{name.begin(), name.end()};
        for (const auto mode : {L"on", L"off"}) {
            const auto command = parse({L"feature", wide, mode});
            ASSERT_TRUE(command.has_value());
            EXPECT_EQ(command->action, cli::kind::feature);
            EXPECT_EQ(command->feature_id, descriptor.value);
            EXPECT_EQ(command->enable, std::wstring_view{mode} == L"on");
        }
    }
}

TEST(LoaderTest, EmptyConfigurationUsesSafeSharedDefaults) {
    const auto config = cli::parse_config("");
    ASSERT_TRUE(config.has_value());
    EXPECT_FALSE(config->allow_users);
    EXPECT_EQ(config->feature_mask, 0u);
    EXPECT_EQ(config->role_count, 0u);
    EXPECT_TRUE(config->hide_timing);
    EXPECT_EQ(config->page_fault_trace, 0u);
}

TEST(LoaderTest, ConfigurationDelegatesToSharedUtf8Parser) {
    const auto config = cli::parse_config(
        "\xef\xbb\xbf# comment\n[device]\r\nallow_users=false\n"
        "[features]\nwindow.query=true\n[roles]\ntool=debugger.exe\n");
    ASSERT_TRUE(config.has_value());
    EXPECT_FALSE(config->allow_users);
    EXPECT_EQ(config->feature_mask,
              blook::feature::bit(blook::feature::id::window_query));
    EXPECT_EQ(config->role_count, 1u);
    EXPECT_STREQ(config->roles[0].name, "debugger.exe");
}

TEST(LoaderTest, ConfigurationErrorIncludesLineNumber) {
    const auto invalid = cli::parse_config("[device]\nallow_users=maybe\n");
    ASSERT_FALSE(invalid.has_value());
    EXPECT_EQ(invalid.error().line, 2u);
    EXPECT_FALSE(invalid.error().message.empty());
}

TEST(LoaderTest, ConfigurationRejectsLegacyAndUnknownSyntax) {
    for (const auto text :
         {"[hooks]\nhook_mask=1", "[roles]\ntool=dir/debugger.exe",
          "[future]\nsetting=anything", "[device", "invalid"})
        EXPECT_FALSE(cli::parse_config(text).has_value()) << text;
}

TEST(LoaderTest, ConfigurationParsesStartupOnlySettings) {
    for (unsigned trace = 0; trace <= 2; ++trace) {
        const auto config = cli::parse_config(
            "[hypervisor]\nhide_timing=false\n[diagnostics]\npage_fault_"
            "trace=" +
            std::to_string(trace));
        ASSERT_TRUE(config.has_value());
        EXPECT_FALSE(config->hide_timing);
        EXPECT_EQ(config->page_fault_trace, trace);
    }
    const auto invalid = cli::parse_config("[diagnostics]\npage_fault_trace=3");
    ASSERT_FALSE(invalid.has_value());
    EXPECT_EQ(invalid.error().line, 2u);
    EXPECT_NE(invalid.error().message.find("0, 1 or 2"), std::string::npos);
    EXPECT_FALSE(cli::parse_config("[hypervisor]\nhide_timing=1").has_value());
}

TEST(LoaderTest, NumericRoleRulesReportMigration) {
    const auto config = cli::parse_config("[roles]\ntool=42");
    ASSERT_FALSE(config.has_value());
    EXPECT_EQ(config.error().line, 2u);
    EXPECT_NE(config.error().message.find("PID role rules"), std::string::npos);
}

TEST(LoaderTest, ConfigurationRejectsNulAndMalformedUtf8) {
    std::string nul = "# comment";
    nul.push_back('\0');
    EXPECT_FALSE(cli::parse_config(nul).has_value());
    EXPECT_FALSE(cli::parse_config("#\xc0\xaf").has_value());
    EXPECT_FALSE(cli::parse_config(
                     std::string(blook::configuration::max_file_bytes + 1, ' '))
                     .has_value());
}

TEST(LoaderTest, LegacyStringHelpersRemainAvailable) {
    EXPECT_EQ(cli::trim(L" \t value\r\n"), L"value");
    EXPECT_EQ(cli::lower(L"AbC.exe"), L"abc.exe");
}
TEST(LoaderTest, PageQueryParsesExplicitDomainAndRejectsAmbiguousArguments) {
    auto kernel = parse({L"page", L"kernel", L"ffff800000001234"});
    ASSERT_TRUE(kernel);
    EXPECT_TRUE(kernel->kernel);
    EXPECT_EQ(kernel->pid, 0u);
    EXPECT_EQ(kernel->address, 0xffff800000001234ull);
    auto user = parse({L"page", L"42", L"0x12345"});
    ASSERT_TRUE(user);
    EXPECT_FALSE(user->kernel);
    EXPECT_EQ(user->pid, 42u);
    EXPECT_TRUE(parse({L"page", L"self", L"10000"}));
    rejects({L"page"});
    rejects({L"page", L"kernel"});
    rejects({L"page", L"0", L"10000"});
    rejects({L"page", L"self", L"0"});
    rejects({L"page", L"self", L"oops"});
    rejects({L"page", L"self", L"10000", L"extra"});
}
