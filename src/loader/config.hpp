#pragma once

#include "cli.hpp"
#include "policy/configuration.hpp"

namespace blook::loader::cli {
using configuration = blook::configuration::snapshot;
struct config_error {
    std::size_t line;
    std::string message;
};
// Retained portable helpers for callers; configuration syntax is parsed only by
// the shared kernel/user parser below.
[[nodiscard]] inline std::wstring_view trim(std::wstring_view text) {
    constexpr auto spaces = L" \t\r\n";
    const auto begin = text.find_first_not_of(spaces);
    return begin == text.npos
               ? std::wstring_view{}
               : text.substr(begin, text.find_last_not_of(spaces) - begin + 1);
}
[[nodiscard]] inline std::wstring lower(std::wstring_view text) {
    std::wstring result{text};
    for (auto& ch : result)
        if (ch >= L'A' && ch <= L'Z')
            ch += L'a' - L'A';
    return result;
}
[[nodiscard]] inline const char* config_error_message(
    blook::configuration::error_code code) {
    using enum blook::configuration::error_code;
    switch (code) {
        case invalid_argument:
            return "Invalid configuration buffer.";
        case file_too_large:
            return "Configuration exceeds the shared file size limit.";
        case invalid_utf8:
            return "Configuration must be valid UTF-8.";
        case embedded_nul:
            return "Embedded NUL characters are not allowed.";
        case syntax:
            return "Malformed section or key = value syntax.";
        case unknown_section:
            return "Unknown configuration section.";
        case unknown_key:
            return "Unknown configuration key or feature name.";
        case invalid_boolean:
            return "Boolean values must be true or false.";
        case duplicate_key:
            return "Duplicate configuration key.";
        case migration_required:
            return "Legacy hook masks/PID role rules are not supported; "
                   "migrate "
                   "to named [features] entries and exact executable "
                   "basenames.";
        case invalid_value:
            return "Invalid setting value; page_fault_trace must be 0, 1 or 2.";
        case unsupported_name:
            return "Role rules require supported exact executable basenames.";
        case name_too_long:
            return "Role executable basename is too long.";
        case too_many_roles:
            return "Too many role rules.";
        case duplicate_name:
            return "Duplicate role executable basename.";
        default:
            return "Invalid configuration.";
    }
}
[[nodiscard]] inline std::expected<configuration, config_error> parse_config(
    std::string_view bytes) {
    configuration out{};
    blook::configuration::parse_error error{};
    if (!blook::configuration::parse(bytes.data(), bytes.size(), out, error))
        return std::unexpected(
            config_error{error.line, config_error_message(error.code)});
    return out;
}
}  // namespace blook::loader::cli
