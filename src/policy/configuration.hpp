#pragma once
#include <stddef.h>

#include "policy/features.hpp"
#include "policy/names.hpp"

// Bounded UTF-8 INI, shared by the driver and host tools; no allocation or STL.
// Full snapshots, never patches: absent features/roles are disabled/empty;
// hide_timing retains its historical true default. A UTF-8 BOM
// is accepted only at byte zero. Comments occupy a whole line (# or ;).
// [roles] has repeated target/tool/watched keys with exact ASCII basenames.
// There are no PID rules, wildcard/substring rules, quoting or inline comments.
namespace blook::configuration {
inline constexpr size_t max_file_bytes = 64 * 1024;
inline constexpr size_t max_roles = 32;
inline constexpr size_t max_name_bytes = 63;

struct role_rule {
    role value{};
    char name[max_name_bytes + 1]{};
};
struct snapshot {
    bool allow_users{};
    bool hide_timing{true};       // Restart-only; preserves the former default.
    uint32_t page_fault_trace{};  // Restart-only: 0=off, 1=record+reflect,
                                  // 2=reflect only.
    uint64_t feature_mask{};
    uint32_t role_count{};
    role_rule roles[max_roles]{};
};
inline void reset(snapshot& value) noexcept {
    value.allow_users = false;
    value.hide_timing = true;
    value.page_fault_trace = 0;
    value.feature_mask = 0;
    value.role_count = 0;
    for (auto& rule : value.roles) {
        rule.value = role::other;
        for (auto& c : rule.name)
            c = 0;
    }
}
enum class error_code : uint8_t {
    none,
    invalid_argument,
    file_too_large,
    invalid_utf8,
    embedded_nul,
    syntax,
    unknown_section,
    unknown_key,
    invalid_boolean,
    duplicate_key,
    migration_required,
    unsupported_name,
    name_too_long,
    too_many_roles,
    duplicate_name,
    invalid_value
};
struct parse_error {
    error_code code{};
    uint32_t line{};  // One-based; zero for non-text argument/size errors.
};
namespace detail {
struct view {
    const char* data;
    size_t size;
};
inline bool equal(view a, const char* b) noexcept {
    size_t n = 0;
    while (b[n])
        ++n;
    if (a.size != n)
        return false;
    for (size_t i = 0; i < n; ++i)
        if (a.data[i] != b[i])
            return false;
    return true;
}
inline view trim(view v) noexcept {
    while (v.size && (v.data[0] == ' ' || v.data[0] == '\t')) {
        ++v.data;
        --v.size;
    }
    while (v.size && (v.data[v.size - 1] == ' ' || v.data[v.size - 1] == '\t'))
        --v.size;
    return v;
}
inline bool fail(parse_error& e, error_code code, uint32_t line) noexcept {
    e = {code, line};
    return false;
}
// Validate every byte, including comments and otherwise ignored whitespace.
inline bool utf8(const char* bytes, size_t size, parse_error& e) noexcept {
    uint32_t line = 1;
    for (size_t i = 0; i < size;) {
        const auto c = static_cast<uint8_t>(bytes[i]);
        if (!c)
            return fail(e, error_code::embedded_nul, line);
        if (c < 0x80) {
            if (c == '\n' ||
                (c == '\r' && (i + 1 == size || bytes[i + 1] != '\n')))
                ++line;
            ++i;
            continue;
        }
        size_t n;
        uint32_t scalar;
        if (c >= 0xc2 && c <= 0xdf) {
            n = 2;
            scalar = c & 31;
        } else if (c >= 0xe0 && c <= 0xef) {
            n = 3;
            scalar = c & 15;
        } else if (c >= 0xf0 && c <= 0xf4) {
            n = 4;
            scalar = c & 7;
        } else
            return fail(e, error_code::invalid_utf8, line);
        if (size - i < n)
            return fail(e, error_code::invalid_utf8, line);
        for (size_t j = 1; j < n; ++j) {
            const auto d = static_cast<uint8_t>(bytes[i + j]);
            if ((d & 0xc0) != 0x80)
                return fail(e, error_code::invalid_utf8, line);
            scalar = (scalar << 6) | (d & 63);
        }
        if ((n == 2 && scalar < 0x80) || (n == 3 && scalar < 0x800) ||
            (n == 4 && scalar < 0x10000) || scalar > 0x10ffff ||
            (scalar >= 0xd800 && scalar <= 0xdfff))
            return fail(e, error_code::invalid_utf8, line);
        i += n;
    }
    return true;
}
inline bool boolean(view v, bool& out) noexcept {
    if (equal(v, "true")) {
        out = true;
        return true;
    }
    if (equal(v, "false")) {
        out = false;
        return true;
    }
    return false;
}
}  // namespace detail

// Output is untouched on every failure. Do not pass an active snapshot without
// external synchronization: parsing is intentionally independent of
// publication.
// workspace must be distinct from output; its contents are disposable. Kernel
// callers can supply pool storage to avoid a full snapshot on the kernel stack.
inline bool parse_with_workspace(const char* bytes, size_t length,
                                 snapshot& output, parse_error& error,
                                 snapshot& candidate) noexcept {
    using namespace detail;
    error = {};
    if ((!bytes && length) || &output == &candidate)
        return fail(error, error_code::invalid_argument, 0);
    if (length > max_file_bytes)
        return fail(error, error_code::file_too_large, 0);
    if (!utf8(bytes, length, error))
        return false;
    reset(candidate);
    enum class section {
        none,
        device,
        features,
        roles,
        hypervisor,
        diagnostics
    } current = section::none;
    bool seen_device = false;
    bool seen_hide_timing = false;
    bool seen_page_fault_trace = false;
    uint64_t seen_features = 0;
    size_t offset = 0;
    if (length >= 3 && static_cast<uint8_t>(bytes[0]) == 0xef &&
        static_cast<uint8_t>(bytes[1]) == 0xbb &&
        static_cast<uint8_t>(bytes[2]) == 0xbf)
        offset = 3;
    uint32_t line_number = 0;
    while (offset < length) {
        ++line_number;
        const size_t start = offset;
        while (offset < length && bytes[offset] != '\n' &&
               bytes[offset] != '\r')
            ++offset;
        view line = trim({bytes + start, offset - start});
        if (offset < length && bytes[offset++] == '\r' && offset < length &&
            bytes[offset] == '\n')
            ++offset;
        if (!line.size || line.data[0] == '#' || line.data[0] == ';')
            continue;
        if (line.data[0] == '[') {
            if (line.size < 3 || line.data[line.size - 1] != ']')
                return fail(error, error_code::syntax, line_number);
            const view name = trim({line.data + 1, line.size - 2});
            if (equal(name, "hooks"))
                return fail(error, error_code::migration_required, line_number);
            if (equal(name, "device"))
                current = section::device;
            else if (equal(name, "features"))
                current = section::features;
            else if (equal(name, "roles"))
                current = section::roles;
            else if (equal(name, "hypervisor"))
                current = section::hypervisor;
            else if (equal(name, "diagnostics"))
                current = section::diagnostics;
            else
                return fail(error, error_code::unknown_section, line_number);
            continue;
        }
        size_t sep = 0;
        while (sep < line.size && line.data[sep] != '=')
            ++sep;
        if (!sep || sep == line.size)
            return fail(error, error_code::syntax, line_number);
        const view key = trim({line.data, sep});
        const view value = trim({line.data + sep + 1, line.size - sep - 1});
        if (equal(key, "hooks") || equal(key, "hooks.mask") ||
            equal(key, "hook_mask"))
            return fail(error, error_code::migration_required, line_number);
        if (current == section::device) {
            if (!equal(key, "allow_users"))
                return fail(error, error_code::unknown_key, line_number);
            if (seen_device)
                return fail(error, error_code::duplicate_key, line_number);
            if (!boolean(value, candidate.allow_users))
                return fail(error, error_code::invalid_boolean, line_number);
            seen_device = true;
        } else if (current == section::hypervisor) {
            if (!equal(key, "hide_timing"))
                return fail(error, error_code::unknown_key, line_number);
            if (seen_hide_timing)
                return fail(error, error_code::duplicate_key, line_number);
            if (!boolean(value, candidate.hide_timing))
                return fail(error, error_code::invalid_boolean, line_number);
            seen_hide_timing = true;
        } else if (current == section::diagnostics) {
            if (!equal(key, "page_fault_trace"))
                return fail(error, error_code::unknown_key, line_number);
            if (seen_page_fault_trace)
                return fail(error, error_code::duplicate_key, line_number);
            if (value.size != 1 || value.data[0] < '0' || value.data[0] > '2')
                return fail(error, error_code::invalid_value, line_number);
            candidate.page_fault_trace =
                static_cast<uint32_t>(value.data[0] - '0');
            seen_page_fault_trace = true;
        } else if (current == section::features) {
            uint64_t mask = 0;
            for (const auto& descriptor : feature::descriptors)
                if (equal(key, descriptor.name)) {
                    mask = feature::bit(descriptor.value);
                    break;
                }
            if (!mask)
                return fail(error, error_code::unknown_key, line_number);
            if (seen_features & mask)
                return fail(error, error_code::duplicate_key, line_number);
            bool enabled;
            if (!boolean(value, enabled))
                return fail(error, error_code::invalid_boolean, line_number);
            seen_features |= mask;
            if (enabled)
                candidate.feature_mask |= mask;
        } else if (current == section::roles) {
            role r;
            if (equal(key, "target"))
                r = role::target;
            else if (equal(key, "tool"))
                r = role::tool;
            else if (equal(key, "watched"))
                r = role::watched;
            else
                return fail(error, error_code::unknown_key, line_number);
            if (!value.size)
                return fail(error, error_code::unsupported_name, line_number);
            if (value.size > max_name_bytes)
                return fail(error, error_code::name_too_long, line_number);
            // A decimal-only value is an ambiguous legacy PID, not a name.
            bool numeric = true;
            for (size_t i = 0; i < value.size; ++i)
                if (value.data[i] < '0' || value.data[i] > '9')
                    numeric = false;
            if (numeric)
                return fail(error, error_code::migration_required, line_number);
            // Conservative basename alphabet: never truncate/decode non-ASCII.
            for (size_t i = 0; i < value.size; ++i) {
                const char c = value.data[i];
                if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') || c == '.' || c == '_' ||
                      c == '-'))
                    return fail(error, error_code::unsupported_name,
                                line_number);
            }
            if (equal(value, ".") || equal(value, "..") ||
                value.data[value.size - 1] == '.')
                return fail(error, error_code::unsupported_name, line_number);
            for (uint32_t i = 0; i < candidate.role_count; ++i) {
                bool same = true;
                for (size_t j = 0; j <= value.size; ++j) {
                    const char c =
                        j == value.size ? '\0' : ascii_lower(value.data[j]);
                    if (candidate.roles[i].name[j] != c) {
                        same = false;
                        break;
                    }
                }
                if (same)
                    return fail(error, error_code::duplicate_name, line_number);
            }
            if (candidate.role_count == max_roles)
                return fail(error, error_code::too_many_roles, line_number);
            auto& rule = candidate.roles[candidate.role_count++];
            rule.value = r;
            for (size_t i = 0; i < value.size; ++i)
                rule.name[i] = ascii_lower(value.data[i]);
        } else
            return fail(error, error_code::unknown_section, line_number);
    }
    output = candidate;
    return true;
}
inline bool parse(const char* bytes, size_t length, snapshot& output,
                  parse_error& error) noexcept {
    snapshot workspace{};
    return parse_with_workspace(bytes, length, output, error, workspace);
}
}  // namespace blook::configuration
