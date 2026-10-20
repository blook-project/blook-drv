#pragma once
#include <stddef.h>

#include "policy/names.hpp"

namespace blook::role_rules {
// Full paths are accepted as input, but rules are ASCII basenames, never
// substrings. Bounded names without a terminator are invalid rather than
// silently truncated. No allocation or kernel dependencies.
template <class Char, size_t Capacity>
[[nodiscard]] constexpr bool matches(const Char* path, size_t length,
                                     const char (&name)[Capacity]) noexcept {
    if (!path || !length)
        return false;
    size_t start = 0;
    for (size_t i = 0; i < length; ++i) {
        if (!path[i])
            return false;
        if (path[i] == '\\' || path[i] == '/')
            start = i + 1;
    }
    size_t count = 0;
    while (count < Capacity && name[count]) {
        const auto value = static_cast<unsigned char>(name[count]);
        if (value > 127 || name[count] == '\\' || name[count] == '/')
            return false;
        ++count;
    }
    if (!count || count == Capacity || count != length - start)
        return false;
    for (size_t i = 0; i < count; ++i) {
        const auto value = static_cast<unsigned long>(path[start + i]);
        if (value > 127 ||
            ascii_lower(static_cast<char>(value)) != ascii_lower(name[i]))
            return false;
    }
    return true;
}

// Declaration order determines precedence for duplicate basenames. An invalid
// count fails closed instead of reading beyond the fixed-size rule array.
template <class Char, class Rule, size_t Capacity>
[[nodiscard]] constexpr role classify(const Char* path, size_t length,
                                      const Rule (&rules)[Capacity],
                                      size_t count) noexcept {
    if (count > Capacity)
        return role::other;
    for (size_t i = 0; i < count; ++i) {
        const auto value = rules[i].value;
        if (value != role::target && value != role::tool &&
            value != role::watched)
            continue;
        if (matches(path, length, rules[i].name))
            return value;
    }
    return role::other;
}
}  // namespace blook::role_rules
