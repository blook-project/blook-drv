#pragma once
#include <ntifs.h>

#include "policy/configuration.hpp"

namespace blook::configuration {
struct load_error {
    NTSTATUS status{};
    parse_error parse{};
    bool path_configured{};
};
// PASSIVE_LEVEL only. RegistryPath is the DriverEntry argument (the service
// key), not a hard-coded service name. Parameters\\ConfigPath is REG_SZ.
// Missing key/value => safe empty snapshot. Any configured-path failure is
// returned, never converted to defaults. No writes or feature publication.
// Only \\??\\X:\\... local absolute paths; no UNC, device namespaces, relative
// paths, alternate streams, dot components or reparse traversal are accepted.
NTSTATUS load_candidate(PCUNICODE_STRING registry_path, snapshot& output,
                        load_error& error) noexcept;
}  // namespace blook::configuration
