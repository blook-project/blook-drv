#include "configuration_state.hpp"

#include "configuration.hpp"
#include "policy/configuration_transition.hpp"
#include "features.hpp"
#include "hide/roles.hpp"
#include "resources.hpp"

namespace blook::configuration_state {
namespace {
EX_PUSH_LOCK lock{};
UNICODE_STRING service_path{};
configuration::snapshot current{};
uint64_t generation{};
NTSTATUS last_status{};
uint32_t error_line{};
bool restart_required{};
wire::ConfigurationResponse response() {
    wire::ConfigurationResponse value{};
    value.header = {wire::abi_version, sizeof(value)};
    value.generation = generation;
    value.features = current.feature_mask;
    value.allow_users = current.allow_users ? 1u : 0u;
    value.restart_required = restart_required ? 1u : 0u;
    value.last_status = last_status;
    value.error_line = error_line;
    return value;
}
}  // namespace
NTSTATUS initialize(PCUNICODE_STRING path) {
    if (!path || !path->Buffer || !path->Length || path->Length > 32764)
        return STATUS_INVALID_PARAMETER;
    service_path.Buffer = static_cast<PWCH>(
        ExAllocatePool2(POOL_FLAG_PAGED, path->Length + sizeof(WCHAR), 'cfkB'));
    if (!service_path.Buffer)
        return STATUS_INSUFFICIENT_RESOURCES;
    service_path.Length = path->Length;
    service_path.MaximumLength = path->Length + sizeof(WCHAR);
    RtlCopyMemory(service_path.Buffer, path->Buffer, path->Length);
    service_path.Buffer[path->Length / sizeof(WCHAR)] = L'\0';
    configuration::load_error error{};
    last_status = configuration::load_candidate(&service_path, current, error);
    error_line = error.parse.line;
    return last_status;
}
NTSTATUS activate() {
    const auto applied = features::set_policy(current);
    last_status = applied.status;
    if (!NT_SUCCESS(last_status))
        return last_status;
    generation = 1;
    return STATUS_SUCCESS;
}
bool allow_users() {
    return current.allow_users;
}
bool hide_timing() {
    return current.hide_timing;
}
uint32_t page_fault_trace() {
    return current.page_fault_trace;
}
wire::ConfigurationResponse query() {
    exclusive_lock guard{lock};
    return response();
}
wire::ConfigurationResponse reload() {
    exclusive_lock guard{lock};
    error_line = 0;
    restart_required = false;
    // Allocate the candidate rather than putting a full rule table on the
    // limited kernel stack. Failed parsing/application leaves current intact.
    auto* candidate = allocate_object<configuration::snapshot>();
    if (!candidate) {
        last_status = STATUS_INSUFFICIENT_RESOURCES;
        return response();
    }
    configuration::load_error error{};
    last_status =
        configuration::load_candidate(&service_path, *candidate, error);
    error_line = error.parse.line;
    if (NT_SUCCESS(last_status)) {
        const auto result = configuration::commit(
            current, generation, *candidate,
            [](const configuration::snapshot& policy) {
                last_status = features::set_policy(policy).status;
                return NT_SUCCESS(last_status);
            });
        restart_required =
            result == configuration::transition::restart_required;
        if (restart_required)
            last_status = STATUS_INVALID_DEVICE_STATE;
        if (result == configuration::transition::generation_exhausted)
            last_status = STATUS_INTEGER_OVERFLOW;
    }
    delete_object(candidate);
    return response();
}
void shutdown() {
    features::shutdown();
    if (service_path.Buffer)
        ExFreePoolWithTag(service_path.Buffer, 'cfkB');
    service_path = {};
    current = {};
    generation = 0;
}
}  // namespace blook::configuration_state
