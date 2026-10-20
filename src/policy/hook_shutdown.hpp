#pragma once
namespace blook {
// Shared by the real shutdown path and its host regression. unpatch/stop must
// return only after EVERY launched CPU acknowledged. No lifecycle/store lock
// may be held over wait(): a counted original can sleep or need those locks.
// No timeout may advance to stop/free with live callers. DriverUnload cannot
// report failure; retaining the driver/VMX (possibly delaying SCM stop) is
// safer than returning and letting Windows unload code that is still executing.
template <class Backend>
void drain_hook_shutdown(Backend& backend) {
    backend.close_and_unpatch();
    while (backend.inflight() != 0)
        backend.wait();
    backend.stop_cpus();
    backend.release();
}
}  // namespace blook
