#include <cstdio>

// In-guest external-process hook tests (software breakpoint, hardware
// breakpoint, hook/unhook stress). Driver- and process-level assertions live
// here; the host-side runner is scripts/E2E.ps1.
int main() {
    std::printf("blook-guest-hooks: not implemented yet\n");
    return 77;  // skip
}
