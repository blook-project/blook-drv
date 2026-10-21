# Development guide

## Toolchain

| Component | Version used locally | Notes |
|---|---|---|
| Visual Studio | 2022/2026 with the C++ desktop workload | MSVC 19.4x+ |
| WDK | 10.0.26100.0 (`Y:\Program Files (x86)\Windows Kits\10` here) | CI installs it from the NuGet content package (`ci`'s `docs/CI-WDK.md`) |
| xmake | 3.0.8 | `--wdk=`/`--kchannel_dir=` overrides are the only environment knobs |
| blook-kchannel | pinned commit `40a5337a2d69c79fb049361f616aacc58ae75d4d` | real sources are compiled in; there is no stub in the driver build |
| clang-format | 20.1.0 (CI pins the same) | `.clang-format` is copied from the original tree |

## Build

```powershell
# configure once
xmake f -p windows -a x64 -m releasedbg --kchannel_dir=..\blook-kchannel -y
xmake -y
xmake run blook-tests
```

`BLOOK_VERSION` (from `version.txt`) is exported by the wrappers because xmake's
project-description sandbox cannot read files. `scripts/Build.ps1` does
configure + build + host tests + SPC signing and **stops there**: kernel loads
happen only through `scripts/E2E.ps1` inside a bvmenv guest (see
[evidence policy](<evidence/README.md>)).

## Tests

* `tests/unit/` — host GoogleTests. No kernel, no hypervisor, no VM. Covers
  policy decisions (CPUID/MSR presentation, nested plan, breakpoint state
  machine, hook/config/page rules), EPT page-table math with a mocked platform,
  the wire ABI, and the SDK against a fake transport.
* `tests/e2e/` — the 56-case VM matrix and its guest helpers; driven by
  `scripts/E2E.ps1` through bvmenv. A crash/hang is a failed case, never a skip.
* `scripts/VmPreflight.ps1` — fast real-VM smoke (baseline antidetect → driver
  start → antidetect with hypervisor → sw-bp hit → hw-bp hit → clean stop).

## Code rules

* Kernel targets: C++17, `/kernel`, no exceptions, no RTTI, no STL containers,
  no allocation or registry access from vm-exit context. `_KERNEL_MODE` is
  defined for the driver target so the kchannel header picks its kernel types.
* User-mode targets: C++23 (the SDK returns `std::expected`; MSVC only provides
  it in C++23 mode). `/W4` + `/WX`-style hygiene, clang-format enforced in CI.
* Keep decision logic in `src/policy/` (pure, host-testable) and I/O/side
  effects in `src/driver/`. A new rule that cannot be tested on the host belongs
  in a policy header *and* an e2e case; both are required.
* Only `src/ipc/kchannel_{adapter,client}.cc` may include a kchannel header.
* Only `src/driver/control.cc` may interpret wire payloads.
* Never add a device object, symbolic link, named object or exported symbol to
  the driver; the transport is kchannel and the load path is manual-map or the
  service+registry-bootstrap dev path.

## Debugging a bring-up failure

1. `Parameters\TraceMarkers = 1` (startup-only) makes the driver record its phase
   in `Parameters\TraceLast`/`TraceExtra`/`TraceCount`. Read it after a crash to
   see whether it died in `initialize_sessions`, the channel or per-CPU
   virtualisation.
2. `Parameters\InterceptDebug = 0` disables MOV-DR/#BP/#DB interception;
   `Parameters\InterceptRdtscp = 1` enables RDTSCP interception (off by default,
   see [nested](<nested.md>)). Both are startup-only and exist so a
   machine-specific failure can be bisected without a rebuild.
3. `Parameters\Solo = 1` starts the hypervisor with no client (service load);
   the kchannel path is the normal one.
4. `hv_info` reports the nested host, the accepted capability set and the
   degradation flags; `detect_probe` reports which anti-detection mitigations are
   active; `trace_scan` reports what a detector could still see.

## Style

`clang-format -i` with the repository `.clang-format` before every commit;
`scripts/Reformat.ps1` exists for convenience. Commits use `scope: message`.