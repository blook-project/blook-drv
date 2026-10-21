# blook-drv

Hardened Intel VT-x hypervisor driver for Windows x64 with user-mode EPT and
debug-register hook APIs, built for security research and authorised testing.

> **HOST SAFETY (non-negotiable).** Kernel code in this repository runs only
> inside a bvmenv-managed VMware guest. There is no supported way to load the
> driver on a physical host: `scripts/Build.ps1` refuses `-Deploy/-Start`,
> `blook-loader start` requires the `BLOOK_VM_GUEST` +
> `BLOOK_ALLOW_KERNEL_LOAD` markers that only `scripts/E2E.ps1` sets on a
> `bvmenv exec` command line, and the guest test binaries exit with
> "refusing to run kernel code outside a bvmenv guest" when the marker is
> missing. A host-mode hypervisor load can bugcheck or hang the machine; that
> is not a supported configuration. See [evidence policy](<docs/evidence/README.md>).

## What it does

| Area | Implementation |
|---|---|
| Hypervisor | Intel VT-x/EPT, one VMCS per logical processor, root-mode handlers adapted from [jonomango/hv](https://github.com/jonomango/hv) and hardened here |
| Self-hiding | `PsLoadedModuleList` unlink (all three chains, with consistency checks), `ObMakeTemporaryObject` on the driver object, recursive service-key removal, benign pool tag from the first allocation, relink on unload |
| Hypervisor hiding | CPUID hypervisor bit and vendor-leaf spoofing, VMX/SVM feature masking consistent with VMX-MSR filtering, `IA32_FEATURE_CONTROL` constant answer, TSC offsetting with RDTSC/RDTSCP compensation, APERF/MPERF compensation, exception-behaviour preservation |
| Nested virtualisation | Capability probe (CPUID + VMX MSRs) and a tested degradation matrix; runs inside a VMware guest with `vhv.enable = "TRUE"` — see [nested](<docs/nested.md>) |
| IPC | **blook-kchannel only** (pinned sources, ABI 1.0): one adapter per side, no device object, no symbolic link, no IOCTL path |
| EPT hooks | Shadow-page execute hooks for any process: split large pages, patched shadow, original view for reads, call-original windows, dormant hooks for JIT pages, COW rebind, drain-before-free shutdown |
| Software-breakpoint hooks | External-process int3 shadow hook: `#BP` VM-exit, hit accounting, original instruction executed exactly once under trap-flag/MTF single-step, re-arm, race-safe disarm |
| Hardware-breakpoint hooks | DR0-DR3 armed for a target thread, `#DB` interception, `MOV DRn` read/write interception with CR3-scoped sanitisation, DR7 enable bits protected against guest writes |
| Anti-detection tests | `blook-antidetect.exe`: VMAware-style in-guest suite (CPUID, MSR, TSC/APERF/MPERF, exceptions, DR access, debugger surface, memory latency) with JSON output |
| e2e | 56-case matrix through `bvmenv` inside a VMware guest: nested boot, hypervisor start/stop, EPT/sw-bp/hw-bp hooks, hook/unhook stress, unload under load, invalid inputs, memory pressure, crash-timeout watchdog |

## Architecture

```
include/blook/drv/     public SDK (header-only): ept.hpp (hooks), wire.hpp (ABI),
                       transport.hpp (kchannel), handle.hpp
include/blook/drv/km   kernel-shared wire types
src/driver/            driver: entry, session, control, hooks, watch, hide/*,
                       hv/* (vcpu, vmcs, ept, exit handlers, timing, nested,
                       swbreak, hwbreak, detect), ssdt, tuning
src/ipc/               the ONLY blook-kchannel integration (kernel adapter +
                       user-side client); no other file includes a kchannel header
src/loader/            blook-loader CLI (status, hooks, hide, config, service)
src/policy/            pure, host-testable policy: CPUID/MSR presentation,
                       breakpoint state machine, nested degradation matrix,
                       hook/config/page-query rules, x86 instruction length
tests/unit/            host GoogleTests (143 tests, no kernel, no VM)
tests/guest/           in-guest binaries (antidetect, hook tests)
tests/e2e/             56-case matrix + guest helpers + bvmenv runner
scripts/               Build.ps1 (build+sign+test only), E2E.ps1, registry publish
signer/                local SPC signer used by Build.ps1 (no new private keys)
```

The command layer (`src/driver/control.cc`) is transport-neutral: the kchannel
adapter only validates the frame, hands over the peer identity and copies the
reply. That is what makes "all IPC is kchannel, and nothing else is IPC"
checkable instead of aspirational.

## Build

Requirements: Windows 11 x64, Visual Studio 2022/2026 C++ workload, WDK (the CI
installs it from the NuGet content package), xmake 3.x, and a
[blook-kchannel](https://github.com/blook-project/blook-kchannel) checkout at the
pinned commit (the driver links the real transport sources — there is no stub).

```powershell
xmake f -p windows -a x64 -m releasedbg --kchannel_dir=..\blook-kchannel -y
xmake -y
xmake run blook-tests           # 143 host unit tests
```

One-command local build + sign + unit tests (this script never loads the driver):

```powershell
gsudo -d .\scripts\Build.ps1            # build + sign + host tests
```

Kernel code is C++17 (`/kernel`, no exceptions, no RTTI, no STL); user-mode code
is C++23 (the SDK returns `std::expected`, which MSVC only provides in C++23
mode). Rationale and warning policy: [development](<docs/development.md>).

## Tests and evidence

- **Host unit tests** (always run by CI): EPT page-table math, hook state
  machine, breakpoint state machine, CPUID/MSR presentation policy, nested
  degradation matrix, configuration, wire ABI, hiding rules — 143 tests.
- **e2e (bvmenv VMware guest)**: `pwsh -File scripts/E2E.ps1 -Vm vm-drv`. Each
  case produces stdout/stderr, a host-side screenshot, `state.json` and a
  timeout/crash classification; a BSOD or hang fails the run and is never
  skipped silently.

Current evidence status:

| Run | Kind | Result |
|---|---|---|
| `docs/evidence/20261021-031131-e2e-dryrun` | dry run (harness validation only) | 56/56 skipped, **not driver evidence** |
| `docs/evidence/20261021-031954-e2e-dryrun` | dry run (harness validation only) | 56/56 skipped, **not driver evidence** |
| real nested-VM run | pending env's rebuilt base image | to be committed with screenshots + `result.json` (`dry_run` absent) |

## Detection and evasion notes (honest limits)

- Hidden: hypervisor-present bit and vendor leaves, VMX/SVM CPUID bits, VMX
  capability MSRs, `IA32_FEATURE_CONTROL` view, TSC/APERF/MPERF compensation for
  intercepted instructions, module list / driver object / service key / device
  and symbolic link traces, pool tag.
- Not hidden: the driver image still exists in kernel memory (a scanner that
  searches the whole kernel address space for PE headers can find it); nested
  execution has a measurable exit-cost tail (double exit) that bare metal does
  not have; the hardware-breakpoint hook has to emulate `MOV DRn`, so a detector
  that expects `#GP` from a CPL3 access can observe the emulation while a
  breakpoint is armed for that address space; thread-context paths
  (`NtGetContextThread`) are not yet sanitised (the DR path is).
- The anti-detection suite reports those gaps as `info` instead of pretending.

## Docs

- [Architecture](<docs/architecture.md>) · [Nested virtualisation](<docs/nested.md>)
- [Hook lifecycle](<docs/hook-lifecycle.md>) · [Features](<docs/features.md>)
- [Development](<docs/development.md>) · [SDK](<sdk/README.md>)
- [Evidence policy](<docs/evidence/README.md>)

## License and disclaimer

MIT (see [LICENSE](<LICENSE>)); vendored third-party notices in
[third_party](<third_party/README.md>) and [LICENSES](<LICENSES>). For authorised
security research and testing only: do not deploy on systems you do not own or
have written permission to test.