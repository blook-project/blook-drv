# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [4.0.0] - 2026-10-21

The first release of the hardened tree. The 3.x line was a working hypervisor;
4.x is about not being detected, not freezing the machine, and being testable
inside a nested VM.

### Added

- Nested-virtualisation support: the driver detects it is running under another
  hypervisor (VMware, Hyper-V, KVM), probes which VMX/EPT capabilities the
  nested host actually exposes, and degrades instead of refusing to start.
- Anti-detection: CPUID hypervisor-bit and vendor-leaf spoofing, VMX/SVM feature
  masking, VMX-MSR access filtering, TSC/RDTSC/RDTSCP compensation, APERF/MPERF
  compensation, exception-behaviour filtering and an in-guest VMAware-style
  detection suite (`blook-antidetect`) that reports pass/fail per check.
- Self-hiding: `PsLoadedModuleList` unlink, object-directory unlink of the device
  and symbolic link, registry service trace cleanup, pool tag rewriting, and a
  `trace_scan` op that reports what a detector could still see.
- External-process software-breakpoint hooks: int3 shadow page, #BP VM-exit,
  kernel handler, MTF single-step with the original byte restored, re-arm.
- External-process hardware-breakpoint hooks: DR0-DR3 armed for a target thread,
  #DB / MOV-DR interception, and debug-register sanitisation for
  `NtGetContextThread`, `NtSetContextThread`, `NtContinue`, thread creation and
  `XSAVE`/`XSAVES` debug state.
- `blook-kchannel` transport: all kernel<->user traffic is a kchannel CALL/REPLY
  with the fixed wire ABI in `include/blook/drv/wire.hpp`. No device IOCTL path.
- Large in-VM e2e suite (`scripts/E2E.ps1` + `bvmenv`): per-case result JSON,
  screenshots and logs under `docs/evidence/`, with BSOD/hang detection and
  automatic reset.
- Host unit tests for the pure parts: EPT page-table math, hook state machine,
  wire ABI framing, configuration and hiding rules.

### Changed

- Kernel code is C++17 (`/kernel`, no exceptions, no RTTI); user-mode code is
  C++20.
- Build is xmake-only; `scripts/Build.ps1` remains the one-command
  build+sign+deploy path.

### Fixed

- Hook teardown no longer frees EPT entries while another logical processor can
  still be executing the hooked page (drain before free).
- Same-page self-reads return the original bytes instead of ping-ponging
  between two shadow views.
