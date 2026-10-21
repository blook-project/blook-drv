# Architecture

blook-drv is a type-2 Intel VT-x hypervisor that virtualises every logical
processor from a Windows kernel driver, plus a user-mode SDK that installs EPT
and debug-register hooks into arbitrary processes through blook-kchannel.

## Layers

```
 user mode                     kernel mode
 ---------                     -----------
 blook-loader CLI  ---\
 blook-antidetect  ----> blook-kchannel (shared page, ChaCha20+HMAC)
 test binaries     ---/            |
                                   v
                        src/ipc/kchannel_adapter.cc   (one adapter, no policy)
                                   |
                        src/driver/control.cc         (wire op -> command)
                                   |
   src/driver/{session,hooks,watch,hide,hv,ssdt}.cc   (policy + state)
```

* **Transport**: blook-kchannel owns the shared region, the rings, encryption,
  authentication, heartbeats and the single peer. `src/ipc/` is the only place
  that includes a kchannel header. The driver never creates a device object, a
  symbolic link or a registry value, and it exports no symbol.
* **Commands**: `control.cc` is transport-neutral. It validates the fixed wire
  header (`include/blook/drv/wire.hpp`), enforces the caller identity
  (peer pid, admin flag, per-session hook ownership token) and calls the same
  code paths the old device ABI called. A second transport could be added without
  touching the commands; no second transport exists.
* **Policy**: `src/policy/` holds pure, host-testable decisions (CPUID/MSR
  presentation, nested degradation matrix, breakpoint state machine, hook
  ownership, configuration, page-query arithmetic, x86 instruction length).
  Kernel code calls into these headers; the host tests exercise the same code.

## Hypervisor

* One `vcpu` per logical processor: VMXON region, VMCS, MSR bitmap, host stack,
  host IDT/GDT/TSS, per-CPU EPT root.
* `hv::start()` preflights every processor (VMX availability, EPT support, CR4
  fixed bits, dangerous-feature checks), then virtualises them one at a time.
  Failure of any processor rolls back through VMXOFF.
* VM exits handled: CPUID, RDMSR/WRMSR, MOV CR, MOV DR, XSETBV, VMCALL, VMX
  instructions, RDTSC/RDTSCP, EPT violations/misconfigurations, \#BP, \#DB,
  \#PF (bring-up trace only), NMI window, preemption timer, MTF.
* EPT: identity-mapped memory with 2 MiB large pages split on demand; a hooked
  page is replaced by a shadow page in the owning process's view only (the hook
  identity is the target PEB), so a shared image page can be hooked for one
  process and left untouched for every other.
* Timing: TSC offsetting removes the world-switch cost from every intercepted
  instruction; APERF/MPERF/PERF_GLOBAL_CTRL are snapshotted on exit and restored
  on entry; the preemption timer resynchronises the offset when available.
* Debug registers: `MOV DRn` is intercepted for the address space of an armed
  target; other address spaces keep the architectural behaviour (CPL3 access
  faults), so "the read did not fault" is not a hypervisor signal.
* Nested hosts: capability probe drives the VMCS control plan (see
  [nested](<nested.md>)); unsupported controls are never requested.

## Hooks

An EPT hook is a pair of views of one 4 KiB page: the *original* view (what the
guest reads) and the *shadow* view (what the guest fetches). The shadow contains
the caller's patch bytes; every other byte of the page is the original. Hooks are
merged per page, per process, and can be installed on a committed but
non-executable page (JIT) as *dormant*, arming when the page becomes executable.

* **Call-original window**: a handler that needs the real function asks the
  hypervisor to map the original view on *its* logical processor for the duration
  of the call, so the patched entry is bypassed without unpatching anything.
* **Software breakpoints** (`#BP`): the shadow page holds `0xCC`; the VM exit
  rewinds RIP, maps the original view on that processor, sets the trap flag and
  resumes; the single-step `#DB` drops the original view and resumes after the
  instruction. The original instruction executes exactly once, and the target's
  own reads keep seeing the original bytes.
* **Hardware breakpoints**: DR0-DR3 are armed for a target thread (the client
  calls `SetThreadContext`, as a debugger would); `#DB` is consumed for the
  armed breakpoints, `MOV DRn` reads are sanitised and writes that would disable
  a breakpoint are swallowed. DR access in any other address space keeps the
  architectural fault.

## Teardown

Unload order is: stop accepting new hook installs, unpatch every processor,
drain in-flight handlers (without holding the locks a handler needs), stop and
free every vCPU, drop notifications, restore the module list (so a hidden driver
never leaves a dangling entry), then free the pool. Unloading under load is an
e2e case; an in-flight original can delay unload but never gets freed under a
running handler.

## Consistency rules the code enforces

1. Every wire message is fixed-layout with an exact-size header; replies are
   validated by the SDK before use.
2. A hook can only be removed/refreshed by the session token that created it.
3. `PsLoadedModuleList` unlink happens only after a consistency check of all
   three chains, and is reversed before the image can be unmapped.
4. `hide_timing`, the interception switches and the trace markers are read once
   at PASSIVE_LEVEL; nothing in root-mode code reads the registry or allocates.
5. All optional VMCS controls come from the unit-tested nested plan.