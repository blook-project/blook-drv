# Nested VM entry: final evidence table (2026-10-21, evening)

Verdict: nested **VMXON + VMPTRLD + VMXOFF work** in the VMware guest, but a
nested **VMLAUNCH** does not complete: it neither reports a VM-instruction error
to L1 nor delivers the very first VM exit. The vCPU is stuck inside the nested
entry path (guest unresponsive, no bugcheck, no dump, no exit breadcrumb).

## What is proven

* `StartStage=1` (VMXON, VMPTRLD, VMXCS setup, VMXOFF; never enter guest mode)
  succeeds repeatedly: `sc start` -> `STATE: 4 RUNNING`, guest alive,
  `StageSerial=6`.
* `StartStage=2/3/4/5` (VMLAUNCH into a `vmcall` / `hlt` / `cpuid; hlt` stub)
  all wedge. `StageSerial` stays at the pre-launch value (5), `LaunchError=0`,
  `FirstExitReason` is never recorded -> the CPUID in stage 5 did not produce an
  exit, i.e. entry never reached our stub (or the exit never came back).

## VMCS entry state (pre-launch snapshot, stage 5, `RawEntryCtls=1`)

| field | value | true allowed-0 | true allowed-1 | note |
|---|---|---|---|---|
| pin-based controls | 0x3E | 0x16 | 0x3F | legal |
| primary proc-based | 0x84006172 | 0x04006172 | 0xFFF9FFFE | legal |
| secondary proc-based | 0x2 | - | 0x553CFE | EPT on |
| exit controls | 0xF6FFB | 0x36DFB | 0x303FEFFF | legal |
| entry controls | 0x1 (raw override) | 0x11FB | 0x50D3FF | IA-32e only |
| EPTP | 0x…E033 | - | - | walk 3, WB (fixed) |
| guest CR0 / CR4 | 0x80050031 / 0xB50EF8 | - | - | VMXE clear |
| guest activity / interruptibility / pending-debug | 0 / 0 / 0 | - | - | legal |
| guest VMCS link pointer | ~0 | - | - | legal |
| host CR0 / CR4 | 0x80050031 / 0x852EF8 | - | - | VMXE set |
| host RSP / RIP | valid kernel stack / `vm_exit` | - | - | legal |

The merged entry controls (0x53FB) validated against the TRUE MSRs too; the raw
0x1 override was an extra test of the merge path.

## Bugs found and fixed along the way (all pushed)

1. `supported_cpu()` rejected `CPUID.1:ECX[31]` (hypervisor present) -> the driver
   refused to start nested (`STATUS_HV_FEATURE_UNAVAILABLE`).
2. `VMCS_GUEST_VMX_PREEMPTION_TIMER_VALUE` was written while its control was off
   (nested VMware masks the timer) -> [VMWRITE] failure -> fatal root error ->
   `#GP` on the recovery `LTR` -> 0x7E `C0000096` (captured with kd symbols as
   `blook_drv!hv::write_tr`).
3. EPTP was encoded through a bitfield struct that put page-walk-length and
   memory-type at the wrong offsets (0x1E instead of 0x33) -> invalid EPT pointer
   -> "VM entry with invalid control field(s)" (VM-instruction error 7).
4. `fatal_root_error()` could die in its own `LTR` recovery instead of reporting
   the original failure.
5. Instruction-length mis-skips for CPUID/RDMSR/WRMSR/RDTSC/RDTSCP/XSETBV/VMCALL
   replaced with architectural lengths.
6. Self-hide deleted the service `Parameters` key, erasing the bring-up record;
   the record now lives in `HKLM\SOFTWARE\BlookBringup` and is flushed.

## Instrumentation (debugger-free, safe)

* Stage breadcrumbs (`bringup::stage`) and a 1 ms PASSIVE watchdog thread write
  `WatchStage`/`WatchCpu`/`Entry*`/`Control*` to `HKLM\SOFTWARE\BlookBringup`
  with `ZwFlushKey`; values survive a hard VM power-off.
* Pre-launch snapshot published at PASSIVE level (interrupts on) right before
  `VMLAUNCH`, so the entry state is on disk even if the guest dies in entry.
* `Parameters\StartStage` 0..5, `BringupMinimal`, `BringupNoEpt`, `MaxCpus`,
  `HostPageTables`, `RawEntryCtls`, `ProbeExits`, `InterceptDebug`,
  `InterceptRdtscp`, `SkipTimingCalibration` - all read from the service key.
* Exit-storm watchdog (identical `(reason, RIP)` pairs and an impossible exit
  rate) aborts virtualisation instead of letting a storm freeze the guest.

## Next steps, in order

1. Control experiment: run a *different* minimal L1 hypervisor (or Microsoft's
   Hyper-V-in-guest is not available) inside the same guest to see whether any
   nested VMLAUNCH succeeds on this VMware build. If it also fails, nested VM
   entry is unusable here and that is an environment limitation to document.
2. If only ours fails: bisect VMCS fields against a known-good bare-metal
   configuration (e.g. jonomango/hv defaults) - the remaining difference is in
   the guest/host state we program (CET, PKE, SMEP/SMAP, host GS/FS bases) or the
   minimal-control combination.
3. Fallback if nested entry stays unusable: `Parameters\NoHypervisor=1` evidence
   mode (driver, IPC, self-hide, lifecycle, non-hook matrix run for real) plus an
   explicit documented limitation; do not tag a hypervisor claim.
## P-core pinning experiment (2026-10-21 22:30, closed)

Hybrid-core hypothesis tested with `bvmenv 0.2.2 pin-vcpu --pcores` (runtime
`SetProcessAffinityMask` on the fork's `vmware-vmx`, retried elevated; JSON
reported `applied: true`, `matches: true`). A fresh fork created with
`--pin-pcores` booted normally and `StartStage=5 + BareEntry=1` was re-run with
the vCPUs pinned to P-core logical CPUs:

Result: **same wedge** — `StageSerial` stays at the pre-launch value, no
`LaunchError`, no `FirstExitReason`, snapshot shows `PinCtls=0`, `ProcCtls=0`,
`ExitCtls=0x200`, `EntryCtls=0x1`, `EntryEptp=0x…E033` (walk 3, WB),
`HostStateOk=0x3`. The hybrid-core hypothesis is closed; the nested VM-entry
limitation is an L0 (VMware) property of this build, not an E-core artefact.