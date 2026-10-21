# Nested-VM bring-up: root cause found (2026-10-21, second update)

Status: the nested freeze is **diagnosed and fixed**; VMXON/VMCS/VMXOFF now run
inside the VMware guest. Full start (VMLAUNCH) still wedges the guest and is the
only remaining blocker. No real 56-case run yet.

## Root cause of the freeze (confirmed with a kd capture)

kd (symbols resolved) caught:

```
BUGCHECK_CODE: 7e   P1: C0000096 (STATUS_PRIVILEGED_INSTRUCTION)
FAILURE_BUCKET_ID: 0x7E_C0000096_blook_drv!hv::write_tr
STACK: write_tr <- fatal_root_error <- (VMCS field writes) <- virtualize_cpu <- hv::start
```

The new non-fatal diagnostics then named the failed write:

```
Parameters\VmwriteField = 0x482E  (VMCS_GUEST_VMX_PREEMPTION_TIMER_VALUE)
```

`write_vmcs_guest_fields()` wrote the preemption-timer **value** field
unconditionally. A nested VMware guest masks the "activate VMX preemption timer"
control (allowed-1 bit 6 = 0), so the control is off and writing that field makes
**VMWRITE fail**. The old code called `fatal_root_error()`, whose recovery ran
`LTR` with a guest TR selector that is not a valid TSS: `#GP` in root mode ->
0x7E -> black screen with no dump (the base image has `CrashDumpEnabled=0`).
That is exactly the "guest freeze" seen from outside.

Fixes (all pushed):
* write the timer value only when the control bit is actually set;
* `fatal_root_error()` no longer dies in its own `LTR` recovery;
* every VMWRITE failure is recorded and published (`Parameters\VmwriteField`,
  `LaunchError*`, `StageSerial/StageCpu`, `Storm*`) and fails `hv::start`
  cleanly instead of bugchecking inside root mode;
* CPUID/RDMSR/WRMSM/RDTSC/xsetbv advance RIP by their architectural lengths
  instead of the unreliable `VMCS_VMEXIT_INSTRUCTION_LENGTH` (mis-skip guard).

## Verified after the fix (no kd attached)

`StartStage=1` (VMXON + VMPTRLD + VMXOFF, 1 CPU, minimal controls, solo):
`sc start` -> `STATE: 4 RUNNING`, `TraceLast=0x3`, `VmwriteField=0`,
`LaunchError=0`, `StageSerial=5`, guest healthy afterwards. So nested VMX
bring-up works.

## Remaining blocker: VMLAUNCH

`StartStage=0` (minimal preset, 1 CPU) still wedges the guest: `sc start` never
returns, `exec`/`state` time out, screen black. No bugcheck and no stage marker
beyond `vmcs-ready`, which points at the entry/exit path rather than root-mode
setup. Next steps, in order:

1. kd capture with the target *continuing* so `Bringup::stage` DbgPrint streams
   (kd-pipe + kd-log); the last `[blook] stage=` line names the failing step.
   The pipe-server creation is still flaky: `kd-pipe vm-drv` reports success and
   `bvmenv kd vm-drv` prints the right `kd -k com:pipe,port=\\.\pipe\blook-vm-drv-kd`
   command, but kd stays in `Waiting for pipe` even after a stop/start cycle, so
   the capture has not been obtained yet.
2. If the wedge is an exit loop with changing RIP: tighten the watchdog beyond
   the current "average < 100 cycles" rule (compare the exit *count per
   millisecond*, not cycles per exit).
3. If it is VM entry state: `Parameters\BringupNoEpt=1` and a bare guest, then
   re-enable controls one at a time.