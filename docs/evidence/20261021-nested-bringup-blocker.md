# Nested-VM bring-up: current blocker (2026-10-21)

Status: **not resolved**. The driver loads and the hypervisor starts inside the
VMware guest, but `hv::start()` freezes the guest. No real 56-case e2e run has
passed yet; the dry-run artefacts in this directory are harness validation only.

## What works (measured, not inferred)

* `bvmenv` VM lifecycle, `push`, `exec --elevated` (with the SYSTEM fallback),
  `state`, screenshots and the per-VM serial log all work on the refreshed base.
* Inside the guest, `blook-antidetect.exe` runs (`docs/evidence/20261021-1400-vm-preflight/antidetect-baseline.json`):
  `CPUID.1:ECX[31]` set, vendor `VMwareVMware`, `CPUID.1:ECX[5]` (VMX) set,
  `smx=0`, `svm=0`. env's signed ring-0 probe independently reports
  `VMX=1 HYPERVISOR_PRESENT=1 HYPERVISOR_VENDOR=VMwareVMware
  FIRMWARE_VIRTUALIZATION_ENABLED=1`. So nested VT-x **is** exposed.
* `blook-loader install` succeeds (`SERVICE_NAME: BlookDrv`, exit 0), the
  host-safety marker guard passes inside the guest, and `start` reaches the
  driver's `DriverEntry`.

## What fails

`blook-loader start` (i.e. `hv::start()`) never returns; the guest becomes
unresponsive to `exec`/`state` (both time out), `vmware-vmx` keeps burning CPU
(~1.7 cores), and the MKS screen capture is black. This is a guest-side freeze,
not a BSOD: no bugcheck text, no new minidump.

Two distinct failures were observed:

1. **Fixed:** `TraceLast=0x102` (initialize_sessions) + `TraceExtra=0xC035001E`
   (`STATUS_HV_FEATURE_UNAVAILABLE`): `supported_cpu()` rejected the guest
   because `CPUID.1:ECX[31]` (hypervisor present) was set. Nested guests are
   *supposed* to have that bit; it is no longer part of the gate (commit
   `c1f…`, see `src/driver/hv/vcpu.cpp`).
2. **Open:** after the gate fix the driver gets further and then the guest
   freezes. Reproduced with the *minimal* preset
   (`Parameters\BringupMinimal=1`, `InterceptDebug=0`, `InterceptRdtscp=0`,
   `SkipTimingCalibration=1`): only VMXON, VMPTRLD, VM entry/exit and the
   unavoidable CPUID/VMCALL handling are active. No MSR bitmap, no CR exits, no
   EPT hook work, no timing calibration, no debug-register interception. The
   freeze therefore lives in the **minimum guest-entry path**, not in a
   particular interception feature.

## Instruments added for the next attempt

* `hv::bringup::stage()` breadcrumbs (`vmxon`, `vmptrld`, `vmcs-ready`,
  `vmxon-only-ok`, `launched`, `exit-storm`, `exit-rate-storm`) written to
  `Parameters\StageSerial` / `StageCpu` by `publish_stage()`.
* Exit-storm watchdog: per-processor identical `(exit reason, guest RIP)` pairs
  and a sustained exit rate no real VM exit can produce are treated as a runaway
  loop; the processor aborts virtualisation so `hv::start` returns an error and
  publishes `Parameters\Storm*` instead of freezing the guest.
* `Parameters\StartStage=1`: VMXON + VMPTRLD + VMXOFF only, **never enters guest
  mode**. This cannot hang the guest; it splits "root-mode setup broken" from
  "VM entry/exit broken". Start here.
* `Parameters\BringupMinimal=1`, `InterceptDebug`, `InterceptRdtscp`,
  `SkipTimingCalibration`: startup-only bisect switches (see `docs/nested.md`).

## Most likely causes (to check first)

1. VM entry/exit in the nested host with a control/field VMware did not
   actually expose (the freeze is before any feature-specific work, so a VMCS
   control combination is the prime suspect).
2. Root-mode page tables / host state: a root-mode fault with the guest state
   still loaded turns into a triple fault and a VM reset rather than a bugcheck,
   which matches the black screen and the CPU spin.
3. `vm_exit.asm` resume path on a nested host (the earlier bare-metal failure
   was an unhandled root-mode `#UD` at `rdtscp` inside `hv::start`).

## What is needed to finish this

* Text-level kernel debug output from the guest (attach `kd` to the VM's serial
  device, or a VMCI debug channel). `DbgPrint` without an attached debugger does
  not reach the serial file, which is why `serial.log` is only KD packet noise.
* Or run `Parameters\StartStage=1` first and report `Parameters\StageSerial` —
  it needs no debugger and tells us whether VMXON/PVMPTRLD/VMXOFF work nested.