# Nested virtualisation

The driver must run both on bare metal and inside a VMware Workstation guest
configured with `vhv.enable = "TRUE"`. A nested host exposes the intersection of
its own VMX capabilities with the L0 hypervisor policy, so several VMCS controls
that a native run takes for granted are simply not accepted there. Requesting a
control the capability MSRs report as disallowed makes **VM entry fail**, which
on a nested host presents as a hang or a triple fault, not as a clean error.

## How the driver decides

1. At bring-up, `hv::nested::probe()` (PASSIVE_LEVEL, once) reads
   `CPUID.1:ECX[31]`, the vendor signature at `CPUID.0x40000000`, and the VMX
   capability MSRs (`IA32_VMX_BASIC`, pin/proc/exit/entry controls,
   `IA32_VMX_PROCBASED_CTLS2`, CR4 fixed bits) through `rdmsr_safe`.
2. The pure policy in `src/policy/nested_matrix.hpp` turns those capabilities into
   a `vmcs_plan`: which optional controls to request and which degradation flags
   to report. The plan is unit-tested on the host
   (`tests/unit/policy_nested.cc`), so every row below is an expectation the e2e
   suite can assert.
3. `vmcs.cpp` requests exactly the controls in the plan and records the accepted
   set in the VMCS; nothing else is written blindly.
4. The plan's flags are reported through `hv_info` / `query`, so a degraded run is
   visible instead of silent.

## Degradation matrix

| Capability | Bare metal | VMware guest (`vhv.enable`) | Hyper-V guest | KVM guest |
|---|---|---|---|---|
| EPT | required, must work | required, must work | required | required |
| VP-assist (`enable_vp_assist`) | used if reported | **usually absent** -> disabled | usually present | usually present |
| VMX preemption timer | used if reported | **usually absent** -> TSC offset resynchronised on every exit | usually present | usually present |
| EPT A/D | used if reported | **sometimes absent** -> EPTP keeps A/D off | usually present | usually present |
| VPID | enabled | **disabled** (nested flush semantics are not modelled) | disabled (same reason) | disabled |
| INVPCID | enabled if reported | enabled if reported | enabled if reported | enabled if reported |
| XSAVES | enabled if reported | enabled if reported | enabled if reported | enabled if reported |
| RDTSCP interception | off by default (see below) | off by default | off by default | off by default |
| MTF (monitor trap flag) | available | may be absent -> single-step uses trap-flag emulation | may be absent | may be absent |
| TSC offsetting | enabled (`hide_timing`) | enabled; compensation is coarser without the preemption timer | enabled | enabled |
| APERF/MPERF compensation | enabled | enabled when the host saves/restores them | enabled | enabled |

Reported flags (`wire::hv_flag_*`): `nested`, `vmware`/`hyperv`,
`no_vp_assist`, `no_preemption_timer`, `no_ept_ad`, `no_vpid`, `no_invpcid`,
`no_xsaves`, `no_rdtscp`, `tsc_scaling`.

## Why RDTSCP interception is off by default

Intercepting `RDTSCP` requires re-executing it in root mode and then resuming the
guest at `RIP + instruction_length`. Both halves are hazardous:

* the VMCS instruction-length field has been observed to be wrong on real
  hardware for some exits (the bring-up diagnostics in `hv.h` record exactly
  that), and resuming mid-instruction executes garbage;
* executing RDTSCP in root operation has different behaviour across CPUs and
  nested hosts.

The TSC offset already hides the world-switch cost for every *other* intercepted
instruction, so RDTSCP is left to execute natively. It can be re-enabled for
experiments with `Parameters\InterceptRdtscp = 1` (startup-only, see
`src/driver/tuning.cpp`).

## What is deliberately not hidden

Nested execution costs more than native execution: every exit is a double exit
(L1 -> L0). Memory-latency and CPUID-round-trip measurements can therefore show a
tail that a bare-metal machine does not have. The anti-detection suite reports
those numbers as `info`, and the e2e gate compares a run **with** the driver
against a baseline **without** it on the same VM: the requirement is that the
driver adds no new failures, not that a nested VM is indistinguishable from bare
metal.

## Debugging a nested bring-up

`Parameters\TraceMarkers = 1` makes the driver record its startup phase in
`Parameters\TraceLast` (and `TraceExtra`/`TraceCount`). If a machine dies during
bring-up, reading the last phase after the reboot says whether it was
`initialize_sessions` (phase 2), the channel (phase 3) or per-CPU
virtualisation. This is a bring-up aid, not a production feature; the keys live
under the service key and are removed by `hide_self`.