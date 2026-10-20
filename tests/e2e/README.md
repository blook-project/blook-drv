# blook-drv end-to-end tests (VMware Windows 11 guest)

`scripts/E2E.ps1` is the host-side runner for the live driver.  It builds the
driver/SDK/guest binaries, prepares a Windows 11 VMware guest through
`bvmenv`, pushes the
artifacts into `C:\blook-e2e\`, runs the ordered matrix in
[`cases.psd1`](cases.psd1), and writes machine-readable + human-readable
evidence.

The harness deliberately treats the guest as an unreliable remote machine:
every case is followed by a `bvmenv state --json` query, and a blue screen,
hang, powered-off VM or lost state query becomes a **crash** result with
screenshot, state JSON and a `vmware.log` tail in the case directory.  The
harness itself never runs inside the guest, so it survives a dead VM.

## Prerequisites

- Windows 11 x64 guest, created/managed by the teammate `bvmenv` CLI.  The
  default VM name is `vm-drv`; use `-Vm` for another linked clone.
- The guest must be bootable with **testsigning on** (the local test signature
  is applied by this runner).  Nested VT-x/VMX must be exposed by VMware for
  the hypervisor lifecycle tests.
- The VM base snapshot must contain PowerShell 5.1, `bcdedit.exe`, `ping.exe`
  and the usual Windows tools.  No network is used by any test or helper.
- Host: PowerShell 7, xmake, MSVC + WDK.  The repository-local
  `signer/spcsign/spcsign.exe` signs the driver after the build.
- `bvmenv.exe` on `PATH`, or under
  `D:\blook-kernel-project\blook-vmware-environment\build\**\bvmenv.exe`, or
  passed explicitly with `-Bvmenv <path>`.
- The harness does not create, modify or reset VMs in `-DryRun` or
  `-ValidateOnly` mode.

## Quick start

```powershell
# Parse/validate the matrix only.  No build, no VM, no artifacts.
pwsh -File scripts/E2E.ps1 -ValidateOnly

# Full dry run: validates, prints every planned bvmenv command and writes a
# result.json marked dry_run:true.  Missing bvmenv/artifacts are warnings.
pwsh -File scripts/E2E.ps1 -DryRun

# Normal run (builds, signs, creates/resets vm-drv, pushes, runs all cases).
pwsh -File scripts/E2E.ps1

# One category / one case, with a non-default artifact directory.
pwsh -File scripts/E2E.ps1 -Filter '^ept-' -Artifacts docs/evidence/manual-ept
pwsh -File scripts/E2E.ps1 -From driver-start-solo -KeepGoing

# Use a prebuilt tree without invoking xmake.
pwsh -File scripts/E2E.ps1 -NoBuild -Bvmenv D:\tools\bvmenv.exe
```

| Parameter | Default | Meaning |
| --- | --- | --- |
| `-Vm` | `vm-drv` | `bvmenv` VM name |
| `-Bvmenv` | PATH, then the teammate build tree | explicit CLI path |
| `-Configuration` | `releasedbg` | xmake mode (`debug`/`releasedbg`/`release`) |
| `-Filter` | — | regex over case ids |
| `-From` | — | start at this case id (inclusive, after `-Filter`) |
| `-DryRun` | off | no build/VM; writes `dry_run:true` result |
| `-NoReset` | off | do not create/reset; crash recovery is impossible |
| `-Artifacts` | `docs/evidence/<yyyyMMdd-HHmmss>-e2e` | artifact root |
| `-TimeoutScale` | `1.0` | multiplier on every case timeout |
| `-KeepGoing` | off | reset + re-prepare the guest after a crash and continue |
| `-ValidateOnly` | off | matrix schema/id validation only |
| `-NoBuild` | off | use existing `build/windows/x64/<config>` outputs |
| `-ReadyTimeoutSeconds` | `180` | boot-to-desktop wait per create/reset |

## What the runner does

1. **(a) Build** — `xmake f -p windows -a x64 -m <config> -y` and
   `xmake build blook-drv blook-sdk blook-loader blook-antidetect
   blook-guest-hooks`, then signs `blook-drv.sys` in place with `spcsign`.
2. **(b) Resolve** — verifies `blook-drv.sys`, `blook-loader.exe`,
   `blook-antidetect.exe`, `blook-guest-hooks.exe` under
   `build/windows/x64/<config>`.
3. **(c) VM lifecycle** — `bvmenv create`, falling back to `bvmenv reset` if
   the VM already exists; polls `bvmenv state --json` until
   `power=on`, `classification=desktop`, `tools_heartbeat=true`.
4. **(d) Guest prep** — creates `C:\blook-e2e\`, pushes the two binaries, the
   antidetect binary, the guest-hooks binary, `blook.ini`, and every file in
   [`guest/`](guest/).  Pushes are re-done after a crash reset because the
   linked clone reverts to its base snapshot.
5. **(e) Run** — executes the selected cases in `cases.psd1` order through
   `bvmenv exec --timeout <scaled> [--elevated] --workdir C:\blook-e2e -- ...`.
6. **(f) State** — queries `bvmenv state --json` after every case.  On
   `bsod`/`hang`/`off`, a failed state query, or timeout sentinel `124`, the
   case is `crash` or `timeout`; screenshot, state JSON and the last 200 lines
   of `vmware.log` are copied into `cases/<id>/`.
7. **(g) result.json** — run metadata, one object per case, summary counts.
8. **(h) report.md** — summary table, one link per case directory, failure/crash
   evidence and reproduction command.
9. **(i) Exit code** — see below.

### Crash / timeout policy

- `classification=bsod|hang|off` or an unreadable state query → `crash`.
- `bvmenv exec` exit `124` or a host-side hard timeout → `timeout`.
- Default (`-KeepGoing` absent): the VM is reset once (evidence preserved) and
  the run aborts; remaining cases are recorded as `skip` with
  `not run: aborted after ...`.
- `-KeepGoing`: reset, wait for desktop, re-push the guest bundle, continue.
- `-NoReset`: no create/reset at startup and no recovery; a crash aborts
  immediately.
- `watchdog-detects-hang` is intentionally a `timeout` (5 s limit running
  `ping -n 600 127.0.0.1`).  It has `expected=true`, does **not** abort the run,
  and its post-check requires `classification=desktop` to prove the VM survived.

## Adding a case

Add a hashtable to the ordered array in [`cases.psd1`](cases.psd1):

```powershell
@{
    id = 'my-new-case'
    name = 'One-line description'
    category = 'smoke'
    command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass',
                '-File', 'C:\blook-e2e\my-helper.ps1', '-Check', 'x')
    timeout_s = 180
    expect_exit = 0
    requires_admin = $true
    allow_skip = $true          # exit 77 = not implemented in this build
    post_checks = @{
        state_classification = 'desktop'
        stdout_contains = @('my_check=ok')
        stdout_not_contains = @('FAIL')
        max_duration_s = 120
    }
    acceptance = 'What must be true in the project requirements.'
    notes = 'Optional note copied into evidence.'
}
```

Rules enforced by `-ValidateOnly`:

- unique kebab-case `id`; non-empty `name`; `category` must be one of the
  eleven categories; positive integer `timeout_s`; `expect_exit` 0–255;
  boolean switches; only the documented `post_checks` keys.
- Keep data-collection cases before cases that consume their output
  (`antidetect-baseline` before `antidetect-with-hv`).
- Guest commands are argv arrays, not shell strings.  Prefer a helper in
  `guest/` over a long `-Command` string.
- Exit-code contract for helpers: **0 = pass**, **1 = fail**, **77 = feature
  not implemented / skip**, **124 = timeout**.
- Helpers must be Windows PowerShell 5.1 + built-in .NET only.  Do not add a
  network dependency.
- Every case should leave the driver in a state the next case can handle
  (`Ensure-Driver` in `lib.ps1` is idempotent), or explicitly document why not.

## Guest helpers

All files in [`guest/`](guest/) are pushed flat into `C:\blook-e2e\`.

| File | Purpose |
| --- | --- |
| `lib.ps1` | shared loader/process/admin helpers, 0/1/77 contract |
| `boot-baseline.ps1` | OS, testsigning, loader/driver presence |
| `driver-lifecycle.ps1` | install, start-solo, start-nested, stop, 10x/50x cycles |
| `hv-info.ps1` | CPUID 0x40000000 vendor / nested-VMX report |
| `run-antidetect.ps1` | no-driver baseline and with-hv comparison |
| `detect-check.ps1` | one anti-detection check via `blook-antidetect.exe` |
| `run-ept-hook.ps1` | spawn hot target, delegate EPT hook mode to guest-hooks |
| `hook-target.ps1` | tiny Add-Type C# target with a hot `Target(int)` method |
| `guest-hooks.ps1` | wrapper for swbreak/hwbreak/stress modes |
| `get-dr-context.ps1` | GetThreadContext DR0–DR7 query + sanitisation check |
| `scan-drivers.ps1` | `SystemModuleInformation` (class 11) scan |
| `scan-devices.ps1` | `\Device` enumeration + `CreateFile \\.\BlookDrv` |
| `scan-services.ps1` | service registry key + SCM/`sc query` scan |
| `scan-pool.ps1` | `SystemPoolTagInformation` (class 22) scan |
| `trace-scan.ps1` | driver `trace_scan` wrapper |
| `self-hide-then-unload.ps1` | hide, stop, uninstall, verify `sc query` fails |
| `kchannel-fuzz.ps1` | payload/opcode negatives + no-attach/detach via `ping` |
| `invalid-parameters.ps1` | 22 malformed loader requests, all must fail fast |
| `memory-pressure.ps1` | commit to ~80%, then hook/unhook |
| `run-unload-under-load.ps1` | `sc stop` while target threads execute |
| `hang-helper.ps1` | the deliberate 10-minute `ping` for the watchdog case |

The repository currently ships `blook-antidetect.exe` and
`blook-guest-hooks.exe` as stubs returning 77.  Cases that depend on them set
`allow_skip = $true`, so a full run records them as `skip` until the probe and
the hook test binary are implemented.  Remove `allow_skip` once the real
binary is in place.

## Artifacts

```
docs/evidence/<timestamp>-e2e/
  result.json                 # schema below
  report.md                   # summary + per-case links
  run.log                     # full host-side log
  run/cases.psd1              # exact matrix used for this run
  run/state-initial.json      # state after boot / reset
  cases/<case-id>/
    command.txt               # exact argv, timeout, post_checks
    stdout.txt                # bvmenv process stdout (guest stdout)
    stderr.txt
    state.json                # post-case bvmenv state
    state.raw.txt
    screenshot.png            # copied when state.screenshot exists
    vmware_log_tail.txt       # last 200 lines of state.vmware_log
    crash.txt                 # present for crash/timeout
    bvmenv-exec.json          # optional, if exec printed artifact JSON
    guest-stdout.txt          # optional, copied from that JSON
    guest-stderr.txt
```

`result.json` shape (fields are always present; paths may be `null`):

```json
{
  "run": {
    "started_utc": "...", "finished_utc": "...", "vm": "vm-drv",
    "config": "releasedbg", "bvmenv": "...", "host": "...",
    "git_commit": "...", "dry_run": false, "aborted": false,
    "abort_reason": "", "artifact_root": "...", "timeout_scale": 1.0,
    "timeout_sentinel": 124, "filter": "", "from": "", "keep_going": false,
    "no_reset": false, "error": ""
  },
  "cases": [{
    "id": "...", "name": "...", "category": "...", "timeout_s": 180,
    "started_utc": "...", "duration_s": 1.23, "status": "pass",
    "exit_code": 0,
    "artifacts": {"dir": "...", "stdout": "...", "stderr": "...",
                  "state_json": "...", "screenshot": "...",
                  "vmware_log_tail": "..."},
    "assertions": [{"name": "...", "ok": true, "detail": "..."}],
    "notes": "", "expected": false
  }],
  "summary": {"total": 56, "pass": 0, "fail": 0, "skip": 56,
              "crash": 0, "timeout": 0, "expected_timeout": 0},
  "dry_run": false
}
```

### Reading crash evidence

1. `cases/<id>/state.json` — `classification` (`bsod`/`hang`/`off`),
   `stop_code`, `power`, `tools_heartbeat`.
2. `cases/<id>/screenshot.png` — desktop/login/BSOD screen captured by
   `bvmenv state`.
3. `cases/<id>/vmware_log_tail.txt` — `vmware.log` tail (BSOD, VMX errors,
   reset/panic messages).
4. `cases/<id>/stdout.txt` / `stderr.txt` — last guest output before death; a
   driver fault usually leaves no guest stderr.
5. `cases/<id>/crash.txt` — consolidated summary (exit code, timeout,
   classification, tails, screenshot/log paths).
6. For a reset-after-crash, `state-after-reset.json` records whether the VM
   recovered.

A single `crash` is a release blocker.  The default run aborts after resetting
the VM; the report marks the case and every not-run case so the blocker cannot
be lost in a green summary.

## Exit codes

| Code | Meaning |
| ---: | --- |
| 0 | every executed case passed; only expected `watchdog` timeout allowed |
| 1 | at least one fail/crash, or an unexpected timeout |
| 2 | no failures, but at least one skip (incomplete coverage) |
| 3 | harness/build/VM infrastructure error (bvmenv missing, build broken, reset failed, invalid matrix) |

`-DryRun` and `-ValidateOnly` exit 0 when the matrix and inputs are valid.
Strictly, a run with `skip` cases is not green: exit 2 tells CI the matrix was
incomplete even though nothing failed.

## bvmenv assumptions (must be confirmed with env)

All CLI knowledge is in `Invoke-Bvmenv` in `scripts/E2E.ps1`; changing one
function is enough if the real interface differs.

1. `bvmenv create <vm>` creates a linked clone from the base snapshot; if the
   VM already exists the runner falls back to `bvmenv reset <vm>`.  A reset
   that leaves the VM off is followed by `bvmenv start <vm>`.
2. `bvmenv state <vm> --json` prints one JSON object with `vm`, `power`,
   `tools_heartbeat`, `classification`, `stop_code`, `screenshot`,
   `vmware_log`, `errors` (flat contract) **or** the nested
   `bvmenv.state.v1` equivalent.  `screenshot` and `vmware_log` are **host**
   paths; otherwise no image/log evidence can be copied.
3. `classification` is one of `desktop|login|bsod|hang|off`; bvmenv 0.1.0
   may also emit `black|boot|unknown` (off/boot/screenshot failure).  `power`
   is `on|off|suspended`; `power=off` is treated as a crash even when the
   screen classifier says `unknown`.
4. `bvmenv exec <vm> --timeout <s> [--elevated] [--workdir <dir>] -- <argv>`
   exits with the **guest command's** exit code in contract mode.  With
   bvmenv 0.1.0 the process exits 1 for any non-zero guest exit; the runner
   therefore requests `exec <vm> --json` and uses `ExecResult.exit_code`.
   A timeout is normalised to `124`; change `$script:TimeoutSentinel` if the
   real sentinel differs.  The host also enforces `timeout + 60 s` and kills
   the process, so a misbehaving `bvmenv` cannot hang the harness.
5. `bvmenv exec` may print a JSON object on stdout; the harness keeps it as
   `bvmenv-exec.json` and copies the host `stdout_path`/`stderr_path` files
   when present, but never depends on that shape.
6. `bvmenv push <vm> <hostfile> <guestpath>` and `pull` are file/directory
   copies; the runner pushes individual files so a failed push names the exact
   artifact.
7. `bvmenv reset <vm>` returns the VM to the base snapshot and may take tens of
   seconds; the runner waits for desktop readiness again.
8. `--elevated` is applied per case from `requires_admin`; without it driver
   install/start/stop and hide operations will fail.
9. Guest paths use `C:\blook-e2e\` and Windows PowerShell 5.1; no network,
   secrets or external modules are required.
10. The stubbed `blook-antidetect.exe` / `blook-guest-hooks.exe` return 77;
    cases use `allow_skip` until the real probes exist.  `hv-info` and
    `trace-scan` are also probed for unknown-command/77 output and skipped.
11. The hook runner contract is `blook-guest-hooks.exe ept <mode> --target-pid
    <pid> --target-address <hex> --target-log <path> --json`, plus
    `kchannel-fuzz --mode`, `memory-pressure`, and the swbreak/hwbreak mode
    names used in `cases.psd1`.  Change `run-ept-hook.ps1`/`guest-hooks.ps1`
    in one place if env's test binary chooses different argv.

### bvmenv 0.1.0 compatibility (verified against the local build)

The runner was checked against `bvmenv.exe` 0.1.0 while it was being built and
handles its differences from the original contract:

- `state <vm> --json` uses the nested `bvmenv.state.v1` schema
  (`screen.classification`, `screen.stop_code`, `screen.screenshot`,
  `tools.running`).  `ConvertTo-FlatVmState` adds the flat aliases the rest of
  the harness expects and also derives `vmware_log` from the sibling
  `vmware.log` of `vmx`.
- `exec` returns **1 for any non-zero guest exit**.  The runner requests
  `exec <vm> --json` and reads `ExecResult.exit_code` / `timed_out` /
  `stdout_path` / `stderr_path`; for a contract-style CLI it falls back to the
  `exit_code    : N` line and then to the process exit code.
- `reset` leaves the VM powered off in 0.1.0; after every reset the runner
  issues `start` when `state` says `power=off`, then waits for desktop.
- 0.1.0 calls the destroy operation `delete`; this harness never destroys VMs.
- The global `--json` switch is command-local in 0.1.0; the runner puts it
  after `exec <vm>` and after `state <vm>`.

## Case-id → acceptance criterion

Generated from the `acceptance` field in [`cases.psd1`](cases.psd1).  This is
the mapping required by the project test plan; update both files together.

| Case id | Category | Acceptance criterion |
| --- | --- | --- |
| `boot-baseline` | smoke | Windows 11 guest is alive, testsigning is enabled, and blook-loader.exe runs. |
| `driver-install` | smoke | A fresh signed blook-drv.sys installs as the BlookDrv kernel service. |
| `driver-start-solo` | smoke | Start virtualises every CPU and `sc query BlookDrv` reports RUNNING. |
| `driver-stop` | smoke | Stop exits VMX cleanly and the SCM service reaches STOPPED. |
| `driver-restart-10x` | smoke | Repeated VMX bring-up/teardown does not leak or wedge the service. |
| `cpuid-nested-host` | nested-virt | The outer hypervisor is VMware and its CPUID vendor leaf is visible inside the guest. |
| `nested-vmx-available` | nested-virt | VMX is usable in the nested guest or hv-info reports an explicit, documented degradation. |
| `hv-start-in-nested` | hv-lifecycle | VMX initialisation succeeds under nested virtualisation. |
| `hv-stop-in-nested` | hv-lifecycle | Every CPU leaves VMX and the driver unloads without a bugcheck. |
| `hv-start-stop-50x` | hv-lifecycle | Nested VMX lifecycle is stable over 50 cycles (no leak, no hang). |
| `antidetect-baseline` | antidetect | A no-driver baseline is recorded; its FAILs are data, not a test failure. |
| `antidetect-with-hv` | antidetect | Compared with the no-driver baseline, hiding adds zero new detector FAILs. |
| `cpuid-hypervisor-bit-hidden` | antidetect | CPUID.1:ECX[31] reads zero for the target while the driver is active. |
| `cpuid-vendor-leaves-empty` | antidetect | CPUID leaves above 0x3FFFFFFF return the configured non-disclosing values. |
| `vmx-msr-filtered` | antidetect | RDMSR of VMX capability MSRs in the target does not reveal the hypervisor. |
| `tsc-timing-clean` | antidetect | Timing checks stay within the detector threshold (hide_timing enabled). |
| `rdtscp-clean` | antidetect | RDTSCP executes natively; TSC_AUX and ordering match bare behaviour. |
| `aperf-mperf-clean` | antidetect | APERF/MPERF access and CPUID invariant-TSC reporting are not disclosing. |
| `exception-behaviour-clean` | antidetect | Instruction faults and exception delivery are indistinguishable from bare metal. |
| `ept-hook-self-page-read` | ept-hooks | A target reading its own hooked page sees the original instruction bytes. |
| `ept-hook-foreign-process` | ept-hooks | A spawned target executes the detour and the hit counter is greater than zero. |
| `ept-hook-multi-same-page` | ept-hooks | The driver merges eight non-overlapping hooks into one shadow page. |
| `ept-unhook-restores` | ept-hooks | After remove, the target executes the original code path again. |
| `ept-hook-while-thread-executes` | ept-hooks | A thread executing the hooked instruction survives install/remove without corruption. |
| `ept-hook-invalid-address` | ept-hooks | Non-canonical, unmapped and read-only addresses return a clean error and the VM stays alive. |
| `ept-hook-unload-under-load` | ept-hooks | Global teardown drains in-flight hooks before freeing trampolines. |
| `swbreak-arm-hit-restore` | swbreak | INT3 fires, the original instruction executes, and the page is restored. |
| `swbreak-single-step-correctness` | swbreak | The monitored thread advances by exactly one instruction, with no duplicate side effect. |
| `swbreak-rearm-after-hit` | swbreak | After a hit is consumed, a second arm fires again. |
| `swbreak-multi-hooks` | swbreak | Several int3 hooks on distinct addresses all resolve to the correct handler. |
| `swbreak-disarm-race` | swbreak | Disarm while the target is executing does not lose or duplicate the instruction. |
| `swbreak-hook-unhook-1000x` | swbreak | 1000 cycles finish and leave no hook, pool or page reference leak. |
| `hwbreak-arm-hit` | hwbreak | A DR execution breakpoint fires for the target and is accounted to the correct hook. |
| `hwbreak-dr7-query-sanitised` | hwbreak | NtGetContextThread returns zero/hidden DR0-DR3, DR6 and DR7 to the target. |
| `hwbreak-scan-clean` | hwbreak | Repeated DR queries from the target never observe the armed breakpoint. |
| `hwbreak-setcontext-does-not-clobber` | hwbreak | NtSetContextThread cannot overwrite/disable the hypervisor-managed DR state. |
| `hwbreak-multi-index` | hwbreak | All four hardware-breakpoint slots are usable with independent conditions. |
| `hwbreak-disarm` | hwbreak | Disarm clears the slot and the target no longer triggers. |
| `hwbreak-unload-with-bp-armed` | hwbreak | Service stop removes an armed hypervisor breakpoint without blue-screening the VM. |
| `self-hide-module-list` | self-hide | NtQuerySystemInformation SystemModuleInformation does not expose the driver image. |
| `self-hide-device-symlink` | self-hide | `\Device` scan and `CreateFile \\.\BlookDrv` both fail while hidden. |
| `self-hide-registry` | self-hide | `HKLM\SYSTEM\CurrentControlSet\Services\<svc>` is unlinked while hidden. |
| `self-hide-pool-tag` | self-hide | Allocations use the benign MmSt tag; no blook-specific tag is observable. |
| `trace-scan-clean` | self-hide | `trace_scan` reports `found==0` after self-hide. |
| `self-hide-then-unload` | self-hide | Self-hidden driver still stops/unlinks cleanly; the service query fails afterwards. |
| `kchannel-bad-payload` | invalid-input | Malformed payloads produce error codes, no crash and no hang. |
| `kchannel-unknown-opcode` | invalid-input | An unregistered opcode returns a clean error; the adapter stays live. |
| `kchannel-no-attach` | invalid-input | A request with no attached peer returns an error instead of blocking. |
| `kchannel-double-attach` | invalid-input | `adapter_start` is idempotent and reports `kc_status::already`. |
| `kchannel-detach-then-call` | invalid-input | After `adapter_stop`/detach, a CALL returns an error rather than a stale success. |
| `invalid-parameters-table` | invalid-input | Every malformed request returns an error code quickly; none hangs or crashes. |
| `hook-stress-1000` | stress | 1000 hook cycles finish; pool/page/session counts return to baseline. |
| `concurrent-processes` | stress | Per-process hook state is isolated and all four targets see their own detour. |
| `memory-pressure` | stress | Install/uninstall still succeeds with commit near 80% and releases cleanly. |
| `unload-under-load` | crash-safety | `sc stop` drains in-flight work and returns within the timeout, with no BSOD. |
| `watchdog-detects-hang` | crash-safety | The watchdog kills a 5 s case, reports timeout, and the next state query still says desktop. |

## Matrix coverage

The matrix has **56 cases** across the required categories:
`smoke` (5), `nested-virt` (2), `hv-lifecycle` (3), `antidetect` (9),
`ept-hooks` (7), `swbreak` (6), `hwbreak` (7), `self-hide` (6),
`invalid-input` (6), `stress` (3), `crash-safety` (2).

`nested-virt` covers CPUID/VMX availability; the start/stop lifecycle cases are
in `hv-lifecycle`, which keeps the category names meaningful.  All baseline
cases run before the cases that depend on their output.  `watchdog-detects-hang`
is last so an intentional timeout cannot delay the rest of the matrix.

## Troubleshooting

- **`bvmenv was not found`** — only fatal outside `-DryRun`/`-ValidateOnly`.
  Build `blook-vmware-environment` or pass `-Bvmenv`.
- **`VM did not become desktop-ready`** — inspect the readiness messages in
  `run.log`; the VM may be at a login screen, still booting, or
  `tools_heartbeat=false`.
  `-ReadyTimeoutSeconds` can be raised.
- **Everything is `skip` with exit 77** — the guest test binaries are still
  stubs; this is the expected state for the current repository.
- **A crash resets and aborts** — this is intentional.  Use `-KeepGoing` only
  when you want to collect the rest of the matrix after a known crash; the
  report still lists the crash as a blocker.
- **`-NoReset` crash** — no recovery is attempted; reset the VM manually and
  rerun.

