# Evidence policy

This directory holds the artefacts the acceptance claims are based on. Two kinds
of runs exist, and they are never mixed:

| Directory | What it proves |
|---|---|
| `2026*-e2e/` with `"dry_run": true` | The e2e harness can validate the 56-case matrix, resolve bvmenv and write result/report files. **It does not prove the driver works.** |
| `2026*-e2e/` with `"dry_run": false` (or no flag) | A real run: the driver was loaded inside a bvmenv VMware guest, each case produced stdout/stderr and a host-side screen capture/state JSON, and the run's summary is the pass/fail table. |

## Host safety rule (non-negotiable)

Kernel code runs **only** inside a bvmenv-managed VMware guest. The repository
enforces this structurally:

* `scripts/Build.ps1` refuses `-Deploy`, `-Start` and `-StopRunningDriver`
  outright: it builds, signs and runs host unit tests only.
* `blook-loader start` refuses to run unless `BLOOK_VM_GUEST` **and**
  `BLOOK_ALLOW_KERNEL_LOAD` are set, which only `scripts/E2E.ps1` does, on a
  command line executed through `bvmenv exec`.
* `tests/guest/*` binaries and `tests/e2e/guest/lib.ps1` exit with
  "refusing to run kernel code outside a bvmenv guest" when the marker is absent.

The earlier `host-live`/`host-crash` artefacts were produced by running the
hypervisor on the physical host, which power-cycled the machine twice. They were
removed, the script was deleted, and the guards above are what prevents a repeat.

## Reproducing a real run

```powershell
# from the repo root, with bvmenv available
pwsh -File scripts/E2E.ps1 -Vm vm-drv
```

The runner builds driver/SDK/guest binaries, creates or resets `vm-drv` through
bvmenv, pushes the bundle, runs every case with a hard timeout, captures
`screenshot.png`/`state.json`/`vmware.log` evidence per case, resets the VM on a
crash, and writes `result.json` + `report.md` into the evidence directory. A
crash or hang fails the run; it is never silently skipped.