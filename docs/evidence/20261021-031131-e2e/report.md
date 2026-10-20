# blook-drv end-to-end report (DRY RUN)

- Started: 2026-10-20 19:11:31Z
- Finished: 2026-10-20 19:11:32Z
- VM: `vm-drv`
- Configuration: `releasedbg`
- bvmenv: `not found (dry run)`
- Host: MB-CLOUD
- Git: e8b444d
- Artifacts: `D:\blook-kernel-project\blook-drv\docs\evidence\20261021-031131-e2e`

## Summary

| total | pass | fail | skip | crash | timeout | expected timeout |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 56 | 0 | 0 | 56 | 0 | 0 | 0 |

## Cases

| # | id | category | status | exit | duration | evidence |
| ---: | --- | --- | --- | ---: | ---: | --- |
| 1 | boot-baseline | smoke | skip |  | 0s | [boot-baseline](cases/boot-baseline/) |
| 2 | driver-install | smoke | skip |  | 0s | [driver-install](cases/driver-install/) |
| 3 | driver-start-solo | smoke | skip |  | 0s | [driver-start-solo](cases/driver-start-solo/) |
| 4 | driver-stop | smoke | skip |  | 0s | [driver-stop](cases/driver-stop/) |
| 5 | driver-restart-10x | smoke | skip |  | 0s | [driver-restart-10x](cases/driver-restart-10x/) |
| 6 | cpuid-nested-host | nested-virt | skip |  | 0s | [cpuid-nested-host](cases/cpuid-nested-host/) |
| 7 | nested-vmx-available | nested-virt | skip |  | 0s | [nested-vmx-available](cases/nested-vmx-available/) |
| 8 | hv-start-in-nested | hv-lifecycle | skip |  | 0s | [hv-start-in-nested](cases/hv-start-in-nested/) |
| 9 | hv-stop-in-nested | hv-lifecycle | skip |  | 0s | [hv-stop-in-nested](cases/hv-stop-in-nested/) |
| 10 | hv-start-stop-50x | hv-lifecycle | skip |  | 0s | [hv-start-stop-50x](cases/hv-start-stop-50x/) |
| 11 | antidetect-baseline | antidetect | skip |  | 0s | [antidetect-baseline](cases/antidetect-baseline/) |
| 12 | antidetect-with-hv | antidetect | skip |  | 0s | [antidetect-with-hv](cases/antidetect-with-hv/) |
| 13 | cpuid-hypervisor-bit-hidden | antidetect | skip |  | 0s | [cpuid-hypervisor-bit-hidden](cases/cpuid-hypervisor-bit-hidden/) |
| 14 | cpuid-vendor-leaves-empty | antidetect | skip |  | 0s | [cpuid-vendor-leaves-empty](cases/cpuid-vendor-leaves-empty/) |
| 15 | vmx-msr-filtered | antidetect | skip |  | 0s | [vmx-msr-filtered](cases/vmx-msr-filtered/) |
| 16 | tsc-timing-clean | antidetect | skip |  | 0s | [tsc-timing-clean](cases/tsc-timing-clean/) |
| 17 | rdtscp-clean | antidetect | skip |  | 0s | [rdtscp-clean](cases/rdtscp-clean/) |
| 18 | aperf-mperf-clean | antidetect | skip |  | 0s | [aperf-mperf-clean](cases/aperf-mperf-clean/) |
| 19 | exception-behaviour-clean | antidetect | skip |  | 0s | [exception-behaviour-clean](cases/exception-behaviour-clean/) |
| 20 | ept-hook-self-page-read | ept-hooks | skip |  | 0s | [ept-hook-self-page-read](cases/ept-hook-self-page-read/) |
| 21 | ept-hook-foreign-process | ept-hooks | skip |  | 0s | [ept-hook-foreign-process](cases/ept-hook-foreign-process/) |
| 22 | ept-hook-multi-same-page | ept-hooks | skip |  | 0s | [ept-hook-multi-same-page](cases/ept-hook-multi-same-page/) |
| 23 | ept-unhook-restores | ept-hooks | skip |  | 0s | [ept-unhook-restores](cases/ept-unhook-restores/) |
| 24 | ept-hook-while-thread-executes | ept-hooks | skip |  | 0s | [ept-hook-while-thread-executes](cases/ept-hook-while-thread-executes/) |
| 25 | ept-hook-invalid-address | ept-hooks | skip |  | 0s | [ept-hook-invalid-address](cases/ept-hook-invalid-address/) |
| 26 | ept-hook-unload-under-load | ept-hooks | skip |  | 0s | [ept-hook-unload-under-load](cases/ept-hook-unload-under-load/) |
| 27 | swbreak-arm-hit-restore | swbreak | skip |  | 0s | [swbreak-arm-hit-restore](cases/swbreak-arm-hit-restore/) |
| 28 | swbreak-single-step-correctness | swbreak | skip |  | 0s | [swbreak-single-step-correctness](cases/swbreak-single-step-correctness/) |
| 29 | swbreak-rearm-after-hit | swbreak | skip |  | 0s | [swbreak-rearm-after-hit](cases/swbreak-rearm-after-hit/) |
| 30 | swbreak-multi-hooks | swbreak | skip |  | 0s | [swbreak-multi-hooks](cases/swbreak-multi-hooks/) |
| 31 | swbreak-disarm-race | swbreak | skip |  | 0s | [swbreak-disarm-race](cases/swbreak-disarm-race/) |
| 32 | swbreak-hook-unhook-1000x | swbreak | skip |  | 0s | [swbreak-hook-unhook-1000x](cases/swbreak-hook-unhook-1000x/) |
| 33 | hwbreak-arm-hit | hwbreak | skip |  | 0s | [hwbreak-arm-hit](cases/hwbreak-arm-hit/) |
| 34 | hwbreak-dr7-query-sanitised | hwbreak | skip |  | 0s | [hwbreak-dr7-query-sanitised](cases/hwbreak-dr7-query-sanitised/) |
| 35 | hwbreak-scan-clean | hwbreak | skip |  | 0s | [hwbreak-scan-clean](cases/hwbreak-scan-clean/) |
| 36 | hwbreak-setcontext-does-not-clobber | hwbreak | skip |  | 0s | [hwbreak-setcontext-does-not-clobber](cases/hwbreak-setcontext-does-not-clobber/) |
| 37 | hwbreak-multi-index | hwbreak | skip |  | 0s | [hwbreak-multi-index](cases/hwbreak-multi-index/) |
| 38 | hwbreak-disarm | hwbreak | skip |  | 0s | [hwbreak-disarm](cases/hwbreak-disarm/) |
| 39 | hwbreak-unload-with-bp-armed | hwbreak | skip |  | 0s | [hwbreak-unload-with-bp-armed](cases/hwbreak-unload-with-bp-armed/) |
| 40 | self-hide-module-list | self-hide | skip |  | 0s | [self-hide-module-list](cases/self-hide-module-list/) |
| 41 | self-hide-device-symlink | self-hide | skip |  | 0s | [self-hide-device-symlink](cases/self-hide-device-symlink/) |
| 42 | self-hide-registry | self-hide | skip |  | 0s | [self-hide-registry](cases/self-hide-registry/) |
| 43 | self-hide-pool-tag | self-hide | skip |  | 0s | [self-hide-pool-tag](cases/self-hide-pool-tag/) |
| 44 | trace-scan-clean | self-hide | skip |  | 0s | [trace-scan-clean](cases/trace-scan-clean/) |
| 45 | self-hide-then-unload | self-hide | skip |  | 0s | [self-hide-then-unload](cases/self-hide-then-unload/) |
| 46 | kchannel-bad-payload | invalid-input | skip |  | 0s | [kchannel-bad-payload](cases/kchannel-bad-payload/) |
| 47 | kchannel-unknown-opcode | invalid-input | skip |  | 0s | [kchannel-unknown-opcode](cases/kchannel-unknown-opcode/) |
| 48 | kchannel-no-attach | invalid-input | skip |  | 0s | [kchannel-no-attach](cases/kchannel-no-attach/) |
| 49 | kchannel-double-attach | invalid-input | skip |  | 0s | [kchannel-double-attach](cases/kchannel-double-attach/) |
| 50 | kchannel-detach-then-call | invalid-input | skip |  | 0s | [kchannel-detach-then-call](cases/kchannel-detach-then-call/) |
| 51 | invalid-parameters-table | invalid-input | skip |  | 0s | [invalid-parameters-table](cases/invalid-parameters-table/) |
| 52 | hook-stress-1000 | stress | skip |  | 0s | [hook-stress-1000](cases/hook-stress-1000/) |
| 53 | concurrent-processes | stress | skip |  | 0s | [concurrent-processes](cases/concurrent-processes/) |
| 54 | memory-pressure | stress | skip |  | 0s | [memory-pressure](cases/memory-pressure/) |
| 55 | unload-under-load | crash-safety | skip |  | 0s | [unload-under-load](cases/unload-under-load/) |
| 56 | watchdog-detects-hang | crash-safety | skip |  | 0s | [watchdog-detects-hang](cases/watchdog-detects-hang/) |

## How to interpret this run

- `pass`: guest exit code and every assertion matched.
- `fail`: the guest ran but an expectation failed; the VM stayed alive.
- `skip`: the guest returned 77 (feature not implemented in this build) or the case was not run.
- `crash`: post-case state was `bsod`, `hang`, `off`, or the state query itself failed.
- `timeout`: bvmenv hit the case timeout (sentinel 124) or the host killed it.
- `watchdog-detects-hang` is intentionally a `timeout` result; it validates the watchdog and the VM-alive post-check. It does not abort the run.
- Exit code is 0 only when every executed case passed and no unexpected crash/timeout occurred.

## Reproduction

```powershell
pwsh -File scripts/E2E.ps1 -Vm vm-drv -Configuration releasedbg -Artifacts "D:\blook-kernel-project\blook-drv\docs\evidence\20261021-031131-e2e"
```
