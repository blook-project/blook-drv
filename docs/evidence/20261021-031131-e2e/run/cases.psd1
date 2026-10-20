# blook-drv end-to-end case matrix.
#
# This is a PowerShell data file: it may contain only literals (no variables,
# no expressions, no commands).  scripts/E2E.ps1 validates every entry before a
# VM is touched.
#
# Keys
#   id             stable kebab-case id (unique, used as the artifact dir name)
#   name           human-readable name
#   category       smoke | nested-virt | hv-lifecycle | ept-hooks | swbreak |
#                  hwbreak | self-hide | antidetect | stress | crash-safety |
#                  invalid-input
#   command        string or array: guest command line (argv, no shell quoting)
#   timeout_s      guest timeout handed to `bvmenv exec --timeout`
#   expect_exit    expected guest exit code (77 = stub/skip when allow_skip)
#   requires_admin pass `bvmenv exec --elevated`
#   allow_skip     exit 77 means "feature not implemented in this build", not fail
#   expect_timeout the case is expected to be killed by the timeout sentinel
#   post_checks    optional assertions:
#                    state_classification, stdout_contains, stdout_not_contains,
#                    stderr_contains, stderr_not_contains, min_stdout_bytes,
#                    max_duration_s
#   acceptance     one-line acceptance criterion (mapped in tests/e2e/README.md)
#   notes          free-form note copied into result.json/report.md
#
# Order is the execution order.  Keep baseline/data-collection cases before the
# cases that consume their output.
@(
    # ------------------------------------------------------------------
    # smoke: the VM and driver service exist and can be driven
    # ------------------------------------------------------------------
    @{
        id = 'boot-baseline'
        name = 'Guest boots, testsigning on, loader executable runs'
        category = 'smoke'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\boot-baseline.ps1')
        timeout_s = 180
        expect_exit = 0
        requires_admin = $false
        allow_skip = $false
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('testsigning=Yes', 'loader=ok') }
        acceptance = 'Windows 11 guest is alive, testsigning is enabled, and blook-loader.exe runs.'
    }
    @{
        id = 'driver-install'
        name = 'Install the signed driver service'
        category = 'smoke'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\driver-lifecycle.ps1', '-Action', 'install')
        timeout_s = 180
        expect_exit = 0
        requires_admin = $true
        allow_skip = $false
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('installed=ok') }
        acceptance = 'A fresh signed blook-drv.sys installs as the BlookDrv kernel service.'
    }
    @{
        id = 'driver-start-solo'
        name = 'Start the driver in solo mode (no profile) and query it'
        category = 'smoke'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\driver-lifecycle.ps1', '-Action', 'start-solo')
        timeout_s = 240
        expect_exit = 0
        requires_admin = $true
        allow_skip = $false
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('state=running') }
        acceptance = 'Start virtualises every CPU and `sc query BlookDrv` reports RUNNING.'
    }
    @{
        id = 'driver-stop'
        name = 'Stop the driver and verify the service is stopped'
        category = 'smoke'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\driver-lifecycle.ps1', '-Action', 'stop')
        timeout_s = 180
        expect_exit = 0
        requires_admin = $true
        allow_skip = $false
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('state=stopped') }
        acceptance = 'Stop exits VMX cleanly and the SCM service reaches STOPPED.'
    }
    @{
        id = 'driver-restart-10x'
        name = 'Start/stop the driver ten times'
        category = 'smoke'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\driver-lifecycle.ps1', '-Action', 'restart-10x')
        timeout_s = 900
        expect_exit = 0
        requires_admin = $true
        allow_skip = $false
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('restarts=10') }
        acceptance = 'Repeated VMX bring-up/teardown does not leak or wedge the service.'
    }

    # ------------------------------------------------------------------
    # nested-virt: this driver runs inside VMware, so VT-x must be exposed
    # ------------------------------------------------------------------
    @{
        id = 'cpuid-nested-host'
        name = 'CPUID 0x40000000 reports the VMware hypervisor vendor'
        category = 'nested-virt'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\hv-info.ps1', '-Check', 'cpuid-vendor')
        timeout_s = 120
        expect_exit = 0
        requires_admin = $false
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('cpuid_40000000_vendor=VMware') }
        acceptance = 'The outer hypervisor is VMware and its CPUID vendor leaf is visible inside the guest.'
    }
    @{
        id = 'nested-vmx-available'
        name = 'Nested VMX is available or its degradation is documented'
        category = 'nested-virt'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\hv-info.ps1', '-Check', 'nested-vmx')
        timeout_s = 180
        expect_exit = 0
        requires_admin = $false
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('nested_vmx=available'); stdout_not_contains = @('degraded=yes') }
        acceptance = 'VMX is usable in the nested guest or hv-info reports an explicit, documented degradation.'
    }
    @{
        id = 'hv-start-in-nested'
        name = 'Start blook-drv while already running inside VMware'
        category = 'hv-lifecycle'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\driver-lifecycle.ps1', '-Action', 'start-nested')
        timeout_s = 300
        expect_exit = 0
        requires_admin = $true
        allow_skip = $false
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('state=running', 'nested=started') }
        acceptance = 'VMX initialisation succeeds under nested virtualisation.'
    }
    @{
        id = 'hv-stop-in-nested'
        name = 'Stop blook-drv cleanly in the nested guest'
        category = 'hv-lifecycle'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\driver-lifecycle.ps1', '-Action', 'stop')
        timeout_s = 180
        expect_exit = 0
        requires_admin = $true
        allow_skip = $false
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('state=stopped') }
        acceptance = 'Every CPU leaves VMX and the driver unloads without a bugcheck.'
    }
    @{
        id = 'hv-start-stop-50x'
        name = 'Fifty nested start/stop cycles'
        category = 'hv-lifecycle'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\driver-lifecycle.ps1', '-Action', 'start-stop-50x')
        timeout_s = 1200
        expect_exit = 0
        requires_admin = $true
        allow_skip = $false
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('cycles=50') }
        acceptance = 'Nested VMX lifecycle is stable over 50 cycles (no leak, no hang).'
    }

    # ------------------------------------------------------------------
    # antidetect: baseline data collection, then no new detector FAILs
    # ------------------------------------------------------------------
    @{
        id = 'antidetect-baseline'
        name = 'Collect the no-driver anti-detection baseline'
        category = 'antidetect'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\run-antidetect.ps1', '-Mode', 'baseline')
        timeout_s = 240
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('baseline_saved=yes') }
        acceptance = 'A no-driver baseline is recorded; its FAILs are data, not a test failure.'
        notes = 'Collects the baseline used by antidetect-with-hv; FAILs here are expected and recorded.'
    }
    @{
        id = 'antidetect-with-hv'
        name = 'Anti-detection suite adds no new FAILs with blook-drv running'
        category = 'antidetect'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\run-antidetect.ps1', '-Mode', 'with-hv')
        timeout_s = 300
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('new_fails=0') }
        acceptance = 'Compared with the no-driver baseline, hiding adds zero new detector FAILs.'
    }
    @{
        id = 'cpuid-hypervisor-bit-hidden'
        name = 'CPUID hypervisor-present bit is hidden'
        category = 'antidetect'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\detect-check.ps1', '-Check', 'cpuid-hypervisor-bit')
        timeout_s = 120
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('check=cpuid-hypervisor-bit pass=true') }
        acceptance = 'CPUID.1:ECX[31] reads zero for the target while the driver is active.'
    }
    @{
        id = 'cpuid-vendor-leaves-empty'
        name = 'Hypervisor vendor leaves 0x40000000+ are empty'
        category = 'antidetect'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\detect-check.ps1', '-Check', 'cpuid-vendor-leaves')
        timeout_s = 120
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('check=cpuid-vendor-leaves pass=true') }
        acceptance = 'CPUID leaves above 0x3FFFFFFF return the configured non-disclosing values.'
    }
    @{
        id = 'vmx-msr-filtered'
        name = 'IA32_VMX_BASIC MSR is filtered for the target'
        category = 'antidetect'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\detect-check.ps1', '-Check', 'vmx-msr')
        timeout_s = 120
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('check=vmx-msr pass=true') }
        acceptance = 'RDMSR of VMX capability MSRs in the target does not reveal the hypervisor.'
    }
    @{
        id = 'tsc-timing-clean'
        name = 'TSC/CPUID timing is not measurably hypervisor-skewed'
        category = 'antidetect'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\detect-check.ps1', '-Check', 'tsc-timing')
        timeout_s = 300
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('check=tsc-timing pass=true') }
        acceptance = 'Timing checks stay within the detector threshold (hide_timing enabled).'
    }
    @{
        id = 'rdtscp-clean'
        name = 'RDTSCP is consistent and not trapped'
        category = 'antidetect'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\detect-check.ps1', '-Check', 'rdtscp')
        timeout_s = 180
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('check=rdtscp pass=true') }
        acceptance = 'RDTSCP executes natively; TSC_AUX and ordering match bare behaviour.'
    }
    @{
        id = 'aperf-mperf-clean'
        name = 'APERF/MPERF and invariant-TSC leaves are clean'
        category = 'antidetect'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\detect-check.ps1', '-Check', 'aperf-mperf')
        timeout_s = 180
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('check=aperf-mperf pass=true') }
        acceptance = 'APERF/MPERF access and CPUID invariant-TSC reporting are not disclosing.'
    }
    @{
        id = 'exception-behaviour-clean'
        name = 'Exception and fault behaviour matches bare metal'
        category = 'antidetect'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\detect-check.ps1', '-Check', 'exception-behaviour')
        timeout_s = 180
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('check=exception-behaviour pass=true') }
        acceptance = 'Instruction faults and exception delivery are indistinguishable from bare metal.'
    }

    # ------------------------------------------------------------------
    # ept-hooks: software EPT hooks (target reads keep original bytes)
    # ------------------------------------------------------------------
    @{
        id = 'ept-hook-self-page-read'
        name = 'Hooked page reads return the original bytes'
        category = 'ept-hooks'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\run-ept-hook.ps1', '-Mode', 'self-page-read')
        timeout_s = 240
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('self_read=original') }
        acceptance = 'A target reading its own hooked page sees the original instruction bytes.'
    }
    @{
        id = 'ept-hook-foreign-process'
        name = 'Hook a foreign process, observe hits and detour output'
        category = 'ept-hooks'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\run-ept-hook.ps1', '-Mode', 'foreign-process')
        timeout_s = 240
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('detour_observed=yes', 'hit_count_positive=yes') }
        acceptance = 'A spawned target executes the detour and the hit counter is greater than zero.'
    }
    @{
        id = 'ept-hook-multi-same-page'
        name = 'At least eight hooks share one page'
        category = 'ept-hooks'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\run-ept-hook.ps1', '-Mode', 'multi-same-page')
        timeout_s = 300
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('hooks_on_page=8') }
        acceptance = 'The driver merges eight non-overlapping hooks into one shadow page.'
    }
    @{
        id = 'ept-unhook-restores'
        name = 'Unhook restores the original bytes and behaviour'
        category = 'ept-hooks'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\run-ept-hook.ps1', '-Mode', 'unhook-restores')
        timeout_s = 240
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('restored=yes') }
        acceptance = 'After remove, the target executes the original code path again.'
    }
    @{
        id = 'ept-hook-while-thread-executes'
        name = 'Install/remove while the target thread spins in the function'
        category = 'ept-hooks'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\run-ept-hook.ps1', '-Mode', 'while-thread-executes')
        timeout_s = 240
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('thread_survived=yes') }
        acceptance = 'A thread executing the hooked instruction survives install/remove without corruption.'
    }
    @{
        id = 'ept-hook-invalid-address'
        name = 'Invalid hook address is rejected without a BSOD'
        category = 'ept-hooks'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\run-ept-hook.ps1', '-Mode', 'invalid-address')
        timeout_s = 180
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('invalid_rejected=yes') }
        acceptance = 'Non-canonical, unmapped and read-only addresses return a clean error and the VM stays alive.'
    }
    @{
        id = 'ept-hook-unload-under-load'
        name = 'Unload the driver while a threaded hook target is active'
        category = 'ept-hooks'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\run-unload-under-load.ps1', '-Mode', 'ept')
        timeout_s = 300
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('stop_clean=yes') }
        acceptance = 'Global teardown drains in-flight hooks before freeing trampolines.'
    }

    # ------------------------------------------------------------------
    # swbreak: external-process int3 hooks
    # ------------------------------------------------------------------
    @{
        id = 'swbreak-arm-hit-restore'
        name = 'Software breakpoint arms, hits and restores'
        category = 'swbreak'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\guest-hooks.ps1', '-Mode', 'swbreak-arm-hit-restore')
        timeout_s = 240
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('hit=yes', 'restored=yes') }
        acceptance = 'INT3 fires, the original instruction executes, and the page is restored.'
    }
    @{
        id = 'swbreak-single-step-correctness'
        name = 'MTF executes the original instruction exactly once'
        category = 'swbreak'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\guest-hooks.ps1', '-Mode', 'swbreak-single-step-correctness')
        timeout_s = 240
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('single_step=exactly_once') }
        acceptance = 'The monitored thread advances by exactly one instruction, with no duplicate side effect.'
    }
    @{
        id = 'swbreak-rearm-after-hit'
        name = 'Software breakpoint can be re-armed after a hit'
        category = 'swbreak'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\guest-hooks.ps1', '-Mode', 'swbreak-rearm-after-hit')
        timeout_s = 240
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('rearmed=yes') }
        acceptance = 'After a hit is consumed, a second arm fires again.'
    }
    @{
        id = 'swbreak-multi-hooks'
        name = 'Multiple software breakpoints coexist'
        category = 'swbreak'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\guest-hooks.ps1', '-Mode', 'swbreak-multi-hooks')
        timeout_s = 300
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('multi_hooks=yes') }
        acceptance = 'Several int3 hooks on distinct addresses all resolve to the correct handler.'
    }
    @{
        id = 'swbreak-disarm-race'
        name = 'Disarm racing an executing target is safe'
        category = 'swbreak'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\guest-hooks.ps1', '-Mode', 'swbreak-disarm-race')
        timeout_s = 300
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('race=clean') }
        acceptance = 'Disarm while the target is executing does not lose or duplicate the instruction.'
    }
    @{
        id = 'swbreak-hook-unhook-1000x'
        name = 'One thousand software-breakpoint hook/unhook cycles'
        category = 'swbreak'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\guest-hooks.ps1', '-Mode', 'swbreak-hook-unhook-1000x')
        timeout_s = 1200
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('cycles=1000', 'leaks=0') }
        acceptance = '1000 cycles finish and leave no hook, pool or page reference leak.'
    }

    # ------------------------------------------------------------------
    # hwbreak: DR0-DR3 and context sanitisation
    # ------------------------------------------------------------------
    @{
        id = 'hwbreak-arm-hit'
        name = 'Hardware breakpoint arms and fires'
        category = 'hwbreak'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\guest-hooks.ps1', '-Mode', 'hwbreak-arm-hit')
        timeout_s = 240
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('hit=yes') }
        acceptance = 'A DR execution breakpoint fires for the target and is accounted to the correct hook.'
    }
    @{
        id = 'hwbreak-dr7-query-sanitised'
        name = 'GetThreadContext hides the target DR registers'
        category = 'hwbreak'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\get-dr-context.ps1', '-SpawnTarget', '-PinAsTarget', '-ExpectZero', '-EnsureHidden')
        timeout_s = 240
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('dr_sanitised=yes') }
        acceptance = 'NtGetContextThread returns zero/hidden DR0-DR3, DR6 and DR7 to the target.'
    }
    @{
        id = 'hwbreak-scan-clean'
        name = 'A scanner-style DR read loop sees no breakpoint'
        category = 'hwbreak'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\get-dr-context.ps1', '-SpawnTarget', '-PinAsTarget', '-ScanLoop', '100', '-ExpectZero', '-EnsureHidden')
        timeout_s = 300
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('scan_clean=yes') }
        acceptance = 'Repeated DR queries from the target never observe the armed breakpoint.'
    }
    @{
        id = 'hwbreak-setcontext-does-not-clobber'
        name = 'Target NtSetContextThread does not disable our breakpoint'
        category = 'hwbreak'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\guest-hooks.ps1', '-Mode', 'hwbreak-setcontext-does-not-clobber')
        timeout_s = 240
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('not_clobbered=yes') }
        acceptance = 'NtSetContextThread cannot overwrite/disable the hypervisor-managed DR state.'
    }
    @{
        id = 'hwbreak-multi-index'
        name = 'DR0 through DR3 can be armed independently'
        category = 'hwbreak'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\guest-hooks.ps1', '-Mode', 'hwbreak-multi-index')
        timeout_s = 240
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('multi_index=yes') }
        acceptance = 'All four hardware-breakpoint slots are usable with independent conditions.'
    }
    @{
        id = 'hwbreak-disarm'
        name = 'Hardware breakpoint disarms cleanly'
        category = 'hwbreak'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\guest-hooks.ps1', '-Mode', 'hwbreak-disarm')
        timeout_s = 180
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('disarmed=yes') }
        acceptance = 'Disarm clears the slot and the target no longer triggers.'
    }
    @{
        id = 'hwbreak-unload-with-bp-armed'
        name = 'Unload with a hardware breakpoint still armed'
        category = 'hwbreak'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\guest-hooks.ps1', '-Mode', 'hwbreak-unload-with-bp-armed')
        timeout_s = 300
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('unload_clean=yes') }
        acceptance = 'Service stop removes an armed hypervisor breakpoint without blue-screening the VM.'
    }

    # ------------------------------------------------------------------
    # self-hide: the driver hides its own module/device/service/pool traces
    # ------------------------------------------------------------------
    @{
        id = 'self-hide-module-list'
        name = 'SystemModuleInformation does not list blook-drv'
        category = 'self-hide'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\scan-drivers.ps1', '-ExpectHidden', '-EnsureHidden')
        timeout_s = 240
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('module_visible=no') }
        acceptance = 'NtQuerySystemInformation SystemModuleInformation does not expose the driver image.'
    }
    @{
        id = 'self-hide-device-symlink'
        name = 'The BlookDrv device and symlink are not discoverable'
        category = 'self-hide'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\scan-devices.ps1', '-ExpectHidden', '-EnsureHidden')
        timeout_s = 180
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('device_visible=no') }
        acceptance = '\Device scan and CreateFile \\.\BlookDrv both fail while hidden.'
    }
    @{
        id = 'self-hide-registry'
        name = 'The SCM service key is removed'
        category = 'self-hide'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\scan-services.ps1', '-ExpectHidden', '-EnsureHidden')
        timeout_s = 180
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('service_key_visible=no') }
        acceptance = 'HKLM\SYSTEM\CurrentControlSet\Services\<svc> is unlinked while hidden.'
    }
    @{
        id = 'self-hide-pool-tag'
        name = 'A pool-tag scan finds no project-specific tag'
        category = 'self-hide'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\scan-pool.ps1', '-ExpectHidden', '-EnsureHidden')
        timeout_s = 240
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('project_tags_found=0') }
        acceptance = 'Allocations use the benign MmSt tag; no blook-specific tag is observable.'
    }
    @{
        id = 'trace-scan-clean'
        name = 'The driver trace_scan reports zero findings'
        category = 'self-hide'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\trace-scan.ps1', '-ExpectFound', '0', '-EnsureHidden')
        timeout_s = 180
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('trace_found=0') }
        acceptance = 'trace_scan reports found==0 after self-hide.'
    }
    @{
        id = 'self-hide-then-unload'
        name = 'Clean unload after self-hide, then sc query fails'
        category = 'self-hide'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\self-hide-then-unload.ps1')
        timeout_s = 300
        expect_exit = 0
        requires_admin = $true
        allow_skip = $false
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('unloaded=yes') }
        acceptance = 'Self-hidden driver still stops/unlinks cleanly; the service query fails afterwards.'
    }

    # ------------------------------------------------------------------
    # invalid-input: hostile requests must fail fast, never hang
    # ------------------------------------------------------------------
    @{
        id = 'kchannel-bad-payload'
        name = 'Truncated/oversized/garbage kchannel payloads are rejected'
        category = 'invalid-input'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\kchannel-fuzz.ps1', '-Mode', 'bad-payload')
        timeout_s = 180
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('bad_payload_rejected=yes') }
        acceptance = 'Malformed payloads produce error codes, no crash and no hang.'
    }
    @{
        id = 'kchannel-unknown-opcode'
        name = 'Unknown kchannel opcodes are rejected'
        category = 'invalid-input'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\kchannel-fuzz.ps1', '-Mode', 'unknown-opcode')
        timeout_s = 180
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('unknown_opcode_rejected=yes') }
        acceptance = 'An unregistered opcode returns a clean error; the adapter stays live.'
    }
    @{
        id = 'kchannel-no-attach'
        name = 'Calls without a transport session fail cleanly'
        category = 'invalid-input'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\kchannel-fuzz.ps1', '-Mode', 'no-attach')
        timeout_s = 180
        expect_exit = 0
        requires_admin = $true
        allow_skip = $false
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('no_attach_rejected=yes') }
        acceptance = 'A request with no attached peer returns an error instead of blocking.'
    }
    @{
        id = 'kchannel-double-attach'
        name = 'A second attach returns KC_ERR_ALREADY'
        category = 'invalid-input'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\kchannel-fuzz.ps1', '-Mode', 'double-attach')
        timeout_s = 180
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('double_attach=already') }
        acceptance = 'adapter_start is idempotent and reports kc_status::already.'
    }
    @{
        id = 'kchannel-detach-then-call'
        name = 'Calls after detach are rejected'
        category = 'invalid-input'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\kchannel-fuzz.ps1', '-Mode', 'detach-then-call')
        timeout_s = 180
        expect_exit = 0
        requires_admin = $true
        allow_skip = $false
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('detach_then_call=rejected') }
        acceptance = 'After adapter_stop/detach, a CALL returns an error rather than a stale success.'
    }
    @{
        id = 'invalid-parameters-table'
        name = 'A table of malformed loader requests is rejected'
        category = 'invalid-input'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\invalid-parameters.ps1')
        timeout_s = 300
        expect_exit = 0
        requires_admin = $false
        allow_skip = $false
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('all_rejected=yes') }
        acceptance = 'Every malformed request returns an error code quickly; none hangs or crashes.'
    }

    # ------------------------------------------------------------------
    # stress / crash-safety
    # ------------------------------------------------------------------
    @{
        id = 'hook-stress-1000'
        name = 'One thousand install/remove cycles on rotating addresses'
        category = 'stress'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\guest-hooks.ps1', '-Mode', 'hook-stress-1000')
        timeout_s = 1200
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('cycles=1000', 'leaks=0') }
        acceptance = '1000 hook cycles finish; pool/page/session counts return to baseline.'
    }
    @{
        id = 'concurrent-processes'
        name = 'Four target processes are hooked simultaneously'
        category = 'stress'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\guest-hooks.ps1', '-Mode', 'concurrent-processes')
        timeout_s = 400
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('processes=4', 'hits_positive=yes') }
        acceptance = 'Per-process hook state is isolated and all four targets see their own detour.'
    }
    @{
        id = 'memory-pressure'
        name = 'Hook/unhook under 80% commit pressure'
        category = 'stress'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\memory-pressure.ps1')
        timeout_s = 900
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('pressure=ok', 'hook_unhook=ok') }
        acceptance = 'Install/uninstall still succeeds with commit near 80% and releases cleanly.'
    }
    @{
        id = 'unload-under-load'
        name = 'Stop the driver while target threads are executing'
        category = 'crash-safety'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\run-unload-under-load.ps1', '-Mode', 'load')
        timeout_s = 300
        expect_exit = 0
        requires_admin = $true
        allow_skip = $true
        post_checks = @{ state_classification = 'desktop'; stdout_contains = @('stop_clean=yes') }
        acceptance = 'sc stop drains in-flight work and returns within the timeout, with no BSOD.'
    }
    @{
        id = 'watchdog-detects-hang'
        name = 'Synthetic hang is classified timeout and the VM stays alive'
        category = 'crash-safety'
        command = @('powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', 'C:\blook-e2e\hang-helper.ps1', '-Seconds', '600')
        timeout_s = 5
        expect_exit = 124
        requires_admin = $false
        allow_skip = $false
        expect_timeout = $true
        post_checks = @{ state_classification = 'desktop' }
        acceptance = 'The watchdog kills a 5s case, reports timeout, and the next state query still says desktop.'
        notes = 'Intentional timeout: validates the watchdog and VM-alive post-check. Does not abort the run.'
    }
)
