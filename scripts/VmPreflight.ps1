# Real-VM preflight for blook-drv.
#
# Runs a minimal, high-signal subset of the e2e matrix against a bvmenv VMware
# guest: baseline anti-detection, driver install/start, anti-detection with the
# hypervisor running, a software-breakpoint hook hit, a hardware-breakpoint hook
# hit, then clean stop. It is the fast feedback loop before the full 56-case
# matrix (scripts/E2E.ps1) and it never runs anything on the physical host.
[CmdletBinding()]
param(
    [string]$Vm = "vm-drv",
    [string]$Bvmenv,
    [int]$ReadyTimeoutSeconds = 600,
    [switch]$KeepVm,
    [int]$InterceptDebug = 0,
    [int]$SkipTimingCalibration = 1,
    [int]$BringupMinimal = 1,
    [int]$StartStage = 0,
    [int]$MaxCpus = 0,
    [int]$BringupNoEpt = 0,
    [string]$Artifacts
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$build = Join-Path $repo "build\windows\x64\releasedbg"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
if (-not $Artifacts) { $Artifacts = Join-Path $repo "docs\evidence\$stamp-vm-preflight" }
New-Item -ItemType Directory -Force $Artifacts | Out-Null
$runLog = Join-Path $Artifacts "preflight.log"
$stream = [IO.File]::Open($runLog, "Create", "Write", "ReadWrite")
$writer = New-Object IO.StreamWriter($stream)
function L($message) {
    $line = "$(Get-Date -Format o) $message"
    Write-Host $line
    $writer.WriteLine($line); $writer.Flush(); $stream.Flush($true)
}
function Fail($message) {
    L "FAIL: $message"
    $writer.Close(); $stream.Close()
    exit 1
}

# ---------------------------------------------------------------- bvmenv
if (-not $Bvmenv) {
    $Bvmenv = (Get-Command bvmenv -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1).Source
    if (-not $Bvmenv) {
        $candidate = Get-ChildItem "D:\blook-kernel-project\blook-vmware-environment\build" -Recurse -Filter bvmenv.exe -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($candidate) { $Bvmenv = $candidate.FullName }
    }
}
if (-not $Bvmenv -or -not (Test-Path -LiteralPath $Bvmenv)) { Fail "bvmenv.exe not found" }
L "bvmenv=$Bvmenv vm=$Vm artifacts=$Artifacts"

# Every bvmenv call gets a hard host-side timeout and a killed process tree.
function Invoke-Bvmenv {
    param([string[]]$Arguments, [int]$TimeoutSeconds = 120, [switch]$Echo)
    $commandLine = ($Arguments | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
    L "  $ bvmenv $commandLine"
    $out = "$env:TEMP\bv-out.txt"
    $err = "$env:TEMP\bv-err.txt"
    $p = $null
    foreach ($attempt in 1..3) {
        try {
            $p = Start-Process -FilePath $Bvmenv -ArgumentList $Arguments -PassThru -WindowStyle Hidden `
                -RedirectStandardOutput $out -RedirectStandardError $err
            break
        } catch {
            # bvmenv may be rebuilt in place while we run; retry briefly.
            Start-Sleep -Seconds 2
        }
    }
    if (-not $p) { L "  cannot start bvmenv ($Bvmenv)"; return [pscustomobject]@{ ExitCode = 127; StdOut = ''; StdErr = 'missing bvmenv' } }
    if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
        try { & taskkill /PID $p.Id /T /F | Out-Null } catch { }
        L "  TIMEOUT after ${TimeoutSeconds}s"
        return [pscustomobject]@{ ExitCode = 124; StdOut = ''; StdErr = 'timeout' }
    }
    $stdout = Get-Content -LiteralPath $out -Raw -ErrorAction SilentlyContinue
    $stderr = Get-Content -LiteralPath $err -Raw -ErrorAction SilentlyContinue
    if ($Echo) {
        foreach ($line in @(($stdout + "`n" + $stderr) -split "`r?`n")) {
            if ($line.Trim()) { L "    $line" }
        }
    }
    return [pscustomobject]@{ ExitCode = $p.ExitCode; StdOut = $stdout; StdErr = $stderr }
}

function Invoke-Guest {
    param([string]$Command, [int]$TimeoutSeconds = 180)
    # The markers are set by run-guest.cmd inside the guest, not by an inline
    # `set` in the bvmenv command line: bvmenv runs the command through a
    # generated job script / SYSTEM task, where an inline `set` does not reach
    # the child process.
    return Invoke-Bvmenv -TimeoutSeconds ($TimeoutSeconds + 60) -Arguments @(
        'exec', $Vm, '--timeout', [string]$TimeoutSeconds, '--elevated', '--',
        'cmd.exe', '/c', "C:\blook-e2e\run-guest.cmd $Command") -Echo
}

try {
    # ------------------------------------------------------------ build
    L "=== build"
    $env:BLOOK_VERSION = (Get-Content -LiteralPath (Join-Path $repo 'version.txt') -Raw).Trim()
    $kchannel = if ($env:KCHANNEL_DIR) { $env:KCHANNEL_DIR } else { Join-Path (Split-Path -Parent $repo) 'blook-kchannel' }
    Push-Location $repo
    try {
        & xmake f -p windows -a x64 -m releasedbg --kchannel_dir=$kchannel -y | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail "xmake configure failed" }
        & xmake -y | Out-Null
        if ($LASTEXITCODE -ne 0) { Fail "xmake build failed" }
    } finally { Pop-Location }
    foreach ($name in @('blook-drv.sys', 'blook-loader.exe', 'blook-antidetect.exe', 'blook-guest-hooks.exe')) {
        $path = Join-Path $build $name
        if (-not (Test-Path -LiteralPath $path)) { Fail "missing $path" }
        L "  built $name"
    }
    # Sign the driver with the repository signer (test signing for the guest).
    $sys = Join-Path $build 'blook-drv.sys'
    $signer = Join-Path $repo 'signer\spcsign\spcsign.exe'
    if (Test-Path -LiteralPath $signer) {
        L "=== sign"
        & $signer sign --sha1 --cert XINDA --tsa-time 2013-01-01T00:00:00Z `
            --chain (Join-Path $repo 'signer\certs\verisign-cscs-2010.cer') `
            --chain (Join-Path $repo 'signer\certs\verisign-g5-mcvr.cer') $sys | ForEach-Object { L "  $_" }
        if ($LASTEXITCODE -ne 0) { L "  warning: signing failed; guest needs testsigning" }
    }

    # ------------------------------------------------------------ vm
    L "=== vm lifecycle"
    $list = Invoke-Bvmenv -Arguments @('list', '--json') -TimeoutSeconds 60
    if ($list.ExitCode -ne 0) { Fail "bvmenv list failed: $($list.StdErr)" }
    # "does the fork exist" is answered by the VMX file, not by parsing the
    # list output: a fresh clone and an existing one must not be distinguished by
    # a help-text footer.
    $vmx = Join-Path (Join-Path (Join-Path 'C:\blook-vms' 'vms') $Vm) "$Vm.vmx"
    if (-not (Test-Path -LiteralPath $vmx)) {
        L "  creating $Vm"
        $created = Invoke-Bvmenv -Arguments @('create', $Vm, '--no-start', '--cpus', '4', '--memory', '6144') -TimeoutSeconds 240 -Echo
        if ($created.ExitCode -ne 0 -and -not (Test-Path -LiteralPath $vmx)) {
            Fail "create failed: $($created.StdOut) $($created.StdErr)"
        }
    } else {
        L "  $Vm already exists"
    }
    $started = Invoke-Bvmenv -Arguments @('start', $Vm) -TimeoutSeconds 120
    if ($started.ExitCode -ne 0) { L "  start returned $($started.ExitCode) (may already be running)" }
    # Readiness is "a guest command round-trips", not "the desktop is up":
    # bvmenv exec falls back to a SYSTEM scheduled task while the guest sits at
    # the lock UI, so this is the condition the tests actually need (and
    # wait-ready's user-session probe is known to stall on a lock-UI clone).
    $deadline = (Get-Date).AddSeconds($ReadyTimeoutSeconds)
    $guestReady = $false
    while ((Get-Date) -lt $deadline) {
        $probe = Invoke-Bvmenv -Arguments @('exec', $Vm, '--timeout', '15', '--', 'cmd.exe', '/c', 'echo READY') -TimeoutSeconds 45
        if ($probe.ExitCode -eq 0 -and $probe.StdOut -match 'READY') { $guestReady = $true; break }
        Start-Sleep -Seconds 10
    }
    if (-not $guestReady) { Fail "guest never became reachable (exec poll, ${ReadyTimeoutSeconds}s)" }
    L "  guest reachable"
    $state = Invoke-Bvmenv -Arguments @('state', $Vm, '--json') -TimeoutSeconds 60
    L "  state: $($state.StdOut)"

    # ------------------------------------------------------------ bundle
    L "=== push bundle"
    $guestRoot = 'C:\blook-e2e'
    # No wrapper for this one: it creates the directory the wrapper is pushed to.
    $boot = Invoke-Bvmenv -TimeoutSeconds 90 -Arguments @(
        'exec', $Vm, '--timeout', '60', '--elevated', '--',
        'cmd.exe', '/c', "if not exist $guestRoot mkdir $guestRoot") -Echo
    if ($boot.ExitCode -ne 0) { Fail "cannot create $guestRoot in the guest" }
    foreach ($name in @('blook-drv.sys', 'blook-loader.exe', 'blook-antidetect.exe', 'blook-guest-hooks.exe')) {
        $r = Invoke-Bvmenv -Arguments @('push', $Vm, (Join-Path $build $name), "$guestRoot\$name") -TimeoutSeconds 120
        if ($r.ExitCode -ne 0) { Fail "push $name failed: $($r.StdErr)" }
        L "  pushed $name"
    }
    Get-ChildItem (Join-Path $repo 'tests\e2e\guest') -File |
        Where-Object { $_.Extension -in '.ps1', '.cmd' } | ForEach-Object {
        $r = Invoke-Bvmenv -Arguments @('push', $Vm, $_.FullName, "$guestRoot\$($_.Name)") -TimeoutSeconds 120
        if ($r.ExitCode -ne 0) { Fail "push $($_.Name) failed" }
    }
    if (-not (Test-Path -LiteralPath (Join-Path $repo 'tests\e2e\guest\run-guest.cmd'))) {
        Fail "tests\e2e\guest\run-guest.cmd is missing"
    }
    L "  pushed guest helpers"
    # Belt and braces: machine-wide markers so any process the guest starts
    # (including SYSTEM scheduled tasks) sees them even if a wrapper is missed.
    Invoke-Guest -Command "cmd.exe /c setx /M BLOOK_VM_GUEST $Vm" -TimeoutSeconds 60 | Out-Null
    Invoke-Guest -Command "cmd.exe /c setx /M BLOOK_ALLOW_KERNEL_LOAD 1" -TimeoutSeconds 60 | Out-Null
    L "  machine markers set"

    # ------------------------------------------------------------ baseline
    L "=== antidetect baseline (no driver)"
    $baselinePath = Join-Path $Artifacts 'antidetect-baseline.json'
    $baseline = Invoke-Guest -Command "cmd /c $guestRoot\blook-antidetect.exe --json $guestRoot\baseline.json --quick" -TimeoutSeconds 180
    $baselineJson = Invoke-Bvmenv -Arguments @('pull', $Vm, "$guestRoot\baseline.json", $baselinePath) -TimeoutSeconds 60
    L "  baseline exit=$($baseline.ExitCode)"
    foreach ($line in ($baseline.StdOut -split "`r?`n")) { if ($line -match '^\[' ) { L "    $line" } }

    # ------------------------------------------------------------ driver
    L "=== driver install + start"
    $install = Invoke-Guest -Command "cmd /c $guestRoot\blook-loader.exe install $guestRoot\blook-drv.sys"
    L "  install exit=$($install.ExitCode): $($install.StdOut)"
    # Startup-only switches: keep the first nested bring-up minimal (no MOV-DR /
    # #BP / #DB interception) and enable the stage breadcrumbs. They are read by
    # DriverEntry from the service key's Parameters subkey.
    $params = "HKLM\SYSTEM\CurrentControlSet\Services\BlookDrv\Parameters"
    Invoke-Guest -Command "cmd.exe /c reg.exe add $params /f /v InterceptDebug /t REG_DWORD /d $InterceptDebug" -TimeoutSeconds 60 | Out-Null
    Invoke-Guest -Command "cmd.exe /c reg.exe add $params /f /v InterceptRdtscp /t REG_DWORD /d 0" -TimeoutSeconds 60 | Out-Null
    Invoke-Guest -Command "cmd.exe /c reg.exe add $params /f /v TraceMarkers /t REG_DWORD /d 1" -TimeoutSeconds 60 | Out-Null
    Invoke-Guest -Command "cmd.exe /c reg.exe add $params /f /v SkipTimingCalibration /t REG_DWORD /d $SkipTimingCalibration" -TimeoutSeconds 60 | Out-Null
    Invoke-Guest -Command "cmd.exe /c reg.exe add $params /f /v BringupMinimal /t REG_DWORD /d $BringupMinimal" -TimeoutSeconds 60 | Out-Null
    Invoke-Guest -Command "cmd.exe /c reg.exe add $params /f /v StartStage /t REG_DWORD /d $StartStage" -TimeoutSeconds 60 | Out-Null
    Invoke-Guest -Command "cmd.exe /c reg.exe add $params /f /v MaxCpus /t REG_DWORD /d $MaxCpus" -TimeoutSeconds 60 | Out-Null
    Invoke-Guest -Command "cmd.exe /c reg.exe add $params /f /v BringupNoEpt /t REG_DWORD /d $BringupNoEpt" -TimeoutSeconds 60 | Out-Null
    $start = Invoke-Guest -Command "cmd /c $guestRoot\blook-loader.exe start"
    # Read the bring-up markers immediately: the service key is removed at the
    # end of the preflight, so this is the only chance to see StageSerial,
    # LaunchError and Storm*.
    $markers = Invoke-Guest -Command "cmd.exe /c reg.exe query $params" -TimeoutSeconds 60
    foreach ($line in ($markers.StdOut -split "`r?`n")) { if ($line.Trim()) { L ("  marker: " + $line.Trim()) } }
    L "  start exit=$($start.ExitCode): $($start.StdOut)"
    $afterState = Invoke-Bvmenv -Arguments @('state', $Vm, '--json') -TimeoutSeconds 60
    if ($afterState.StdOut -match '"classification":\s*"(bsod|hang)"') { Fail "guest crashed after driver start: $($afterState.StdOut)" }
    L "  guest alive after start"

    L "=== antidetect with hypervisor running"
    $withHvPath = Join-Path $Artifacts 'antidetect-with-hv.json'
    $withHv = Invoke-Guest -Command "cmd /c $guestRoot\blook-antidetect.exe --json $guestRoot\with-hv.json --quick" -TimeoutSeconds 180
    Invoke-Bvmenv -Arguments @('pull', $Vm, "$guestRoot\with-hv.json", $withHvPath) -TimeoutSeconds 60 | Out-Null
    L "  with-hv exit=$($withHv.ExitCode)"
    foreach ($line in ($withHv.StdOut -split "`r?`n")) { if ($line -match '^\[' ) { L "    $line" } }

    L "=== software breakpoint hook"
    $sw = Invoke-Guest -Command "cmd /c $guestRoot\blook-guest-hooks.exe swbreak-arm-hit-restore" -TimeoutSeconds 240
    L "  swbreak exit=$($sw.ExitCode)"
    foreach ($line in ($sw.StdOut -split "`r?`n")) { if ($line.Trim()) { L "    $line" } }

    L "=== hardware breakpoint hook"
    $hw = Invoke-Guest -Command "cmd /c $guestRoot\blook-guest-hooks.exe hwbreak-arm-hit" -TimeoutSeconds 240
    L "  hwbreak exit=$($hw.ExitCode)"
    foreach ($line in ($hw.StdOut -split "`r?`n")) { if ($line.Trim()) { L "    $line" } }

    L "=== stop + uninstall"
    $stop = Invoke-Guest -Command "cmd /c $guestRoot\blook-loader.exe stop"
    L "  stop exit=$($stop.ExitCode): $($stop.StdOut)"
    $uninstall = Invoke-Guest -Command "cmd /c $guestRoot\blook-loader.exe uninstall"
    L "  uninstall exit=$($uninstall.ExitCode): $($uninstall.StdOut)"
    $finalState = Invoke-Bvmenv -Arguments @('state', $Vm, '--json') -TimeoutSeconds 60
    L "  final state: $($finalState.StdOut)"
    if ($finalState.StdOut -match '"classification":\s*"(bsod|hang)"') { Fail "guest not healthy at the end" }

    # Serial carries the kernel debug breadcrumbs (bringup::stage) and the
    # exit-storm watchdog record; keep it with the evidence either way.
    Invoke-Bvmenv -Arguments @('pull', $Vm, 'C:\blook-vms\vms\vm-drv\serial.log', "$Artifacts\serial.log") -TimeoutSeconds 60 | Out-Null
    Invoke-Bvmenv -Arguments @('state', $Vm, '--json') -TimeoutSeconds 60 | Out-Null
    L "PREFLIGHT OK"
} finally {
    if (-not $KeepVm) {
        L "=== reset vm (leave it clean)"
        Invoke-Bvmenv -Arguments @('reset', $Vm) -TimeoutSeconds 180 | Out-Null
    }
    $writer.Close(); $stream.Close()
}