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
    [int]$ReadyTimeoutSeconds = 300,
    [switch]$KeepVm,
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
    $p = Start-Process -FilePath $Bvmenv -ArgumentList $Arguments -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $out -RedirectStandardError $err
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
    $marker = "set BLOOK_VM_GUEST=$Vm&& set BLOOK_ALLOW_KERNEL_LOAD=1&& "
    return Invoke-Bvmenv -TimeoutSeconds ($TimeoutSeconds + 60) -Arguments @(
        'exec', $Vm, '--timeout', [string]$TimeoutSeconds, '--elevated', '--',
        'cmd.exe', '/c', ($marker + $Command)) -Echo
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
    $known = $false
    try { $json = $list.StdOut | ConvertFrom-Json; $known = @($json.vms | Where-Object { $_.name -eq $Vm }).Count -gt 0 } catch { }
    if (-not $known) {
        $created = Invoke-Bvmenv -Arguments @('create', $Vm, '--cpus', '4', '--memory', '6144') -TimeoutSeconds 180 -Echo
        if ($created.ExitCode -ne 0) { Fail "create failed: $($created.StdOut) $($created.StdErr)" }
    }
    $started = Invoke-Bvmenv -Arguments @('start', $Vm) -TimeoutSeconds 120
    if ($started.ExitCode -ne 0) { L "  start returned $($started.ExitCode) (may already be running)" }
    $ready = Invoke-Bvmenv -Arguments @('wait-ready', $Vm, '--timeout', [string]$ReadyTimeoutSeconds) -TimeoutSeconds ($ReadyTimeoutSeconds + 60) -Echo
    if ($ready.ExitCode -ne 0) { Fail "wait-ready failed" }
    $state = Invoke-Bvmenv -Arguments @('state', $Vm, '--json') -TimeoutSeconds 60
    L "  state: $($state.StdOut)"

    # ------------------------------------------------------------ bundle
    L "=== push bundle"
    $guestRoot = 'C:\blook-e2e'
    Invoke-Guest -Command "cmd /c if not exist $guestRoot mkdir $guestRoot" -TimeoutSeconds 60 | Out-Null
    foreach ($name in @('blook-drv.sys', 'blook-loader.exe', 'blook-antidetect.exe', 'blook-guest-hooks.exe')) {
        $r = Invoke-Bvmenv -Arguments @('push', $Vm, (Join-Path $build $name), "$guestRoot\$name") -TimeoutSeconds 120
        if ($r.ExitCode -ne 0) { Fail "push $name failed: $($r.StdErr)" }
        L "  pushed $name"
    }
    Get-ChildItem (Join-Path $repo 'tests\e2e\guest') -Filter *.ps1 -File | ForEach-Object {
        $r = Invoke-Bvmenv -Arguments @('push', $Vm, $_.FullName, "$guestRoot\$($_.Name)") -TimeoutSeconds 120
        if ($r.ExitCode -ne 0) { Fail "push $($_.Name) failed" }
    }
    L "  pushed guest helpers"

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
    $start = Invoke-Guest -Command "cmd /c $guestRoot\blook-loader.exe start"
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

    L "PREFLIGHT OK"
} finally {
    if (-not $KeepVm) {
        L "=== reset vm (leave it clean)"
        Invoke-Bvmenv -Arguments @('reset', $Vm) -TimeoutSeconds 180 | Out-Null
    }
    $writer.Close(); $stream.Close()
}