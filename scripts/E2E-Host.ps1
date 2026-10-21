# Non-VT-x end-to-end suite for CI or a disposable VM.
#
# Covers everything the hosted runner can exercise without nested VT-x: driver
# install/start/stop/uninstall, the kernel->user verification round trip (the
# driver records its bring-up markers in its service key and the harness reads
# them back), lifecycle stress and negative input. Hypervisor and hook cases are
# reported as documented skips: they need nested VT-x/EPT and run in the bvmenv
# VM matrix (scripts/E2E.ps1, docs/evidence).
#
# Never run this on the physical lab host: it loads a kernel driver. It is meant
# for the GitHub runner (a disposable VM) or a bvmenv guest.
[CmdletBinding()]
param(
    [string]$Sys,
    [string]$Loader,
    [string]$Hooks,
    [string]$Artifacts = "out/host-e2e",
    [string]$Service = "BlookDrv"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$build = Join-Path $repo "build\windows\x64\releasedbg"
if (-not $Sys) { $Sys = Join-Path $build "blook-drv.sys" }
if (-not $Loader) { $Loader = Join-Path $build "blook-loader.exe" }
if (-not $Hooks) { $Hooks = Join-Path $build "blook-guest-hooks.exe" }
New-Item -ItemType Directory -Force $Artifacts | Out-Null

# The tools and the service refuse to run without the harness markers; this
# script *is* the harness (a disposable VM), so it sets them for its children.
$env:BLOOK_VM_GUEST = if ($env:BLOOK_VM_GUEST) { $env:BLOOK_VM_GUEST } else { "host-e2e" }
$env:BLOOK_ALLOW_KERNEL_LOAD = "1"

$cases = [System.Collections.Generic.List[object]]::new()
$skips = [System.Collections.Generic.List[object]]::new()
$key = "HKLM\SYSTEM\CurrentControlSet\Services\$Service\Parameters"

function Add-Case([string]$name, [string]$status, [string]$detail) {
    $cases.Add([ordered]@{ name = $name; status = $status; detail = $detail })
    Write-Host ("[{0}] {1}: {2}" -f $status, $name, $detail)
}

function Invoke-Tool([string]$exe, [string[]]$arguments, [int]$timeoutSeconds = 90) {
    $stdout = Join-Path $Artifacts ((Split-Path -Leaf $exe) + "." + [guid]::NewGuid().ToString("N") + ".out")
    $p = Start-Process -FilePath $exe -ArgumentList $arguments -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $stdout -RedirectStandardError "$stdout.err"
    if (-not $p.WaitForExit($timeoutSeconds * 1000)) {
        try { & taskkill /PID $p.Id /T /F | Out-Null } catch { }
        return [ordered]@{ exit = 124; stdout = "timeout"; stderr = "" }
    }
    return [ordered]@{
        exit = $p.ExitCode
        stdout = (Get-Content $stdout -Raw -ErrorAction SilentlyContinue)
        stderr = (Get-Content "$stdout.err" -Raw -ErrorAction SilentlyContinue)
    }
}

function Set-Param([string]$name, [int]$value) {
    & reg add $key /f /v $name /t REG_DWORD /d $value | Out-Null
}

function Get-Param([string]$name) {
    $out = (& reg query $key /v $name 2>$null | Out-String)
    if ($out -match '0x([0-9a-fA-F]+)') { return [Convert]::ToInt32($Matches[1], 16) }
    return -1
}

function Invoke-Case([string]$name, [scriptblock]$body) {
    try {
        $detail = & $body
        Add-Case $name "pass" "$detail"
    } catch {
        Add-Case $name "fail" ($_.Exception.Message)
    }
}

# A previous run may have left the service behind; start from a clean slate.
& sc.exe stop $Service 2>$null | Out-Null
Start-Sleep -Seconds 1
& sc.exe delete $Service 2>$null | Out-Null
Start-Sleep -Seconds 1

function Test-ServiceState([string]$state) {
    $query = (Invoke-Tool "sc.exe" @("query", $Service)).stdout
    return ($query -match $state)
}

Invoke-Case "loader-install" {
    # The loader reports success in its message; its process exit code is not a
    # reliable signal on every Windows build, so the service state decides.
    $r = Invoke-Tool $Loader @("install", $Sys)
    if (($r.stdout + $r.stderr) -match "Installed" -eq $false) {
        throw ("loader install failed: " + $r.stdout + $r.stderr)
    }
    if (-not (Test-ServiceState "STOPPED")) { throw "service key missing after install" }
    "service installed from $Sys"
}

Invoke-Case "start-no-hypervisor" {
    # NoHypervisor keeps DriverEntry away from VT-x; the loader detects it and
    # starts the driver solo instead of waiting for a channel peer.
    Set-Param "NoHypervisor" 1
    Set-Param "Solo" 1
    Set-Param "TraceMarkers" 1
    $r = Invoke-Tool $Loader @("start")
    $query = (Invoke-Tool "sc.exe" @("query", $Service)).stdout
    if ($query -notmatch "RUNNING") {
        throw ("service did not start: " + $r.stdout + $r.stderr + $query)
    }
    "STATE 4 RUNNING"
}

Invoke-Case "kernel-roundtrip-markers" {
    # The driver wrote these from kernel mode in DriverEntry; reading them back
    # is the kernel->user verification round trip that does not need a channel.
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline -and (Get-Param "TraceLast") -ne 0x3) {
        Start-Sleep -Milliseconds 200
    }
    $last = Get-Param "TraceLast"
    $count = Get-Param "TraceCount"
    if ($last -ne 0x3) { throw ("TraceLast=$last, expected 3 (session ready)") }
    if ($count -lt 3) { throw ("TraceCount=$count, expected >= 3") }
    "TraceLast=0x3 TraceCount=$count (kernel-written, read back)"
}

Invoke-Case "start-when-running" {
    $r = Invoke-Tool $Loader @("start")
    $query = (Invoke-Tool "sc.exe" @("query", $Service)).stdout
    if ($query -notmatch "RUNNING") { throw "service left RUNNING state after a duplicate start" }
    "duplicate start handled (loader exit $($r.exit))"
}

Invoke-Case "lifecycle-restart-cycle" {
    for ($i = 0; $i -lt 3; $i++) {
        $stop = Invoke-Tool $Loader @("stop")
        if (($stop.stdout + $stop.stderr) -notmatch "Stopped" -and -not (Test-ServiceState "STOPPED")) {
            throw ("stop $i failed: " + $stop.stdout + $stop.stderr)
        }
        $start = Invoke-Tool $Loader @("start")
        if (-not (Test-ServiceState "RUNNING")) {
            throw ("start $i did not reach RUNNING: " + $start.stdout + $start.stderr)
        }
    }
    "3 stop/start cycles"
}

Invoke-Case "negative-invalid-image-path" {
    $bad = Join-Path $env:TEMP "does-not-exist-$([guid]::NewGuid().ToString('N')).sys"
    & sc.exe stop $Service | Out-Null
    Start-Sleep -Seconds 1
    & sc.exe delete $Service | Out-Null
    Start-Sleep -Seconds 1
    $r = Invoke-Tool $Loader @("install", $bad)
    if ($r.exit -eq 0) { throw "installing a nonexistent driver image must fail" }
    $present = (& sc.exe query $Service | Out-String)
    if ($present -match "RUNNING") { throw "failed install left the service running" }
    "rejected cleanly (exit $($r.exit))"
}

Invoke-Case "uninstall-cleanup" {
    $r = Invoke-Tool $Loader @("install", $Sys)
    if (($r.stdout + $r.stderr) -notmatch "Installed") { throw ("re-install failed: " + $r.stdout + $r.stderr) }
    $r = Invoke-Tool $Loader @("uninstall")
    if (($r.stdout + $r.stderr) -notmatch "removed|Removed|uninstall") {
        $still = (& sc.exe query $Service 2>$null | Out-String)
        if ($still -match "RUNNING|STOPPED") { throw ("uninstall failed: " + $r.stdout + $r.stderr) }
    }
    "service removed"
}

# ---- documented skips (vm-only, need nested VT-x/EPT) ----------------------
foreach ($skip in @(
    @{ name = "vmx-bringup"; status = "skip"; detail = "platform-skip: requires VT-x - VMXON/VMLAUNCH/EPT need nested VT-x; covered by the bvmenv VM matrix (docs/evidence/20261021-nested-*)" },
    @{ name = "ept-software-breakpoint-hook"; status = "skip"; detail = "platform-skip: requires VT-x - EPT execute hook in a live guest (bvmenv matrix)" },
    @{ name = "hardware-breakpoint-hook"; status = "skip"; detail = "platform-skip: requires VT-x - DR0-3/#DB interception (bvmenv matrix)" },
    @{ name = "target-process-hook"; status = "skip"; detail = "platform-skip: requires VT-x - cross-process EPT hook needs the hypervisor (bvmenv matrix)" },
    @{ name = "with-hypervisor-antidetect"; status = "skip"; detail = "platform-skip: requires VT-x - masking CPUID/MSR needs the hypervisor running (bvmenv matrix)" },
    @{ name = "kchannel-ipc-tools"; status = "skip"; detail = "platform-skip: requires VT-x - the control channel is created by the hypervisor session (bvmenv matrix)" },
    @{ name = "self-hide-trace-scan"; status = "skip"; detail = "platform-skip: requires VT-x - self-hide/trace-scan are driven over the control channel (bvmenv matrix)" }
)) {
    $skips.Add([ordered]@{ name = $skip.name; status = $skip.status; detail = $skip.detail })
    Write-Host ("[skip] {0}: {1}" -f $skip.name, $skip.detail)
}

$platform = [ordered]@{}
try {
    $bcd = (& bcdedit /enum '{current}' | Out-String)
    $platform.testsigning = if ($bcd -match '(?im)^testsigning\s+Yes') { "Yes" } elseif ($bcd -match '(?im)^testsigning\s+No') { "No" } else { "unknown" }
    $platform.nointegritychecks = if ($bcd -match '(?im)^nointegritychecks\s+Yes') { "Yes" } elseif ($bcd -match '(?im)^nointegritychecks\s+No') { "No" } else { "unknown" }
} catch { $platform.testsigning = "unknown" }
$signtool = Get-ChildItem 'C:\Program Files (x86)\Windows Kits\10\bin' -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\' } | Select-Object -First 1
if ($signtool -and (Test-Path $Sys)) {
    $kp = (& $signtool.FullName verify /kp $Sys 2>&1 | Out-String)
    $platform.kp_verified = ($LASTEXITCODE -eq 0)
    $platform.kp_output = $kp.Trim().Substring(0, [Math]::Min(400, $kp.Trim().Length))
} else {
    $platform.kp_verified = $null
}

$failures = @($cases | Where-Object { $_.status -eq "fail" })
$result = [ordered]@{
    schema = "blook.e2e.host.v1"
    platform = $platform
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    cases = @($cases) + @($skips)
    summary = [ordered]@{
        pass = @($cases | Where-Object { $_.status -eq "pass" }).Count
        fail = $failures.Count
        skip = $skips.Count
    }
}
# The result file is written even when cases fail: the CI gate consumes it.
$resultPath = Join-Path $Artifacts "result.json"
$result | ConvertTo-Json -Depth 6 | Set-Content $resultPath
Write-Host ("host e2e: {0} pass, {1} fail, {2} documented skips -> {3}" -f $result.summary.pass, $result.summary.fail, $result.summary.skip, $resultPath)
if ($failures.Count -ne 0) { throw ("host e2e failures: " + (($failures | ForEach-Object { $_.name }) -join ', ')) }