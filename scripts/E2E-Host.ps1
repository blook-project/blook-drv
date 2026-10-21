# Non-VT-x end-to-end suite for CI or a disposable VM.
#
# Runs the parts of the blook-drv matrix that do not need a hypervisor: driver
# install/start/stop/uninstall, the kchannel command surface, self-hide, trace
# scan, stress and negative input. Hypervisor cases (VMXON/VMLAUNCH/EPT/
# hardware-breakpoint hooks) are listed as documented skips because they need
# nested VT-x and only run in the bvmenv VM matrix (scripts/E2E.ps1).
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

function Add-Case([string]$name, [string]$status, [string]$detail, [int]$exit = 0) {
    $cases.Add([ordered]@{ name = $name; status = $status; detail = $detail; exit = $exit })
    Write-Host ("[{0}] {1}: {2}" -f $status, $name, $detail)
}

function Invoke-Tool([string]$exe, [string[]]$arguments, [int]$timeoutSeconds = 60) {
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

function Invoke-Case([string]$name, [scriptblock]$body) {
    try {
        $detail = & $body
        Add-Case $name "pass" $detail
    } catch {
        Add-Case $name "fail" ($_.Exception.Message) 1
    }
}

# ---- lifecycle -------------------------------------------------------------
Invoke-Case "loader-install" {
    $r = Invoke-Tool $Loader @("install", $Sys)
    if ($r.exit -ne 0) { throw ("loader install failed: " + $r.stderr) }
    "service installed"
}

Invoke-Case "start-without-hypervisor" {
    $key = "HKLM\SYSTEM\CurrentControlSet\Services\$Service\Parameters"
    # NoHypervisor keeps DriverEntry away from VT-x, Solo means no channel peer.
    & reg add $key /f /v NoHypervisor /t REG_DWORD /d 1 | Out-Null
    & reg add $key /f /v Solo /t REG_DWORD /d 1 | Out-Null
    $r = Invoke-Tool "sc.exe" @("start", $Service) 60
    $query = (Invoke-Tool "sc.exe" @("query", $Service)).stdout
    if ($query -notmatch "RUNNING") { throw ("service did not start: " + $query) }
    "RUNNING"
}

# ---- kchannel / driver surface --------------------------------------------
Invoke-Case "hv-info" {
    $r = Invoke-Tool $Hooks @("hv-info")
    if ($r.exit -ne 0) { throw ("hv-info failed: " + $r.stderr) }
    $r.stdout.Trim()
}

Invoke-Case "trace-scan" {
    $r = Invoke-Tool $Hooks @("trace-scan")
    if ($r.exit -ne 0) { throw ("trace-scan failed: " + $r.stderr) }
    "scanned"
}

Invoke-Case "self-hide" {
    $r = Invoke-Tool $Hooks @("self-hide")
    if ($r.exit -ne 0) { throw ("self-hide failed: " + $r.stderr) }
    "hidden"
}

Invoke-Case "stress-lifecycle" {
    for ($i = 0; $i -lt 3; $i++) {
        & sc.exe stop $Service | Out-Null
        Start-Sleep -Seconds 2
        & sc.exe start $Service | Out-Null
        $query = (& sc.exe query $Service | Out-String)
        if ($query -notmatch "RUNNING") { throw "restart $i did not reach RUNNING" }
    }
    "3 restart cycles"
}

Invoke-Case "memory-pressure" {
    $r = Invoke-Tool $Hooks @("memory-pressure")
    if ($r.exit -ne 0) { throw ("memory-pressure failed: " + $r.stderr) }
    "ok"
}

Invoke-Case "invalid-parameters" {
    $r = Invoke-Tool $Hooks @("invalid-parameters")
    if ($r.exit -ne 0) { throw ("invalid-parameters reported failure: " + $r.stderr) }
    "clean rejection"
}

Invoke-Case "kchannel-fuzz" {
    $r = Invoke-Tool $Hooks @("kchannel-fuzz") 120
    if ($r.exit -ne 0) { throw ("kchannel-fuzz failed: " + $r.stderr) }
    "fuzzed"
}

Invoke-Case "loader-uninstall" {
    & sc.exe stop $Service | Out-Null
    Start-Sleep -Seconds 2
    $r = Invoke-Tool $Loader @("uninstall")
    if ($r.exit -ne 0) { throw ("uninstall failed: " + $r.stderr) }
    $query = (Invoke-Tool "sc.exe" @("query", $Service)).stdout
    if ($query -match "RUNNING") { throw "service still running after uninstall" }
    "removed"
}

# ---- documented skips ------------------------------------------------------
foreach ($skip in @(
    @{ name = "vmx-bringup"; reason = "VMXON/VMLAUNCH needs nested VT-x (bvmenv VM matrix)" },
    @{ name = "ept-software-breakpoint-hook"; reason = "requires EPT + nested VT-x" },
    @{ name = "hardware-breakpoint-hook"; reason = "requires VT-x debug-register interception" },
    @{ name = "target-process-hook"; reason = "requires EPT hooks in a live guest" },
    @{ name = "with-hypervisor-antidetect"; reason = "needs a running hypervisor to mask CPUID/MSR" }
)) {
    $skips.Add($skip)
    Write-Host ("[skip] {0}: {1}" -f $skip.name, $skip.reason)
}

$failures = @($cases | Where-Object { $_.status -eq "fail" })
$result = [ordered]@{
    schema = "blook.e2e.host.v1"
    generated_at = (Get-Date).ToUniversalTime().ToString("o")
    cases = $cases
    skips = $skips
    summary = [ordered]@{
        pass = @($cases | Where-Object { $_.status -eq "pass" }).Count
        fail = $failures.Count
        skip = $skips.Count
    }
}
$result | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $Artifacts "result.json")
Write-Host ("host e2e: {0} pass, {1} fail, {2} documented skips" -f $result.summary.pass, $result.summary.fail, $result.summary.skip)
if ($failures.Count -ne 0) { throw ("host e2e failures: " + (($failures | ForEach-Object { $_.name }) -join ', ')) }