# Shared guest-side helpers for the blook-drv e2e matrix.
#
# Windows PowerShell 5.1 compatible.  No modules, no network, no external
# dependencies.  Dot-source it from every helper:
#
#   . "$PSScriptRoot\lib.ps1"
#
# Exit-code contract: 0 = pass, 1 = fail, 77 = feature not implemented in this
# build (the host records a skip), 124 = timeout (the host normally kills first).

$ErrorActionPreference = 'Continue'

$script:Root = 'C:\blook-e2e'
$script:Loader = Join-Path $script:Root 'blook-loader.exe'
$script:Driver = Join-Path $script:Root 'blook-drv.sys'
$script:Antidetect = Join-Path $script:Root 'blook-antidetect.exe'
$script:Hooks = Join-Path $script:Root 'blook-guest-hooks.exe'

function Write-GuestLine {
    param([string]$Text)
    Write-Output $Text
}

function Fail-Guest {
    param([string]$Message)
    [Console]::Error.WriteLine("FAIL: $Message")
    Write-Output "FAIL: $Message"
    exit 1
}

function Skip-Guest {
    param([string]$Message)
    Write-Output "SKIP: $Message"
    exit 77
}

function Test-GuestAdmin {
    try {
        return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch {
        return $false
    }
}

function Invoke-Loader {
    param([string[]]$Arguments, [int]$TimeoutSeconds = 0)
    if (-not (Test-Path -LiteralPath $script:Loader)) {
        return [pscustomobject]@{ Code = 127; Output = @("loader not found: $($script:Loader)"); Seconds = 0.0 }
    }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $out = & $script:Loader @Arguments 2>&1
    $code = $LASTEXITCODE
    $sw.Stop()
    return [pscustomobject]@{
        Code = $code
        Output = @($out | ForEach-Object { [string]$_ })
        Seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 2)
    }
}

function Invoke-GuestExe {
    param([string]$FilePath, [string[]]$Arguments = @())
    if (-not (Test-Path -LiteralPath $FilePath)) {
        return [pscustomobject]@{ Code = 127; Output = @("not found: $FilePath"); Seconds = 0.0 }
    }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $out = & $FilePath @Arguments 2>&1
    $code = $LASTEXITCODE
    $sw.Stop()
    return [pscustomobject]@{
        Code = $code
        Output = @($out | ForEach-Object { [string]$_ })
        Seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 2)
    }
}

function Get-LoaderText {
    param($Result)
    if ($null -eq $Result) { return '' }
    return (@($Result.Output) -join [Environment]::NewLine)
}

function Get-ServiceState {
    try {
        $service = Get-Service -Name 'BlookDrv' -ErrorAction SilentlyContinue
        if ($service) { return [string]$service.Status }
        return 'Missing'
    } catch {
        return 'Unknown'
    }
}

function Stop-DriverQuietly {
    $null = Invoke-Loader -Arguments @('stop')
    Start-Sleep -Milliseconds 400
}

function Ensure-Driver {
    if (-not (Test-Path -LiteralPath $script:Loader)) { Fail-Guest "loader not found: $($script:Loader)" }
    if (-not (Test-Path -LiteralPath $script:Driver)) { Fail-Guest "driver not found: $($script:Driver)" }

    $service = Get-Service -Name 'BlookDrv' -ErrorAction SilentlyContinue
    if (-not $service) {
        $install = Invoke-Loader -Arguments @('install', $script:Driver)
        if ($install.Code -ne 0) {
            Fail-Guest ("install failed ({0}): {1}" -f $install.Code, (Get-LoaderText $install))
        }
        Start-Sleep -Milliseconds 500
        $service = Get-Service -Name 'BlookDrv' -ErrorAction SilentlyContinue
        if (-not $service) { Fail-Guest 'service did not appear after install' }
    }

    if ($service.Status -ne 'Running') {
        $start = Invoke-Loader -Arguments @('start')
        if ($start.Code -ne 0) {
            Fail-Guest ("start failed ({0}): {1}" -f $start.Code, (Get-LoaderText $start))
        }
        Start-Sleep -Milliseconds 800
    }

    $state = Get-ServiceState
    if ($state -ne 'Running') { Fail-Guest "driver is not running after start (state=$state)" }
    return $true
}

function Enable-Hide {
    $hide = Invoke-Loader -Arguments @('hide', 'on')
    if ($hide.Code -ne 0) {
        Fail-Guest ("hide on failed ({0}): {1}" -f $hide.Code, (Get-LoaderText $hide))
    }
    Start-Sleep -Milliseconds 600
    return $true
}

function Invoke-WithTimeout {
    # PowerShell 5.1 lacks a reliable native-command timeout.  Start-Process +
    # Process.WaitForExit(ms) gives us a hard bound and captured output.
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 30
    )
    if (-not (Test-Path -LiteralPath $FilePath)) {
        return [pscustomobject]@{ Code = 127; Output = @("not found: $FilePath"); TimedOut = $false; Seconds = 0.0 }
    }
    $outFile = [IO.Path]::GetTempFileName()
    $errFile = [IO.Path]::GetTempFileName()
    $quoted = @()
    foreach ($a in $Arguments) {
        $s = [string]$a
        if ($s -match '[\s"]') { $quoted += ('"' + ($s -replace '"', '\"') + '"') } else { $quoted += $s }
    }
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $timedOut = $false
    try {
        $p = Start-Process -FilePath $FilePath -ArgumentList ($quoted -join ' ') -PassThru -NoNewWindow `
            -RedirectStandardOutput $outFile -RedirectStandardError $errFile
        if (-not $p.WaitForExit($TimeoutSeconds * 1000)) {
            $timedOut = $true
            try { $p.Kill() } catch { }
            $p.WaitForExit(5000) | Out-Null
        }
        $code = if ($timedOut) { 124 } else { $p.ExitCode }
        $sw.Stop()
        $output = @()
        if (Test-Path -LiteralPath $outFile) { $output += @(Get-Content -LiteralPath $outFile -ErrorAction SilentlyContinue) }
        if (Test-Path -LiteralPath $errFile) { $output += @(Get-Content -LiteralPath $errFile -ErrorAction SilentlyContinue) }
        return [pscustomobject]@{
            Code = $code
            Output = @($output | ForEach-Object { [string]$_ })
            TimedOut = $timedOut
            Seconds = [Math]::Round($sw.Elapsed.TotalSeconds, 2)
        }
    } finally {
        Remove-Item -LiteralPath $outFile, $errFile -Force -ErrorAction SilentlyContinue
    }
}

function Wait-GuestFile {
    param([string]$Path, [int]$TimeoutSeconds = 30)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $Path) { return $true }
        Start-Sleep -Milliseconds 200
    }
    return $false
}

function Wait-JsonFile {
    param([string]$Path, [int]$TimeoutSeconds = 30)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-Path -LiteralPath $Path) {
            try {
                $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
                if ($raw.Trim()) { return ($raw | ConvertFrom-Json) }
            } catch { }
        }
        Start-Sleep -Milliseconds 200
    }
    return $null
}
