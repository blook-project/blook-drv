#requires -Version 7.0
<#
.SYNOPSIS
    Host-side end-to-end test harness for blook-drv on a VMware Windows 11 guest.

.DESCRIPTION
    Builds the driver/SDK/guest test binaries, prepares a VM through bvmenv,
    pushes the artifacts into C:\blook-e2e, runs the matrix in tests/e2e/cases.psd1,
    and writes result.json + report.md with per-case evidence.

    The harness never assumes the guest is alive.  Every case is followed by a
    `bvmenv state --json` query; bsod/hang/off and the timeout sentinel become
    crash/timeout results with screenshot + state + vmware.log evidence.  Unless
    -KeepGoing is used, the first real crash resets the VM and aborts the run.

    All bvmenv invocation lives in Invoke-Bvmenv so an interface change is one
    local edit.  -DryRun never needs a VM or bvmenv.

.PARAMETER Vm
    bvmenv VM name.  Default: vm-drv.

.PARAMETER Bvmenv
    Path to bvmenv.exe.  Default: PATH, then
    D:\blook-kernel-project\blook-vmware-environment\build\**\bvmenv.exe.

.PARAMETER Configuration
    xmake mode: debug, releasedbg (default) or release.

.PARAMETER Filter
    Regular expression matched against case ids.

.PARAMETER From
    Start at this case id (inclusive) after -Filter is applied.

.PARAMETER DryRun
    Parse/validate the matrix and print every command that would run.  Missing
    build outputs and a missing bvmenv are warnings, not errors.  Writes a
    result.json marked dry_run:true.

.PARAMETER NoReset
    Do not create/reset the VM at startup and never attempt crash recovery.
    A crash aborts immediately (with -KeepGoing it is still unsafe to continue).

.PARAMETER Artifacts
    Artifact root.  Default: docs/evidence/<yyyyMMdd-HHmmss>-e2e.

.PARAMETER TimeoutScale
    Multiplier applied to every case timeout.

.PARAMETER KeepGoing
    Continue after a crash/timeout by resetting and re-preparing the VM.

.PARAMETER ValidateOnly
    Validate cases.psd1 schema/ids and report build/bvmenv presence.  No VM, no
    build, no artifact writes.

.PARAMETER NoBuild
    Use the existing build outputs instead of invoking xmake/spcsign.  Useful
    for CI prebuilds and for harness-only validation.

.EXAMPLE
    pwsh -File scripts/E2E.ps1 -DryRun

.EXAMPLE
    pwsh -File scripts/E2E.ps1 -Vm vm-drv -KeepGoing -Filter '^ept-'

.EXAMPLE
    pwsh -File scripts/E2E.ps1 -ValidateOnly
#>
[CmdletBinding()]
param(
    [string]$Vm = 'vm-drv',
    [string]$Bvmenv,
    [ValidateSet('debug', 'releasedbg', 'release')]
    [string]$Configuration = 'releasedbg',
    [string]$Filter,
    [string]$From,
    [switch]$DryRun,
    [switch]$NoReset,
    [string]$Artifacts,
    [ValidateRange(0.05, 100.0)]
    [double]$TimeoutScale = 1.0,
    [switch]$KeepGoing,
    [switch]$ValidateOnly,
    [switch]$NoBuild,
    [ValidateRange(10, 3600)]
    [int]$ReadyTimeoutSeconds = 180
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# constants / run state
# ---------------------------------------------------------------------------

$script:RepoRoot = Split-Path -Parent $PSScriptRoot
$script:CaseFile = Join-Path $script:RepoRoot 'tests/e2e/cases.psd1'
$script:GuestDir = Join-Path $script:RepoRoot 'tests/e2e/guest'
$script:BuildRoot = Join-Path $script:RepoRoot 'build'
$script:BuildOut = Join-Path $script:BuildRoot "windows/x64/$Configuration"
$script:GuestRoot = 'C:\blook-e2e'
$script:TimeoutSentinel = 124
$script:RunId = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:StartedUtc = [DateTime]::UtcNow
$script:ArtifactRoot = $null
$script:CasesDir = $null
$script:RunDir = $null
$script:LogPath = $null
$script:BvmenvPath = $null
$script:BvmenvFound = $false
$script:BvmenvSupportsJson = $false
$script:Cases = @()
$script:Results = [System.Collections.Generic.List[object]]::new()
$script:Aborted = $false
$script:AbortReason = ''
$script:RunError = ''
$script:SawUnexpectedCrash = $false
$script:IsDryRun = [bool]$DryRun.IsPresent
$script:IsValidateOnly = [bool]$ValidateOnly.IsPresent

$script:AllowedCategories = @(
    'smoke', 'nested-virt', 'hv-lifecycle', 'ept-hooks', 'swbreak',
    'hwbreak', 'self-hide', 'antidetect', 'stress', 'crash-safety',
    'invalid-input'
)

# ---------------------------------------------------------------------------
# logging / small helpers
# ---------------------------------------------------------------------------

function Write-Log {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR', 'DEBUG', 'STEP')]
        [string]$Level = 'INFO'
    )
    $stamp = (Get-Date -Format 'HH:mm:ss')
    $line = '{0} [{1}] {2}' -f $stamp, $Level, $Message
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'WARN' { Write-Host $line -ForegroundColor Yellow }
        'STEP' { Write-Host $line -ForegroundColor Cyan }
        'DEBUG' { Write-Host $line -ForegroundColor DarkGray }
        default { Write-Host $line }
    }
    if ($script:LogPath) {
        try { Add-Content -LiteralPath $script:LogPath -Value $line -Encoding utf8 } catch { }
    }
}

function Write-Step([string]$Text) {
    Write-Log '' -Level INFO
    Write-Log ('=== ' + $Text) -Level STEP
}

function Write-Utf8Text {
    param([Parameter(Mandatory = $true)][string]$Path, [AllowNull()][string]$Text)
    $dir = Split-Path -Parent $Path
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
    }
    [IO.File]::WriteAllText($Path, [string]$Text, [Text.UTF8Encoding]::new($false))
}

function ConvertTo-ArgText {
    param([AllowEmptyString()][string]$Value)
    if ($null -eq $Value) { return '""' }
    if ($Value -match '^[A-Za-z0-9_./\\:=+,@-]+$') { return $Value }
    return '"' + ($Value -replace '"', '\"') + '"'
}

function Format-CommandLine {
    param([string]$FilePath, [string[]]$Arguments = @())
    $parts = @((ConvertTo-ArgText $FilePath))
    foreach ($a in $Arguments) { $parts += (ConvertTo-ArgText ([string]$a)) }
    return ($parts -join ' ')
}

function Get-ObjectProperty {
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $null }
    if ($Object -is [System.Collections.IDictionary]) {
        if ($Object.Contains($Name)) { return $Object[$Name] }
        return $null
    }
    $property = $Object.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Test-Admin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Resolve-FullPath {
    param([string]$Path)
    if ([IO.Path]::IsPathRooted($Path)) { return [IO.Path]::GetFullPath($Path) }
    return [IO.Path]::GetFullPath((Join-Path $script:RepoRoot $Path))
}

function Get-GitCommit {
    try {
        $out = & git -C $script:RepoRoot rev-parse --short HEAD 2>$null
        if ($LASTEXITCODE -eq 0 -and $out) { return ([string]$out).Trim() }
    } catch { }
    $versionFile = Join-Path $script:RepoRoot 'version.txt'
    if (Test-Path -LiteralPath $versionFile) {
        return ('version:' + ((Get-Content -LiteralPath $versionFile -Raw).Trim()))
    }
    return 'unknown'
}

# ---------------------------------------------------------------------------
# process execution (hard host-side timeout)
# ---------------------------------------------------------------------------

function Invoke-Native {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [int]$TimeoutSeconds = 120,
        [string]$WorkingDirectory = $script:RepoRoot,
        [switch]$Echo
    )
    $commandLine = Format-CommandLine -FilePath $FilePath -Arguments $Arguments
    $started = [DateTime]::UtcNow
    $sw = [Diagnostics.Stopwatch]::StartNew()

    if ($script:IsDryRun) {
        Write-Log ('[dry-run] ' + $commandLine) -Level DEBUG
        return [pscustomobject]@{
            FilePath      = $FilePath
            Arguments     = $Arguments
            CommandLine   = $commandLine
            ExitCode      = 0
            StdOut        = ''
            StdErr        = ''
            TimedOut      = $false
            DurationSeconds = 0.0
            StartedUtc    = $started
            DryRun        = $true
        }
    }

    if (-not (Test-Path -LiteralPath $FilePath)) {
        throw "Executable not found: $FilePath"
    }

    Write-Log ('  $ ' + $commandLine) -Level DEBUG
    $psi = [Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $FilePath
    foreach ($a in $Arguments) { $psi.ArgumentList.Add([string]$a) }
    $psi.WorkingDirectory = $WorkingDirectory
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.CreateNoWindow = $true

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $psi
    $timedOut = $false
    $stdout = ''
    $stderr = ''
    try {
        if (-not $process.Start()) { throw "Failed to start: $FilePath" }
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $timeoutMs = [int][Math]::Min(2147483647, [Math]::Max(1000, $TimeoutSeconds * 1000))
        if (-not $process.WaitForExit($timeoutMs)) {
            $timedOut = $true
            try { $process.Kill($true) } catch { }
            try { $process.WaitForExit(5000) | Out-Null } catch { }
        }
        try { $stdout = [string]$stdoutTask.GetAwaiter().GetResult() } catch { }
        try { $stderr = [string]$stderrTask.GetAwaiter().GetResult() } catch { }
        $exitCode = if ($timedOut) { $script:TimeoutSentinel } else { $process.ExitCode }
    } finally {
        $process.Dispose()
        $sw.Stop()
    }

    $result = [pscustomobject]@{
        FilePath      = $FilePath
        Arguments     = $Arguments
        CommandLine   = $commandLine
        ExitCode      = $exitCode
        StdOut        = $stdout
        StdErr        = $stderr
        TimedOut      = $timedOut
        DurationSeconds = [Math]::Round($sw.Elapsed.TotalSeconds, 3)
        StartedUtc    = $started
        DryRun        = $false
    }

    if ($timedOut) {
        Write-Log ('  process exceeded {0}s and was killed' -f $TimeoutSeconds) -Level WARN
    }
    if ($Echo) {
        if ($stdout) {
            foreach ($line in ($stdout -split "`r?`n")) { Write-Log ('  | ' + $line) -Level DEBUG }
        }
        if ($stderr) {
            foreach ($line in ($stderr -split "`r?`n")) { Write-Log ('  ! ' + $line) -Level DEBUG }
        }
    }
    return $result
}

# ---------------------------------------------------------------------------
# bvmenv adapter: BvmenvCli is the ONLY place that knows the CLI shape.
# If env changes an option or a sentinel, edit this section only.
# ---------------------------------------------------------------------------

function Invoke-Bvmenv {
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [int]$TimeoutSeconds = 120,
        [switch]$Echo
    )
    if (-not $script:BvmenvFound) {
        if ($script:IsDryRun) {
            $line = Format-CommandLine -FilePath '<bvmenv.exe>' -Arguments $Arguments
            Write-Log ('[dry-run] ' + $line) -Level DEBUG
            return [pscustomobject]@{
                ExitCode = 0; StdOut = ''; StdErr = ''; TimedOut = $false
                DurationSeconds = 0.0; DryRun = $true
                CommandLine = $line
            }
        }
        throw ("bvmenv was not found. Pass -Bvmenv <path> or make sure it is on PATH " +
            "or built under D:\blook-kernel-project\blook-vmware-environment\build.\n" +
            "This error is intentionally suppressed by -DryRun/-ValidateOnly.")
    }
    return Invoke-Native -FilePath $script:BvmenvPath -Arguments $Arguments `
        -TimeoutSeconds $TimeoutSeconds -WorkingDirectory $script:RepoRoot -Echo:$Echo
}

function Resolve-Bvmenv {
    param([string]$Explicit)
    if ($Explicit) {
        $candidate = $Explicit
        if (Test-Path -LiteralPath $candidate -PathType Container) {
            $candidate = Join-Path $candidate 'bvmenv.exe'
        }
        if (Test-Path -LiteralPath $candidate -PathType Leaf) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
        if ($script:IsDryRun -or $script:IsValidateOnly) {
            Write-Log "bvmenv not found at '$Explicit' (ignored in dry/validate mode)." -Level WARN
            return $null
        }
        throw "bvmenv not found at '$Explicit'. Build blook-vmware-environment or pass -Bvmenv <path>."
    }

    $onPath = Get-Command -Name 'bvmenv' -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($onPath) { return $onPath.Source }

    $vmwareRoot = 'D:\blook-kernel-project\blook-vmware-environment\build'
    if (Test-Path -LiteralPath $vmwareRoot) {
        $hit = Get-ChildItem -LiteralPath $vmwareRoot -Recurse -Filter 'bvmenv.exe' -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }

    if (-not ($script:IsDryRun -or $script:IsValidateOnly)) {
        throw ("bvmenv was not found. Expected it on PATH or under " +
            "D:\blook-kernel-project\blook-vmware-environment\build\**\bvmenv.exe. " +
            "Build it with your teammate (blook-vmware-environment) or pass -Bvmenv <path>.")
    }
    Write-Log 'bvmenv not found; dry/validate mode continues with placeholders.' -Level WARN
    return $null
}

function Initialize-BvmenvCapabilities {
    # bvmenv 0.1.0 accepts a command-local --json option; `exec <vm> --json`
    # then prints an ExecResult object instead of the guest's raw stream.
    # Probe --help once and use the richer output when available.  A
    # contract-style CLI falls back to "process exit code is the guest exit
    # code" and the human `exit_code : N` line.
    $script:BvmenvSupportsJson = $false
    if (-not $script:BvmenvFound -or $script:IsDryRun -or $script:IsValidateOnly) { return }
    try {
        $help = Invoke-Native -FilePath $script:BvmenvPath -Arguments @('--help') -TimeoutSeconds 15
        $text = ($help.StdOut + "`n" + $help.StdErr)
        if ($text -match '(?i)--json' -and $text -match '(?i)exec') {
            $script:BvmenvSupportsJson = $true
            Write-Log 'bvmenv supports --json; exec/state JSON will be parsed.'
        }
    } catch {
        Write-Log ('bvmenv capability probe failed (using contract mode): ' + $_.Exception.Message) -Level WARN
    }
}

function Start-VmIfNeeded {
    # reset on bvmenv 0.1.0 leaves the VM powered off unless --wait is passed.
    # A contract-style reset may already leave it running, so only start when
    # the state query says off.
    $query = Save-VmState -OutputDir $script:RunDir -Prefix 'state-before-start' -NoSave
    if (-not $query.Ok) { return }
    $power = [string](Get-ObjectProperty -Object $query.Data -Name 'power')
    if ($power -ne 'off') { return }
    Write-Log 'VM is off after reset; starting it.'
    $start = Invoke-Bvmenv -Arguments @('start', $Vm) -TimeoutSeconds 300
    if ($start.ExitCode -ne 0) {
        throw "bvmenv start failed after reset ($($start.ExitCode)): $($start.StdErr)"
    }
}

# ---------------------------------------------------------------------------
# case matrix loading / validation
# ---------------------------------------------------------------------------

function ConvertFrom-CaseAst {
    # Import-PowerShellDataFile only accepts a single hashtable root; the matrix
    # is an ordered array.  Evaluate the small literal subset used by .psd1
    # without invoking arbitrary code.
    param($Ast)
    if ($null -eq $Ast) { return $null }
    switch ($Ast.GetType().Name) {
        'PipelineAst' {
            if ($Ast.PipelineElements.Count -eq 0) { return $null }
            if ($Ast.PipelineElements.Count -ne 1) {
                throw "unsupported pipeline in cases.psd1 at line $($Ast.Extent.StartLineNumber)"
            }
            return (ConvertFrom-CaseAst $Ast.PipelineElements[0])
        }
        'CommandExpressionAst' { return (ConvertFrom-CaseAst $Ast.Expression) }
        'ParenExpressionAst' { return (ConvertFrom-CaseAst $Ast.Pipeline) }
        'ArrayExpressionAst' {
            $items = @()
            foreach ($statement in $Ast.SubExpression.Statements) {
                $value = ConvertFrom-CaseAst $statement
                if ($value -is [array]) { $items += $value } else { $items += $value }
            }
            return @($items)
        }
        'ArrayLiteralAst' {
            $items = @()
            foreach ($element in $Ast.Elements) { $items += (ConvertFrom-CaseAst $element) }
            return @($items)
        }
        'HashtableAst' {
            $table = [ordered]@{}
            foreach ($pair in $Ast.KeyValuePairs) {
                $key = ConvertFrom-CaseAst $pair.Item1
                if ($null -eq $key) { throw "empty hashtable key at line $($Ast.Extent.StartLineNumber)" }
                $table[[string]$key] = (ConvertFrom-CaseAst $pair.Item2)
            }
            return $table
        }
        'StringConstantExpressionAst' { return $Ast.Value }
        'ConstantExpressionAst' { return $Ast.Value }
        'VariableExpressionAst' {
            $name = $Ast.VariablePath.UserPath
            if ($name -eq 'true') { return $true }
            if ($name -eq 'false') { return $false }
            throw "unsupported variable `$$name in cases.psd1 at line $($Ast.Extent.StartLineNumber)"
        }
        default {
            throw ("unsupported {0} in cases.psd1 at line {1}: {2}" -f `
                    $Ast.GetType().Name, $Ast.Extent.StartLineNumber, $Ast.Extent.Text)
        }
    }
}

function Import-CaseDataFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$parseErrors)
    if ($parseErrors -and $parseErrors.Count -gt 0) {
        throw ("cases.psd1 does not parse: " + (($parseErrors | ForEach-Object { $_.Message }) -join '; '))
    }
    $statements = @($ast.EndBlock.Statements)
    if ($statements.Count -ne 1) {
        throw "cases.psd1 must contain exactly one root expression (found $($statements.Count))."
    }
    return (ConvertFrom-CaseAst $statements[0])
}

function Get-CaseCommand {
    param($Item)
    $value = $null
    if ($Item.Contains('command')) { $value = $Item['command'] }
    elseif ($Item.Contains('guest_command')) { $value = $Item['guest_command'] }
    if ($null -eq $value) { return @() }
    if ($value -is [string]) { return @($value) }
    return @($value | ForEach-Object { [string]$_ })
}

function Test-CaseMatrix {
    $errors = [System.Collections.Generic.List[string]]::new()
    $cases = [System.Collections.Generic.List[object]]::new()

    if (-not (Test-Path -LiteralPath $script:CaseFile)) {
        $errors.Add("Case matrix not found: $($script:CaseFile)")
        return [pscustomobject]@{ Cases = @(); Errors = $errors }
    }

    try {
        $raw = Import-CaseDataFile -Path $script:CaseFile
    } catch {
        $errors.Add("cases.psd1 could not be parsed: $($_.Exception.Message)")
        return [pscustomobject]@{ Cases = @(); Errors = $errors }
    }

    $rawItems = @($raw)
    if ($rawItems.Count -eq 0) {
        $errors.Add('cases.psd1 must contain a non-empty ordered array of case hashtables.')
        return [pscustomobject]@{ Cases = @(); Errors = $errors }
    }

    $seen = @{}
    $index = 0
    foreach ($item in $rawItems) {
        $index++
        $label = "case[$index]"
        if ($item -isnot [System.Collections.IDictionary]) {
            $errors.Add("$label is $($item.GetType().Name), expected a hashtable.")
            continue
        }

        foreach ($required in @('id', 'name', 'category', 'timeout_s', 'expect_exit')) {
            if (-not $Item.Contains($required)) {
                $errors.Add("$label is missing required key '$required'.")
            }
        }
        $command = Get-CaseCommand -Item $item
        if ($command.Count -eq 0) {
            $errors.Add("$label is missing a non-empty 'command' array/string.")
        }

        $id = if ($Item.Contains('id')) { [string]$item['id'] } else { '' }
        if ($id) {
            $label = "case '$id'"
            if ($id -notmatch '^[a-z0-9]+(-[a-z0-9]+)*$') {
                $errors.Add("$label has an invalid id (kebab-case lower-case required).")
            }
            if ($seen.ContainsKey($id)) {
                $errors.Add("$label is a duplicate of case #$($seen[$id]).")
            } else {
                $seen[$id] = $index
            }
        }

        $name = if ($Item.Contains('name')) { [string]$item['name'] } else { '' }
        if ([string]::IsNullOrWhiteSpace($name)) { $errors.Add("$label has an empty name.") }

        $category = if ($Item.Contains('category')) { [string]$item['category'] } else { '' }
        if ($category -and $script:AllowedCategories -notcontains $category) {
            $errors.Add("$label has unknown category '$category'. Allowed: $($script:AllowedCategories -join ', ').")
        }

        $timeout = 0
        if ($Item.Contains('timeout_s')) {
            try { $timeout = [int]$item['timeout_s'] } catch { $timeout = 0 }
            if ($timeout -lt 1 -or $timeout -gt 86400) {
                $errors.Add("$label timeout_s must be an integer from 1 to 86400.")
            }
        }

        $expectExit = -1
        if ($Item.Contains('expect_exit')) {
            try { $expectExit = [int]$item['expect_exit'] } catch { $expectExit = -1 }
            if ($expectExit -lt 0 -or $expectExit -gt 255) {
                $errors.Add("$label expect_exit must be an integer from 0 to 255.")
            }
        }

        $requiresAdmin = $false
        if ($Item.Contains('requires_admin')) {
            if ($item['requires_admin'] -isnot [bool]) { $errors.Add("$label requires_admin must be `$true/`$false.") }
            else { $requiresAdmin = [bool]$item['requires_admin'] }
        }

        $allowSkip = $false
        if ($Item.Contains('allow_skip')) {
            if ($item['allow_skip'] -isnot [bool]) { $errors.Add("$label allow_skip must be `$true/`$false.") }
            else { $allowSkip = [bool]$item['allow_skip'] }
        }

        $expectTimeout = $false
        if ($Item.Contains('expect_timeout')) {
            if ($item['expect_timeout'] -isnot [bool]) { $errors.Add("$label expect_timeout must be `$true/`$false.") }
            else { $expectTimeout = [bool]$item['expect_timeout'] }
        }

        $postChecks = @{}
        if ($Item.Contains('post_checks')) {
            if ($item['post_checks'] -isnot [System.Collections.IDictionary]) {
                $errors.Add("$label post_checks must be a hashtable.")
            } else {
                $postChecks = $item['post_checks']
                foreach ($key in $postChecks.Keys) {
                    switch ([string]$key) {
                        'state_classification' {
                            $v = [string]$postChecks[$key]
                            if (@('desktop', 'login', 'off', 'bsod', 'hang', 'black', 'boot', 'unknown') -notcontains $v) {
                                $errors.Add("$label post_checks.state_classification has invalid value '$v'.")
                            }
                        }
                        { $_ -in @('stdout_contains', 'stdout_not_contains', 'stderr_contains', 'stderr_not_contains') } {
                            $v = $postChecks[$key]
                            if ($v -is [string]) { if ([string]::IsNullOrEmpty($v)) { $errors.Add("$label post_checks.$key is empty.") } }
                            elseif (@($v).Count -eq 0) { $errors.Add("$label post_checks.$key is empty.") }
                        }
                        'min_stdout_bytes' {
                            try { [void][int]$postChecks[$key] } catch { $errors.Add("$label post_checks.min_stdout_bytes must be an integer.") }
                        }
                        'max_duration_s' {
                            try { [void][double]$postChecks[$key] } catch { $errors.Add("$label post_checks.max_duration_s must be a number.") }
                        }
                        default { $errors.Add("$label post_checks has unknown key '$key'.") }
                    }
                }
            }
        }

        if ($expectTimeout -and $expectExit -ne $script:TimeoutSentinel) {
            $errors.Add("$label sets expect_timeout but expect_exit is $expectExit (expected $($script:TimeoutSentinel)).")
        }

        $notes = if ($Item.Contains('notes')) { [string]$item['notes'] } else { '' }
        $acceptance = if ($Item.Contains('acceptance')) { [string]$item['acceptance'] } else { '' }

        $cases.Add([pscustomobject]@{
                Index         = $index
                Id            = $id
                Name          = $name
                Category      = $category
                Command       = $command
                TimeoutS      = $timeout
                ExpectExit    = $expectExit
                RequiresAdmin = $requiresAdmin
                AllowSkip     = $allowSkip
                ExpectTimeout = $expectTimeout
                PostChecks    = $postChecks
                Notes         = $notes
                Acceptance    = $acceptance
            })
    }

    return [pscustomobject]@{ Cases = @($cases); Errors = $errors }
}

function Select-Cases {
    param([object[]]$Cases)
    $selected = @($Cases)
    if ($Filter) {
        try { [void][regex]::new($Filter) } catch { throw "Invalid -Filter regex: $($_.Exception.Message)" }
        $selected = @($selected | Where-Object { $_.Id -match $Filter })
    }
    if ($From) {
        $index = -1
        for ($i = 0; $i -lt $selected.Count; $i++) {
            if ($selected[$i].Id -eq $From) { $index = $i; break }
        }
        if ($index -lt 0) { throw "-From '$From' did not match a selected case id." }
        $selected = @($selected[$index..($selected.Count - 1)])
    }
    return @($selected)
}

# ---------------------------------------------------------------------------
# build / artifact resolution
# ---------------------------------------------------------------------------

function Invoke-HostStep {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [string[]]$Arguments = @(),
        [Parameter(Mandatory = $true)][string]$Label
    )
    Write-Log ('  $ ' + (Format-CommandLine -FilePath $FilePath -Arguments $Arguments)) -Level DEBUG
    & $FilePath @Arguments 2>&1 | ForEach-Object { Write-Log ('  ' + [string]$_) -Level INFO }
    $code = $LASTEXITCODE
    if ($code -ne 0) { throw "$Label failed with exit code $code." }
}

function Invoke-Build {
    Write-Step "build driver + sdk + guest binaries ($Configuration)"
    if ($script:IsDryRun) {
        Write-Log '[dry-run] xmake f -p windows -a x64 -m <config> -y'
        Write-Log '[dry-run] xmake build blook-drv blook-sdk blook-loader blook-antidetect blook-guest-hooks'
        Write-Log '[dry-run] signer\spcsign\spcsign.exe sign ... blook-drv.sys'
        return
    }

    $xmake = Get-Command -Name 'xmake' -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $xmake) { throw 'xmake was not found on PATH.' }

    Push-Location -LiteralPath $script:RepoRoot
    try {
        Invoke-HostStep -FilePath $xmake.Source `
            -Arguments @('f', '-p', 'windows', '-a', 'x64', '-m', $Configuration, '-y') `
            -Label 'xmake configure'
        Invoke-HostStep -FilePath $xmake.Source `
            -Arguments @('build', 'blook-drv', 'blook-sdk', 'blook-loader', 'blook-antidetect', 'blook-guest-hooks') `
            -Label 'xmake build'
    } finally {
        Pop-Location
    }

    $driver = Join-Path $script:BuildOut 'blook-drv.sys'
    $signer = Join-Path $script:RepoRoot 'signer\spcsign\spcsign.exe'
    if ((Test-Path -LiteralPath $driver) -and (Test-Path -LiteralPath $signer)) {
        Write-Log 'signing driver in place (test signature)'
        $signArgs = @('sign', '--sha1', '--cert', 'XINDA', '--tsa-time', '2013-01-01T00:00:00Z')
        foreach ($cer in @(
                    (Join-Path $script:RepoRoot 'signer\certs\verisign-cscs-2010.cer'),
                    (Join-Path $script:RepoRoot 'signer\certs\verisign-g5-mcvr.cer'))) {
            if (Test-Path -LiteralPath $cer) { $signArgs += @('--chain', $cer) }
        }
        $signArgs += $driver
        $sign = Invoke-Native -FilePath $signer -Arguments $signArgs -TimeoutSeconds 180
        if ($sign.ExitCode -ne 0) {
            throw "spcsign failed ($($sign.ExitCode)): $($sign.StdErr)"
        }
    } else {
        Write-Log 'signer or driver missing; skipping test signature.' -Level WARN
    }
}

function Get-BuildArtifacts {
    return @(
        [pscustomobject]@{ Name = 'driver'; Path = (Join-Path $script:BuildOut 'blook-drv.sys'); Required = $true }
        [pscustomobject]@{ Name = 'loader'; Path = (Join-Path $script:BuildOut 'blook-loader.exe'); Required = $true }
        [pscustomobject]@{ Name = 'antidetect'; Path = (Join-Path $script:BuildOut 'blook-antidetect.exe'); Required = $true }
        [pscustomobject]@{ Name = 'guest-hooks'; Path = (Join-Path $script:BuildOut 'blook-guest-hooks.exe'); Required = $true }
    )
}

function Assert-BuildArtifacts {
    param([object[]]$Artifacts)
    if ($script:IsDryRun) { return }
    $missing = @($Artifacts | Where-Object { $_.Required -and -not (Test-Path -LiteralPath $_.Path) })
    if ($missing.Count -gt 0) {
        throw ("Build outputs are missing:`n" + (($missing | ForEach-Object { '  ' + $_.Path }) -join "`n") +
            "`nRun the build without -DryRun or fix the xmake target output.")
    }
}

# ---------------------------------------------------------------------------
# VM state, readiness, guest preparation
# ---------------------------------------------------------------------------

function ConvertFrom-EmbeddedJson {
    param([string]$Text)
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    $start = $Text.IndexOf('{')
    $end = $Text.LastIndexOf('}')
    if ($start -lt 0 -or $end -le $start) { return $null }
    $json = $Text.Substring($start, $end - $start + 1)
    try { return ($json | ConvertFrom-Json -ErrorAction Stop) } catch { return $null }
}

function ConvertTo-FlatVmState {
    # bvmenv 0.1.0 prints the nested bvmenv.state.v1 schema:
    #   { power, tools:{state,running}, screen:{classification,stop_code,
    #     screenshot}, vmx, log:{issues}, ... }
    # The user-facing contract is flatter.  Keep both: state.json preserves the
    # original fields and adds the aliases the harness asserts on.
    param($Data)
    if ($null -eq $Data) { return $null }
    $flat = [ordered]@{}
    if ($Data -is [System.Collections.IDictionary]) {
        foreach ($key in $Data.Keys) { $flat[[string]$key] = $Data[$key] }
    } else {
        foreach ($property in $Data.PSObject.Properties) { $flat[$property.Name] = $property.Value }
    }

    $screen = Get-ObjectProperty -Object $Data -Name 'screen'
    $tools = Get-ObjectProperty -Object $Data -Name 'tools'

    $classification = Get-ObjectProperty -Object $Data -Name 'classification'
    if (-not $classification) { $classification = Get-ObjectProperty -Object $screen -Name 'classification' }
    $flat['classification'] = $classification

    $stopCode = Get-ObjectProperty -Object $Data -Name 'stop_code'
    if (-not $stopCode) { $stopCode = Get-ObjectProperty -Object $screen -Name 'stop_code' }
    $flat['stop_code'] = $stopCode

    $screenshot = Get-ObjectProperty -Object $Data -Name 'screenshot'
    if (-not $screenshot) { $screenshot = Get-ObjectProperty -Object $screen -Name 'screenshot' }
    $flat['screenshot'] = $screenshot

    $heartbeat = Get-ObjectProperty -Object $Data -Name 'tools_heartbeat'
    if ($null -eq $heartbeat) { $heartbeat = Get-ObjectProperty -Object $tools -Name 'running' }
    if ($null -eq $heartbeat) {
        $heartbeat = ((Get-ObjectProperty -Object $tools -Name 'state') -eq 'running')
    }
    $flat['tools_heartbeat'] = [bool]$heartbeat

    $vmwareLog = Get-ObjectProperty -Object $Data -Name 'vmware_log'
    if (-not $vmwareLog) {
        $vmx = [string](Get-ObjectProperty -Object $Data -Name 'vmx')
        if ($vmx) {
            try { $vmwareLog = Join-Path (Split-Path -Parent $vmx) 'vmware.log' } catch { }
        }
    }
    $flat['vmware_log'] = $vmwareLog

    if (-not $flat.Contains('errors')) {
        $log = Get-ObjectProperty -Object $Data -Name 'log'
        $flat['errors'] = Get-ObjectProperty -Object $log -Name 'issues'
    }
    return [pscustomobject]$flat
}

function Save-VmState {
    param(
        [Parameter(Mandatory = $true)][string]$OutputDir,
        [string]$Prefix = 'state',
        [switch]$NoSave
    )
    $timeout = [int][Math]::Max(15, [Math]::Ceiling(60 * $TimeoutScale))
    $r = Invoke-Bvmenv -Arguments @('state', $Vm, '--json') -TimeoutSeconds $timeout
    $data = ConvertTo-FlatVmState -Data (ConvertFrom-EmbeddedJson -Text ($r.StdOut + "`n" + $r.StdErr))
    $stateFile = $null
    $screenshotFile = $null
    $vmwareLogFile = $null
    $errorText = ''

    if ($r.TimedOut) {
        $errorText = "bvmenv state timed out after ${timeout}s"
    } elseif ($r.ExitCode -ne 0) {
        $errorText = "bvmenv state exited $($r.ExitCode): $($r.StdErr.Trim())"
    } elseif ($null -eq $data) {
        $errorText = 'bvmenv state output was not valid JSON'
    }

    if (-not $NoSave) {
        if (-not (Test-Path -LiteralPath $OutputDir)) {
            New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null
        }
        $rawPath = Join-Path $OutputDir "$Prefix.raw.txt"
        Write-Utf8Text -Path $rawPath -Text (($r.StdOut + "`n" + $r.StdErr).Trim())
        $stateFile = Join-Path $OutputDir "$Prefix.json"
        if ($null -ne $data) {
            Write-Utf8Text -Path $stateFile -Text ($data | ConvertTo-Json -Depth 10)
        } elseif ($r.StdOut.Trim()) {
            Write-Utf8Text -Path $stateFile -Text $r.StdOut
        } else {
            Write-Utf8Text -Path $stateFile -Text '{"error":"no state json"}'
        }

        $shot = [string](Get-ObjectProperty -Object $data -Name 'screenshot')
        if ($shot -and (Test-Path -LiteralPath $shot -PathType Leaf)) {
            $screenshotFile = Join-Path $OutputDir 'screenshot.png'
            try { Copy-Item -LiteralPath $shot -Destination $screenshotFile -Force } catch {
                Write-Log "could not copy screenshot '$shot': $($_.Exception.Message)" -Level WARN
                $screenshotFile = $null
            }
        }

        $vmLog = [string](Get-ObjectProperty -Object $data -Name 'vmware_log')
        $tailPath = Join-Path $OutputDir 'vmware_log_tail.txt'
        if ($vmLog -and (Test-Path -LiteralPath $vmLog -PathType Leaf)) {
            try {
                $tail = @(Get-Content -LiteralPath $vmLog -Tail 200 -ErrorAction Stop)
                Write-Utf8Text -Path $tailPath -Text (($tail -join [Environment]::NewLine))
                $vmwareLogFile = $tailPath
            } catch {
                Write-Utf8Text -Path $tailPath -Text "failed to read vmware log '$vmLog': $($_.Exception.Message)"
                $vmwareLogFile = $tailPath
            }
        } else {
            Write-Utf8Text -Path $tailPath -Text ("vmware_log not available in state json or path does not exist: " + $vmLog)
            $vmwareLogFile = $tailPath
        }
    }

    return [pscustomobject]@{
        # bvmenv 0.1.0 returns 4 when it suspects a hang but still emits a
        # complete state JSON; 2 is an error object with no state fields.
        Ok              = ($null -ne $data -and -not $r.TimedOut -and $r.ExitCode -in @(0, 4))
        Data            = $data
        Raw             = ($r.StdOut + "`n" + $r.StdErr)
        ExitCode        = $r.ExitCode
        TimedOut        = $r.TimedOut
        Error           = $errorText
        StateJson       = $stateFile
        Screenshot      = $screenshotFile
        VmwareLogTail   = $vmwareLogFile
    }
}

function Wait-VmReady {
    Write-Step "wait for VM '$Vm' to be ready (timeout $ReadyTimeoutSeconds s)"
    if ($script:IsDryRun) {
        Write-Log '[dry-run] bvmenv state <vm> --json (poll until desktop)'
        return
    }
    $deadline = (Get-Date).AddSeconds($ReadyTimeoutSeconds * $TimeoutScale)
    $last = $null
    while ((Get-Date) -lt $deadline) {
        $query = Save-VmState -OutputDir $script:RunDir -Prefix 'state-poll' -NoSave
        if ($query.Ok) {
            $last = $query.Data
            $power = [string](Get-ObjectProperty -Object $last -Name 'power')
            $classification = [string](Get-ObjectProperty -Object $last -Name 'classification')
            $heartbeat = [bool](Get-ObjectProperty -Object $last -Name 'tools_heartbeat')
            if ($power -eq 'on' -and $classification -eq 'desktop' -and $heartbeat) {
                Write-Log "VM ready: power=$power classification=$classification tools_heartbeat=$heartbeat"
                Save-VmState -OutputDir $script:RunDir -Prefix 'state-initial' | Out-Null
                return
            }
            Write-Log "VM not ready: power=$power classification=$classification heartbeat=$heartbeat" -Level DEBUG
        } else {
            Write-Log ('state query failed while waiting: ' + $query.Error) -Level DEBUG
        }
        Start-Sleep -Seconds 3
    }
    $detail = if ($last) { "last state: $($last | ConvertTo-Json -Compress -Depth 5)" } else { 'no state was ever returned' }
    throw "VM '$Vm' did not become desktop-ready within $ReadyTimeoutSeconds s ($detail)."
}

function Push-GuestFile {
    param([string]$LocalPath, [string]$GuestPath)
    if (-not (Test-Path -LiteralPath $LocalPath)) {
        throw "Cannot push missing file: $LocalPath"
    }
    Write-Log "push $LocalPath -> $GuestPath"
    $r = Invoke-Bvmenv -Arguments @('push', $Vm, $LocalPath, $GuestPath) -TimeoutSeconds 300
    if ($r.ExitCode -ne 0) {
        throw "push failed ($($r.ExitCode)): $LocalPath -> $GuestPath`n$($r.StdErr)"
    }
}

function Initialize-Guest {
    Write-Step "prepare guest $($script:GuestRoot)"
    $binaries = @(
        @{ Local = (Join-Path $script:BuildOut 'blook-drv.sys'); Guest = "$($script:GuestRoot)\blook-drv.sys" }
        @{ Local = (Join-Path $script:BuildOut 'blook-loader.exe'); Guest = "$($script:GuestRoot)\blook-loader.exe" }
        @{ Local = (Join-Path $script:BuildOut 'blook-antidetect.exe'); Guest = "$($script:GuestRoot)\blook-antidetect.exe" }
        @{ Local = (Join-Path $script:BuildOut 'blook-guest-hooks.exe'); Guest = "$($script:GuestRoot)\blook-guest-hooks.exe" }
    )
    $config = Join-Path $script:RepoRoot 'blook.ini'
    if (Test-Path -LiteralPath $config) {
        $binaries += @{ Local = $config; Guest = "$($script:GuestRoot)\blook.ini" }
    }

    if ($script:IsDryRun) {
        Write-Log "[dry-run] exec cmd.exe /c `"if not exist $($script:GuestRoot) mkdir $($script:GuestRoot)`""
        foreach ($item in $binaries) {
            Write-Log "[dry-run] push $($item.Local) -> $($item.Guest)"
        }
        $guestFiles = @(Get-ChildItem -LiteralPath $script:GuestDir -File -ErrorAction SilentlyContinue)
        foreach ($file in $guestFiles) {
            Write-Log "[dry-run] push $($file.FullName) -> $($script:GuestRoot)\$($file.Name)"
        }
        return
    }

    $mkdir = Invoke-Bvmenv -Arguments @(
        'exec', $Vm, '--timeout', '60', '--', 'cmd.exe', '/c',
        "if not exist $($script:GuestRoot) mkdir $($script:GuestRoot)"
    ) -TimeoutSeconds 90
    if ($mkdir.ExitCode -ne 0) {
        throw "could not create $($script:GuestRoot) in guest: $($mkdir.StdErr)"
    }

    foreach ($item in $binaries) { Push-GuestFile -LocalPath $item.Local -GuestPath $item.Guest }

    if (-not (Test-Path -LiteralPath $script:GuestDir)) {
        throw "Guest helper directory not found: $($script:GuestDir)"
    }
    $guestFiles = @(Get-ChildItem -LiteralPath $script:GuestDir -File -ErrorAction Stop)
    if ($guestFiles.Count -eq 0) { throw "No guest helper files in $($script:GuestDir)." }
    foreach ($file in $guestFiles) {
        Push-GuestFile -LocalPath $file.FullName -GuestPath "$($script:GuestRoot)\$($file.Name)"
    }
    Write-Log "guest prepared with $($binaries.Count) binaries and $($guestFiles.Count) helper files"
}

function Reset-Vm {
    param([switch]$ForRecovery)
    if ($NoReset) {
        throw 'VM reset is disabled by -NoReset; a dead VM cannot be recovered.'
    }
    Write-Step ("reset VM '$Vm'" + $(if ($ForRecovery) { ' (crash recovery)' } else { '' }))
    $r = Invoke-Bvmenv -Arguments @('reset', $Vm) -TimeoutSeconds 300
    if ($r.ExitCode -ne 0) {
        throw "bvmenv reset failed ($($r.ExitCode)): $($r.StdErr)"
    }
    Start-VmIfNeeded
    Wait-VmReady
    Initialize-Guest
}

# ---------------------------------------------------------------------------
# assertion helpers
# ---------------------------------------------------------------------------

function Add-Assertion {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Collections.Generic.List[object]]$List,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][bool]$Ok,
        [string]$Detail = ''
    )
    $List.Add([pscustomobject]@{ name = $Name; ok = $Ok; detail = $Detail })
}

function Test-ContainsAny {
    param([string]$Haystack, [object]$Needles, [bool]$Present)
    $result = [System.Collections.Generic.List[object]]::new()
    if ($null -eq $Needles) { return $result }
    $items = @($Needles | Where-Object { $null -ne $_ -and [string]$_ -ne '' })
    foreach ($needle in $items) {
        $text = [string]$needle
        $found = $Haystack.IndexOf($text, [StringComparison]::OrdinalIgnoreCase) -ge 0
        $ok = if ($Present) { $found } else { -not $found }
        $label = if ($Present) { 'stdout-contains' } else { 'stdout-not-contains' }
        $result.Add([pscustomobject]@{ name = "${label}:$text"; ok = $ok; detail = if ($ok) { '' } else { "matched=$found" } })
    }
    return $result
}

# ---------------------------------------------------------------------------
# per-case execution
# ---------------------------------------------------------------------------

function Invoke-CaseExec {
    # bvmenv 0.1.0 returns 1 for any non-zero guest exit and prints raw guest
    # output.  With `exec <vm> --json` it prints an ExecResult with the real
    # exit_code/timed_out and host paths for stdout/stderr; prefer that.  The
    # switch is command-local in 0.1.0 (a leading global --json prints help),
    # and contract-style CLIs that only return the guest exit code still work.
    param(
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [int]$TimeoutSeconds = 120
    )
    if ($script:BvmenvSupportsJson -and $Arguments.Count -ge 2) {
        $callArgs = @($Arguments[0], $Arguments[1], '--json') + @($Arguments | Select-Object -Skip 2)
    } else {
        $callArgs = $Arguments
    }
    $r = Invoke-Bvmenv -Arguments $callArgs -TimeoutSeconds $TimeoutSeconds -Echo

    $json = ConvertFrom-EmbeddedJson -Text $r.StdOut
    if ($json -and $null -ne (Get-ObjectProperty -Object $json -Name 'exit_code')) {
        $timedOut = [bool](Get-ObjectProperty -Object $json -Name 'timed_out')
        $code = if ($timedOut) { $script:TimeoutSentinel } else { [int](Get-ObjectProperty -Object $json -Name 'exit_code') }
        $guestOut = ''
        $guestErr = ''
        $outPath = [string](Get-ObjectProperty -Object $json -Name 'stdout_path')
        $errPath = [string](Get-ObjectProperty -Object $json -Name 'stderr_path')
        if ($outPath -and (Test-Path -LiteralPath $outPath -PathType Leaf)) {
            try { $guestOut = [IO.File]::ReadAllText($outPath) } catch { }
        } else {
            $guestOut = [string](Get-ObjectProperty -Object $json -Name 'stdout_tail')
        }
        if ($errPath -and (Test-Path -LiteralPath $errPath -PathType Leaf)) {
            try { $guestErr = [IO.File]::ReadAllText($errPath) } catch { }
        } else {
            $guestErr = [string](Get-ObjectProperty -Object $json -Name 'stderr_tail')
        }
        $r.StdOut = $guestOut
        $r.StdErr = $guestErr
        $r.ExitCode = $code
        $r.TimedOut = $timedOut
        $r | Add-Member -NotePropertyName ExecJson -NotePropertyValue $json -Force
        return $r
    }

    # No ExecResult JSON: bvmenv's human printer includes the guest exit code.
    $match = [regex]::Match($r.StdOut, '(?m)^exit_code\s*:\s*(\d+)(\s*\(timed out\))?')
    if ($match.Success) {
        $r.ExitCode = [int]$match.Groups[1].Value
        if ($match.Groups[2].Value) {
            $r.TimedOut = $true
            $r.ExitCode = $script:TimeoutSentinel
        }
    }
    return $r
}

function Invoke-Case {
    param([Parameter(Mandatory = $true)]$Case)

    $caseDir = Join-Path $script:CasesDir $Case.Id
    if (-not (Test-Path -LiteralPath $caseDir)) {
        New-Item -ItemType Directory -Force -Path $caseDir | Out-Null
    }

    $startedUtc = [DateTime]::UtcNow
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $timeout = [int][Math]::Ceiling($Case.TimeoutS * $TimeoutScale)
    $assertions = [System.Collections.Generic.List[object]]::new()

    $execArgs = @('exec', $Vm, '--timeout', [string]$timeout)
    if ($Case.RequiresAdmin) { $execArgs += '--elevated' }
    $execArgs += @('--workdir', $script:GuestRoot, '--')
    $execArgs += $Case.Command

    Write-Utf8Text -Path (Join-Path $caseDir 'command.txt') -Text (@(
            ('vm=' + $Vm)
            ('timeout_s=' + $timeout)
            ('requires_admin=' + $Case.RequiresAdmin)
            ('post_checks=' + ($Case.PostChecks | ConvertTo-Json -Compress))
            ('command=' + (Format-CommandLine -FilePath $Case.Command[0] -Arguments @($Case.Command | Select-Object -Skip 1)))
        ) -join [Environment]::NewLine)

    Write-Log ''
    Write-Log ("--- case {0} [{1}/{2}] timeout={3}s admin={4}" -f `
            $Case.Id, $Case.Category, $Case.Name, $timeout, $Case.RequiresAdmin) -Level STEP
    Write-Log ('  $ bvmenv ' + (Format-CommandLine -FilePath 'exec' -Arguments @($execArgs | Select-Object -Skip 1)))
    $exec = Invoke-CaseExec -Arguments $execArgs -TimeoutSeconds ($timeout + 60)

    Write-Utf8Text -Path (Join-Path $caseDir 'stdout.txt') -Text $exec.StdOut
    Write-Utf8Text -Path (Join-Path $caseDir 'stderr.txt') -Text $exec.StdErr

    # bvmenv exec may print a JSON descriptor with additional artifacts.  Keep
    # whatever host-side files it points at without depending on that shape.
    $execJson = if ($exec.PSObject.Properties['ExecJson']) {
        $exec.ExecJson
    } else {
        ConvertFrom-EmbeddedJson -Text $exec.StdOut
    }
    if ($execJson) {
        Write-Utf8Text -Path (Join-Path $caseDir 'bvmenv-exec.json') -Text ($execJson | ConvertTo-Json -Depth 10)
        $pairs = @(
            @{ Prop = 'stdout_path'; Name = 'guest-stdout.txt' },
            @{ Prop = 'stderr_path'; Name = 'guest-stderr.txt' },
            @{ Prop = 'stdout'; Name = 'guest-stdout.txt' },
            @{ Prop = 'stderr'; Name = 'guest-stderr.txt' }
        )
        foreach ($pair in $pairs) {
            $path = [string](Get-ObjectProperty -Object $execJson -Name $pair.Prop)
            if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) {
                try { Copy-Item -LiteralPath $path -Destination (Join-Path $caseDir $pair.Name) -Force } catch { }
            }
        }
    }

    Write-Log ("  exit={0} duration={1}s timed_out={2}" -f $exec.ExitCode, $exec.DurationSeconds, $exec.TimedOut)

    # Post-case state, with one retry: a dead VM must not be mistaken for a
    # broken case, and a transient bvmenv failure must not look like a crash.
    $state = Save-VmState -OutputDir $caseDir -Prefix 'state'
    if (-not $state.Ok) {
        Write-Log ('state query failed; retrying once: ' + $state.Error) -Level WARN
        Start-Sleep -Seconds 2
        $state = Save-VmState -OutputDir $caseDir -Prefix 'state-retry'
    }

    $stateClass = [string](Get-ObjectProperty -Object $state.Data -Name 'classification')
    $stopCode = [string](Get-ObjectProperty -Object $state.Data -Name 'stop_code')
    $power = [string](Get-ObjectProperty -Object $state.Data -Name 'power')
    $isCrashState = (-not $state.Ok) -or ($stateClass -in @('bsod', 'hang', 'off')) -or ($power -eq 'off')
    $isTimeout = ($exec.TimedOut -or $exec.ExitCode -eq $script:TimeoutSentinel)
    $isSkip = ($exec.ExitCode -eq 77 -and $Case.AllowSkip)

    # ----- assertions -------------------------------------------------------
    $stateDetail = if ($state.Ok) { "classification=$stateClass power=$power" } else { $state.Error }
    Add-Assertion -List $assertions -Name 'state-query' -Ok $state.Ok -Detail $stateDetail

    if ($state.Ok) {
        $expectedClass = [string](Get-ObjectProperty -Object $Case.PostChecks -Name 'state_classification')
        if (-not $expectedClass) { $expectedClass = 'desktop' }
        Add-Assertion -List $assertions -Name 'vm-state-classification' -Ok ($stateClass -eq $expectedClass) `
            -Detail "expected=$expectedClass actual=$stateClass power=$power"
    }

    if ($Case.ExpectTimeout) {
        Add-Assertion -List $assertions -Name 'timeout-expected' -Ok $isTimeout `
            -Detail "expected the case to exceed its ${timeout}s timeout and be killed by bvmenv"
    } elseif ($isSkip) {
        Add-Assertion -List $assertions -Name 'guest-skip' -Ok $true `
            -Detail 'guest returned 77 (feature not implemented in this build); recorded as skip'
    } else {
        Add-Assertion -List $assertions -Name 'guest-exit-code' -Ok ($exec.ExitCode -eq $Case.ExpectExit -and -not $isTimeout) `
            -Detail "expected=$($Case.ExpectExit) actual=$($exec.ExitCode) timed_out=$isTimeout"
    }

    foreach ($assertion in (Test-ContainsAny -Haystack $exec.StdOut -Needles $Case.PostChecks['stdout_contains'] -Present $true)) {
        $assertions.Add($assertion)
    }
    foreach ($assertion in (Test-ContainsAny -Haystack $exec.StdOut -Needles $Case.PostChecks['stdout_not_contains'] -Present $false)) {
        $assertions.Add($assertion)
    }
    foreach ($assertion in (Test-ContainsAny -Haystack $exec.StdErr -Needles $Case.PostChecks['stderr_contains'] -Present $true)) {
        $assertion.name = $assertion.name -replace '^stdout-', 'stderr-'
        $assertions.Add($assertion)
    }
    foreach ($assertion in (Test-ContainsAny -Haystack $exec.StdErr -Needles $Case.PostChecks['stderr_not_contains'] -Present $false)) {
        $assertion.name = $assertion.name -replace '^stdout-', 'stderr-'
        $assertions.Add($assertion)
    }

    if ($Case.PostChecks.Contains('min_stdout_bytes')) {
        $minimum = [int]$Case.PostChecks['min_stdout_bytes']
        $length = if ($exec.StdOut) { $exec.StdOut.Length } else { 0 }
        Add-Assertion -List $assertions -Name 'min-stdout-bytes' -Ok ($length -ge $minimum) `
            -Detail "expected>=$minimum actual=$length"
    }
    if ($Case.PostChecks.Contains('max_duration_s')) {
        $maximum = [double]$Case.PostChecks['max_duration_s']
        Add-Assertion -List $assertions -Name 'max-duration-s' -Ok ($exec.DurationSeconds -le $maximum) `
            -Detail "expected<=$maximum actual=$($exec.DurationSeconds)"
    }

    # ----- classification ---------------------------------------------------
    $failed = @($assertions | Where-Object { -not $_.ok })
    if ($isCrashState) {
        $status = 'crash'
    } elseif ($isTimeout) {
        $status = 'timeout'
    } elseif ($isSkip) {
        $status = 'skip'
    } elseif ($failed.Count -gt 0) {
        $status = 'fail'
    } else {
        $status = 'pass'
    }

    $notes = @()
    if ($Case.Notes) { $notes += $Case.Notes }
    if ($isCrashState) {
        $notes += "VM classification=$stateClass power=$power stop_code=$stopCode"
        if (-not $state.Ok) { $notes += "state query failed: $($state.Error)" }
    }
    if ($isTimeout -and -not $Case.ExpectTimeout) { $notes += "case exceeded ${timeout}s" }
    if ($isSkip) { $notes += 'guest returned 77 (unsupported in this build)' }

    $result = [ordered]@{
        id              = $Case.Id
        name            = $Case.Name
        category        = $Case.Category
        timeout_s       = $timeout
        started_utc     = $startedUtc.ToString('o')
        duration_s      = [Math]::Round($sw.Elapsed.TotalSeconds, 3)
        status          = $status
        exit_code       = if ($exec.TimedOut) { $null } else { $exec.ExitCode }
        artifacts       = [ordered]@{
            dir             = $caseDir
            stdout          = (Join-Path $caseDir 'stdout.txt')
            stderr          = (Join-Path $caseDir 'stderr.txt')
            state_json      = $state.StateJson
            screenshot      = $state.Screenshot
            vmware_log_tail = $state.VmwareLogTail
        }
        assertions      = @($assertions)
        notes           = ($notes -join '; ')
        expected        = [bool]$Case.ExpectTimeout
    }

    # ----- crash evidence ---------------------------------------------------
    if ($status -in @('crash', 'timeout')) {
        $evidence = @(
            "case: $($Case.Id) ($($Case.Name))"
            "status: $status"
            "classification: $stateClass"
            "power: $power"
            "stop_code: $stopCode"
            "exit_code: $($exec.ExitCode)"
            "host_timed_out: $($exec.TimedOut)"
            "duration_s: $($result.duration_s)"
            "timeout_s: $timeout"
            "state_query_ok: $($state.Ok)"
            "state_query_error: $($state.Error)"
            "screenshot: $($state.Screenshot)"
            "vmware_log_tail: $($state.VmwareLogTail)"
            ''
            'stdout (tail):'
            (($exec.StdOut -split "`r?`n" | Select-Object -Last 80) -join [Environment]::NewLine)
            ''
            'stderr (tail):'
            (($exec.StdErr -split "`r?`n" | Select-Object -Last 80) -join [Environment]::NewLine)
        )
        Write-Utf8Text -Path (Join-Path $caseDir 'crash.txt') -Text ($evidence -join [Environment]::NewLine)
    }

    $sw.Stop()
    $result.duration_s = [Math]::Round($sw.Elapsed.TotalSeconds, 3)

    # ----- recovery / abort policy -----------------------------------------
    $blocking = $isCrashState -or ($isTimeout -and -not $Case.ExpectTimeout)
    $abort = $false
    if ($blocking) {
        $script:SawUnexpectedCrash = $true
        $reason = if ($isCrashState) { "VM $stateClass" } else { 'timeout' }
        Write-Log "BLOCKING FAILURE: $($Case.Id) ($reason)" -Level ERROR

        if ($NoReset) {
            $abort = $true
            $script:AbortReason = "case $($Case.Id) ended in $status and -NoReset forbids VM recovery"
            Write-Log 'NoReset is active; the VM cannot be recovered. Aborting.' -Level ERROR
        } elseif (-not $KeepGoing) {
            $abort = $true
            $script:AbortReason = "case $($Case.Id) ended in $status; run aborted (use -KeepGoing to continue)"
            Write-Log 'Aborting after the first blocking failure (-KeepGoing not set).' -Level ERROR
            try {
                $r = Invoke-Bvmenv -Arguments @('reset', $Vm) -TimeoutSeconds 300
                if ($r.ExitCode -eq 0) {
                    Write-Log 'VM reset after blocking failure.'
                    Save-VmState -OutputDir $caseDir -Prefix 'state-after-reset' | Out-Null
                } else {
                    Write-Log "VM reset failed after blocking failure: $($r.StdErr)" -Level ERROR
                }
            } catch {
                Write-Log "VM reset failed after blocking failure: $($_.Exception.Message)" -Level ERROR
            }
        } else {
            Write-Log 'KeepGoing: resetting and re-preparing the VM.' -Level WARN
            try {
                Reset-Vm -ForRecovery
            } catch {
                $abort = $true
                $script:AbortReason = "VM recovery failed after $($Case.Id): $($_.Exception.Message)"
                Write-Log $script:AbortReason -Level ERROR
            }
        }
    }

    $script:Results.Add($result)
    return [pscustomobject]@{ Result = $result; Abort = $abort }
}

function New-SkippedResult {
    param($Case, [string]$Reason)
    $caseDir = Join-Path $script:CasesDir $Case.Id
    if (-not (Test-Path -LiteralPath $caseDir)) {
        New-Item -ItemType Directory -Force -Path $caseDir | Out-Null
        Write-Utf8Text -Path (Join-Path $caseDir 'skipped.txt') -Text $Reason
    }
    return [ordered]@{
        id              = $Case.Id
        name            = $Case.Name
        category        = $Case.Category
        timeout_s       = [int][Math]::Ceiling($Case.TimeoutS * $TimeoutScale)
        started_utc     = $null
        duration_s      = 0.0
        status          = 'skip'
        exit_code       = $null
        artifacts       = [ordered]@{
            dir = $caseDir; stdout = $null; stderr = $null; state_json = $null
            screenshot = $null; vmware_log_tail = $null
        }
        assertions      = @()
        notes           = $Reason
        expected        = [bool]$Case.ExpectTimeout
    }
}

function New-DryRunResult {
    param($Case)
    $caseDir = Join-Path $script:CasesDir $Case.Id
    return [ordered]@{
        id              = $Case.Id
        name            = $Case.Name
        category        = $Case.Category
        timeout_s       = [int][Math]::Ceiling($Case.TimeoutS * $TimeoutScale)
        started_utc     = $null
        duration_s      = 0.0
        status          = 'skip'
        exit_code       = $null
        artifacts       = [ordered]@{
            dir = $caseDir; stdout = $null; stderr = $null; state_json = $null
            screenshot = $null; vmware_log_tail = $null
        }
        assertions      = @([pscustomobject]@{ name = 'dry-run'; ok = $true; detail = 'case was not executed' })
        notes           = 'dry run: not executed'
        expected        = [bool]$Case.ExpectTimeout
    }
}

# ---------------------------------------------------------------------------
# artifacts: result.json / report.md
# ---------------------------------------------------------------------------

function Get-Summary {
    $summary = [ordered]@{
        total = 0; pass = 0; fail = 0; skip = 0; crash = 0; timeout = 0
        expected_timeout = 0
    }
    foreach ($case in $script:Results) {
        $summary.total++
        $status = [string]$case.status
        if ($summary.Contains($status)) { $summary[$status]++ }
        if ($case.expected -and $status -eq 'timeout') { $summary.expected_timeout++ }
    }
    return $summary
}

function Write-ResultJson {
    $summary = Get-Summary
    $result = [ordered]@{
        run = [ordered]@{
            started_utc   = $script:StartedUtc.ToString('o')
            finished_utc  = [DateTime]::UtcNow.ToString('o')
            vm            = $Vm
            config        = $Configuration
            bvmenv        = if ($script:BvmenvFound) { $script:BvmenvPath } else { $null }
            host          = ("{0} / {1}" -f $env:COMPUTERNAME, [Environment]::OSVersion.VersionString)
            git_commit    = (Get-GitCommit)
            dry_run       = $script:IsDryRun
            aborted       = $script:Aborted
            abort_reason  = $script:AbortReason
            artifact_root = $script:ArtifactRoot
            timeout_scale = $TimeoutScale
            timeout_sentinel = $script:TimeoutSentinel
            filter        = $Filter
            from          = $From
            keep_going    = [bool]$KeepGoing
            no_reset      = [bool]$NoReset
            error         = $script:RunError
        }
        cases = @($script:Results)
        summary = $summary
        dry_run = $script:IsDryRun
    }
    $path = Join-Path $script:ArtifactRoot 'result.json'
    Write-Utf8Text -Path $path -Text ($result | ConvertTo-Json -Depth 14)
    return $path
}

function Format-ReportCell {
    param([object]$Value)
    if ($null -eq $Value) { return '' }
    return ([string]$Value) -replace '\|', '\|'
}

function Write-Report {
    $summary = Get-Summary
    $lines = [System.Collections.Generic.List[string]]::new()
    $mode = if ($script:IsDryRun) { 'DRY RUN' } else { 'RUN' }
    $lines.Add("# blook-drv end-to-end report ($mode)")
    $lines.Add('')
    $lines.Add("- Started: $($script:StartedUtc.ToString('u'))")
    $lines.Add("- Finished: $([DateTime]::UtcNow.ToString('u'))")
    $lines.Add("- VM: ``$Vm``")
    $lines.Add("- Configuration: ``$Configuration``")
    $lines.Add("- bvmenv: ``$(if ($script:BvmenvFound) { $script:BvmenvPath } else { 'not found (dry run)' })``")
    $lines.Add("- Host: $env:COMPUTERNAME")
    $lines.Add("- Git: $(Get-GitCommit)")
    $lines.Add("- Artifacts: ``$($script:ArtifactRoot)``")
    if ($script:Aborted) { $lines.Add("- **Aborted:** $($script:AbortReason)") }
    if ($script:RunError) { $lines.Add("- **Run error:** $($script:RunError)") }
    $lines.Add('')
    $lines.Add('## Summary')
    $lines.Add('')
    $lines.Add('| total | pass | fail | skip | crash | timeout | expected timeout |')
    $lines.Add('| ---: | ---: | ---: | ---: | ---: | ---: | ---: |')
    $lines.Add(('| {0} | {1} | {2} | {3} | {4} | {5} | {6} |' -f `
                $summary.total, $summary.pass, $summary.fail, $summary.skip, $summary.crash, $summary.timeout, $summary.expected_timeout))
    $lines.Add('')

    $lines.Add('## Cases')
    $lines.Add('')
    $lines.Add('| # | id | category | status | exit | duration | evidence |')
    $lines.Add('| ---: | --- | --- | --- | ---: | ---: | --- |')
    $i = 0
    foreach ($case in $script:Results) {
        $i++
        $dir = [string](Get-ObjectProperty -Object $case.artifacts -Name 'dir')
        $link = if ($dir) {
            $rel = [IO.Path]::GetRelativePath($script:ArtifactRoot, $dir).Replace('\', '/')
            "[$($case.id)]($rel/)"
        } else { '' }
        $status = [string]$case.status
        if ($case.expected -and $status -eq 'timeout') { $status = 'timeout (expected)' }
        $exit = if ($null -eq $case.exit_code) { '' } else { [string]$case.exit_code }
        $lines.Add(('| {0} | {1} | {2} | {3} | {4} | {5}s | {6} |' -f `
                    $i, (Format-ReportCell $case.id), (Format-ReportCell $case.category),
                    (Format-ReportCell $status), $exit, $case.duration_s, $link))
    }
    $lines.Add('')

    $problems = @($script:Results | Where-Object { $_.status -in @('fail', 'crash', 'timeout') })
    if ($problems.Count -gt 0) {
        $lines.Add('## Failure and crash evidence')
        $lines.Add('')
        foreach ($case in $problems) {
            $dir = [string](Get-ObjectProperty -Object $case.artifacts -Name 'dir')
            $rel = if ($dir) { [IO.Path]::GetRelativePath($script:ArtifactRoot, $dir).Replace('\', '/') } else { '' }
            $label = if ($case.status -eq 'timeout' -and $case.expected) { 'timeout (expected)' } else { [string]$case.status }
            $lines.Add("### $($case.id) - $label")
            $lines.Add('')
            if ($case.notes) { $lines.Add("- Notes: $($case.notes)") }
            $lines.Add("- Artifacts: [$rel/]($rel/)")
            foreach ($assertion in @($case.assertions)) {
                if (-not $assertion.ok) {
                    $lines.Add(("- FAILED assertion ``{0}``: {1}" -f $assertion.name, $assertion.detail))
                }
            }
            if ($rel) {
                $lines.Add("- [stdout]($rel/stdout.txt) | [stderr]($rel/stderr.txt) | [state]($rel/state.json) | [crash log]($rel/crash.txt)")
            }
            $lines.Add('')
        }
    }

    $lines.Add('## How to interpret this run')
    $lines.Add('')
    $lines.Add('- `pass`: guest exit code and every assertion matched.')
    $lines.Add('- `fail`: the guest ran but an expectation failed; the VM stayed alive.')
    $lines.Add('- `skip`: the guest returned 77 (feature not implemented in this build) or the case was not run.')
    $lines.Add('- `crash`: post-case state was `bsod`, `hang`, `off`, or the state query itself failed.')
    $lines.Add('- `timeout`: bvmenv hit the case timeout (sentinel 124) or the host killed it.')
    $lines.Add('- `watchdog-detects-hang` is intentionally a `timeout` result; it validates the watchdog and the VM-alive post-check. It does not abort the run.')
    $lines.Add('- Exit code is 0 only when every executed case passed and no unexpected crash/timeout occurred.')
    $lines.Add('')
    $lines.Add('## Reproduction')
    $lines.Add('')
    $lines.Add('```powershell')
    $lines.Add("pwsh -File scripts/E2E.ps1 -Vm $Vm -Configuration $Configuration -Artifacts `"$($script:ArtifactRoot)`"$(if ($KeepGoing) { ' -KeepGoing' })")
    $lines.Add('```')

    $path = Join-Path $script:ArtifactRoot 'report.md'
    Write-Utf8Text -Path $path -Text (($lines -join [Environment]::NewLine) + [Environment]::NewLine)
    return $path
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------

$exitCode = 0
try {
    if ($DryRun -and $ValidateOnly) {
        throw '-DryRun and -ValidateOnly are mutually exclusive.'
    }
    if (-not (Test-Admin)) {
        Write-Log 'This shell is not elevated. Cases that need driver installation/start are marked requires_admin and use bvmenv --elevated; build/sign may still work.' -Level WARN
    }

    Write-Log "blook-drv e2e harness (mode=$(if ($DryRun) { 'dry-run' } elseif ($ValidateOnly) { 'validate-only' } else { 'run' }))"

    if (-not $ValidateOnly) {
        $artifactPath = if ($Artifacts) { $Artifacts } else { "docs/evidence/$($script:RunId)-e2e" }
        $script:ArtifactRoot = Resolve-FullPath $artifactPath
        if (Test-Path -LiteralPath $script:ArtifactRoot) {
            $n = 1
            while (Test-Path -LiteralPath ($script:ArtifactRoot + "-$n")) { $n++ }
            $script:ArtifactRoot = $script:ArtifactRoot + "-$n"
        }
        New-Item -ItemType Directory -Force -Path $script:ArtifactRoot | Out-Null
        $script:CasesDir = Join-Path $script:ArtifactRoot 'cases'
        $script:RunDir = Join-Path $script:ArtifactRoot 'run'
        New-Item -ItemType Directory -Force -Path $script:CasesDir | Out-Null
        New-Item -ItemType Directory -Force -Path $script:RunDir | Out-Null
        $script:LogPath = Join-Path $script:ArtifactRoot 'run.log'
        Write-Log "artifacts: $($script:ArtifactRoot)"
        if (Test-Path -LiteralPath $script:CaseFile) {
            Copy-Item -LiteralPath $script:CaseFile -Destination (Join-Path $script:RunDir 'cases.psd1') -Force
        }
    }

    $matrix = Test-CaseMatrix
    if ($matrix.Errors.Count -gt 0) {
        foreach ($errorText in $matrix.Errors) { Write-Log ('matrix: ' + $errorText) -Level ERROR }
        throw ("cases.psd1 validation failed with $($matrix.Errors.Count) error(s).")
    }
    $script:Cases = @($matrix.Cases)
    Write-Log ("matrix: {0} cases across {1} categories" -f $script:Cases.Count,
        (@($script:Cases | ForEach-Object { $_.Category } | Sort-Object -Unique).Count))

    if ($ValidateOnly) {
        $byCategory = $script:Cases | Group-Object Category | Sort-Object Name
        Write-Step 'matrix validation'
        foreach ($group in $byCategory) {
            Write-Log ("  {0,-14} {1,3}" -f $group.Name, $group.Count)
        }
        Write-Log ("  total          {0,3}" -f $script:Cases.Count)
        $dupes = @($script:Cases | Group-Object Id | Where-Object Count -gt 1)
        if ($dupes.Count -gt 0) { throw "duplicate ids: $($dupes.Name -join ', ')" }

        $build = Get-BuildArtifacts
        Write-Step 'build outputs'
        foreach ($artifact in $build) {
            $state = if (Test-Path -LiteralPath $artifact.Path) { 'present' } else { 'missing (build with xmake)' }
            Write-Log ("  {0,-12} {1}  [{2}]" -f $artifact.Name, $artifact.Path, $state)
        }

        Write-Step 'guest helpers'
        if (Test-Path -LiteralPath $script:GuestDir) {
            $guestFiles = @(Get-ChildItem -LiteralPath $script:GuestDir -File -ErrorAction SilentlyContinue)
            Write-Log ("  {0} files in {1}" -f $guestFiles.Count, $script:GuestDir)
        } else {
            Write-Log "  missing guest dir: $($script:GuestDir)" -Level WARN
        }

        Write-Step 'bvmenv'
        $resolved = Resolve-Bvmenv -Explicit $Bvmenv
        if ($resolved) {
            Write-Log "  $resolved"
        } else {
            Write-Log '  not found (validate-only continues)' -Level WARN
        }

        Write-Log ''
        Write-Log 'VALIDATE-ONLY: matrix schema and ids are valid.' -Level STEP
        $exitCode = 0
        return
    }

    $selected = Select-Cases -Cases $script:Cases
    if ($selected.Count -eq 0) { throw 'No cases selected by -Filter/-From.' }

    $script:BvmenvPath = Resolve-Bvmenv -Explicit $Bvmenv
    $script:BvmenvFound = [bool]$script:BvmenvPath
    if ($script:BvmenvFound) { Write-Log "bvmenv: $($script:BvmenvPath)" }
    Initialize-BvmenvCapabilities

    if ($NoBuild) {
        Write-Log '-NoBuild: using the existing build outputs.'
    } else {
        Invoke-Build
    }

    $buildArtifacts = Get-BuildArtifacts
    Write-Step 'build artifacts'
    foreach ($artifact in $buildArtifacts) {
        $exists = Test-Path -LiteralPath $artifact.Path
        Write-Log ("  {0,-12} {1}  [{2}]" -f $artifact.Name, $artifact.Path, $(if ($exists) { 'present' } else { 'MISSING' }))
    }
    Assert-BuildArtifacts -Artifacts $buildArtifacts

    if ($DryRun) {
        Write-Step 'planned VM lifecycle'
        Write-Log "[dry-run] bvmenv create $Vm (or reset $Vm)"
        Write-Log "[dry-run] wait for state classification=desktop, tools_heartbeat=true"
        Initialize-Guest
        Write-Step 'planned cases'
        foreach ($case in $selected) {
            $timeout = [int][Math]::Ceiling($case.TimeoutS * $TimeoutScale)
            $args = @('exec', $Vm, '--timeout', [string]$timeout)
            if ($case.RequiresAdmin) { $args += '--elevated' }
            $args += @('--workdir', $script:GuestRoot, '--') + $case.Command
            Write-Log ("  {0,-42} {1,4}s  {2}" -f $case.Id, $timeout, (Format-CommandLine -FilePath 'bvmenv' -Arguments $args)) -Level DEBUG
            $script:Results.Add((New-DryRunResult -Case $case))
        }
        Write-Step 'dry-run summary'
        $summary = Get-Summary
        Write-Log ("total={0} pass={1} fail={2} skip={3} crash={4} timeout={5} (dry run: no guest was started)" -f `
                $summary.total, $summary.pass, $summary.fail, $summary.skip, $summary.crash, $summary.timeout)
    } else {
        Write-Step "VM lifecycle for '$Vm'"
        if ($NoReset) {
            Write-Log '-NoReset: create/reset skipped; using the VM as-is.' -Level WARN
            Wait-VmReady
            Initialize-Guest
        } else {
            Write-Log "creating/resetting VM '$Vm'"
            $create = Invoke-Bvmenv -Arguments @('create', $Vm) -TimeoutSeconds 300
            if ($create.ExitCode -ne 0) {
                Write-Log "create failed (maybe the VM already exists); trying reset: $($create.StdErr)" -Level WARN
                $reset = Invoke-Bvmenv -Arguments @('reset', $Vm) -TimeoutSeconds 300
                if ($reset.ExitCode -ne 0) {
                    throw "could not create or reset VM '$Vm' (create=$($create.ExitCode), reset=$($reset.ExitCode)): $($reset.StdErr)"
                }
            }
            Start-VmIfNeeded
            Wait-VmReady
            Initialize-Guest
        }

        Write-Step 'run cases'
        $aborted = $false
        foreach ($case in $selected) {
            if ($aborted) {
                $script:Results.Add((New-SkippedResult -Case $case -Reason "not run: aborted after $($script:AbortReason)"))
                continue
            }
            $outcome = Invoke-Case -Case $case
            if ($outcome.Abort) {
                $aborted = $true
                $script:Aborted = $true
                if (-not $script:AbortReason) { $script:AbortReason = "aborted after $($case.Id)" }
            }
        }
        if ($aborted) { Write-Log "run aborted: $($script:AbortReason)" -Level ERROR }
    }

    $summary = Get-Summary
    $resultPath = Write-ResultJson
    $reportPath = Write-Report

    Write-Step 'e2e summary'
    Write-Log ("total={0} pass={1} fail={2} skip={3} crash={4} timeout={5} expected_timeout={6}" -f `
            $summary.total, $summary.pass, $summary.fail, $summary.skip, $summary.crash, $summary.timeout, $summary.expected_timeout)
    Write-Log "result: $resultPath"
    Write-Log "report: $reportPath"

    # A run is green only when every executed case passed and no *unexpected*
    # crash/timeout occurred.  watchdog-detects-hang is intentionally a
    # timeout, carries expected=true, and does not fail the gate.
    $unexpectedTimeouts = $summary.timeout - $summary.expected_timeout
    if ($script:RunError) { $exitCode = 3 }
    elseif ($summary.crash -gt 0 -or $summary.fail -gt 0 -or $unexpectedTimeouts -gt 0) { $exitCode = 1 }
    elseif (($summary.pass + $summary.expected_timeout) -eq $summary.total) { $exitCode = 0 }
    elseif ($summary.skip -gt 0) { $exitCode = 2 }
    else { $exitCode = 1 }

    if ($DryRun) { $exitCode = 0 }
} catch {
    $script:RunError = $_.Exception.Message
    Write-Log ('FATAL: ' + $script:RunError) -Level ERROR
    if (-not $ValidateOnly -and $script:ArtifactRoot) {
        try {
            $summary = Get-Summary
            Write-ResultJson | Out-Null
            Write-Report | Out-Null
        } catch { }
    }
    $exitCode = 3
}

Write-Log ''
Write-Log "exit code: $exitCode" -Level STEP
exit $exitCode



