# Orchestrates the EPT hook cases: spawn a hot target process, hand its
# (pid, address) to blook-guest-hooks.exe, and let the binary make the
# driver-level assertions.
#
# The contract with blook-guest-hooks.exe is:
#   ept <mode> --target-pid <pid> --target-address <hex> --target-log <path> --json
# A 77 exit means the mode is not implemented in this build (host records skip).
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('self-page-read', 'foreign-process', 'multi-same-page', 'unhook-restores',
        'while-thread-executes', 'invalid-address')]
    [string]$Mode
)
. "$PSScriptRoot\lib.ps1"

if (-not (Test-Path -LiteralPath $script:Hooks)) {
    Skip-Guest "missing $($script:Hooks)"
}

Ensure-Driver | Out-Null

$stamp = Get-Date -Format 'yyyyMMddHHmmssfff'
$jsonPath = Join-Path $script:Root ("ept-target-$stamp.json")
$logPath = Join-Path $script:Root ("ept-target-$stamp.log")
$targetArgs = @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $script:Root 'hook-target.ps1'),
    '-DurationSeconds', '90', '-Output', $jsonPath, '-LogPath', $logPath
)
$target = Start-Process -FilePath 'powershell.exe' -ArgumentList $targetArgs -PassThru -WindowStyle Hidden

try {
    $info = Wait-JsonFile -Path $jsonPath -TimeoutSeconds 30
    if (-not $info) { Fail-Guest 'hook target did not start' }
    Write-GuestLine ("target_pid=" + $info.pid)
    Write-GuestLine ("target_address=" + $info.address)

    $r = Invoke-GuestExe -FilePath $script:Hooks -Arguments @(
        'ept', $Mode,
        '--target-pid', [string]$info.pid,
        '--target-address', [string]$info.address,
        '--target-log', $logPath,
        '--json'
    )
    foreach ($line in $r.Output) { Write-GuestLine $line }
    if ($r.Code -eq 77) {
        Skip-Guest "blook-guest-hooks.exe does not implement ept $Mode in this build"
    }
    if ($r.Code -ne 0) {
        Fail-Guest "blook-guest-hooks.exe ept $Mode exited $($r.Code)"
    }

    # The binary owns the mode-specific markers; just expose the target log for
    # the host artifact record.
    if (Test-Path -LiteralPath $logPath) {
        $tail = @(Get-Content -LiteralPath $logPath -Tail 5 -ErrorAction SilentlyContinue)
        foreach ($line in $tail) { Write-GuestLine ("target_log: " + $line) }
    }
    Write-GuestLine ("mode=" + $Mode)
    exit 0
} finally {
    if ($target -and -not $target.HasExited) {
        try { Stop-Process -Id $target.Id -Force -ErrorAction SilentlyContinue } catch { }
    }
}
