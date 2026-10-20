# Thin wrapper around blook-guest-hooks.exe.
#
# The binary owns the actual driver-level assertions (breakpoint hit counters,
# context sanitisation, leak checks, ...).  The wrapper only guarantees the
# driver is running and propagates the 0/1/77 contract.
param(
    [Parameter(Mandatory = $true)]
    [string]$Mode
)
. "$PSScriptRoot\lib.ps1"

if (-not (Test-Path -LiteralPath $script:Hooks)) {
    Skip-Guest "missing $($script:Hooks)"
}

Ensure-Driver | Out-Null

$r = Invoke-GuestExe -FilePath $script:Hooks -Arguments @($Mode, '--json')
foreach ($line in $r.Output) { Write-GuestLine $line }
if ($r.Code -eq 77) {
    Skip-Guest "blook-guest-hooks.exe does not implement '$Mode' in this build"
}
if ($r.Code -ne 0) {
    Fail-Guest "blook-guest-hooks.exe $Mode exited $($r.Code)"
}
Write-GuestLine ("mode=" + $Mode)
exit 0
