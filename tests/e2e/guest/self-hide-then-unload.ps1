# Self-hide then clean unload: the service must still stop and unlink, and a
# subsequent `sc query` must fail (the service registration is gone).
. "$PSScriptRoot\lib.ps1"

if (-not (Test-GuestAdmin)) { Fail-Guest 'requires elevation' }

Ensure-Driver | Out-Null
Enable-Hide | Out-Null

$stop = Invoke-Loader -Arguments @('stop')
if ($stop.Code -ne 0) {
    Fail-Guest ("stop after hide failed ({0}): {1}" -f $stop.Code, (Get-LoaderText $stop))
}
Start-Sleep -Milliseconds 800
$state = Get-ServiceState
Write-GuestLine ("state=" + $state)
if ($state -ne 'Stopped') { Fail-Guest "driver did not stop after self-hide (state=$state)" }

$uninstall = Invoke-Loader -Arguments @('uninstall')
if ($uninstall.Code -ne 0) {
    Fail-Guest ("uninstall after hide failed ({0}): {1}" -f $uninstall.Code, (Get-LoaderText $uninstall))
}
Start-Sleep -Milliseconds 800

$key = 'HKLM:\SYSTEM\CurrentControlSet\Services\BlookDrv'
$keyVisible = Test-Path -LiteralPath $key
$sc = & sc.exe query BlookDrv 2>&1
$scCode = $LASTEXITCODE

Write-GuestLine ("service_key_visible=" + $(if ($keyVisible) { 'yes' } else { 'no' }))
Write-GuestLine ("sc_exit=" + $scCode)

if ($scCode -eq 0) { Fail-Guest 'sc query BlookDrv still succeeds after uninstall' }
if ($keyVisible) { Fail-Guest 'service registry key survived uninstall' }

Write-GuestLine 'unloaded=yes'
exit 0
