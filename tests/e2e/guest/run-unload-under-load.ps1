# Stop the driver while target threads are executing.
#
# This is the crash-safety scenario: the host watchdog is not involved; the
# guest's own stop must drain in-flight work and return.  A target process is
# spawned and (when the guest-hooks binary supports it) a hook is armed before
# the stop.
param(
    [ValidateSet('ept', 'load')]
    [string]$Mode = 'load'
)
. "$PSScriptRoot\lib.ps1"

if (-not (Test-GuestAdmin)) { Fail-Guest 'requires elevation' }
Ensure-Driver | Out-Null

$stamp = Get-Date -Format 'yyyyMMddHHmmssfff'
$jsonPath = Join-Path $script:Root ("unload-target-$stamp.json")
$logPath = Join-Path $script:Root ("unload-target-$stamp.log")
$targetArgs = @(
    '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $script:Root 'hook-target.ps1'),
    '-DurationSeconds', '60', '-Output', $jsonPath, '-LogPath', $logPath
)
$target = Start-Process -FilePath 'powershell.exe' -ArgumentList $targetArgs -PassThru -WindowStyle Hidden
$hookState = 'none'

try {
    $info = Wait-JsonFile -Path $jsonPath -TimeoutSeconds 30
    if (-not $info) { Fail-Guest 'target did not start' }
    Write-GuestLine ("target_pid=" + $info.pid)
    Write-GuestLine ("target_address=" + $info.address)

    if (Test-Path -LiteralPath $script:Hooks) {
        $arm = Invoke-GuestExe -FilePath $script:Hooks -Arguments @(
            'ept-hook-while-thread-executes', '--target-pid', [string]$info.pid,
            '--target-address', [string]$info.address, '--json'
        )
        foreach ($line in $arm.Output) { Write-GuestLine ("arm: " + $line) }
        if ($arm.Code -eq 77) {
            $hookState = 'unavailable'
        } elseif ($arm.Code -eq 0) {
            $hookState = 'armed'
        } else {
            Fail-Guest "could not arm hook before unload (exit $($arm.Code))"
        }
    }
    Write-GuestLine ("hook_state=" + $hookState)

    $stop = Invoke-WithTimeout -FilePath $script:Loader -Arguments @('stop') -TimeoutSeconds 45
    foreach ($line in $stop.Output) { Write-GuestLine ("stop: " + $line) }
    Write-GuestLine ("stop_seconds=" + $stop.Seconds)
    if ($stop.TimedOut) { Fail-Guest 'sc stop hung for 45s under load' }
    if ($stop.Code -ne 0) { Fail-Guest "sc stop failed ($($stop.Code)) under load" }

    Start-Sleep -Milliseconds 500
    $state = Get-ServiceState
    Write-GuestLine ("state=" + $state)
    if ($state -ne 'Stopped') { Fail-Guest "service did not stop (state=$state)" }

    $alive = $false
    try { $alive = [bool](Get-Process -Id $target.Id -ErrorAction SilentlyContinue) } catch { }
    Write-GuestLine ("target_alive=" + $(if ($alive) { 'yes' } else { 'no' }))
    if (-not $alive) { Fail-Guest 'target process died during driver unload' }

    Write-GuestLine 'stop_clean=yes'
    exit 0
} finally {
    if ($target -and -not $target.HasExited) {
        try { Stop-Process -Id $target.Id -Force -ErrorAction SilentlyContinue } catch { }
    }
}
