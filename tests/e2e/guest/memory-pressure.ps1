# Allocate/lock memory until ~80% commit is in use, then run the driver's
# hook/unhook path under that pressure.  The list is always released.
. "$PSScriptRoot\lib.ps1"

if (-not (Test-Path -LiteralPath $script:Hooks)) {
    Skip-Guest "missing $($script:Hooks)"
}

$chunks = New-Object System.Collections.Generic.List[byte[]]
$chunkBytes = 64MB
$started = Get-Date
$commitPercent = 0
try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $totalKb = [double]$os.TotalVirtualMemorySize
    if ($totalKb -le 0) { Fail-Guest 'could not read TotalVirtualMemorySize' }
    $targetKb = $totalKb * 0.80

    while ($true) {
        if (((Get-Date) - $started).TotalSeconds -gt 180) { Fail-Guest 'memory pressure allocation timed out' }
        $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
        $freeKb = [double]$os.FreeVirtualMemory
        $usedKb = $totalKb - $freeKb
        $commitPercent = [Math]::Round(($usedKb / $totalKb) * 100, 1)
        Write-GuestLine ("commit_pct=" + $commitPercent)
        if ($usedKb -ge $targetKb) { break }

        $remainingKb = $targetKb - $usedKb
        $bytes = [int][Math]::Min($chunkBytes, $remainingKb * 1024)
        if ($bytes -lt 1MB) { break }
        $buffer = New-Object byte[] $bytes
        # Touch every page so the commit is real, not just reserved address space.
        for ($i = 0; $i -lt $buffer.Length; $i += 4096) { $buffer[$i] = 1 }
        $chunks.Add($buffer)
    }

    Write-GuestLine ("pressure=ok")
    Write-GuestLine ("chunks=" + $chunks.Count)

    $r = Invoke-GuestExe -FilePath $script:Hooks -Arguments @('memory-pressure', '--hold-seconds', '5', '--json')
    foreach ($line in $r.Output) { Write-GuestLine ("hook: " + $line) }
    if ($r.Code -eq 77) {
        Skip-Guest 'blook-guest-hooks.exe does not implement memory-pressure in this build'
    }
    if ($r.Code -ne 0) { Fail-Guest "hook/unhook under pressure exited $($r.Code)" }
    Write-GuestLine 'hook_unhook=ok'
    exit 0
} finally {
    $chunks.Clear()
    [GC]::Collect()
    [GC]::WaitForPendingFinalizers()
}
