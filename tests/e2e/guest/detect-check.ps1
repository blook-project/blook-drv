# Run one anti-detection check through blook-antidetect.exe.
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('cpuid-hypervisor-bit', 'cpuid-vendor-leaves', 'vmx-msr', 'tsc-timing', 'rdtscp', 'aperf-mperf', 'exception-behaviour')]
    [string]$Check
)
. "$PSScriptRoot\lib.ps1"

if (-not (Test-Path -LiteralPath $script:Antidetect)) {
    Skip-Guest "missing $($script:Antidetect)"
}

Ensure-Driver | Out-Null
Enable-Hide | Out-Null

$r = Invoke-GuestExe -FilePath $script:Antidetect -Arguments @('--check', $Check, '--json')
if ($r.Code -eq 77) { Skip-Guest "blook-antidetect.exe does not implement --check $Check in this build" }
$text = Get-LoaderText $r

$json = $null
$start = $text.IndexOf('{')
$end = $text.LastIndexOf('}')
if ($start -ge 0 -and $end -gt $start) {
    try { $json = $text.Substring($start, $end - $start + 1) | ConvertFrom-Json } catch { }
}

$passed = ($r.Code -eq 0)
if ($json -and $json.PSObject.Properties['pass']) {
    $passed = [bool]$json.pass
} elseif ($json -and $json.PSObject.Properties['ok']) {
    $passed = [bool]$json.ok
}
if ($text -match 'pass=false') { $passed = $false }

Write-GuestLine ("check=" + $Check + " pass=" + $(if ($passed) { 'true' } else { 'false' }))
if ($text) { foreach ($line in $r.Output) { Write-GuestLine ("detail: " + $line) } }
if (-not $passed) { Fail-Guest "check $Check failed (guest exit $($r.Code))" }
exit 0
