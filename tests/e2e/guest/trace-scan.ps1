# Driver artifact scan (wire op trace_scan 0x801A).
#
# The loader/guest binary is expected to expose `trace-scan --json` with a
# `found` count.  If neither implements it, report 77 (skip).
param(
    [int]$ExpectFound = 0,
    [switch]$EnsureHidden
)
. "$PSScriptRoot\lib.ps1"

if ($EnsureHidden) {
    Ensure-Driver | Out-Null
    Enable-Hide | Out-Null
}

$attempts = @(
    @{ Path = $script:Hooks; Args = @('trace-scan', '--json') }
    @{ Path = $script:Loader; Args = @('trace-scan', '--json') }
    @{ Path = $script:Hooks; Args = @('trace_scan', '--json') }
    @{ Path = $script:Loader; Args = @('trace_scan', '--json') }
)

$result = $null
foreach ($attempt in $attempts) {
    if (-not (Test-Path -LiteralPath $attempt.Path)) { continue }
    $r = Invoke-GuestExe -FilePath $attempt.Path -Arguments $attempt.Args
    $text = Get-LoaderText $r
    if ($r.Code -eq 77 -or $text -match 'not implemented') { continue }
    if ($text -match 'Unknown command|unknown command') { continue }
    $result = [pscustomobject]@{ Result = $r; Text = $text }
    break
}

if (-not $result) {
    Skip-Guest 'trace_scan is not exposed by blook-loader.exe or blook-guest-hooks.exe in this build'
}

$text = $result.Text
$r = $result.Result
$found = $null

$start = $text.IndexOf('{')
$end = $text.LastIndexOf('}')
if ($start -ge 0 -and $end -gt $start) {
    try {
        $json = $text.Substring($start, $end - $start + 1) | ConvertFrom-Json
        foreach ($name in @('found', 'trace_found', 'findings')) {
            if ($json.PSObject.Properties[$name]) { $found = [int]$json.$name; break }
        }
    } catch { }
}
if ($null -eq $found -and $text -match 'found=([0-9]+)') { $found = [int]$Matches[1] }
if ($null -eq $found -and $text -match 'trace_found=([0-9]+)') { $found = [int]$Matches[1] }

if ($null -eq $found) {
    # No parsable count: fall back to the exit code (0 = clean).
    $found = if ($r.Code -eq 0) { 0 } else { 1 }
}

foreach ($line in $r.Output) { Write-GuestLine ("trace: " + $line) }
Write-GuestLine ("trace_found=" + $found)
Write-GuestLine ("trace_expect=" + $ExpectFound)

if ($found -ne $ExpectFound) {
    Fail-Guest "trace_scan found $found artifact(s), expected $ExpectFound"
}
exit 0
