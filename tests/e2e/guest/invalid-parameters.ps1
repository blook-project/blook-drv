# A table of malformed loader requests.  Every one must be rejected quickly and
# no request may hang or crash the guest.  This is the user-mode half of the
# invalid-input category; the payload-level cases live in kchannel-fuzz.ps1.
. "$PSScriptRoot\lib.ps1"

if (-not (Test-Path -LiteralPath $script:Loader)) {
    Fail-Guest "missing $($script:Loader); cannot exercise the loader parser"
}

$cases = @(
    @{ Name = 'unknown-command'; Args = @('frobnicate') },
    @{ Name = 'help-extra'; Args = @('help', 'extra') },
    @{ Name = 'hook-missing-args'; Args = @('hook') },
    @{ Name = 'hook-bad-owner'; Args = @('hook', 'bogus', '401000', '90') },
    @{ Name = 'hook-zero-address'; Args = @('hook', 'self', '0', '90') },
    @{ Name = 'hook-odd-bytes'; Args = @('hook', 'self', '401000', 'ABC') },
    @{ Name = 'hook-empty-bytes'; Args = @('hook', 'self', '401000', '') },
    @{ Name = 'hook-oversize-bytes'; Args = @('hook', 'self', '401000', ('90' * 65)) },
    @{ Name = 'page-zero'; Args = @('page', 'self', '0') },
    @{ Name = 'page-bad-owner'; Args = @('page', 'bogus', '1234') },
    @{ Name = 'pin-zero'; Args = @('pin', 'tool', '0') },
    @{ Name = 'pin-bad-role'; Args = @('pin', 'user', '1234') },
    @{ Name = 'unpin-zero'; Args = @('unpin', '0') },
    @{ Name = 'scrub-zero'; Args = @('scrub', '0') },
    @{ Name = 'feature-unknown'; Args = @('feature', 'not.a.feature', 'on') },
    @{ Name = 'feature-bad-mode'; Args = @('feature', 'nt.get_context', 'maybe') },
    @{ Name = 'hide-bad-mode'; Args = @('hide', 'maybe') },
    @{ Name = 'hide-bad-prefix'; Args = @('hide', 'windows', 'maybe') },
    @{ Name = 'version-extra'; Args = @('version', 'extra') },
    @{ Name = 'start-extra'; Args = @('start', 'extra') },
    @{ Name = 'install-empty'; Args = @('install', '') },
    @{ Name = 'config-path-missing'; Args = @('config-path', 'C:\blook-e2e\definitely-not-there.ini') }
)

$rejected = 0
$bad = @()
foreach ($case in $cases) {
    $r = Invoke-Loader -Arguments $case.Args
    $ok = ($r.Code -ne 0 -and $r.Seconds -le 15)
    Write-GuestLine ("case=" + $case.Name + " exit=" + $r.Code + " seconds=" + $r.Seconds + " ok=" + $(if ($ok) { 'yes' } else { 'no' }))
    if ($ok) {
        $rejected++
    } else {
        $bad += $case.Name
        foreach ($line in $r.Output) { Write-GuestLine ("  detail: " + $line) }
    }
}

Write-GuestLine ("rejected=" + $rejected + "/" + $cases.Count)
if ($bad.Count -gt 0) {
    Fail-Guest ("not rejected cleanly: " + ($bad -join ', '))
}
Write-GuestLine 'all_rejected=yes'
exit 0
