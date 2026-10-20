# Anti-detection baseline / with-hypervisor comparison.
#
# The full VMAware-style probe lives in blook-antidetect.exe.  Its JSON output is
# expected to contain a `checks` array (name/pass) or a `fails` array.  This
# helper is deliberately tolerant of both shapes and of the current 77 stub.
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('baseline', 'with-hv')]
    [string]$Mode,
    [string]$BaselinePath = 'C:\blook-e2e\baseline.json'
)
. "$PSScriptRoot\lib.ps1"

if (-not (Test-Path -LiteralPath $script:Antidetect)) {
    Skip-Guest "missing $($script:Antidetect)"
}

function Get-FailNames {
    param($Json, [string]$Text)
    $names = @()
    if ($Json) {
        if ($Json.PSObject.Properties['fails']) { $names += @($Json.fails | ForEach-Object { [string]$_ }) }
        if ($Json.PSObject.Properties['checks']) {
            foreach ($check in @($Json.checks)) {
                $pass = [bool]$check.pass
                if (-not $pass) { $names += [string]$check.name }
            }
        }
        if ($Json.PSObject.Properties['failed']) {
            if ([int]$Json.failed -gt 0 -and $names.Count -eq 0) { $names += "failed=$($Json.failed)" }
        }
    }
    if ($names.Count -eq 0 -and $Text -match 'fails?=([0-9]+)') {
        $count = [int]$Matches[1]
        if ($count -gt 0) { $names += "fails=$count" }
    }
    return @($names | Where-Object { $_ } | Sort-Object -Unique)
}

function Read-JsonText {
    param([string]$Text)
    $start = $Text.IndexOf('{')
    $end = $Text.LastIndexOf('}')
    if ($start -lt 0 -or $end -le $start) { return $null }
    try { return ($Text.Substring($start, $end - $start + 1) | ConvertFrom-Json) } catch { return $null }
}

switch ($Mode) {
    'baseline' {
        Stop-DriverQuietly
        $r = Invoke-GuestExe -FilePath $script:Antidetect -Arguments @('--json')
        if ($r.Code -eq 77) { Skip-Guest 'blook-antidetect.exe is a stub in this build' }
        if ($r.Code -notin @(0, 1)) { Fail-Guest "antidetect baseline exited $($r.Code): $(Get-LoaderText $r)" }
        $text = Get-LoaderText $r
        $json = Read-JsonText $text
        $fails = Get-FailNames -Json $json -Text $text
        Set-Content -LiteralPath $BaselinePath -Value $text -Encoding UTF8
        Write-GuestLine 'baseline_saved=yes'
        Write-GuestLine ("baseline_fails=" + $fails.Count)
        foreach ($name in $fails) { Write-GuestLine ("baseline_fail=" + $name) }
        exit 0
    }
    'with-hv' {
        Ensure-Driver | Out-Null
        Enable-Hide | Out-Null
        if (-not (Test-Path -LiteralPath $BaselinePath)) { Fail-Guest "baseline missing: $BaselinePath (baseline case did not run)" }

        $r = Invoke-GuestExe -FilePath $script:Antidetect -Arguments @('--json', '--baseline', $BaselinePath)
        if ($r.Code -eq 77) { Skip-Guest 'blook-antidetect.exe is a stub in this build' }
        if ($r.Code -notin @(0, 1)) { Fail-Guest "antidetect with-hv exited $($r.Code): $(Get-LoaderText $r)" }
        $text = Get-LoaderText $r
        $json = Read-JsonText $text

        $newFails = @()
        if ($json -and $json.PSObject.Properties['new_fails']) {
            $rawNewFails = $json.new_fails
            if ($rawNewFails -is [int] -or $rawNewFails -is [long]) {
                if ([int]$rawNewFails -gt 0) { $newFails = @("new_fails=$rawNewFails") }
            } else {
                $newFails = @($rawNewFails | ForEach-Object { [string]$_ })
            }
        } else {
            $newFails = Get-FailNames -Json $json -Text $text
            # Without an explicit baseline comparison, report all FAILs; the
            # acceptance gate requires zero new FAILs.
        }
        Write-GuestLine ("new_fails=" + $newFails.Count)
        foreach ($name in $newFails) { Write-GuestLine ("new_fail=" + $name) }
        if ($newFails.Count -gt 0) { Fail-Guest "anti-detection added $($newFails.Count) FAIL(s)" }
        Write-GuestLine 'compare=ok'
        exit 0
    }
}

Fail-Guest "unknown mode '$Mode'"
