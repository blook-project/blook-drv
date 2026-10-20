# Nested-virtualisation report.
#
# The driver exposes an hv_info wire op (0x8019) and the guest test binary is
# expected to surface it as `hv-info --json`.  If neither binary implements the
# command yet, report 77 (skip) instead of pretending to know.
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('cpuid-vendor', 'nested-vmx')]
    [string]$Check
)
. "$PSScriptRoot\lib.ps1"

function Get-HvJson {
    $attempts = @(
        @{ Path = $script:Hooks; Args = @('hv-info', '--json') }
        @{ Path = $script:Loader; Args = @('hv-info', '--json') }
        @{ Path = $script:Hooks; Args = @('hv_info', '--json') }
        @{ Path = $script:Loader; Args = @('hv_info', '--json') }
    )
    foreach ($attempt in $attempts) {
        if (-not (Test-Path -LiteralPath $attempt.Path)) { continue }
        $r = Invoke-GuestExe -FilePath $attempt.Path -Arguments $attempt.Args
        $text = Get-LoaderText $r
        if ($r.Code -eq 77 -or $text -match 'not implemented') { continue }
        if ($text -match 'Unknown command|unknown command') { continue }
        $start = $text.IndexOf('{')
        $end = $text.LastIndexOf('}')
        if ($start -ge 0 -and $end -gt $start) {
            try {
                $json = $text.Substring($start, $end - $start + 1) | ConvertFrom-Json
                return [pscustomobject]@{ Ok = $true; Json = $json; Text = $text; Code = $r.Code }
            } catch { }
        }
        if ($r.Code -eq 0) {
            return [pscustomobject]@{ Ok = $false; Json = $null; Text = $text; Code = 0 }
        }
    }
    return [pscustomobject]@{ Ok = $false; Json = $null; Text = ''; Code = 77 }
}

$report = Get-HvJson
if ($report.Code -eq 77) {
    Skip-Guest 'hv-info is not implemented by blook-guest-hooks.exe or blook-loader.exe in this build'
}

$json = $report.Json
$text = $report.Text

switch ($Check) {
    'cpuid-vendor' {
        $vendor = ''
        if ($json) {
            $vendor = [string]$json.cpuid_40000000_vendor
            if (-not $vendor) { $vendor = [string]$json.cpuid_vendor }
        }
        if (-not $vendor -and $text -match 'cpuid_40000000_vendor=([^\s]+)') { $vendor = $Matches[1] }
        if (-not $vendor) { Fail-Guest "no CPUID vendor in hv-info output: $text" }
        Write-GuestLine ("cpuid_40000000_vendor=" + $vendor)
        if ($vendor -notmatch 'VMware') { Fail-Guest "expected VMware in CPUID 0x40000000 vendor, got '$vendor'" }
        exit 0
    }
    'nested-vmx' {
        $available = $false
        $degraded = $false
        if ($json) {
            $available = [bool]$json.nested_vmx
            $degraded = [bool]$json.degraded
        } else {
            if ($text -match 'nested_vmx=available') { $available = $true }
            if ($text -match 'degraded=yes') { $degraded = $true }
        }
        Write-GuestLine ("nested_vmx=" + $(if ($available) { 'available' } else { 'unavailable' }))
        Write-GuestLine ("degraded=" + $(if ($degraded) { 'yes' } else { 'no' }))
        if (-not $available) { Fail-Guest 'nested VMX is unavailable' }
        if ($degraded) { Fail-Guest 'nested VMX is available but degraded' }
        exit 0
    }
}

Fail-Guest "unknown check '$Check'"
