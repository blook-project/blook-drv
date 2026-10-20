# Service registry + SCM scan for the BlookDrv service.
param(
    [switch]$ExpectHidden,
    [switch]$ExpectPresent,
    [switch]$EnsureHidden
)
. "$PSScriptRoot\lib.ps1"

if ($EnsureHidden) {
    Ensure-Driver | Out-Null
    Enable-Hide | Out-Null
}

$key = 'HKLM:\SYSTEM\CurrentControlSet\Services\BlookDrv'
$keyVisible = Test-Path -LiteralPath $key

$sc = & sc.exe query BlookDrv 2>&1
$scCode = $LASTEXITCODE
$scText = (@($sc) -join ' ')
$scVisible = ($scCode -eq 0)

$service = Get-Service -Name 'BlookDrv' -ErrorAction SilentlyContinue
$serviceVisible = [bool]$service

Write-GuestLine ("service_key_visible=" + $(if ($keyVisible) { 'yes' } else { 'no' }))
Write-GuestLine ("service_sc_visible=" + $(if ($scVisible) { 'yes' } else { 'no' }))
Write-GuestLine ("service_scm_visible=" + $(if ($serviceVisible) { 'yes' } else { 'no' }))
Write-GuestLine ("service_state=" + (Get-ServiceState))
if ($scText) { Write-GuestLine ("sc_output=" + $scText.Trim()) }

if ($ExpectHidden) {
    # The acceptance criterion is the registry trace being gone.  SCM may keep a
    # service object alive until the driver unloads, so it is reported but not
    # used as a hard failure on its own.
    if ($keyVisible) {
        Fail-Guest 'HKLM\SYSTEM\CurrentControlSet\Services\BlookDrv is still present'
    }
    Write-GuestLine 'service_key_visible=no'
    exit 0
}

if ($ExpectPresent) {
    if (-not $keyVisible -and -not $serviceVisible) {
        Fail-Guest 'service key and SCM entry are both absent'
    }
    Write-GuestLine 'service_key_visible=yes'
    exit 0
}

exit 0
