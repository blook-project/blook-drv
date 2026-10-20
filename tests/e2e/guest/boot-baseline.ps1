# Boot/smoke baseline: is this the expected Windows 11 test guest?
. "$PSScriptRoot\lib.ps1"

if (-not [Environment]::Is64BitOperatingSystem) { Fail-Guest 'guest is not 64-bit' }

$os = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
$caption = if ($os) { [string]$os.Caption } else { [string]$env:OS }
Write-GuestLine ("os=" + $caption.Trim())
Write-GuestLine 'arch=x64'

# testsigning is required for the locally signed kernel driver.
$bcd = & bcdedit.exe /enum '{current}' 2>&1
$bcdText = (@($bcd) -join "`n")
if ($bcdText -match '(?im)^\s*testsigning\s+Yes\s*$') {
    Write-GuestLine 'testsigning=Yes'
} else {
    Write-GuestLine 'testsigning=No'
    Fail-Guest 'testsigning is not enabled in the current boot entry'
}

if (-not (Test-Path -LiteralPath $script:Loader)) { Fail-Guest "missing $($script:Loader)" }
$help = Invoke-Loader -Arguments @('--help')
if ($help.Code -ne 0) { Fail-Guest ("blook-loader --help failed: {0}" -f (Get-LoaderText $help)) }
Write-GuestLine 'loader=ok'

if (-not (Test-Path -LiteralPath $script:Driver)) { Fail-Guest "missing $($script:Driver)" }
Write-GuestLine 'driver=present'

$admin = if (Test-GuestAdmin) { 'yes' } else { 'no' }
Write-GuestLine ("admin=" + $admin)

exit 0
