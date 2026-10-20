# Publishes the blook-drv package manifest to blook-project/blook-xmake-repo.
#
#   ./scripts/publish-registry.ps1 -Version 4.0.0 -Sha256 <sha256-of-release-zip>
#
# Runs locally with the developer's gh authentication (no org secret needed).
# The release workflow calls the same script with REPO_TOKEN when configured.
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Version,
    [Parameter(Mandatory = $true)][string]$Sha256,
    [string]$RegistryRepo = "blook-project/blook-xmake-repo",
    [string]$WorkDir = "$PSScriptRoot\..\build\registry"
)

$ErrorActionPreference = "Stop"

if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "version must be X.Y.Z, got '$Version'" }
if ($Sha256 -notmatch '^[0-9a-fA-F]{64}$') { throw "sha256 must be 64 hex chars" }

$root = Resolve-Path "$PSScriptRoot\.."
$package = "blook-drv"
$shard = "b"

Write-Host "registry: $RegistryRepo  package: $package $Version"

if (Test-Path $WorkDir) { Remove-Item $WorkDir -Recurse -Force }
New-Item -ItemType Directory -Force $WorkDir | Out-Null

$env:GH_TOKEN = if ($env:REPO_TOKEN) { $env:REPO_TOKEN } else { $env:GH_TOKEN }
gh repo clone $RegistryRepo $WorkDir -- --depth 1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "gh repo clone $RegistryRepo failed" }

$pkgDir = Join-Path $WorkDir "packages\$shard\$package"
$versionsDir = Join-Path $pkgDir "versions"
New-Item -ItemType Directory -Force $versionsDir | Out-Null

$manifest = Get-Content (Join-Path $root "xmake-package\xmake.lua") -Raw
$manifest = $manifest.Replace("<VERSION>", $Version).Replace("<SHA256>", $Sha256.ToLower())
Set-Content -NoNewline -Encoding utf8 (Join-Path $pkgDir "xmake.lua") $manifest

# xmake looks for versions/<version>.lua next to the package definition.
Set-Content -NoNewline -Encoding utf8 (Join-Path $versionsDir "$Version.lua") @"
-- $package $Version
package("$package")
    set_description("blook-drv: hardened VT-x hypervisor driver and user-mode EPT hook SDK")
    add_versions("$Version", "$($Sha256.ToLower())")
package_end()
"@

Push-Location $WorkDir
try {
    git add "packages/$shard/$package"
    git -c user.name="MicroBlock" -c user.email="66859419+std-microblock@users.noreply.github.com" `
        commit -m "registry: blook-drv $Version"
    git push
    if ($LASTEXITCODE -ne 0) { throw "git push failed" }
} finally {
    Pop-Location
}
Write-Host "published $package $Version to $RegistryRepo"
