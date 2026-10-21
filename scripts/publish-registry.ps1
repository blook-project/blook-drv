# Publishes the blook-drv package manifest to blook-project/blook-xmake-repo.
#
#   ./scripts/publish-registry.ps1 -Version 4.0.0 -Sha256 <sha256-of-release-zip>
#   ./scripts/publish-registry.ps1 -Version 4.0.0 -DryRun
#
# Runs locally with the developer's gh authentication (no org secret needed).
# The release workflow calls the same script with REPO_TOKEN when configured.
[CmdletBinding()]
param(
    [string]$Package = "blook-drv",
    [Parameter(Mandatory = $true)][string]$Version,
    [string]$Sha256,
    [string]$ManifestFile,
    [string]$RegistryRepo = "blook-project/blook-xmake-repo",
    [string]$WorkDir = "$PSScriptRoot\..\build\registry",
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw "version must be X.Y.Z, got '$Version'" }

$root = Resolve-Path "$PSScriptRoot\.."
$package = $Package
$shard = $package.Substring(0, 1).ToLowerInvariant()
$zipName = "$package-$Version-windows-x64.zip"
$assetUrl = "https://github.com/blook-project/$package/releases/download/v$Version/$zipName"

if (-not $Sha256) {
    # No hash given: read the one published next to the release asset.
    $shaAsset = "$assetUrl.sha256"
    try {
        $text = (Invoke-WebRequest -UseBasicParsing -Uri $shaAsset).Content
        $Sha256 = ($text -split '\s+')[0]
    } catch {
        throw "no -Sha256 given and $shaAsset is not reachable: $($_.Exception.Message)"
    }
}
if ($Sha256 -notmatch '^[0-9a-fA-F]{64}$') { throw "sha256 must be 64 hex chars" }
$Sha256 = $Sha256.ToLowerInvariant()

Write-Host "registry: $RegistryRepo  package: $package $Version  sha256: $Sha256"

$manifestPath = if ($ManifestFile) { $ManifestFile } else { Join-Path $root "xmake-package\xmake.lua" }
$manifest = Get-Content -LiteralPath $manifestPath -Raw
$manifest = $manifest.Replace("<VERSION>", $Version).Replace("<SHA256>", $Sha256)
$packageLua = @"
package("$package")
    set_description("blook-drv: hardened VT-x hypervisor driver and user-mode EPT hook SDK")
    set_kind("library", { headeronly = true })

    add_urls("$assetUrl")
    add_versions("$Version", "$Sha256")

    on_install("windows", function (package)
        os.cp("include", package:installdir())
        os.cp("sdk", package:installdir())
        os.cp("blook-drv.sys", package:installdir("bin"))
    end)
package_end()
"@
$versionLua = @"
-- $package $Version
package("$package")
    set_description("blook-drv: hardened VT-x hypervisor driver and user-mode EPT hook SDK")
    add_versions("$Version", "$Sha256")
package_end()
"@

if ($DryRun) {
    Write-Host "--- packages/$shard/$package/xmake.lua"
    Write-Host $packageLua
    Write-Host "--- packages/$shard/$package/versions/$Version.lua"
    Write-Host $versionLua
    Write-Host "dry run: nothing was cloned or pushed"
    exit 0
}

if (Test-Path $WorkDir) { Remove-Item $WorkDir -Recurse -Force }
New-Item -ItemType Directory -Force $WorkDir | Out-Null
$env:GH_TOKEN = if ($env:REPO_TOKEN) { $env:REPO_TOKEN } else { $env:GH_TOKEN }
gh repo clone $RegistryRepo $WorkDir -- --depth 1 | Out-Null
if ($LASTEXITCODE -ne 0) { throw "gh repo clone $RegistryRepo failed" }

$pkgDir = Join-Path $WorkDir "packages\$shard\$package"
$versionsDir = Join-Path $pkgDir "versions"
New-Item -ItemType Directory -Force $versionsDir | Out-Null
Set-Content -NoNewline -Encoding utf8 (Join-Path $pkgDir "xmake.lua") $packageLua
Set-Content -NoNewline -Encoding utf8 (Join-Path $versionsDir "$Version.lua") $versionLua

Push-Location $WorkDir
try {
    git add "packages/$shard/$package"
    git -c user.name="MicroBlock" -c user.email="66859419+std-microblock@users.noreply.github.com" `
        commit -m "registry: $package $Version"
    git push
    if ($LASTEXITCODE -ne 0) { throw "git push failed" }
} finally {
    Pop-Location
}
Write-Host "published $package $Version to $RegistryRepo"