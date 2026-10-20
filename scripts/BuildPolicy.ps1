# Pure lifecycle planning: no services, processes, registry or filesystem writes.
function Get-BlookBuildPlan {
    param(
        [bool]$Running,
        [bool]$SameImage,
        [bool]$DeployRequested,
        [bool]$StartRequested,
        [bool]$StopRequested
    )
    if ($Running -and -not $StopRequested -and ($SameImage -or $DeployRequested -or $StartRequested)) {
        throw "Refusing to stop a running driver implicitly. Build offline with -BuildDir build/offline, or explicitly use -StopRunningDriver. An older loaded driver still uses its OLD unload code."
    }
    [pscustomobject]@{
        Stop = $Running -and $StopRequested
        Deploy = $DeployRequested -or $StartRequested
        Start = $StartRequested
    }
}
function ConvertFrom-BlookServiceImagePath([string]$ImagePath) {
    if ([string]::IsNullOrWhiteSpace($ImagePath)) { return $null }
    $path = [Environment]::ExpandEnvironmentVariables($ImagePath.Trim('"'))
    if ($path.StartsWith('\??\')) { $path = $path.Substring(4) }
    if ($path.StartsWith('\SystemRoot\', [StringComparison]::OrdinalIgnoreCase)) {
        $path = Join-Path $env:SystemRoot $path.Substring(12)
    }
    if (-not [IO.Path]::IsPathRooted($path)) { return $null }
    try { return [IO.Path]::GetFullPath($path) } catch { return $null }
}
