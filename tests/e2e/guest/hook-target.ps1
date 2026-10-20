# Tiny target process used by the hook tests.
#
# The C# method below is JIT-compiled once and its native entry point is written
# to a JSON file, so the orchestrator can hand the (pid, address) pair to
# blook-guest-hooks.exe.  The loop keeps the method hot while install/remove
# happens and logs the return value; after a detour replaces the first bytes the
# log shows 0x1337 instead of the original 4.
param(
    [int]$DurationSeconds = 60,
    [string]$Output = 'C:\blook-e2e\hook-target.json',
    [string]$LogPath = 'C:\blook-e2e\hook-target.log',
    [int]$IntervalMs = 25
)

$ErrorActionPreference = 'Stop'

if (-not ('BlookHookTarget' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.CompilerServices;
public static class BlookHookTarget {
    [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
    public static int Target(int x) {
        return (x * 3) + 1;
    }
}
'@
}

# Force JIT before reading the function pointer.
[void][BlookHookTarget]::Target(1)
$method = [BlookHookTarget].GetMethod('Target', [Reflection.BindingFlags]'Public,Static')
if (-not $method) { throw 'could not find BlookHookTarget.Target' }
$address = $method.MethodHandle.GetFunctionPointer().ToInt64()

$info = [ordered]@{
    pid      = $PID
    address  = ('0x{0:X}' -f $address)
    log      = $LogPath
    original = [BlookHookTarget]::Target(1)
    started  = [DateTime]::UtcNow.ToString('o')
}
[IO.File]::WriteAllText($Output, ($info | ConvertTo-Json -Compress), [Text.UTF8Encoding]::new($false))

$sw = [Diagnostics.Stopwatch]::StartNew()
$iteration = 0
while ($sw.Elapsed.TotalSeconds -lt $DurationSeconds) {
    $iteration++
    $value = [BlookHookTarget]::Target(1)
    $line = ('{0} iteration={1} value={2}' -f [DateTime]::UtcNow.ToString('o'), $iteration, $value)
    [IO.File]::AppendAllText($LogPath, $line + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    Start-Sleep -Milliseconds $IntervalMs
}
exit 0
