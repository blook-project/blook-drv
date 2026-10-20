# Read the debug registers of a target thread with GetThreadContext.
#
# Used by the hwbreak sanitisation cases.  A target process is spawned (and can
# be pinned as a `target` role) so the driver's NtGetContextThread hiding path is
# exercised exactly the way a debugger-aware scanner would exercise it.
param(
    [int]$ProcessId = 0,
    [switch]$SpawnTarget,
    [switch]$PinAsTarget,
    [int]$ScanLoop = 1,
    [switch]$ExpectZero,
    [switch]$EnsureHidden
)
. "$PSScriptRoot\lib.ps1"

if (-not ('BlookDrContext' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
public static class BlookDrContext {
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenThread(uint access, bool inherit, uint threadId);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint SuspendThread(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr handle);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetThreadContext(IntPtr handle, IntPtr context);

    private const uint THREAD_SUSPEND_RESUME = 0x0002;
    private const uint THREAD_GET_CONTEXT = 0x0008;
    private const uint THREAD_QUERY_INFORMATION = 0x0040;
    private const int CONTEXT_SIZE = 1232;
    private const int CONTEXT_FLAGS_OFFSET = 48;
    private const int DR0_OFFSET = 72;
    private const uint CONTEXT_AMD64 = 0x00100000;
    private const uint CONTEXT_DEBUG_REGISTERS = 0x00000010;

    public static ulong[] Query(int pid) {
        Process process = Process.GetProcessById(pid);
        if (process.Threads.Count == 0) throw new Exception("process has no threads");
        uint tid = (uint)process.Threads[0].Id;
        IntPtr thread = OpenThread(
            THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
            false, tid);
        if (thread == IntPtr.Zero)
            throw new Exception("OpenThread failed: " + Marshal.GetLastWin32Error());
        IntPtr context = Marshal.AllocHGlobal(CONTEXT_SIZE);
        try {
            byte[] zero = new byte[CONTEXT_SIZE];
            Marshal.Copy(zero, 0, context, CONTEXT_SIZE);
            Marshal.WriteInt32(context, CONTEXT_FLAGS_OFFSET,
                (int)(CONTEXT_AMD64 | CONTEXT_DEBUG_REGISTERS));
            uint suspended = SuspendThread(thread);
            if (suspended == 0xFFFFFFFF)
                throw new Exception("SuspendThread failed: " + Marshal.GetLastWin32Error());
            try {
                if (!GetThreadContext(thread, context))
                    throw new Exception("GetThreadContext failed: " + Marshal.GetLastWin32Error());
            } finally {
                ResumeThread(thread);
            }
            ulong[] drs = new ulong[6];
            for (int i = 0; i < drs.Length; i++)
                drs[i] = (ulong)Marshal.ReadInt64(context, DR0_OFFSET + i * 8);
            return drs;
        } finally {
            Marshal.FreeHGlobal(context);
            CloseHandle(thread);
        }
    }
}
'@
}

$targetProcess = $null
$targetPid = $ProcessId
$targetInfo = $null

try {
    if ($SpawnTarget) {
        $stamp = Get-Date -Format 'yyyyMMddHHmmssfff'
        $jsonPath = Join-Path $script:Root ("hook-target-$stamp.json")
        $logPath = Join-Path $script:Root ("hook-target-$stamp.log")
        $targetArgs = @(
            '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', (Join-Path $script:Root 'hook-target.ps1'),
            '-DurationSeconds', '30', '-Output', $jsonPath, '-LogPath', $logPath
        )
        $targetProcess = Start-Process -FilePath 'powershell.exe' -ArgumentList $targetArgs -PassThru -WindowStyle Hidden
        $targetInfo = Wait-JsonFile -Path $jsonPath -TimeoutSeconds 30
        if (-not $targetInfo) { Fail-Guest "target did not produce $jsonPath" }
        $targetPid = [int]$targetInfo.pid
        Write-GuestLine ("target_pid=" + $targetPid)
        Write-GuestLine ("target_address=" + $targetInfo.address)
    }

    if ($targetPid -le 0) {
        Fail-Guest '-ProcessId is required when -SpawnTarget is not used (querying the current thread would deadlock)'
    }

    if ($EnsureHidden) {
        Ensure-Driver | Out-Null
        Enable-Hide | Out-Null
    }

    if ($PinAsTarget) {
        $pin = Invoke-Loader -Arguments @('pin', 'target', [string]$targetPid)
        if ($pin.Code -ne 0) {
            Fail-Guest ("pin target $targetPid failed ({0}): {1}" -f $pin.Code, (Get-LoaderText $pin))
        }
        Start-Sleep -Milliseconds 400
    }

    $nonZero = $false
    for ($i = 1; $i -le $ScanLoop; $i++) {
        $drs = [BlookDrContext]::Query($targetPid)
        $line = ("query={0} pid={1} dr0=0x{2:X} dr1=0x{3:X} dr2=0x{4:X} dr3=0x{5:X} dr6=0x{6:X} dr7=0x{7:X}" -f `
                $i, $targetPid, $drs[0], $drs[1], $drs[2], $drs[3], $drs[4], $drs[5])
        Write-GuestLine $line
        foreach ($dr in $drs) {
            if ($dr -ne 0) { $nonZero = $true }
        }
        if ($ExpectedZero -and $nonZero) { break }
    }

    if ($ExpectedZero) {
        if ($nonZero) {
            Write-GuestLine 'dr_sanitised=no'
            Fail-Guest 'GetThreadContext exposed a non-zero debug register for the pinned target'
        }
        Write-GuestLine 'dr_sanitised=yes'
    }

    if ($ScanLoop -gt 1) {
        Write-GuestLine 'scan_clean=yes'
    }
    exit 0
} finally {
    if ($targetProcess -and -not $targetProcess.HasExited) {
        try { Stop-Process -Id $targetProcess.Id -Force -ErrorAction SilentlyContinue } catch { }
    }
}
