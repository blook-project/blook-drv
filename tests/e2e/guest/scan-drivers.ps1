# Enumerate loaded kernel modules with NtQuerySystemInformation.
#
# Used to verify the driver's self-hide removed blook-drv from
# SystemModuleInformation (class 11).
param(
    [switch]$ExpectHidden,
    [switch]$ExpectPresent,
    [switch]$EnsureHidden
)
. "$PSScriptRoot\lib.ps1"

if (-not ('BlookNtModules' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class BlookNtModules {
    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, out int returned);

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_MODULE {
        public IntPtr Reserved1;
        public IntPtr Reserved2;
        public IntPtr ImageBase;
        public uint ImageSize;
        public uint Flags;
        public ushort LoadOrderIndex;
        public ushort InitOrderIndex;
        public ushort LoadCount;
        public ushort OffsetToFileName;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 256)]
        public byte[] FullPathName;
    }

    public static string[] GetModules() {
        int length = 0;
        int status = NtQuerySystemInformation(11, IntPtr.Zero, 0, out length);
        if (length <= 0) length = 1024 * 1024;
        length += 64 * 1024;
        IntPtr buffer = Marshal.AllocHGlobal(length);
        try {
            status = NtQuerySystemInformation(11, buffer, length, out length);
            if (status != 0) throw new Exception("NtQuerySystemInformation failed: 0x" + status.ToString("X8"));
            int count = Marshal.ReadInt32(buffer);
            int offset = 8;
            int size = Marshal.SizeOf(typeof(SYSTEM_MODULE));
            List<string> modules = new List<string>(count);
            for (int i = 0; i < count; i++) {
                SYSTEM_MODULE module = (SYSTEM_MODULE)Marshal.PtrToStructure(
                    new IntPtr(buffer.ToInt64() + offset + i * size), typeof(SYSTEM_MODULE));
                string path = "";
                if (module.FullPathName != null) {
                    int n = 0;
                    while (n < module.FullPathName.Length && module.FullPathName[n] != 0) n++;
                    path = System.Text.Encoding.ASCII.GetString(module.FullPathName, 0, n);
                }
                modules.Add(path);
            }
            return modules.ToArray();
        } finally {
            Marshal.FreeHGlobal(buffer);
        }
    }
}
'@
}

if ($EnsureHidden) {
    Ensure-Driver | Out-Null
    Enable-Hide | Out-Null
}

try {
    $modules = [BlookNtModules]::GetModules()
} catch {
    Fail-Guest "module enumeration failed: $($_.Exception.Message)"
}

$ours = @($modules | Where-Object { $_ -match '(?i)blook' })
Write-GuestLine ("modules_total=" + $modules.Count)
foreach ($module in $ours) { Write-GuestLine ("module_found=" + $module) }

if ($ExpectHidden) {
    if ($ours.Count -gt 0) {
        Write-GuestLine 'module_visible=yes'
        Fail-Guest ("SystemModuleInformation still lists: " + ($ours -join ', '))
    }
    Write-GuestLine 'module_visible=no'
    exit 0
}

if ($ExpectPresent) {
    if ($ours.Count -eq 0) {
        Write-GuestLine 'module_visible=no'
        Fail-Guest 'blook-drv is not listed by SystemModuleInformation'
    }
    Write-GuestLine 'module_visible=yes'
    exit 0
}

Write-GuestLine ("module_visible=" + $(if ($ours.Count -gt 0) { 'yes' } else { 'no' }))
exit 0
