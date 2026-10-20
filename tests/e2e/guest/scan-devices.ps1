# Device-object and symbolic-link scan.
#
# Checks both `CreateFile \\.\BlookDrv` and a raw \Device directory enumeration,
# so the two common discovery paths are covered independently.
param(
    [switch]$ExpectHidden,
    [switch]$ExpectPresent,
    [switch]$EnsureHidden
)
. "$PSScriptRoot\lib.ps1"

if (-not ('BlookDeviceScan' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class BlookDeviceScan {
    private const uint OPEN_EXISTING = 3;
    private static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(string name, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct OBJECT_ATTRIBUTES {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct OBJECT_DIRECTORY_INFORMATION {
        public UNICODE_STRING Name;
        public UNICODE_STRING TypeName;
    }

    [DllImport("ntdll.dll")]
    private static extern int NtOpenDirectoryObject(out IntPtr handle, uint access,
        ref OBJECT_ATTRIBUTES attributes);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryDirectoryObject(IntPtr handle, IntPtr buffer,
        int length, bool returnSingleEntry, bool restartScan, ref int context,
        out int returnedLength);

    public static bool DeviceExists(string name) {
        string[] paths = new string[] {
            @"\\.\" + name,
            @"\\.\GLOBALROOT\Device\" + name
        };
        foreach (string path in paths) {
            IntPtr handle = CreateFileW(path, 0, 0, IntPtr.Zero, OPEN_EXISTING, 0, IntPtr.Zero);
            if (handle != INVALID_HANDLE_VALUE && handle != IntPtr.Zero) {
                CloseHandle(handle);
                return true;
            }
        }
        return false;
    }

    public static string[] ListDevices() {
        List<string> names = new List<string>();
        string directory = @"\Device";
        IntPtr nameBuffer = Marshal.StringToHGlobalUni(directory);
        IntPtr unicodeBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
        IntPtr entryBuffer = IntPtr.Zero;
        IntPtr handle = IntPtr.Zero;
        try {
            UNICODE_STRING unicode = new UNICODE_STRING();
            unicode.Length = (ushort)(directory.Length * 2);
            unicode.MaximumLength = (ushort)(directory.Length * 2 + 2);
            unicode.Buffer = nameBuffer;
            Marshal.StructureToPtr(unicode, unicodeBuffer, false);

            OBJECT_ATTRIBUTES attributes = new OBJECT_ATTRIBUTES();
            attributes.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
            attributes.ObjectName = unicodeBuffer;
            attributes.Attributes = 0x40; // OBJ_CASE_INSENSITIVE
            int status = NtOpenDirectoryObject(out handle, 0x0001, ref attributes);
            if (status != 0) return names.ToArray();

            entryBuffer = Marshal.AllocHGlobal(2048);
            int context = 0;
            bool first = true;
            while (true) {
                int returned = 0;
                status = NtQueryDirectoryObject(handle, entryBuffer, 2048, true, first,
                    ref context, out returned);
                if (status != 0 && status != unchecked((int)0x80000005)) break;
                OBJECT_DIRECTORY_INFORMATION info = (OBJECT_DIRECTORY_INFORMATION)
                    Marshal.PtrToStructure(entryBuffer, typeof(OBJECT_DIRECTORY_INFORMATION));
                if (info.Name.Buffer != IntPtr.Zero) {
                    names.Add(Marshal.PtrToStringUni(info.Name.Buffer, info.Name.Length / 2));
                }
                first = false;
                if (names.Count > 65536) break;
            }
        } finally {
            if (entryBuffer != IntPtr.Zero) Marshal.FreeHGlobal(entryBuffer);
            if (handle != IntPtr.Zero) CloseHandle(handle);
            Marshal.FreeHGlobal(unicodeBuffer);
            Marshal.FreeHGlobal(nameBuffer);
        }
        return names.ToArray();
    }
}
'@
}

if ($EnsureHidden) {
    Ensure-Driver | Out-Null
    Enable-Hide | Out-Null
}

$exists = $false
try { $exists = [BlookDeviceScan]::DeviceExists('BlookDrv') } catch { }
$listed = $false
$devices = @()
try {
    $devices = [BlookDeviceScan]::ListDevices()
    $listed = @($devices | Where-Object { $_ -match '(?i)^BlookDrv$' }).Count -gt 0
} catch {
    Write-GuestLine ("device_list_error=" + $_.Exception.Message)
}

Write-GuestLine ("devices_total=" + $devices.Count)
Write-GuestLine ("device_createfile=" + $(if ($exists) { 'yes' } else { 'no' }))
Write-GuestLine ("device_listed=" + $(if ($listed) { 'yes' } else { 'no' }))

if ($ExpectHidden) {
    if ($exists -or $listed) {
        Write-GuestLine 'device_visible=yes'
        Fail-Guest ("device is discoverable (createfile=$exists listed=$listed)")
    }
    Write-GuestLine 'device_visible=no'
    exit 0
}

if ($ExpectPresent) {
    if (-not ($exists -or $listed)) {
        Write-GuestLine 'device_visible=no'
        Fail-Guest 'device is not discoverable'
    }
    Write-GuestLine 'device_visible=yes'
    exit 0
}

Write-GuestLine ("device_visible=" + $(if ($exists -or $listed) { 'yes' } else { 'no' }))
exit 0
