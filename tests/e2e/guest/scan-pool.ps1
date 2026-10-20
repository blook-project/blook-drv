# Pool-tag scan (poolmon-style) via SystemPoolTagInformation (class 22).
#
# The driver is expected to use the benign `MmSt` tag for every allocation, so a
# project-specific tag (bloK/EptH/...) is a detection.  `MmSt` itself is common
# on a real system and is intentionally not forbidden.
param(
    [switch]$ExpectHidden,
    [switch]$EnsureHidden,
    [string[]]$ForbiddenTags = @('blok', 'bloK', 'BlkD', 'bloD', 'EptH', 'HvBk', 'Bloo')
)
. "$PSScriptRoot\lib.ps1"

if (-not ('BlookPoolTags' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class BlookPoolTags {
    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, out int returned);

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_POOLTAG {
        public uint Tag;
        public uint PagedAllocs;
        public uint PagedFrees;
        public UIntPtr PagedUsed;
        public uint NonPagedAllocs;
        public uint NonPagedFrees;
        public UIntPtr NonPagedUsed;
    }

    public struct TagInfo {
        public string Tag;
        public ulong PagedUsed;
        public ulong NonPagedUsed;
    }

    public static TagInfo[] Query() {
        int length = 0;
        NtQuerySystemInformation(22, IntPtr.Zero, 0, out length);
        int size = Math.Max(length + 64 * 1024, 1024 * 1024);
        IntPtr buffer = IntPtr.Zero;
        int status = unchecked((int)0xC0000004);
        for (int attempt = 0; attempt < 10; attempt++) {
            buffer = Marshal.AllocHGlobal(size);
            status = NtQuerySystemInformation(22, buffer, size, out length);
            if (status == 0) break;
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
            size *= 2;
        }
        if (buffer == IntPtr.Zero || status != 0)
            throw new Exception("NtQuerySystemInformation(22) failed: 0x" + status.ToString("X8"));
        try {
            int count = Marshal.ReadInt32(buffer);
            int offset = 8;
            int entrySize = Marshal.SizeOf(typeof(SYSTEM_POOLTAG));
            List<TagInfo> tags = new List<TagInfo>(count);
            for (int i = 0; i < count; i++) {
                SYSTEM_POOLTAG raw = (SYSTEM_POOLTAG)Marshal.PtrToStructure(
                    new IntPtr(buffer.ToInt64() + offset + i * entrySize), typeof(SYSTEM_POOLTAG));
                uint value = raw.Tag;
                char[] chars = new char[4];
                chars[0] = (char)(value & 0xFF);
                chars[1] = (char)((value >> 8) & 0xFF);
                chars[2] = (char)((value >> 16) & 0xFF);
                chars[3] = (char)((value >> 24) & 0xFF);
                TagInfo info = new TagInfo();
                info.Tag = new string(chars);
                info.PagedUsed = (ulong)raw.PagedUsed;
                info.NonPagedUsed = (ulong)raw.NonPagedUsed;
                tags.Add(info);
            }
            return tags.ToArray();
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
    $tags = [BlookPoolTags]::Query()
} catch {
    Fail-Guest "pool tag query failed: $($_.Exception.Message)"
}

Write-GuestLine ("pool_tags_total=" + $tags.Count)
$found = @()
foreach ($tag in $tags) {
    foreach ($forbidden in $ForbiddenTags) {
        if ([string]::Equals($tag.Tag, $forbidden, [StringComparison]::OrdinalIgnoreCase)) {
            $found += $tag
            break
        }
    }
}
$found = @($found | Sort-Object Tag -Unique)
foreach ($tag in $found) {
    Write-GuestLine ("project_tag=" + $tag.Tag + " paged=" + $tag.PagedUsed + " nonpaged=" + $tag.NonPagedUsed)
}
Write-GuestLine ("project_tags_found=" + $found.Count)

foreach ($tag in @($tags | Where-Object { $_.Tag -eq 'MmSt' })) {
    Write-GuestLine ("benign_tag=MmSt paged=" + $tag.PagedUsed + " nonpaged=" + $tag.NonPagedUsed)
}

if ($ExpectHidden -and $found.Count -gt 0) {
    Fail-Guest ("project-specific pool tag(s) visible: " + (($found | ForEach-Object { $_.Tag }) -join ', '))
}
exit 0
