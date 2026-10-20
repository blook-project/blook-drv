# Kchannel / transport negative tests.
#
# The raw kchannel transport is not reachable from PowerShell, so the
# payload-level modes delegate to blook-guest-hooks.exe (the binary that owns the
# session API).  The attach/detach modes use the loader's `ping` command, which
# exercises the same "no live peer" failure path and must never block.
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('bad-payload', 'unknown-opcode', 'no-attach', 'double-attach', 'detach-then-call')]
    [string]$Mode
)
. "$PSScriptRoot\lib.ps1"

if (-not (Test-Path -LiteralPath $script:Loader)) {
    Fail-Guest "missing $($script:Loader); cannot exercise the transport"
}

switch ($Mode) {
    'no-attach' {
        Stop-DriverQuietly
        $r = Invoke-Loader -Arguments @('ping')
        Write-GuestLine ("ping_exit=" + $r.Code)
        Write-GuestLine ("ping_seconds=" + $r.Seconds)
        if ($r.Code -eq 0) { Fail-Guest 'ping succeeded without a running driver / attached peer' }
        if ($r.Seconds -gt 15) { Fail-Guest "ping took $($r.Seconds)s, expected a fast rejection" }
        Write-GuestLine 'no_attach_rejected=yes'
        Write-GuestLine ("no_attach_error=" + ((Get-LoaderText $r) -replace "`r?`n", ' '))
        exit 0
    }
    'detach-then-call' {
        Ensure-Driver | Out-Null
        $before = Invoke-Loader -Arguments @('ping')
        Write-GuestLine ("ping_before_exit=" + $before.Code)
        if ($before.Code -ne 0) { Fail-Guest "driver was not reachable before detach: $(Get-LoaderText $before)" }
        Stop-DriverQuietly
        $after = Invoke-Loader -Arguments @('ping')
        Write-GuestLine ("ping_after_exit=" + $after.Code)
        Write-GuestLine ("ping_after_seconds=" + $after.Seconds)
        if ($after.Code -eq 0) { Fail-Guest 'ping succeeded after the driver was stopped' }
        if ($after.Seconds -gt 15) { Fail-Guest "post-detach ping took $($after.Seconds)s" }
        Write-GuestLine 'detach_then_call=rejected'
        exit 0
    }
    default {
        if (-not (Test-Path -LiteralPath $script:Hooks)) {
            Skip-Guest "missing $($script:Hooks); raw kchannel fuzzing is not available"
        }
        $r = Invoke-GuestExe -FilePath $script:Hooks -Arguments @('kchannel-fuzz', '--mode', $Mode, '--json')
        $text = Get-LoaderText $r
        foreach ($line in $r.Output) { Write-GuestLine $line }
        if ($r.Code -eq 77 -or $text -match 'not implemented') {
            Skip-Guest "blook-guest-hooks.exe does not implement kchannel-fuzz --mode $Mode in this build"
        }
        if ($r.Code -ne 0) { Fail-Guest "kchannel-fuzz $Mode exited $($r.Code)" }

        switch ($Mode) {
            'bad-payload' { Write-GuestLine 'bad_payload_rejected=yes' }
            'unknown-opcode' { Write-GuestLine 'unknown_opcode_rejected=yes' }
            'double-attach' { Write-GuestLine 'double_attach=already' }
        }
        exit 0
    }
}
