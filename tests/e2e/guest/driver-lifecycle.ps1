# Driver service lifecycle used by the smoke/hv-lifecycle cases.
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('install', 'start-solo', 'start-nested', 'stop', 'restart-10x', 'start-stop-50x')]
    [string]$Action
)
. "$PSScriptRoot\lib.ps1"

if (-not (Test-GuestAdmin)) { Fail-Guest 'driver lifecycle requires an elevated guest process' }

function Install-Fresh {
    Stop-DriverQuietly
    $null = Invoke-Loader -Arguments @('uninstall')
    Start-Sleep -Milliseconds 500
    $install = Invoke-Loader -Arguments @('install', $script:Driver)
    if ($install.Code -ne 0) {
        Fail-Guest ("install failed ({0}): {1}" -f $install.Code, (Get-LoaderText $install))
    }
    Start-Sleep -Milliseconds 500
    if (-not (Get-Service -Name 'BlookDrv' -ErrorAction SilentlyContinue)) {
        Fail-Guest 'service is missing after install'
    }
    Write-GuestLine 'installed=ok'
}

function Assert-Running {
    $state = Get-ServiceState
    if ($state -ne 'Running') { Fail-Guest "expected Running, got $state" }
    Write-GuestLine 'state=running'
}

function Assert-Stopped {
    $state = Get-ServiceState
    if ($state -ne 'Stopped') { Fail-Guest "expected Stopped, got $state" }
    Write-GuestLine 'state=stopped'
}

switch ($Action) {
    'install' {
        Install-Fresh
    }
    'start-solo' {
        Ensure-Driver | Out-Null
        Assert-Running
        $query = Invoke-Loader -Arguments @('status')
        foreach ($line in $query.Output) { Write-GuestLine ("status: " + $line) }
    }
    'start-nested' {
        Ensure-Driver | Out-Null
        Assert-Running
        Write-GuestLine 'nested=started'
    }
    'stop' {
        $service = Get-Service -Name 'BlookDrv' -ErrorAction SilentlyContinue
        if ($service) {
            $stop = Invoke-Loader -Arguments @('stop')
            if ($stop.Code -ne 0) {
                Fail-Guest ("stop failed ({0}): {1}" -f $stop.Code, (Get-LoaderText $stop))
            }
        }
        Start-Sleep -Milliseconds 500
        Assert-Stopped
    }
    'restart-10x' {
        Ensure-Driver | Out-Null
        for ($i = 1; $i -le 10; $i++) {
            $stop = Invoke-Loader -Arguments @('stop')
            if ($stop.Code -ne 0) { Fail-Guest "restart $i stop failed: $(Get-LoaderText $stop)" }
            Start-Sleep -Milliseconds 250
            $start = Invoke-Loader -Arguments @('start')
            if ($start.Code -ne 0) { Fail-Guest "restart $i start failed: $(Get-LoaderText $start)" }
            Start-Sleep -Milliseconds 250
            if ((Get-ServiceState) -ne 'Running') { Fail-Guest "restart $i did not reach Running" }
        }
        Write-GuestLine 'restarts=10'
    }
    'start-stop-50x' {
        Ensure-Driver | Out-Null
        for ($i = 1; $i -le 50; $i++) {
            $stop = Invoke-Loader -Arguments @('stop')
            if ($stop.Code -ne 0) { Fail-Guest "cycle $i stop failed: $(Get-LoaderText $stop)" }
            Start-Sleep -Milliseconds 120
            $start = Invoke-Loader -Arguments @('start')
            if ($start.Code -ne 0) { Fail-Guest "cycle $i start failed: $(Get-LoaderText $start)" }
            Start-Sleep -Milliseconds 120
            if ((Get-ServiceState) -ne 'Running') { Fail-Guest "cycle $i did not reach Running" }
        }
        Write-GuestLine 'cycles=50'
    }
}

exit 0
