# Synthetic hang used by watchdog-detects-hang.
#
# The host gives this case a 5 second timeout.  `ping -n 600` would run for
# roughly ten minutes, so a correctly working watchdog must kill it and report
# `timeout`, while the VM remains healthy.
param([int]$Seconds = 600)

Write-Output ("hang-helper: starting {0}s" -f $Seconds)
Write-Output ("hang-helper: pid={0}" -f $PID)
& ping.exe -n $Seconds 127.0.0.1 | Out-Null
Write-Output 'hang-helper: finished (watchdog did not fire)'
exit 0
