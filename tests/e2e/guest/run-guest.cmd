@echo off
rem Marker wrapper for the bvmenv guest harness.
rem
rem The markers must be present in the environment of the *test process*, not in
rem the shell that bvmenv builds around the command: bvmenv's exec path runs the
rem command through a generated job script / SYSTEM scheduled task, and an inline
rem `set` before the executable does not reliably survive that. This wrapper sets
rem them and then runs the requested program.
rem
rem The value can be overridden by the caller (set BLOOK_VM_GUEST first).
if "%BLOOK_VM_GUEST%"=="" set BLOOK_VM_GUEST=vm-drv
set BLOOK_ALLOW_KERNEL_LOAD=1
%*