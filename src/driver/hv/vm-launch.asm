; Adapted from jonomango/hv (MIT). See LICENSES/jonomango-hv.txt and docs/REFERENCES.md.
.code

; bool __vm_launch();
?vm_launch@hv@@YA_NXZ proc
  ; set VMCS_GUEST_RSP to the current value of RSP
  mov rax, 681Ch
  vmwrite rax, rsp

  ; set VMCS_GUEST_RIP to the address of <successful_launch>
  mov rax, 681Eh
  mov rdx, successful_launch
  vmwrite rax, rdx

  vmlaunch

  ; if we reached here, then we failed to launch
  xor al, al
  ret

successful_launch:
  mov al, 1
  ret
?vm_launch@hv@@YA_NXZ endp

; bool blook_vm_launch_stub(uint64_t guest_rip, uint64_t command);
; Enters guest mode at the given stub with RAX = command, so the first thing the
; guest does is a VMCALL with a known hypercall code.
?blook_vm_launch_stub@hv@@YA_N_K0@Z proc
  mov r8, rcx                 ; guest RIP
  mov r9, rdx                 ; hypercall command
  mov rax, 681Ch              ; VMCS_GUEST_RSP
  vmwrite rax, rsp
  mov rax, 681Eh              ; VMCS_GUEST_RIP
  vmwrite rax, r8
  mov rax, r9
  xor rcx, rcx
  vmlaunch
  xor al, al
  ret
?blook_vm_launch_stub@hv@@YA_N_K0@Z endp

; void blook_guest_stub();
; Runs in guest mode: one hypercall, then a halt loop (only reached if root mode
; returned control instead of stopping the processor).
?blook_guest_stub@hv@@YAXXZ proc
  vmcall
  hlt
  jmp $
?blook_guest_stub@hv@@YAXXZ endp

; void blook_guest_stub_hlt();
; Stage 4: guest mode with no VMCALL at all - a halt-only stub, to tell a broken
; VMCALL/exit path apart from a broken entry.
?blook_guest_stub_hlt@hv@@YAXXZ proc
  hlt
  jmp $
?blook_guest_stub_hlt@hv@@YAXXZ endp

; void blook_guest_stub_cpuid();
; Stage 5: guest mode with a CPUID first. CPUID always causes a VM exit, so a
; recorded exit proves guest code executed and the exit path returns to root.
?blook_guest_stub_cpuid@hv@@YAXXZ proc
  cpuid
  hlt
  jmp $
?blook_guest_stub_cpuid@hv@@YAXXZ endp
end
