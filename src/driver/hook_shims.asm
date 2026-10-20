; Windows x64 known-ABI entry shims. Root redirects RIP, NOT CALL: at entry
; [rsp] is the real OS caller return address and rsp modulo 16 is 8.
; No executable bytes or unwind records are generated at runtime.
option casemap:none

EXTERN blook_hook_handlers:QWORD

.code

; Four register arguments need only shadow space + alignment (28h).
; Five arguments also fit in 28h; eight require 48h. After subtraction RSP is
; 16-byte aligned before CALL. Incoming arg N is at entry_rsp + 8*N (N >= 5),
; outgoing arg N is at current_rsp + 8*(N-1), before CALL pushes its return.
; Copy through R11 only: RCX/RDX/R8/R9 and XMM argument registers are untouched.
HOOK_SHIM MACRO entry_name:REQ, slot:REQ, argc:REQ
    LOCAL frame_bytes
    IF argc LE 5
        frame_bytes = 28h
    ELSE
        frame_bytes = 48h
    ENDIF
    PUBLIC entry_name
    ALIGN 16
entry_name PROC FRAME
    sub rsp, frame_bytes
    .allocstack frame_bytes
    .endprolog
    IF argc GE 5
        mov r11, QWORD PTR [rsp + frame_bytes + 28h]
        mov QWORD PTR [rsp + 20h], r11
    ENDIF
    IF argc GE 6
        mov r11, QWORD PTR [rsp + frame_bytes + 30h]
        mov QWORD PTR [rsp + 28h], r11
    ENDIF
    IF argc GE 7
        mov r11, QWORD PTR [rsp + frame_bytes + 38h]
        mov QWORD PTR [rsp + 30h], r11
    ENDIF
    IF argc GE 8
        mov r11, QWORD PTR [rsp + frame_bytes + 40h]
        mov QWORD PTR [rsp + 38h], r11
    ENDIF
    call QWORD PTR [blook_hook_handlers + slot * 8]
    ; Real CALL/RET above balances CET shadow-stack state. Restore the original
    ; caller RSP without touching the handler's integer return value in RAX.
    add rsp, frame_bytes
    jmp blook_hook_leave_site
entry_name ENDP
ENDM

HOOK_SHIM blook_hook_shim_query_system,       0, 4
HOOK_SHIM blook_hook_shim_query_process,      1, 5
HOOK_SHIM blook_hook_shim_set_thread,         2, 4
HOOK_SHIM blook_hook_shim_query_thread,       3, 5
HOOK_SHIM blook_hook_shim_get_context,        4, 2
HOOK_SHIM blook_hook_shim_open_process,       5, 4
HOOK_SHIM blook_hook_shim_open_thread,        6, 4
HOOK_SHIM blook_hook_shim_debug_attach,       7, 2
HOOK_SHIM blook_hook_shim_write_memory,       8, 5
HOOK_SHIM blook_hook_shim_protect_memory,     9, 5
HOOK_SHIM blook_hook_shim_window_query,      10, 2
HOOK_SHIM blook_hook_shim_window_find,       11, 5
HOOK_SHIM blook_hook_shim_window_list,       12, 8
HOOK_SHIM blook_hook_shim_window_foreground, 13, 0
HOOK_SHIM blook_hook_shim_window_point,      14, 1

; Root MUST authenticate this exact guest RIP independently of hypercall
; argument registers, retain RAX, and redirect to a pinned/validated OS-owned
; C3 RET before releasing the inflight reference. Never resume this driver
; site after decrement: the image may be freed as soon as that reference drops.
; No CALL here: both normal and CET stacks still hold the real caller return.
; A leaf frame is sufficient: RSP is already the original entry RSP.
PUBLIC blook_hook_leave_site
ALIGN 16
blook_hook_leave_site PROC FRAME
    .endprolog
    vmcall
    ud2
blook_hook_leave_site ENDP

END
