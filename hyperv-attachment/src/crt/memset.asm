; memset implementation for /NODEFAULTLIB builds.
; MSVC LTCG may emit memset calls for aggregate zero-init.
;
; void* memset(void* dest, int val, size_t count)
;   RCX = dest, EDX = val, R8 = count
;   Returns dest in RAX.

.code

memset proc
    push    rdi             ; save non-volatile register
    mov     r9, rcx         ; save dest for return value
    mov     rdi, rcx        ; rdi = dest (rep stosb destination)
    mov     eax, edx        ; al = byte value to store
    mov     rcx, r8         ; rcx = count (rep stosb counter)
    rep     stosb
    mov     rax, r9         ; return original dest
    pop     rdi             ; restore non-volatile register
    ret
memset endp

end
