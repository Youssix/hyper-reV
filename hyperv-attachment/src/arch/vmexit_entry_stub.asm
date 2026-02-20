extern vmexit_entry_fast_handler : proc
extern original_vmexit_entry_trampoline : qword

.code
	vmexit_entry_hook_stub proc
		sub rsp, 80h

		; save all GPRs matching trap_frame_t layout
		mov [rsp+00h], rax
		mov [rsp+08h], rcx
		mov [rsp+10h], rdx
		mov [rsp+18h], rbx
		; [rsp+20h] = rsp, filled from VMCS below
		mov [rsp+28h], rbp
		mov [rsp+30h], rsi
		mov [rsp+38h], rdi
		mov [rsp+40h], r8
		mov [rsp+48h], r9
		mov [rsp+50h], r10
		mov [rsp+58h], r11
		mov [rsp+60h], r12
		mov [rsp+68h], r13
		mov [rsp+70h], r14
		mov [rsp+78h], r15

		; fill RSP slot from VMCS guest RSP (field 0x681C)
		mov rdx, 681Ch
		vmread rax, rdx
		mov [rsp+20h], rax

		; call C handler: rcx = trap_frame_t* (rsp)
		mov rcx, rsp
		sub rsp, 20h        ; 32-byte shadow space (x64 ABI)
		call vmexit_entry_fast_handler
		add rsp, 20h        ; remove shadow space

		; test result — mov restores don't affect flags
		test al, al

		; restore all GPRs (mov doesn't affect flags)
		mov r15, [rsp+78h]
		mov r14, [rsp+70h]
		mov r13, [rsp+68h]
		mov r12, [rsp+60h]
		mov r11, [rsp+58h]
		mov r10, [rsp+50h]
		mov r9,  [rsp+48h]
		mov r8,  [rsp+40h]
		mov rdi, [rsp+38h]
		mov rsi, [rsp+30h]
		mov rbp, [rsp+28h]
		mov rbx, [rsp+18h]
		mov rdx, [rsp+10h]
		mov rcx, [rsp+08h]
		mov rax, [rsp+00h]

		; lea doesn't affect flags, so ZF from test al,al is preserved
		lea rsp, [rsp+80h]

		jnz handled

		; not handled: fall through to original Hyper-V VMEXIT entry trampoline
		jmp original_vmexit_entry_trampoline

	handled:
		vmresume

	vmexit_entry_hook_stub endp
END
