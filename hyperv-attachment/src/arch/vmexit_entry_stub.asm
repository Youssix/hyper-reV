extern vmexit_entry_fast_handler : proc
extern original_vmexit_entry_trampoline : qword

.code
	vmexit_entry_hook_stub proc
		; === Fix B: Early exit reason filter ===
		; Skip full GPR save/restore + C handler for exit reasons we don't handle.
		; Saves ~300-500ns per non-handled VMEXIT (~90% of exits).
		push rax
		push rdx

		mov rdx, 4402h              ; VMCS_EXIT_REASON
		vmread rax, rdx
		and eax, 0FFFFh             ; mask to basic exit reason

		cmp eax, 00h                ; EXCEPTION_OR_NMI
		je enter_handler
		cmp eax, 0Ah                ; CPUID
		je enter_handler
		cmp eax, 1Ch                ; MOV_CR
		je enter_handler
		cmp eax, 25h                ; MONITOR_TRAP_FLAG
		je enter_handler
		cmp eax, 30h                ; EPT_VIOLATION
		je enter_handler

		; VMX instructions (VMCLEAR..VMXON = 13h..1Bh) — inject #UD
		; Excludes VMCALL (12h) which Hyper-V handles for its own hypercalls
		cmp eax, 13h
		jb not_vmx_instr
		cmp eax, 1Bh
		jbe enter_handler
	not_vmx_instr:

		; Non-handled exit: restore scratch regs, skip to Hyper-V trampoline
		pop rdx
		pop rax
		jmp original_vmexit_entry_trampoline

	enter_handler:
		; Restore scratch regs before full save (trap_frame needs correct values)
		pop rdx
		pop rax

		; --- Original handler code ---
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
		; vmresume failed — should never reach here (Fix F)
		int 3
		hlt
		jmp $-2

	vmexit_entry_hook_stub endp
END
