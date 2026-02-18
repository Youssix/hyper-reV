.code
	invalidate_vpid_mappings proc
		invvpid rcx, oword ptr [rdx]

		ret
	invalidate_vpid_mappings endp
END