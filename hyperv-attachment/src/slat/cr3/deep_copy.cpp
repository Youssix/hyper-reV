#include "deep_copy.h"
#include "../../crt/crt.h"

void slat::make_pml4_copy(const slat_pml4e* const hyperv_pml4, slat_pml4e* const hook_pml4, const std::uint8_t)
{
	crt::copy_memory(hook_pml4, hyperv_pml4, sizeof(slat_pml4e) * 512);
}
