"""IDAPython script to analyze ring-1's MTF handling."""
import idaapi
import idautils
import ida_funcs
import ida_name
import ida_hexrays
import ida_bytes
import ida_search
import idc
import json
import os

OUTPUT_FILE = r"D:\Games\HyperREV\hyper-reV\mtf_analysis_output.txt"

def write(msg):
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

def decompile_func(ea):
    """Decompile function at ea, return pseudocode string."""
    try:
        cfunc = ida_hexrays.decompile(ea)
        if cfunc:
            return str(cfunc)
    except Exception as e:
        return f"[Decompilation failed: {e}]"
    return "[No decompilation]"

def get_func_name(ea):
    name = ida_name.get_name(ea)
    if not name:
        name = f"sub_{ea:X}"
    return name

# Clear output file
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    f.write("=== Ring-1 MTF Analysis ===\n\n")

# 1. Search for functions with MTF-related names
write("=" * 80)
write("SECTION 1: Functions with MTF/single_step/trap/monitor in name")
write("=" * 80)

keywords = ["mtf", "single_step", "trap", "monitor_trap", "single_step", "step"]
found_mtf_funcs = []

for ea in idautils.Functions():
    name = get_func_name(ea).lower()
    for kw in keywords:
        if kw in name:
            found_mtf_funcs.append(ea)
            write(f"\nFound: {get_func_name(ea)} at 0x{ea:X}")
            write("-" * 60)
            write(decompile_func(ea))
            break

if not found_mtf_funcs:
    write("No functions found with MTF-related names.")

# 2. Search for VMEXIT dispatch - look for switch on exit reason including 37 (MTF)
write("\n" + "=" * 80)
write("SECTION 2: Search for exit reason 37 (0x25) - MTF VMEXIT")
write("=" * 80)

# Search for the value 37 being compared in code
# Look for cmp reg, 25h or cmp reg, 37
# Also search for functions referencing the VMEXIT handler dispatch

# First, let's find functions that contain the immediate value 0x25 in comparisons
# We'll search for bytes pattern: cmp eax, 25h = 83 F8 25 or 3D 25 00 00 00
mtf_handler_candidates = set()

# Search for "cmp eax, 0x25" (opcode 3D 25 00 00 00)
pattern_3d = "3D 25 00 00 00"
ea = ida_search.find_binary(0x140001000, 0x140059000, pattern_3d, 16, ida_search.SEARCH_DOWN)
while ea != idaapi.BADADDR and ea < 0x140059000:
    func = ida_funcs.get_func(ea)
    if func:
        mtf_handler_candidates.add(func.start_ea)
        write(f"\nFound 'cmp eax, 0x25' at 0x{ea:X} in {get_func_name(func.start_ea)}")
    ea = ida_search.find_binary(ea + 1, 0x140059000, pattern_3d, 16, ida_search.SEARCH_DOWN)

# Search for "cmp reg, 0x25" (83 F8 25 for eax, 83 F9 25 for ecx, etc.)
for reg_byte in [0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF]:
    pattern = f"83 {reg_byte:02X} 25"
    ea = ida_search.find_binary(0x140001000, 0x140059000, pattern, 16, ida_search.SEARCH_DOWN)
    while ea != idaapi.BADADDR and ea < 0x140059000:
        func = ida_funcs.get_func(ea)
        if func:
            mtf_handler_candidates.add(func.start_ea)
            write(f"\nFound 'cmp reg, 0x25' at 0x{ea:X} in {get_func_name(func.start_ea)}")
        ea = ida_search.find_binary(ea + 1, 0x140059000, pattern, 16, ida_search.SEARCH_DOWN)

# Also search for je/jz after the comparison, or switch-case jumptable patterns
# Look for the number 37 as a case in switch statements

# 3. Search for vmx_vmexit_handler or dispatch function
write("\n" + "=" * 80)
write("SECTION 3: VMEXIT dispatch / handler functions")
write("=" * 80)

vmexit_keywords = ["vmexit", "vm_exit", "exit_handler", "exit_dispatch", "vmx_exit", "handle_exit"]
for ea in idautils.Functions():
    name = get_func_name(ea).lower()
    for kw in vmexit_keywords:
        if kw in name:
            write(f"\nFound: {get_func_name(ea)} at 0x{ea:X}")
            write("-" * 60)
            write(decompile_func(ea))
            break

# 4. For each candidate MTF handler, decompile
write("\n" + "=" * 80)
write("SECTION 4: Decompilation of MTF handler candidates")
write("=" * 80)

for func_ea in mtf_handler_candidates:
    fname = get_func_name(func_ea)
    write(f"\n{'=' * 60}")
    write(f"Function: {fname} at 0x{func_ea:X}")
    write(f"{'=' * 60}")
    write(decompile_func(func_ea))

# 5. Search for per-VP arrays and context structures
write("\n" + "=" * 80)
write("SECTION 5: Per-VP context / arrays (vpid, apic, processor, core)")
write("=" * 80)

vp_keywords = ["per_vp", "per_cpu", "per_core", "per_processor", "vpid", "vp_context",
               "processor_context", "cpu_context", "core_context", "vp_data", "vcpu"]
for ea in idautils.Functions():
    name = get_func_name(ea).lower()
    for kw in vp_keywords:
        if kw in name:
            write(f"\nFound: {get_func_name(ea)} at 0x{ea:X}")
            write("-" * 60)
            write(decompile_func(ea))
            break

# Also look for global arrays indexed by processor number
# Search for KeGetCurrentProcessorNumberEx or similar
write("\n" + "=" * 80)
write("SECTION 6: Functions referencing processor number / APIC ID")
write("=" * 80)

proc_keywords = ["processor_number", "apic_id", "get_current_processor", "current_cpu", "cpuid"]
for ea in idautils.Functions():
    name = get_func_name(ea).lower()
    for kw in proc_keywords:
        if kw in name:
            write(f"\nFound: {get_func_name(ea)} at 0x{ea:X}")
            write("-" * 60)
            write(decompile_func(ea))
            break

# 6. Search for spinlock / atomic operations near EPT/PTE code
write("\n" + "=" * 80)
write("SECTION 7: Spinlock / atomic / lock operations")
write("=" * 80)

lock_keywords = ["spinlock", "spin_lock", "lock", "atomic", "interlocked", "acquire", "release"]
for ea in idautils.Functions():
    name = get_func_name(ea).lower()
    for kw in lock_keywords:
        if kw in name:
            write(f"\nFound: {get_func_name(ea)} at 0x{ea:X}")
            write("-" * 60)
            write(decompile_func(ea))
            break

# Search for LOCK prefix (F0) near XCHG/CMPXCHG in .text
write("\n\nSearching for LOCK CMPXCHG / LOCK XCHG / LOCK BTS patterns...")
lock_patterns = [
    ("lock cmpxchg", "F0 0F B1"),       # lock cmpxchg r/m32, r32
    ("lock xchg", "F0 87"),             # lock xchg r32, r/m32
    ("lock bts", "F0 0F AB"),           # lock bts r/m32, r32
    ("lock inc", "F0 FF"),              # lock inc
    ("lock cmpxchg8b", "F0 0F C7"),     # lock cmpxchg8b
    ("xchg [mem]", "87"),               # xchg (implicit lock)
]

for desc, pattern in lock_patterns:
    ea = ida_search.find_binary(0x140001000, 0x140059000, pattern, 16, ida_search.SEARCH_DOWN)
    count = 0
    while ea != idaapi.BADADDR and ea < 0x140059000 and count < 20:
        func = ida_funcs.get_func(ea)
        func_name = get_func_name(func.start_ea) if func else "unknown"
        write(f"  {desc} at 0x{ea:X} in {func_name}")
        ea = ida_search.find_binary(ea + 1, 0x140059000, pattern, 16, ida_search.SEARCH_DOWN)
        count += 1

# 7. Search for EPT/PTE related functions
write("\n" + "=" * 80)
write("SECTION 8: EPT / PTE / page table functions")
write("=" * 80)

ept_keywords = ["ept", "pte", "pde", "pdpt", "pml4", "page_table", "slat", "split",
                "large_page", "violation", "ept_violation", "ept_hook", "shadow", "hidden"]
for ea in idautils.Functions():
    name = get_func_name(ea).lower()
    for kw in ept_keywords:
        if kw in name:
            write(f"\nFound: {get_func_name(ea)} at 0x{ea:X}")
            write("-" * 60)
            write(decompile_func(ea))
            break

# 8. Look for VMWRITE with MTF-related VMCS field
# Proc-based VM-execution controls field = 0x4002
# Secondary proc-based = 0x401E
# MTF bit is bit 27 in primary proc-based controls
write("\n" + "=" * 80)
write("SECTION 9: VMWRITE / VMREAD patterns (proc controls for MTF)")
write("=" * 80)

# Search for the constant 0x4002 (primary proc-based controls) or 0x401E (secondary)
for pattern_name, pattern in [("0x4002 (VMCS_CTRL_PROC_BASED)", "02 40"),
                                ("0x401E (VMCS_CTRL_PROC_BASED2)", "1E 40")]:
    ea = ida_search.find_binary(0x140001000, 0x140059000, pattern, 16, ida_search.SEARCH_DOWN)
    count = 0
    while ea != idaapi.BADADDR and ea < 0x140059000 and count < 30:
        func = ida_funcs.get_func(ea)
        if func:
            func_name = get_func_name(func.start_ea)
            # Check if this is actually a VMCS field reference (mov ecx, 4002h or similar)
            disasm = idc.generate_disasm_line(ea - 3, 0)
            disasm2 = idc.generate_disasm_line(ea - 2, 0)
            disasm3 = idc.generate_disasm_line(ea, 0)
            write(f"  Potential {pattern_name} ref at 0x{ea:X} in {func_name}")
            write(f"    Context: {disasm} | {disasm2} | {disasm3}")
        ea = ida_search.find_binary(ea + 1, 0x140059000, pattern, 16, ida_search.SEARCH_DOWN)
        count += 1

# 9. Enumerate ALL functions for a complete picture
write("\n" + "=" * 80)
write("SECTION 10: Complete function list in .text")
write("=" * 80)

all_funcs = []
for ea in idautils.Functions():
    if 0x140001000 <= ea < 0x140059000:
        name = get_func_name(ea)
        size = ida_funcs.get_func(ea).size() if ida_funcs.get_func(ea) else 0
        all_funcs.append((ea, name, size))

all_funcs.sort(key=lambda x: x[0])
for ea, name, size in all_funcs:
    write(f"  0x{ea:X}  {name} ({size} bytes)")

write(f"\nTotal functions: {len(all_funcs)}")

write("\n\n=== Analysis Complete ===")
idc.qexit(0)
