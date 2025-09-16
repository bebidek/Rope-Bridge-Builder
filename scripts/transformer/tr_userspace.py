import sys

# length (after assembly) of one trampoline
ENTRY_TRAMPOLINE_OFFSET = 24
EXIT_TRAMPOLINE_OFFSET = 23

# amount of space reserved for .text.rbb section (configured in placeholder.asm)
MAX_AVAILABLE_SPACE = 16*1024

def get_entry_trampoline_addr(index:int, rbb_va_addr:int) -> int:
    return rbb_va_addr + index*ENTRY_TRAMPOLINE_OFFSET

def get_exit_trampoline_addr(index:int, rbb_va_addr:int, number_of_enterable_nodes:int) -> int:
    return rbb_va_addr + number_of_enterable_nodes*ENTRY_TRAMPOLINE_OFFSET + index*EXIT_TRAMPOLINE_OFFSET

def generate_userspace_part(enterable_nodes:list[int], exit_points:list[int], tdata_offset:int, rbb_va_addr:int) -> list[str]:
    # check if construcion is possible
    space_required = ENTRY_TRAMPOLINE_OFFSET*len(enterable_nodes) + EXIT_TRAMPOLINE_OFFSET*len(exit_points)
    if space_required > MAX_AVAILABLE_SPACE:
        sys.exit(f"Not enough space in .text.rbb section: {space_required}B nedded, {MAX_AVAILABLE_SPACE}B reserved")

    # header
    result = [
        f"%define rbb_tdata_offset {hex(tdata_offset)}",
         "section .text.rbb"
    ]

    # entry trampolines for all enterable nodes
    for i, node_addr in enumerate(enterable_nodes):
        result += [
            f"; Entry point number {i}",
             "endbr64", # indirect jump to this place
            f"mov qword fs:[rbb_tdata_offset + 0*8], {i}", # save entrance id
             "mov rax, 471", # syscall rbb_enter
             "syscall"
        ]
    
    # exit trampolines for all possible return paths
    for i, target_addr in enumerate(exit_points):
        this_addr = get_exit_trampoline_addr(i, rbb_va_addr, len(enterable_nodes))
        result += [
            f"; Exit point number {i}",
             "mov rcx, qword fs:[rbb_tdata_offset + 0*8]",
             "mov r11, qword fs:[rbb_tdata_offset + 1*8]",
            f"jmp qword ({hex(target_addr)} - {hex(this_addr+18)} - 1)" # we subtract 1 because NASM is weird
        ]

    return result
