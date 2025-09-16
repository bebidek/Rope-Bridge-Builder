from tr_globals import Node
from capstone import CsInsn
import cpuinfo

def build_debug_function_call(payload: list[str]):
    return ["push rax",
            "push rcx",
            "push rdx",
            "push rsi",
            "push rdi",
            "push r8",
            "push r9",
            "push r10",
            "push r11",
            "pushfq",

            ] + payload + [

            "popfq",
            "pop r11",
            "pop r10",
            "pop r9",
            "pop r8",
            "pop rdi",
            "pop rsi",
            "pop rdx",
            "pop rcx",
            "pop rax"
    ]

def build_print_path_length_call(stack_initially_aligned: bool):
    return build_debug_function_call([
            "mov rdi, qword [rsp + 8*(10+5)]",
            "sub rsp, 8" if not stack_initially_aligned else "",
            "call [rel reloc_print_path_length]",
            "add rsp, 8" if not stack_initially_aligned else "",
    ])

def build_print_pseudo_syscall_call(stack_initially_aligned: bool):
    return build_debug_function_call([
            "sub rsp, 8" if stack_initially_aligned else "",
            "push rax",
            "call [rel reloc_print_pseudo_syscall]",
            "add rsp, 16" if stack_initially_aligned else "add rsp, 8"
    ])

def build_blob_prefix(enterable_nodes: list[int], nodes:dict[int,Node], insns:dict[int,CsInsn], tdata_offset: int, debug_mode: bool) -> list[str]:
    # SMAP requires special instructions, but if CPU is too old, they will be invalid opcodes
    smap_enabled = ('smap' in cpuinfo.get_cpu_info()['flags'])

    # We have four relocations, applied when loading into kernel (during rbb_setup syscall):
    # - reloc_sc_tab = pointer to array of supported pseudo-syscalls (function pointers)
    # - reloc_kill = pointer to function killing the process in case of critical error (or for debug)
    # - reloc_print_path_length = pointer to function logging number of executed instructions (for debug)
    # - reloc_print_pseudo_syscall = pointer to function logging executed pseudo-syscalls (for debug)
    result = [f"%define rbb_tdata_offset {tdata_offset}"] +\
             [f"reloc_{name}: dq 0" for name in ["sc_tab", "kill", "print_path_length", "print_pseudo_syscall"]]

    # Blob entry point
    # It is called as C function, so we must save calee-saved registers.
    # For some reason (maybe anti-speculative mitigations?) sometimes the stack is not properly (mis)aligned
    # so we ensure that manually
    result += [
        "entry:",

        # load pr_regs pointer to R11
        "mov r11, qword [rsp + 8]",

        # ensure the stack is not 16B aligned (but assume it's 8B aligned)
        "test rsp, 0xf",
        "jnz entry_after_alignment",
        "push qword 0",
        "entry_after_alignment:", # at this point, stack is NOT aligned

        # backup callee-saved registers
        "push rbx",
        "push rbp",
        "push r12",
        "push r13",
        "push r14",
        "push r15",

        # save pr_regs pointer for later (we'll need it in the exit procedure)
        "push r11",
        "mov r15, r11", # R15 = pt_regs pointer

        # retrieve jump target and syscall number
        "stac" if smap_enabled else "",
        "mov rbx, fs:[rbb_tdata_offset + 0*8]", # RBX = entrance number
       f"cmp rbx, {len(enterable_nodes)}",
        "jae kill",
        "sal rbx, 1", # x86 doesn't support x16 scale in addressing
        "lea rax, [rel entry_list]",
        "lea r12, [rax + 8*rbx]",
        "add r12, [rax + 8*rbx]", # R12 = jump target
        "mov rax, [rax + 8*rbx + 8]", # RAX = syscall number

        # find proper function and call it
        "cmp rax, 512",
        "jae kill",
        "mov r11, [rel reloc_sc_tab]",
        "mov r11, [r11 + 8 * rax]",
        "test r11, r11",
        "jz kill",
        "clac" if smap_enabled else "",
        ] + (build_print_pseudo_syscall_call(True) if debug_mode else []) + [
        "call r11",
        "stac" if smap_enabled else "",

        # copy registers from the pr_regs
        "mov r11, r15", # R11 = pt_regs pointer
        "mov rcx, r12", # RCX = jump target

        "mov r15, qword [r11 + 0*8]",
        "mov r14, qword [r11 + 1*8]",
        "mov r13, qword [r11 + 2*8]",
        "mov r12, qword [r11 + 3*8]",
        "mov rbp, qword [r11 + 4*8]",
        "mov rbx, qword [r11 + 5*8]",
            # skip R11
        "mov r10, qword [r11 + 7*8]",
        "mov r9, qword [r11 + 8*8]",
        "mov r8, qword [r11 + 9*8]",
            # skip RAX
            # skip RCX
        "mov rdx, qword [r11 + 12*8]",
        "mov rsi, qword [r11 + 13*8]",
        "mov rdi, qword [r11 + 14*8]",
        
        # prepare buffers on the stack (for temporaries)
        "push qword 1", # debug instruction counter
        "sub rsp, 8", # TMP
        "push qword [r11 + 19*8]", # FRSP
        "sub rsp, 8", # MLIM

        # special handling for FLAGS
        # "push qword [r11 + 18*8]", # FLAGS (16 bits)
        "mov r11w, word [r11 + 18*8]",
        "and r11w, 0x0cd5",
        "pushfq",
        "and word [rsp], 0xf32a",
        "or word [rsp], r11w",

        # jump to the node, after its syscall
        # At this point, stack is NOT aligned 
        "jmp rcx"
    ]

    # Enterable node list
    # Each entry stores:
    #     - address of node's blob fragment (after its syscall call) relative to this entry
    #     - number of its syscall
    result += ["entry_list:"]
    for node_addr in enterable_nodes:
        result += [
            f"entrance{hex(node_addr)}:",
            f"dq node{hex(node_addr)}_after_syscall - entrance{hex(node_addr)}",
            f"dq {insns[nodes[node_addr].rax_setter_address].operands[1].imm}"
        ]

    # Blob exit procedure
    result += ["exit:",
        # At this point, stack is aligned 

        # save RCX and R11
        "mov qword fs:[rbb_tdata_offset + 0*8], rcx",
        "mov qword fs:[rbb_tdata_offset + 1*8], r11",
        "clac" if smap_enabled else "",
        "mov r11, qword [rsp + 6*8]", # R11 = pt_regs pointer

        # print debug info if enabled
        ] + (build_print_path_length_call(True) if debug_mode else []) + [

        # free buffers on the stack
        "pop rcx",
        "mov qword [r11 + 16*8], rcx",
        "mov qword [r11 + 11*8], rcx", # userspace RIP

        "mov cx, word [r11 + 18*8]",
        "and cx, 0xf32a",
        "and word [rsp], 0x0cd5",
        "or cx, word [rsp]",
        "mov word [r11 + 6*8], cx",
        "mov word [r11 + 18*8], cx",
        "add rsp, 8", # FLAGS

        # "pop rcx",
        # "mov word [r11 + 6*8], cx",
        # "mov word [r11 + 18*8], cx",

        "add rsp, 8", # MLIM
        "pop qword [r11 + 19*8]", # FRSP
        "add rsp, 24", # TMP, insn_cnt and pt_regs

        # copy registers to pt_regs
        "mov qword [r11 + 0*8], r15",
        "mov qword [r11 + 1*8], r14",
        "mov qword [r11 + 2*8], r13",
        "mov qword [r11 + 3*8], r12",
        "mov qword [r11 + 4*8], rbp",
        "mov qword [r11 + 5*8], rbx",
            # skip R11
        "mov qword [r11 + 7*8], r10",
        "mov qword [r11 + 8*8], r9",
        "mov qword [r11 + 9*8], r8",
            # skip RAX
            # skip RCX
        "mov qword [r11 + 12*8], rdx",
        "mov qword [r11 + 13*8], rsi",
        "mov qword [r11 + 14*8], rdi",
 

        # restore callee-saved registers
        "pop r15",
        "pop r14",
        "pop r13",
        "pop r12",
        "pop rbp",
        "pop rbx",

        # restore the initial stack alignment and return
        # At this point, stack is NOT aligned 
        "mov rcx, qword [rsp]",
        "test rcx, rcx",
        "jnz exit_after_alignment",
        "add rsp, 8",
        "exit_after_alignment:",
        "ret"
    ]

    # Critical error exit procedure
    # It stores all the registers and calls reloc_kill function, which kill the process
    # Because errors can occur in different places, we re-align the stack
    result += [
        "kill:",

        # backup registers for debug printing
        "push r15",
        "push r14",
        "push r13",
        "push r12",
        "push r11",
        "push r10",
        "push r9",
        "push r8",
        "push rsp",
        "push rbp",
        "push rdi",
        "push rsi",
        "push rdx",
        "push rcx",
        "push rbx",
        "push rax",
        "kill_no_copy:",
        "mov rdi, rsp",

        # stack alignment and call
        # At this point, stack alignment is unknown
        "mov rax, 0xfffffffffffffff0",
        "and rsp, rax",
        "call [rel reloc_kill]"
    ]

    # Non-first pseudo-syscall procedure
    # We call it to invoke 'syscall' equivalent from the blob (that is, from kernel space)
    # Because all supported syscalls are C functions, we backup caller-saved registers and convert convention
    result += [
        "try_pseudo_syscall:",
        # At this point, stack is aligned 

        # backup registers
        "push rdx",
        "push rsi",
        "push rdi",
        "push r8",
        "push r9",
        "push r10",
        
        # find proper function
        "cmp rax, 512",
        "jae exit_after_nosys",
        "mov r11, [rel reloc_sc_tab]",
        "mov r11, [r11 + 8 * rax]",
        "test r11, r11",
        "jz exit_after_nosys",

        # convert argument passing convention and call
        "mov rcx, r10",
        "clac" if smap_enabled else ""
        ] + (build_print_pseudo_syscall_call(True) if debug_mode else []) + [
        "call r11",
        "stac" if smap_enabled else "",

        # restore registers
        "pop r10",
        "pop r9",
        "pop r8",
        "pop rdi",
        "pop rsi",
        "pop rdx",

        # jump to continuation
        "ret",

        # in case of unsupported syscall, go back to userspace
        "exit_after_nosys:",
        "add rsp, 6*8",
        "mov qword [rsp], rcx", # RCX = exit point leading to this 'syscall' instruction
        "jmp exit"
    ]

    return result
