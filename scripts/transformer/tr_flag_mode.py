import capstone as cs, capstone.x86 as x86
from tr_globals import Vertex

# Some injected instructions modify RFLAGS, but it shouldn't be observable.
# As a result, sometimes flags must be backuped on the stack
# This is simple heuristic solution minimizing RFLAGS<->STACK transitions



def is_flag_consumer(insn: cs.CsInsn) -> bool:
    # Besides regular flag consumers, we include here:
    # - partial flag setters
    # - node bonduary (syscall)
    # - instructions that can return to unknown place in userspace
    return x86.X86_REG_EFLAGS in insn.regs_access()[0] \
           or insn.mnemonic in ['clc', 'cld', 'cmc', 'dec', 'inc', 'rcl', 'rcr', 'rol', 'ror', 'sahf', 'stc', 'std'] \
           or insn.mnemonic == 'syscall' \
           or insn.mnemonic == 'ret' \
           or (insn.mnemonic in ['jmp', 'call'] and insn.operands[0].type != x86.X86_OP_IMM)

def is_flag_producer(insn: cs.CsInsn) -> bool:
    return x86.X86_REG_EFLAGS in insn.regs_access()[1]

def is_flag_toucher(insn: cs.CsInsn) -> bool:
    return is_flag_producer(insn) or is_flag_consumer(insn)

def does_destroy_flags_before_use(insn: cs.CsInsn) -> bool:
    # Flags are destroyed during memory safety checks
    return (insn.mnemonic != 'lea' and any([op.type==x86.X86_OP_MEM for op in insn.operands])) \
           or insn.mnemonic in ['call', 'leave', 'pop', 'push', 'ret', 'movsb', 'movsw', 'movsd', 'movsq', 'stos', 'stosb', 'stosw', 'stosd', 'stosq']



def compute_flag_importance(graph: dict[int,Vertex], insns: dict[int,cs.CsInsn]):
    # We mark places in which values of flags are important.
    # The algorithm is a simplified version of liveness analysis

    def dfs(v_addr: int, set_before: bool, set_after: bool):
        vertex = graph[v_addr]
        insn = insns[v_addr]

        if set_after and not vertex.flags_important_after:
            vertex.flags_important_after = True
            if not is_flag_producer(insn):
                set_before = True

        if set_before and not vertex.flags_important_before:
            vertex.flags_important_before = True
            for p_addr in vertex.rev_edges:
                dfs(p_addr, False, True)
        
    for insn_addr in graph:
        if is_flag_consumer(insns[insn_addr]):
            dfs(insn_addr, True, False)



def compute_flag_modes(graph: dict[int,Vertex], insns: dict[int,cs.CsInsn], root_addr: int):
    # We decide about flag mode at the begining of each vertex
    # The results are not critical for correctness, but can reduce mode switching overhead

    # First, we identify points at which it's reasonable to have some particular state
    for insn_addr, vertex in graph.items():
        insn = insns[insn_addr]
        if insn_addr == root_addr:
            vertex.init_state.flags_in_mem = True
        elif vertex.flags_important_before:
            if does_destroy_flags_before_use(insn): # we will switch to memory anyway
                vertex.init_state.flags_in_mem = True
            elif is_flag_toucher(insn):
                vertex.init_state.flags_in_mem = False
