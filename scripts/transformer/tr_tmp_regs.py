import capstone as cs, capstone.x86 as x86
from tr_globals import Vertex
from tr_opcodes import promote_reg, involved_big_regs
from tr_asm_elf import disassembler



def needs_tmp(insn: cs.CsInsn) -> bool:
    # TMP is needed for memory access checks or indirect jump instructions
    return (insn.mnemonic != 'lea' and any([op.type==x86.X86_OP_MEM for op in insn.operands])) \
           or insn.mnemonic in ['push', 'pop', 'call', 'ret', 'leave', 'movsb', 'movsw', 'movsd', 'movsq'] \
           or (insn.mnemonic == 'jmp' and insn.operands[0].type != x86.X86_OP_IMM)

def needs_frsp(insn: cs.CsInsn) -> bool:
    return x86.X86_REG_RSP in involved_big_regs(insn)

def needs_mlim(insn: cs.CsInsn) -> bool:
    # MLIM is needed for memory access instructions
    return (insn.mnemonic != 'lea' and any([op.type==x86.X86_OP_MEM for op in insn.operands])) \
           or insn.mnemonic in ['push', 'pop', 'call', 'ret', 'leave', 'movsb', 'movsw', 'movsd', 'movsq', 'stos', 'stosb', 'stosw', 'stosd', 'stosq']



tmp_regs_pool = {x86.X86_REG_R8, x86.X86_REG_R9, x86.X86_REG_R10, x86.X86_REG_R11, x86.X86_REG_R12, x86.X86_REG_R13, x86.X86_REG_R14, x86.X86_REG_R15}

def compute_temp_regs(node_addr: int, graph: dict[int,Vertex], insns: dict[int,cs.CsInsn]):
    visited = set()

    def dfs(insn_addr: int, tmp: int|None, frsp: int|None, mlim: int|None):
        if insn_addr in visited:
            return
        visited.add(insn_addr)
        vertex = graph[insn_addr]
        insn = insns[insn_addr]

        # possibly reclaim some registers if they are used in the instruction
        used_regs = involved_big_regs(insn)
        if tmp in used_regs:
            tmp = None
        if frsp in used_regs:
            frsp = None
        if mlim in used_regs:
            mlim = None

        # assign new registers if needed
        available_regs = tmp_regs_pool - used_regs - {tmp, frsp, mlim}
        if needs_tmp(insn) and tmp is None:
            tmp = available_regs.pop()
        if needs_frsp(insn) and frsp is None:
            frsp = available_regs.pop()
        if needs_mlim(insn) and mlim is None:
            mlim = available_regs.pop()
        
        # save into init state
        vertex.init_state.tmp_reg = disassembler.reg_name(tmp) if tmp is not None else None
        vertex.init_state.frsp_reg = disassembler.reg_name(frsp) if frsp is not None else None
        vertex.init_state.mlim_reg = disassembler.reg_name(mlim) if mlim is not None else None
        
        # follow all edges (as in DFS)
        for succ_addr in vertex.edges:
            dfs(succ_addr, tmp, frsp, mlim)
    
    dfs(node_addr, None, None, None)
