import re
import capstone as cs, capstone.x86 as x86
from tr_flag_mode import is_flag_toucher
from tr_globals import Node, Mode, Vertex
from tr_opcodes import strip_legal_prefixes, normal_insns, involved_regs, conditional_pairs, inverse_conditional_insn
from tr_state import State
from tr_userspace import get_exit_trampoline_addr

def construct_blob_node(node:Node, insns:dict[int,cs.CsInsn], exit_points:list[int], rbb_va_addr:int, number_of_enterable_nodes:int, debug_mode: bool) -> list[str]:
    # Transform a node (with its accepted chains merged into a graph)
    # to kernel-space code.
    result = []
    escape_targets = []

    def new_exit_point(addr:int) -> int:
        # Adds new exit point to the list and returns proper jump address
        # (of userspace trampoline of that exit point)
        # If it already exists, use that one
        if addr in exit_points:
            index = exit_points.index(addr)
        else:
            index = len(exit_points)
            exit_points.append(addr)
        return get_exit_trampoline_addr(index, rbb_va_addr, number_of_enterable_nodes)

    # generate syscall invocation and possibly return right after
    result += ['', '', '', '',
               f'node{hex(node.address)}_syscall:',
               f'mov rcx, {hex(new_exit_point(node.address))}' if node.mode != Mode.ENTERABLE else '; enterable',
                'call try_pseudo_syscall'
               ] + (State(flags_in_mem=True).increment_insn_counter() if debug_mode else []) + [
               f'node{hex(node.address)}_after_syscall:']
    if node.mode < Mode.CONTINUABLE:
        result += [f'push qword {hex(new_exit_point(node.address + 2))}',
                    'jmp exit']
        return result

    root_addr = node.graph[node.address].edges.pop()
    processed_insns = set()

    # DFS-like transforming function
    def process_insn(insn_addr:int, jmp_if_done:bool = True):
        nonlocal result, escape_targets

        # if vertex is already visited, just jump (or even not)
        if insn_addr in processed_insns:
            if jmp_if_done:
                result += [f'jmp node{hex(node.address)}_insn{hex(insn_addr)}']
            return
        processed_insns.add(insn_addr)

        # assembly header, basic variables
        insn = insns[insn_addr]
        vertex = node.graph[insn_addr]
        state = vertex.init_state.copy()

        result += ['',
                  f'; ORIGINAL {insn.mnemonic} {insn.op_str}\t\t{state}',
                  f'node{hex(node.address)}_insn{hex(insn_addr)}:']

        if debug_mode and insn.mnemonic != "syscall":
            result += state.increment_insn_counter()

        # common subprocedures
        def get_vertex_init_state(vertex: Vertex, from_state: State = state):
            # We use lazy approach here, to avoid unnecessary preprocessing phase
            if vertex.init_state.flags_in_mem is None:
                vertex.init_state.flags_in_mem = from_state.flags_in_mem
            return vertex.init_state
            
        def process_next_insn(next_addr):
            nonlocal result
            target = node.graph[next_addr]
            result += state.set_to(get_vertex_init_state(target))
            process_insn(next_addr)

        def generate_escape_target():
            state_copy = state.copy()
            et_result = [f"escape_target_node{hex(node.address)}_insn{(hex(insn_addr))}:"] +\
                        state_copy.set_to(None) +\
                        (state_copy.decrement_insn_counter() if debug_mode else []) +\
                        [f"push qword {hex(new_exit_point(insn_addr))}",
                          "jmp exit"]
            escape_targets.append(et_result)

        def generate_mem_check(addr_op_str: str, add_fs=False):
            # Assumes that there is corresponding escape target, MLIM and TMP are available
            nonlocal result
            result += [f"lea {state.tmp_reg}, {addr_op_str}"]
            if add_fs: # LEA ignores segment registers, so we add it manually
                result += [f"rdfsbase {state.mlim_reg}", # abuse mlim register
                           f"add {state.tmp_reg}, {state.mlim_reg}"] +\
                          state.restore_mlim()
            result += [# f"cmp {state.tmp_reg}, {state.mlim_reg}",
                       # f"ja escape_target_node{hex(node.address)}_insn{hex(insn_addr)}",
                       f"and {state.tmp_reg}, {state.mlim_reg}"]

        def generate_simple_mem_check(addr_reg: str):
            # If we know that address is just a single register, we don't need LEA and tmp register
            nonlocal result
            if addr_reg == 'rsp':
                return # FIXME
            result += [# f"cmp {addr_reg}, {state.mlim_reg}",
                       # f"ja escape_target_node{hex(node.address)}_insn{hex(insn_addr)}",
                       f"and {addr_reg}, {state.mlim_reg}"] # prevent speculation

        def generate_variable_jump(targets: list[int], on_each_target: list[str]):
            # Assumes that target address is in TMP register and MLIM is available
            nonlocal result

            for i, target_addr in enumerate(targets):
                target = node.graph[target_addr]
                substate = state.copy()
                result += [f'node{hex(node.address)}_insn{hex(insn_addr)}_branch{i}:',
                           f'cmp {state.tmp_reg}, {hex(target_addr)}',
                           f'jne node{hex(node.address)}_insn{hex(insn_addr)}_branch{i+1}'] +\
                          on_each_target +\
                          substate.set_to(get_vertex_init_state(target, from_state=substate)) +\
                          [f'jmp node{hex(node.address)}_insn{hex(target_addr)}']

            result += [f'node{hex(node.address)}_insn{hex(insn_addr)}_branch{len(targets)}:'] +\
                      state.set_to(None) +\
                      (state.decrement_insn_counter() if debug_mode else []) +\
                      [f"push qword {hex(new_exit_point(insn_addr))}",
                        "jmp exit"] 

        def op_tr(text: str, mem_sub:bool = False) -> str:
            # translate instruction operands to remove RIP-relative addressing,
            # RSP references and PTRs (NASM don't support that syntax)
            text = re.sub("rip", f"{hex(insn_addr + insn.size)}", text) # relative addressing
            text = re.sub("rsp", lambda _:state.frsp_reg, text) # --------\
            text = re.sub("esp", lambda _:f"{state.frsp_reg}d", text) #   |
            text = re.sub("spl", lambda _:f"{state.frsp_reg}b", text) #   |
            text = re.sub("sp", lambda _:f"{state.frsp_reg}w", text) # ------ RSP references
            text = re.sub(" ptr", " ", text) # PTR syntax
            if mem_sub:
                text = re.sub("\\[.*\\]", f"[{state.tmp_reg}]", text) # memory operand to sanitized TMP
                text = re.sub("fs:", "", text) # forget about FS segment
            return text

        def size_str(size: int):
            return {1:'byte', 2:'word', 4:'dword', 8:'qword'}[size]


        actual_mnemonic = strip_legal_prefixes(insn.mnemonic)

        # no-op instructions
        if actual_mnemonic in ['nop', 'endbr64']:
            process_next_insn(vertex.edges.pop())


        # LEA is special: it looks like a memory access but it isn't one
        elif actual_mnemonic == 'lea':
            result += [f'{insn.mnemonic} {op_tr(insn.op_str)}']
            process_next_insn(vertex.edges.pop())

        
        # MOVABS is like MOV, but with weird name and mo memory access
        elif actual_mnemonic == 'movabs':
            assert insn.operands[0].type == x86.X86_OP_REG and insn.operands[1].type == x86.X86_OP_IMM
            result += [f'mov {op_tr(insn.op_str)}'] # in NASM it's just MOV
            process_next_insn(vertex.edges.pop())

        
        # we consider DF flag special
        elif actual_mnemonic in ['cld', 'std']:
            result += state.set_flags_in_mem(False)
            result += [insn.mnemonic]
            process_next_insn(vertex.edges.pop())


        # normal instructions, possibly refering to memory
        elif actual_mnemonic in normal_insns or actual_mnemonic[:4]=='cmov' or actual_mnemonic[:3]=='set':
            arg_0_is_mem = len(insn.operands) >= 1 and insn.operands[0].type == x86.X86_OP_MEM
            arg_1_is_mem = len(insn.operands) >= 2 and insn.operands[1].type == x86.X86_OP_MEM
            arg_2_is_mem = len(insn.operands) >= 3 and insn.operands[2].type == x86.X86_OP_MEM
            is_mem = arg_0_is_mem or arg_1_is_mem or arg_2_is_mem

            if is_mem:
                mem_op_pos = 0 if arg_0_is_mem else (1 if arg_1_is_mem else 2)
                if vertex.flags_important_before:
                    result += state.set_flags_in_mem(True)
                generate_escape_target()
                generate_mem_check(op_tr(insn.op_str.split(',')[mem_op_pos]), add_fs=(x86.X86_REG_FS in involved_regs(insn)))
            if is_flag_toucher(insn) and (vertex.flags_important_before or vertex.flags_important_after):
                result += state.set_flags_in_mem(False)
            result += [f'{insn.mnemonic} {op_tr(insn.op_str, mem_sub=True)}']

            process_next_insn(vertex.edges.pop())
        

        # string copy - implicit memory access
        elif actual_mnemonic in ['movsb', 'movsw', 'movsd', 'movsq', 'stos', 'stosb', 'stosw', 'stosd', 'stosq']:
            if vertex.flags_important_before:
                result += state.set_flags_in_mem(True)
            # generate_escape_target()
            if actual_mnemonic[:3] == "mov":
                generate_simple_mem_check('rsi')
            generate_simple_mem_check('rdi')
            result += state.set_flags_in_mem(False) # we need DF flag
            result += [insn.mnemonic]

            next_addr = vertex.edges.pop()
            process_next_insn(vertex.edges.pop() if next_addr == insn_addr else next_addr) # this instruction can loop on itself
        

        # unconditional jump/call
        elif actual_mnemonic in ['jmp', 'call']:
            if insn.operands[0].type == x86.X86_OP_IMM: # direct jump
                if actual_mnemonic == 'call':
                    if vertex.flags_important_before:
                        result += state.set_flags_in_mem(True)
                    # generate_escape_target()
                    generate_simple_mem_check(state.frsp_reg)
                    result += [f'mov qword [{state.frsp_reg}-8], {hex(insn_addr+insn.size)}',
                               f'sub {state.frsp_reg}, 8']
                process_next_insn(vertex.edges.pop())

            else: # indirect jump
                if vertex.flags_important_before:
                    result += state.set_flags_in_mem(True)
                generate_escape_target()
                if actual_mnemonic == 'call':
                    generate_simple_mem_check(state.frsp_reg)
                if insn.operands[0].type == x86.X86_OP_MEM:
                    generate_mem_check(op_tr(insn.op_str), add_fs=(x86.X86_REG_FS in involved_regs(insn)))
                result += [f"mov {state.tmp_reg}, {op_tr(insn.op_str, mem_sub=True)}"]
                extra_insns_on_each_target = [
                    f'mov qword [{state.frsp_reg}-8], {hex(insn_addr+insn.size)}',
                    f'sub {state.frsp_reg}, 8'
                ] if actual_mnemonic=='call' else []
                generate_variable_jump(list(vertex.edges), on_each_target=extra_insns_on_each_target)

                for target in vertex.edges:
                    process_insn(target, jmp_if_done=False)


        # direct conditional jump (Jcc)
        elif actual_mnemonic[:1] == 'j' and actual_mnemonic[1:] in conditional_pairs:
            jump_target, no_jump_target = None, None
            if len(vertex.edges) == 1:
                no_jump_target = vertex.edges.pop()
            else:
                jump_target = vertex.edges.pop()
                no_jump_target = vertex.edges.pop()
                if jump_target not in processed_insns:
                    jump_target, no_jump_target = no_jump_target, jump_target
            need_to_reverse = (no_jump_target != insn_addr + insn.size)

            jump_kind = inverse_conditional_insn(actual_mnemonic, 1) if need_to_reverse else actual_mnemonic
            result += state.set_flags_in_mem(False)
            if jump_target is None:
                generate_escape_target()
                result += [f'{jump_kind} escape_target_node{hex(node.address)}_insn{hex(insn_addr)}']
            else:
                result += [f'{inverse_conditional_insn(jump_kind, 1)} node{hex(node.address)}_insn{hex(insn_addr)}_no_jump'] +\
                          state.copy().set_to(get_vertex_init_state(node.graph[jump_target])) +\
                          [f'jmp node{hex(node.address)}_insn{hex(jump_target)}',
                           f'node{hex(node.address)}_insn{hex(insn_addr)}_no_jump:']

            process_next_insn(no_jump_target)
            if jump_target is not None:
                process_insn(jump_target, jmp_if_done=False)


        # stack operations
        elif actual_mnemonic in ['push', 'pop']:
            size = insn.operands[0].size
            if vertex.flags_important_before:
                result += state.set_flags_in_mem(True)
            operand_is_mem = (insn.operands[0].type == x86.X86_OP_MEM)
            if operand_is_mem:
                generate_escape_target()
                generate_mem_check(op_tr(insn.op_str), add_fs=(x86.X86_REG_FS in involved_regs(insn)))
            generate_simple_mem_check(state.frsp_reg)
            if actual_mnemonic == 'push':
                if operand_is_mem:
                    result += [f"mov {state.tmp_reg}, {op_tr(insn.op_str, mem_sub=True)}",
                               f"mov [{state.frsp_reg} - {size}], {state.tmp_reg}",
                               f"sub {state.frsp_reg}, {size}"]
                else:
                    result += [f"mov {size_str(size)} [{state.frsp_reg} - {size}], {insn.op_str}",
                               f"sub {state.frsp_reg}, {size}"]
            else: # if mnemonic == pop
                if operand_is_mem:
                    result += [f"mov {state.mlim_reg}, [{state.frsp_reg}]", # abuse mlim register
                               f"mov {op_tr(insn.op_str, mem_sub=True)}, {state.mlim_reg}",
                               f"add {state.frsp_reg}, {size}"] +\
                               state.restore_mlim()
                else:
                    result += [f"mov {insn.op_str}, {size_str(size)} [{state.frsp_reg}]",
                               f"add {state.frsp_reg}, {size}"]

            process_next_insn(vertex.edges.pop())
        

        # drop the stack frame
        elif actual_mnemonic == 'leave':
            if vertex.flags_important_before:
                result += state.set_flags_in_mem(True)
            # generate_escape_target()
            generate_simple_mem_check('rbp')
            result += [f'mov {state.tmp_reg}, [rbp]',
                       f'lea {state.frsp_reg}, [rbp+8]',
                       f'mov rbp, {state.tmp_reg}']

            process_next_insn(vertex.edges.pop())


        # return from function call
        elif actual_mnemonic == 'ret':
            if vertex.flags_important_before:
                result += state.set_flags_in_mem(True)
            generate_escape_target()
            generate_simple_mem_check(state.frsp_reg)
            result += [f'mov {state.tmp_reg}, [{state.frsp_reg}]']
            extra_insns_on_each_target = [f'add {state.frsp_reg}, 8+{(insn.op_str if insn.operands else "0")}']
            generate_variable_jump(list(vertex.edges), on_each_target=extra_insns_on_each_target)

            for target in vertex.edges:
                process_insn(target, jmp_if_done=False)
        

        # system call
        elif actual_mnemonic == 'syscall':
            result += state.set_to(None)
            result += [f'jmp node{hex(insn_addr)}_syscall']


        # this should be unreachable
        else:
            raise NotImplementedError(f'Cannot process instruction {insn.mnemonic} {insn.op_str}')


    result += State(flags_in_mem=True).set_to(node.graph[root_addr].init_state)
    process_insn(root_addr)

    # append escape targets
    result += ['', '']
    for et in escape_targets:
        result += et
    
    return result
