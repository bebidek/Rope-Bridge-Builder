import sys
import capstone as cs, capstone.x86 as x86
from tr_globals import Node, Mode
from tr_opcodes import involved_big_regs, conditional_pairs, supported_syscalls, is_insn_supported, strip_legal_prefixes


# when we finally make a decision about node's mode, we call this function
def establish_node_mode(node:Node, new_mode:Mode, reason:str):
    node.mode = new_mode
    good_chains_num = sum(node.good_chains.values())
    bad_chains_num = sum(node.bad_chains.values())
    print(f"Node {hex(node.address)} mode is {node.mode.name} due to {reason} ((potentially) good={good_chains_num}, bad={bad_chains_num})", file=sys.stderr)


def decide_node_legality(node:Node, manual_settings:dict[int,Mode], insns:dict[int,cs.CsInsn]):
    # In this phase, we only decide whether node is legal/illegal.
    # To do this, we look for RAX setter and syscall number.

    # if directly requested, set node to illegal
    if manual_settings.get(node.address, None) == Mode.ILLEGAL:
        establish_node_mode(node, Mode.ILLEGAL, 'manual setting')
        return

    # find corresponding 'mov eax, IMM32' instruction (RAX setter)
    if node.pre_chain is not None:
        for insn_addr in node.pre_chain:
            insn = insns[insn_addr]
            if insn.size == 5 and insn.bytes[0] == 0xb8: # encoding of 'mov eax, IMM32'
                node.rax_setter_address = insn_addr
                break

            # there can be 'xor eax, eax' instead of 'mov eax, 0'
            if insn.bytes == b'\x31\xc0':
                node.rax_setter_weird_but_legal = True
                break

            # if there is RAX/RCX access or control flow between SYSCALL and RAX setter, we are likely to break something
            regs_touched = not {x86.X86_REG_RAX, x86.X86_REG_RCX}.isdisjoint(involved_big_regs(insn))
            control_flow_touched = insn.mnemonic in ['call', 'jmp', 'ret', 'syscall', 'endbr64'] or (insn.mnemonic[:1] == 'j' and insn.mnemonic[1:] in conditional_pairs)
            if regs_touched or control_flow_touched:
                break
    
    # if didn't find, stop here (unless user wants otherwise)
    if node.rax_setter_address is None:
        if manual_settings.get(node.address, None) == Mode.ENTERABLE:
            sys.exit(f"Node {hex(node.address)} cannot be enterable due to problem with RAX setter")
        elif manual_settings.get(node.address, None) in {Mode.LEGAL, Mode.CONTINUABLE} or node.rax_setter_weird_but_legal:
            node.mode = Mode.LEGAL
        else:
            # without RAX setter, we don't know the syscall number, thus we assume it's illegal
            establish_node_mode(node, Mode.ILLEGAL, 'problem with RAX setter')
        return

    # filter unsupported syscalls
    syscall_no = insns[node.rax_setter_address].operands[1].imm # syscall number is in RAX
    if syscall_no in supported_syscalls:
        node.mode = Mode.LEGAL
    elif manual_settings.get(node.address, None) in {Mode.LEGAL, Mode.CONTINUABLE, Mode.ENTERABLE}:
        sys.exit(f"Node {hex(node.address)} cannot be legal due to unsupported syscall {syscall_no}")
    else:
        establish_node_mode(node, Mode.ILLEGAL, f'unsupported syscall {syscall_no}')


def decide_node_mode(node:Node, manual_settings:dict[int,Mode], score_threshold: float):
    # In this phase, we finally decide about the mode.
    # This function should be run for nodes which passed previous phase
    # and only after filtering bad chains and calculating score
    assert node.mode == Mode.LEGAL and node.score is not None
        
    # process manual requests
    manual_setting = manual_settings.get(node.address, None)
    if manual_setting is not None:
        establish_node_mode(node, manual_setting, "manual setting")
        return

    # evaluate node usefulness
    good_chains_num, bad_chains_num = sum(node.good_chains.values()), sum(node.bad_chains.values())
    if good_chains_num < 16:
        establish_node_mode(node, Mode.LEGAL, 'irrelevance')
    elif node.score > score_threshold:
        establish_node_mode(node, Mode.LEGAL, 'too high score')
    elif good_chains_num < 0.10 * (good_chains_num + bad_chains_num):
        establish_node_mode(node, Mode.CONTINUABLE, 'good/failed ratio')
    elif node.rax_setter_weird_but_legal:
        establish_node_mode(node, Mode.CONTINUABLE, 'good score but weird RAX setter')
    else:
        establish_node_mode(node, Mode.ENTERABLE, 'good score')
