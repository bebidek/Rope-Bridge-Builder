#!/usr/bin/env python3
import argparse, sys, os, math, struct, stat, warnings, lief

sys.path += [os.path.abspath(os.path.join(os.path.dirname(__file__), 'transformer'))]
from tr_globals import Mode, Vertex
from tr_flag_mode import compute_flag_importance, compute_flag_modes
from tr_userspace import generate_userspace_part, get_entry_trampoline_addr
from tr_tmp_regs import compute_temp_regs
from tr_log_file import load_log_file
from tr_node_mode import decide_node_legality, decide_node_mode
from tr_asm_elf import assemble, update_section_content
from tr_blob_prefix import build_blob_prefix
from tr_blob_nodes import construct_blob_node
from tr_graph_build import calculate_optimization_score, filter_illegal_instructions, merge_chains_into_graph



# parse command line arguments
parser = argparse.ArgumentParser(prog='RBB Transformer')
parser.add_argument('input_elf_path')
parser.add_argument('log_path')
parser.add_argument('output_elf_path')
parser.add_argument('-cll', '--chain_length_limit', type=int, default=1024, required=False)
parser.add_argument('-st', '--score_threshold', type=float, default=256.0, required=False)
parser.add_argument('-mi', '--manual_illegal', type=int, default=[], required=False, nargs='+')
parser.add_argument('-ml', '--manual_legal', type=int, default=[], required=False, nargs='+')
parser.add_argument('-mc', '--manual_continuable', type=int, default=[], required=False, nargs='+')
parser.add_argument('-me', '--manual_enterable', type=int, default=[], required=False, nargs='+')
parser.add_argument('-d', '--debug_mode', action='store_true')
args = parser.parse_args()



# load input ELF binary, find sections etc.
main_elf : lief.ELF.Binary = lief.ELF.parse(args.input_elf_path)

# 'tdata_offset' is an offset of the interface buffer relative to FS segment
rodata_section : lief.ELF.Section = main_elf.get_section('.rodata')
rodata_rbb_symbol_offset = main_elf.get_symtab_symbol("rodata_rbb_chunk_begin").value - rodata_section.virtual_address
tdata_offset = struct.unpack('<i', rodata_section.content[rodata_rbb_symbol_offset:rodata_rbb_symbol_offset+4])[0]

# 'text_rbb_va' is the address of pre-reserved place for our userspace code
text_rbb_symbol : lief.ELF.Symbol = main_elf.get_symtab_symbol("text_rbb_chunk_begin")
text_rbb_va = text_rbb_symbol.value

# load all executable sections
code_sections : dict[str, (int, int, bytearray)] = {} # (start, size, data)
for section in main_elf.sections:
    if section.name == '.blob.rbb':
        sys.exit('Section .blob.rbb is already present in the file')
    if section.has(lief.ELF.Section.FLAGS.EXECINSTR):
        code_sections[section.name] = (section.virtual_address, section.size, bytearray(section.content))



# load log file
nodes, insns = load_log_file(args.log_path, args.chain_length_limit, code_sections)
total_good_chains = sum([sum(node.good_chains.values()) for node in nodes.values()])
total_bad_chains = sum([sum(node.bad_chains.values()) for node in nodes.values()])
print(f'Log file loaded: {len(nodes)} nodes, {total_good_chains} good chains, {total_bad_chains} bad chains', file=sys.stderr)



# decide about node legality
manual_settings:dict[int,Mode] = {}
for addr in args.manual_enterable:
    manual_settings[addr] = Mode.ENTERABLE
for addr in args.manual_continuable:
    manual_settings[addr] = Mode.CONTINUABLE
for addr in args.manual_legal:
    manual_settings[addr] = Mode.LEGAL
for addr in args.manual_illegal:
    manual_settings[addr] = Mode.ILLEGAL

for node in nodes.values():
    decide_node_legality(node, manual_settings, insns)

# build graphs and evaluate node potential for optimization
discard_reasons: dict[str,int] = {}
for node in nodes.values():
    filter_illegal_instructions(node, nodes, insns, discard_reasons)
    node.graph = merge_chains_into_graph(node.good_chains, node.address)
    node.score = calculate_optimization_score(node)

# finally decide about the modes
for node in nodes.values():
    if node.mode == Mode.LEGAL:
        decide_node_mode(node, manual_settings, args.score_threshold)

# print collected statistics
if discard_reasons:
    print('Report of discarded chains:')
    for insn_str, amount in discard_reasons.items():
        print(f'\t{amount} ==> {insn_str}', file=sys.stderr)

print("Score report (for finite scores):")
for node in nodes.values():
    if math.isfinite(node.score):
        print(f"\t{'++' if node.mode >= Mode.CONTINUABLE else '--'} {hex(node.address)} -> {node.score:.1f}")



# Preprocess interesting nodes before transformation
enterable_nodes:list[int] = []
for node in nodes.values():
    if node.mode >= Mode.CONTINUABLE:
        # add to the list
        if node.mode == Mode.ENTERABLE:
            enterable_nodes.append(node.address)

        # merge chains into a single graph
        node.graph[node.address] = Vertex()
        for chain in node.good_chains:
            for x, y in zip((node.address,) + chain, chain):
                node.graph.setdefault(x, Vertex()).edges.add(y)
                node.graph.setdefault(y, Vertex()).rev_edges.add(x)
        
        # compute states
        compute_flag_importance(node.graph, insns)
        [root_addr] = node.graph[node.address].edges
        compute_flag_modes(node.graph, insns, root_addr)
        compute_temp_regs(node.address, node.graph, insns)

if not enterable_nodes:
    warnings.warn("No enterable nodes - transformation will be useless")



# build the kernel blob
blob_asm = ["section .blob.rbb"]
blob_asm += build_blob_prefix(enterable_nodes, nodes, insns, tdata_offset, args.debug_mode)
exit_points : list[int] = []

for node in nodes.values():
    if node.mode >= Mode.LEGAL:
        blob_asm += construct_blob_node(node, insns, exit_points, text_rbb_va, len(enterable_nodes), args.debug_mode)



# Construct userspace code
text_rbb_asm = generate_userspace_part(enterable_nodes, exit_points, tdata_offset, text_rbb_va)
update_section_content(text_rbb_symbol.section, assemble('\n'.join(text_rbb_asm), '.text.rbb'), text_rbb_va)

for i, node_addr in enumerate(enterable_nodes):
    # inject custom jump into existing code:
    # - 'mov eax, SYSCALL_NO' is replaced by 'mov ecx, TRAMPOLINE_ADDR'
    # - 'syscall' is replaced by 'jmp ecx'
    rax_setter_addr = nodes[node_addr].rax_setter_address
    update_section_content(main_elf.get_section(insns[node_addr].section), b'\xB9' + struct.pack('<i', get_entry_trampoline_addr(i, text_rbb_va)), rax_setter_addr)
    update_section_content(main_elf.get_section(insns[node_addr].section), b'\xFF\xE1', node_addr)



# finish building output ELF
rbb_blob_section = lief.ELF.Section('.blob.rbb', lief.ELF.Section.TYPE.PROGBITS)
rbb_blob_section.content = list(assemble('\n'.join(blob_asm), '.blob.rbb'))
rbb_blob_section.size = len(rbb_blob_section.content)
main_elf.add(rbb_blob_section, loaded=False)

main_elf.write(args.output_elf_path)
os.chmod(args.output_elf_path, os.stat(args.output_elf_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
