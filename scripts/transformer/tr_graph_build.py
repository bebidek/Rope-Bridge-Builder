from tr_globals import Node, Mode, Vertex
from tr_opcodes import strip_legal_prefixes, is_insn_supported
import capstone as cs
import math

def filter_illegal_instructions(node:Node, nodes:dict[int,Node], insns:dict[int,cs.CsInsn], discard_reasons: dict[str,int]):
    # filter chains with unsupported instructions and ending with illegal syscalls
    for chain, amount in list(node.good_chains.items()):
        for addr in chain:
            insn = insns[addr]
            mnemonic = strip_legal_prefixes(insn.mnemonic)
            fault_str = None

            if mnemonic == 'syscall':
                if addr not in nodes or nodes[addr].mode == Mode.ILLEGAL:
                    fault_str = "illegal syscall"
            elif not is_insn_supported(insn):
                fault_str = f"{insn.mnemonic} {insn.op_str}"

            # collect faults - this info may suggest what to improve
            if fault_str is not None:
                fault_str = f"{hex(addr)} : {fault_str}"
                discard_reasons.setdefault(fault_str, 0)
                discard_reasons[fault_str] += amount
                del node.good_chains[chain]
                node.bad_chains.setdefault(chain, 0)
                node.bad_chains[chain] += amount
                break

def merge_chains_into_graph(chains: dict[tuple,int], root_address: int) -> dict[int,Vertex]:
    graph : dict[int,Vertex] = { root_address : Vertex() }
    for chain in chains:
        for x, y in zip((root_address,) + chain, chain):
            graph.setdefault(x, Vertex()).edges.add(y)
            graph.setdefault(y, Vertex()).rev_edges.add(x)
    return graph

def calculate_optimization_score(node: Node) -> float:
    # Lower score indicates better optimization
    # Score above certain threshold (dependent on exact architecture) indicates
    # performance decrease, in which case transformation shouldn't proceed
    if len(node.good_chains) == 0:
        return math.inf
    len_sum, good_chains_num = 0, 0

    # good chains are obviously included in the graph
    for chain, amount in node.good_chains.items():
        len_sum += amount * len(chain)
        good_chains_num += amount

    # for bad chains, we take length of their prefix included in the graph
    for chain, amount in node.bad_chains.items():
        current_vertex, prefix_length = node.graph[node.address], 0
        for addr in chain:
            prefix_length += 1
            if addr in current_vertex.edges:
                current_vertex = node.graph[addr]
            else:
                break
        len_sum += amount * prefix_length

    return len_sum / good_chains_num
