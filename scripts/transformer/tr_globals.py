from dataclasses import dataclass, field
from enum import IntEnum
from tr_state import State

@dataclass
class Vertex:
    edges: set[int] = field(default_factory=set)
    rev_edges: set[int] = field(default_factory=set)
    init_state: State = field(default_factory=State)
    flags_important_before: bool = False
    flags_important_after: bool = False

class Mode(IntEnum):
    ILLEGAL = 0
    LEGAL = 1
    CONTINUABLE = 2
    ENTERABLE = 3

@dataclass
class Node:
    address: int
    pre_chain: list[int] = None
    good_chains: dict[tuple, int] = field(default_factory=dict)
    bad_chains: dict[tuple, int] = field(default_factory=dict)
    mode: Mode = None
    rax_setter_address: int|None = None
    rax_setter_weird_but_legal: bool = False
    graph: dict[int,Vertex] = field(default_factory=dict)
    score: float|None = None
