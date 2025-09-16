from dataclasses import dataclass
from copy import copy

# According to Linux docs, all userspace virtual addresses
# should be below this address (at least with 4-level page tables)
USERLAND_LIMIT = 0x7fffffffffff

# We need some temporary registers, so at any point of blob execution
# few unused register values might be stored on the stack.
# Class State describes state of those swapped registers.

# Stack layout:
# INSN_CNT
# TMP_REG
# FRSP_REG
# MLIM_REG <--\ 
# FLAGS  <------  top of the stack (depending on flags_in_mem field)

@dataclass
class State:
    # these default values represent basic state
    tmp_reg: str|None = None
    frsp_reg: str|None = None
    mlim_reg: str|None = None
    flags_in_mem: bool|None = None

    def set_tmp_regs(self, new_tmp: str|None, new_frsp: str|None, new_mlim: str|None) -> list[str]:
        result = []
        st = "rsp" if self.flags_in_mem else "rsp-2" # position of FLAGS on stack

        # disable old temp regs
        if self.tmp_reg != new_tmp and self.tmp_reg is not None:
            result += [f'  mov {self.tmp_reg}, qword [{st}+24]']
        if self.frsp_reg != new_frsp and self.frsp_reg is not None:
            result += [f'  push qword [{st}+16]',
                       f'  mov qword [{st}+24] , {self.frsp_reg}',
                       f'  pop qword {self.frsp_reg}']
        if self.mlim_reg != new_mlim and self.mlim_reg is not None:
            result += [f'  mov {self.mlim_reg}, qword [{st}+8]']

        # enable new temp regs
        if self.tmp_reg != new_tmp and new_tmp is not None:
            result += [f'  mov qword [{st}+24], {new_tmp}']
        if self.frsp_reg != new_frsp and new_frsp is not None:
            result += [f'  push qword [{st}+16]',
                       f'  mov qword [{st}+24], {new_frsp}',
                       f'  pop qword {new_frsp}']
        if self.mlim_reg != new_mlim and new_mlim is not None:
            result += [f'  mov qword [{st}+8], {new_mlim}',
                       f'  mov {new_mlim}, {USERLAND_LIMIT}']

        self.tmp_reg, self.frsp_reg, self.mlim_reg = new_tmp, new_frsp, new_mlim
        return result
    
    def set_flags_in_mem(self, new_flag_in_mem: bool) -> list[str]:
        assert self.flags_in_mem is not None
        if self.flags_in_mem != new_flag_in_mem:
            self.flags_in_mem = new_flag_in_mem
            return ["  pushfw" if new_flag_in_mem else "  popfw"]
        return []
    
    def set_to(self, other) -> str:
        if other is None:
            return self.set_flags_in_mem(True) + self.set_tmp_regs(None, None, None)
        else:
            return self.set_flags_in_mem(other.flags_in_mem) +\
                   self.set_tmp_regs(other.tmp_reg, other.frsp_reg, other.mlim_reg)
    
    def restore_mlim(self) -> str:
        # We sometimes use MLIM as second TMP, but it needs to be restored right after
        assert self.mlim_reg is not None
        return [f'  mov {self.mlim_reg}, {USERLAND_LIMIT}']

    def increment_insn_counter(self) -> str:
        assert self.flags_in_mem is not None
        return [
            "  pushfw" if not self.flags_in_mem else "",
            "  inc qword [rsp + 32]",
            "  popfw" if not self.flags_in_mem else "",
        ]

    def decrement_insn_counter(self) -> str:
        assert self.flags_in_mem is not None
        return [
            "  pushfw" if not self.flags_in_mem else "",
            "  dec qword [rsp + 32]",
            "  popfw" if not self.flags_in_mem else "",
        ]
    
    def copy(self):
        return copy(self)

    def __str__(self) -> str:
        return f'State(tmp={self.tmp_reg}, frsp={self.frsp_reg}, mlim={self.mlim_reg}, flags_in_mem={self.flags_in_mem})'
