import capstone as cs, capstone.x86 as x86

# normal 'arithmetic' instructions
normal_insns = {'adc', 'add', 'and', 'bsf', 'bsr', 'bswap',
                'bt', 'btc', 'btr', 'bts', 'cbw', 'cwde', 'cdqe',
                'cwd', 'cdq', 'cqo', 'clc', 'cld', 'cmc',
                'cmp', 'cmpxchg', 'cpuid', 'dec',
                'div', 'idiv', 'imul', 'inc', 'lahf',
                'lzcnt', 'mov', 'movsx', 'movsxd', 'movzx',
                'mul', 'neg', 'not', 'or', 'pause', 'popcnt',
                'rcl', 'rcr', 'rol', 'ror', 'sahf',
                'sal', 'shl', 'sar', 'sbb', 'shld', 'shr', 'shrd',
                'stc', 'std', 'sub', 'test', 'xchg', 'xor'}

# instructions that require special handling
# 
special_insns = ['call', 'endbr64', 'jmp', 'lea', 'leave',
                 'movabs', 'nop', 'pop', 'push', 'ret',
                 'syscall', 'movsb', 'movsw', 'movsd', 'movsq',
                 'stos', 'stosb', 'stosw', 'stosd', 'stosq']



# conditional suffixes (for Jcc, SETcc, CMOVcc)
# each pair [2i, 2i+1] contains pair of opposite suffixes
conditional_pairs = ['o', 'no', 'b', 'nb', 'c', 'nc', 'ae', 'nae',
                     'z', 'nz', 'e', 'ne', 'be', 'nbe', 'a', 'na',
                   's', 'ns', 'p', 'np', 'pe', 'po', 'l', 'nl',
                   'ge', 'nge', 'le', 'nle', 'g', 'ng']

def inverse_conditional_insn(mnemonic: str, base_len: int) -> str:
    return mnemonic[:base_len] + conditional_pairs[conditional_pairs.index(mnemonic[base_len:]) ^ 1]



# allowed prefixes
prefixes = ['lock', 'rep', 'notrack', 'bnd']

def strip_legal_prefixes(mnemonic: str) -> str:
    tokens = mnemonic.split()
    for i, token in enumerate(tokens):
        if token not in prefixes:
            return ' '.join(tokens[i:])
    return ''



# registers
register_promotions = {
    x86.X86_REG_AH:x86.X86_REG_RAX, x86.X86_REG_AL:x86.X86_REG_RAX, x86.X86_REG_AX:x86.X86_REG_RAX, x86.X86_REG_EAX:x86.X86_REG_RAX, 
    x86.X86_REG_BH:x86.X86_REG_RBX, x86.X86_REG_BL:x86.X86_REG_RBX, x86.X86_REG_BX:x86.X86_REG_RBX, x86.X86_REG_EBX:x86.X86_REG_RBX, 
    x86.X86_REG_CH:x86.X86_REG_RCX, x86.X86_REG_CL:x86.X86_REG_RCX, x86.X86_REG_CX:x86.X86_REG_RCX, x86.X86_REG_ECX:x86.X86_REG_RCX, 
    x86.X86_REG_DH:x86.X86_REG_RDX, x86.X86_REG_DL:x86.X86_REG_RDX, x86.X86_REG_DX:x86.X86_REG_RDX, x86.X86_REG_EDX:x86.X86_REG_RDX, 
    x86.X86_REG_SIL:x86.X86_REG_RSI, x86.X86_REG_SI:x86.X86_REG_RSI, x86.X86_REG_ESI:x86.X86_REG_RSI, 
    x86.X86_REG_DIL:x86.X86_REG_RDI, x86.X86_REG_DI:x86.X86_REG_RDI, x86.X86_REG_EDI:x86.X86_REG_RDI, 
    x86.X86_REG_BPL:x86.X86_REG_RBP, x86.X86_REG_BP:x86.X86_REG_RBP, x86.X86_REG_EBP:x86.X86_REG_RBP, 
    x86.X86_REG_SPL:x86.X86_REG_RSP, x86.X86_REG_SP:x86.X86_REG_RSP, x86.X86_REG_ESP:x86.X86_REG_RSP, 
    x86.X86_REG_R8B:x86.X86_REG_R8, x86.X86_REG_R8W:x86.X86_REG_R8, x86.X86_REG_R8D:x86.X86_REG_R8, 
    x86.X86_REG_R9B:x86.X86_REG_R9, x86.X86_REG_R9W:x86.X86_REG_R9, x86.X86_REG_R9D:x86.X86_REG_R9, 
    x86.X86_REG_R10B:x86.X86_REG_R10, x86.X86_REG_R10W:x86.X86_REG_R10, x86.X86_REG_R10D:x86.X86_REG_R10, 
    x86.X86_REG_R11B:x86.X86_REG_R11, x86.X86_REG_R11W:x86.X86_REG_R11, x86.X86_REG_R11D:x86.X86_REG_R11, 
    x86.X86_REG_R12B:x86.X86_REG_R12, x86.X86_REG_R12W:x86.X86_REG_R12, x86.X86_REG_R12D:x86.X86_REG_R12, 
    x86.X86_REG_R13B:x86.X86_REG_R13, x86.X86_REG_R13W:x86.X86_REG_R13, x86.X86_REG_R13D:x86.X86_REG_R13, 
    x86.X86_REG_R14B:x86.X86_REG_R14, x86.X86_REG_R14W:x86.X86_REG_R14, x86.X86_REG_R14D:x86.X86_REG_R14, 
    x86.X86_REG_R15B:x86.X86_REG_R15, x86.X86_REG_R15W:x86.X86_REG_R15, x86.X86_REG_R15D:x86.X86_REG_R15
}

def promote_reg(reg: int) -> int:
    return register_promotions.get(reg, reg)

def involved_regs(insn: cs.CsInsn) -> set[int]:
    read_regs, write_regs = insn.regs_access()
    return set(read_regs).union(set(write_regs))

def involved_big_regs(insn: cs.CsInsn) -> set[int]:
    return {promote_reg(reg) for reg in involved_regs(insn)}



# syscalls supported by the kernel
supported_syscalls = {
    0, # read
    1, # write
    2, # open
    3, # close
    4, # stat
    5, # fstat
    6, # lstat
    8, # lseek
    9, # mmap
    10, # mprotect
    14, # rt_sigprocmask
    16, # ioctl
    20, # writev
    28, # madvise
    39, # getpid
    40, # sendfile
    41, # socket
    44, # sendto
    45, # recvfrom
    49, # bind
    54, # setsockopt
    # 56, # clone
    60, # exit
    61, # wait4
    72, # fcntl
    80, # chdir
    83, # mkdir
    87, # unlink
    89, # readlink
    92, # chown
    95, # umask
    96, # gettimeofday
    107, # geteuid
    109, # setpgid
    110, # getppid
    161, # chroot
    201, # time
    202, # futex
    217, # getdents64
    228, # clock_gettime
    231, # exit_group
    232, # epoll_wait
    233, # epoll_ctl
    235, # utimes
    257, # openat
    262, # newfstatat
    270, # pselect6
    273, # set_robust_list
    280, # utimenset
    283, # timerfd_create
    286, # timerfd_settime
    288, # accept4
    291, # epoll_create1
}



def is_insn_supported(insn: cs.CsInsn) -> bool:
    mnemonic = strip_legal_prefixes(insn.mnemonic)
    opcode_legal = mnemonic in normal_insns \
                   or mnemonic in special_insns \
                   or (mnemonic[:1] == 'j' and mnemonic[1:] in conditional_pairs) \
                   or (mnemonic[:3] == 'set' and mnemonic[3:] in conditional_pairs) \
                   or (mnemonic[:4] == 'cmov' and mnemonic[4:] in conditional_pairs)
    no_gs_segment = x86.X86_REG_GS not in involved_regs(insn)
    return opcode_legal and no_gs_segment
