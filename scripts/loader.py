#!/usr/bin/env python3
# This script takes an ELF file containing RBB sections
# and loads the blob into the kernel (by calling 'rbb_setup' syscall)
import sys, lief
from ctypes import *

# read ELF and extract blob section
elf_path = sys.argv[1]
elf : lief.ELF.Binary = lief.ELF.parse(elf_path)
blob_section : lief.ELF.Section = elf.get_section('.blob.rbb')
if blob_section is None:
    sys.exit('Provided ELF binary doesn\'t have required section')

blob = bytes(blob_section.content)
print(f'Blob size: {len(blob)} bytes')

# Call syscall 470 'rbb_setup'
syscall_func = CDLL(None).syscall
resp = syscall_func(470, pointer(create_string_buffer(blob)), c_size_t(len(blob)))
print(f'Loading finished {"successfuly" if resp==0 else "with failure"}')
