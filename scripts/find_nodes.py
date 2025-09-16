#!/usr/bin/env python3
# This script scans executable sections of an ELF file and
# prints all addresses of 'syscall' instructions.
# Since this byte sequence might be a part of different instruction(s),
# there will be false positives, but it's OK.
import sys, lief

filename = sys.argv[1]
result = []

elf : lief.ELF.Binary = lief.ELF.parse(filename)

for section in elf.sections:
    if section.has(lief.ELF.Section.FLAGS.EXECINSTR):
        addr = section.virtual_address
        print(f'Processing section {section.name} (offset {hex(addr)})', file=sys.stderr)
        cnt = 0
        data = section.content
        for i in range(len(data)-1):
            if data[i:i+2] == b'\x0F\x05':
                result.append(addr + i)
                cnt += 1
        print(f'\tpotential nodes found: {cnt}', file=sys.stderr)

print(len(result))
for entry in result:
    print(entry)