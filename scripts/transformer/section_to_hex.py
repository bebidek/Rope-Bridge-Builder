#!/usr/bin/env python3
import sys, lief

elf_path = sys.argv[1]
section_name = sys.argv[2]
elf : lief.ELF.Binary = lief.ELF.parse(elf_path)
section = elf.get_section(section_name)

print(section.content.hex(), end='')
