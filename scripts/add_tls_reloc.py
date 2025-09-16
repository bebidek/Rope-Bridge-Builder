#!/usr/bin/env python3
import lief, sys, struct

elf_path = sys.argv[1]

# open ELF file
elf : lief.ELF.Binary = lief.ELF.parse(elf_path)
tdata_rbb_symbol_id : lief.ELF.Symbol = elf.symtab_idx("tdata_rbb_chunk_begin")
if tdata_rbb_symbol_id == -1:
    sys.exit("Symbol tdata_rbb_chunk_begin not found")

# find important fragments
rodata_rbb_section, rodata_rbb_section_id = None, None
symtab_section, symtab_section_id = None, None
for i, sec in enumerate(elf.sections):
    if sec.name == '.rodata.rbb':
        rodata_rbb_section = sec
        rodata_rbb_section_id = i
    elif sec.name == '.symtab':
        symtab_section = sec
        symtab_section_id = i
if rodata_rbb_section is None:
    sys.exit("Section .rodata.rbb not found")
if symtab_section_id is None:
    sys.exit("Section .symtab not found")
if elf.has_section(".rela.rodata.rbb"):
    sys.exit("Section .rela.rodata.rbb already present")

# create RELA section
rela_section = lief.ELF.Section(".rela.rodata.rbb", lief.ELF.Section.TYPE.RELA)
rela_section.entry_size = 0x18
rela_section.add(lief.ELF.Section.FLAGS.INFO_LINK)
rela_section.information = rodata_rbb_section_id
rela_section.link = symtab_section_id
elf.add(rela_section, loaded=False)

# add placeholder relocation
rel = lief.ELF.Relocation(0, lief.ELF.Relocation.TYPE.X86_64_TPOFF32, lief.ELF.Relocation.ENCODING.RELA)
rel.symbol = elf.get_symbol('tdata_rbb_chunk_begin')
rel.addend = 0
elf.add_object_relocation(rel, rodata_rbb_section)
elf.write(sys.argv[1])

# find RELA section address
rela_offset = elf.get_section('.rela.rodata.rbb').offset

# open ELF manually and set actual relocation
with open(elf_path, 'rb+') as raw_elf:
    raw_elf.seek(rela_offset)
    raw_elf.write(struct.pack('<QQQ', 0, 0x17 | (tdata_rbb_symbol_id<<32), 0))
