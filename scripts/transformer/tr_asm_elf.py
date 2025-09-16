import tempfile, subprocess, os, textwrap
import capstone as cs
import lief

disassembler = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
disassembler.detail = True



def read_section_bytes_from_file(elf_path: str, section_name: str) -> bytes:
    # Due to a weird bug in Capstone library (I think),
    # we need to do this from external Python script
    sec_to_hex_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'section_to_hex.py')

    resp = subprocess.run([sec_to_hex_path, elf_path, section_name], capture_output=True, text=True)
    assert resp.returncode == 0

    return bytes([int(b, base=16) for b in textwrap.wrap(resp.stdout, width=2)])

def assemble(asm_code: str, section_name: str) -> bytes:
    # Assemble the code using NASM.
    # Temporary files are not deleted for debug

    with tempfile.NamedTemporaryFile('w', suffix='.asm', delete=False) as asm_file:
        asm_path = asm_file.name
        asm_file.write(asm_code)

    fd, elf_path = tempfile.mkstemp(suffix='.elf')
    os.close(fd)
    print(f"Assembling {asm_path} -> {elf_path}")

    resp = subprocess.run(['nasm', '-f', 'elf64', '-o', elf_path, asm_path])
    assert resp.returncode == 0
    
    return read_section_bytes_from_file(elf_path, section_name)



def disassemble_single_insn(code_sections:dict[str, (int, int, bytearray)], va: int):
    # find containing section
    for name, (start, size, data) in code_sections.items():
        if start <= va < start+size:
            sec_start, sec_content, sec_name = start, data, name
            break

    # disassemble
    insn_bytes = sec_content[va-sec_start:va-sec_start+15] # probably contains more than just one instruction but it's ok
    insn = next(disassembler.disasm(insn_bytes, va, 1))
    insn.section = sec_name
    return insn



def update_section_content(section: lief.ELF.Section, data: bytes, va: int):
    # Replace fragment of section content with given bytes.
    # Position is given as a virtual address

    content = bytearray(section.content)
    content[va-section.virtual_address:va-section.virtual_address+len(data)] = data
    section.content = content
