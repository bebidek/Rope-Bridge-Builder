section .text.rbb progbits alloc exec nowrite align=16
text_rbb_chunk_begin:
times 1024*16 db 0

section .tdata.rbb progbits alloc noexec write align=4
tdata_rbb_chunk_begin:
times 64 db 0

section .rodata.rbb progbits alloc noexec nowrite align=4
rodata_rbb_chunk_begin:
dq 0
