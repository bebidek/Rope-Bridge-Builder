placeholder.o: placeholder.asm
	nasm -f elf64 -o $@ $<
	../scripts/add_tls_reloc.py $@

clean:
	rm -f placeholder.o

.PHONY: clean
.DELETE_ON_ERROR: