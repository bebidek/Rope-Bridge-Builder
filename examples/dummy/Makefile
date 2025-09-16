all: old_dummy new_dummy

old_dummy: dummy.cpp
	gcc-14 -static -O2 -g -I ../../libs/installed_libs/include -L ../../libs/installed_libs/lib -o $@ $^

new_dummy_raw: dummy.cpp ../../asm/placeholder.o
	gcc-14 -static -O2 -g -I ../../libs/installed_libs/include -L ../../libs/installed_libs/lib -o $@ $^

nodes.txt: new_dummy_raw
	../../scripts/find_nodes.py $< > $@

chains.txt: new_dummy_raw nodes.txt
	../../valgrind/output/bin/valgrind --tool=syscall_tracker --pos-file=nodes.txt --out-file=$@ --seg-len=1024 ./new_dummy_raw 100

new_dummy: new_dummy_raw chains.txt
	../../scripts/transformer.py new_dummy_raw chains.txt new_dummy

clean:
	rm -f old_dummy new_dummy_raw nodes.txt chains.txt new_dummy

.PHONY: clean all
.DELETE_ON_ERROR:
