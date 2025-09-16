bb_name_ver = busybox-1.37.0
all: old_busybox new_busybox

$(bb_name_ver).tar:
	wget https://www.busybox.net/downloads/$(bb_name_ver).tar.bz2
	bunzip2 $(bb_name_ver).tar.bz2

old_busybox new_busybox_raw: $(bb_name_ver).tar
	rm -fr old_busybox_source new_busybox_source
	tar xf $(bb_name_ver).tar
	mv $(bb_name_ver) old_busybox_source
	tar xf $(bb_name_ver).tar
	mv $(bb_name_ver) new_busybox_source

	cp -v ../../patches/busybox_old.config old_busybox_source/.config
	make -C old_busybox_source "-j`nproc`"
	cp -v old_busybox_source/busybox old_busybox

	cp -v ../../patches/busybox_new.config new_busybox_source/.config
	make -C new_busybox_source "-j`nproc`"
	cp -v new_busybox_source/busybox_unstripped new_busybox_raw

new_busybox_raw: old_busybox

nodes.txt: new_busybox_raw
	../../scripts/find_nodes.py $< > $@

chains.txt: new_busybox_raw nodes.txt $(bb_name_ver).tar
	ln -s new_busybox_raw busybox
	../../valgrind/output/bin/valgrind --tool=syscall_tracker --pos-file=nodes.txt --out-file=$@ --seg-len=1024 ./busybox tar xf $(bb_name_ver).tar
	rm -r $(bb_name_ver)
	unlink busybox

new_busybox: new_busybox_raw chains.txt
	../../scripts/transformer.py new_busybox_raw chains.txt new_busybox

clean:
	rm -rf old_busybox_source new_busybox_source old_busybox new_busybox_raw nodes.txt chains.txt new_busybox $(bb_name_ver).tar

.PHONY: clean all
.DETETE_ON_ERROR:
