all: old_uftpd new_uftpd

old_uftpd new_uftpd_raw:
	rm -fr old_uftpd_source new_uftpd_source
	wget https://github.com/troglobit/uftpd/releases/download/v2.15/uftpd-2.15.tar.xz
	tar xf uftpd-2.15.tar.xz
	mv uftpd-2.15 old_uftpd_source
	tar xf uftpd-2.15.tar.xz
	mv uftpd-2.15 new_uftpd_source

	(cd old_uftpd_source && ./configure CC="gcc-14" PKG_CONFIG_LIBDIR="../../../libs/installed_libs/lib/pkgconfig" LDFLAGS="-static")
	make -C old_uftpd_source "-j`nproc`"
	cp -v old_uftpd_source/src/uftpd old_uftpd

	(cd new_uftpd_source && ./configure CC="gcc-14" PKG_CONFIG_LIBDIR="../../../libs/installed_libs/lib/pkgconfig" LDFLAGS="-static $(realpath ../../asm/placeholder.o)")
	make -C new_uftpd_source "-j`nproc`"
	cp -v new_uftpd_source/src/uftpd new_uftpd_raw

new_uftpd_raw: old_uftpd

nodes.txt: new_uftpd_raw
	../../scripts/find_nodes.py $< > $@

chains.txt: new_uftpd_raw nodes.txt
	./gen_chains.py

new_uftpd: new_uftpd_raw chains.txt
	../../scripts/transformer.py new_uftpd_raw chains.txt new_uftpd

clean:
	rm -rf uftpd-2.15.tar.xz old_uftpd_source new_uftpd_source old_uftpd new_uftpd_raw nodes.txt chains.txt new_uftpd

.PHONY: clean all
.DELETE_ON_ERROR:
