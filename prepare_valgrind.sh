#!/bin/bash
[ -d valgrind ] && { echo "Valgrind directory already exists!"; exit 1; }
set -e
mkdir -p /tmp/rbb/

vg_name_ver="valgrind-3.23.0"
curl -o /tmp/rbb/${vg_name_ver}.tar.bz2 https://sourceware.org/pub/valgrind/${vg_name_ver}.tar.bz2
tar xf /tmp/rbb/${vg_name_ver}.tar.bz2
mv ${vg_name_ver} valgrind

cd valgrind
patch -p1 < ../patches/valgrind.patch
./autogen.sh
./configure --enable-only64bit --prefix="${PWD}/output/"
make "-j$(nproc)"
make install
