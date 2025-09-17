#!/bin/bash
[ -d libs ] && { echo "Libs directory already exists!"; exit 1; }
set -e
mkdir -p libs
cd libs

# GLIBC
wget https://ftp.man.poznan.pl/gnu/glibc/glibc-2.40.tar.xz 
tar xf glibc-2.40.tar.xz
cd glibc-2.40
mkdir build
cd build
../configure CC="gcc-14" "--prefix=$(realpath ../../installed_libs)"
make -j$(nproc)
make install
cd ../..

# LIBUEV
wget https://github.com/troglobit/libuev/releases/download/v2.4.1/libuev-2.4.1.tar.xz
tar xf libuev-2.4.1.tar.xz
cd libuev-2.4.1
mkdir build
cd build
../configure CC="gcc-14" CFLAGS="-O2 -g -I$(realpath ../../installed_libs/include)" LDFLAGS="-L$(realpath ../../installed_libs/lib)" --prefix="$(realpath ../../installed_libs)"
make -j$(nproc)
make install
cd ../..

# LIBITE
wget https://github.com/troglobit/libite/releases/download/v2.6.1/libite-2.6.1.tar.xz
tar xf libite-2.6.1.tar.xz
cd libite-2.6.1
mkdir build
cd build
../configure CC="gcc-14" CFLAGS="-O2 -g -I$(realpath ../../installed_libs/include)" LDFLAGS="-L$(realpath ../../installed_libs/lib)" --prefix="$(realpath ../../installed_libs)"
make -j$(nproc)
make install
cd ../..

cd ..
