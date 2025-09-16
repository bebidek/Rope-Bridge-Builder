#!/bin/bash
# build procedure is based on https://wiki.archlinux.org/title/Kernel/Traditional_compilation
[ "$(id -u)" = 0 ] || { echo "This must be run as root!" >&2; exit; }
[ -n "${SUDO_USER}" ] || { echo "This must be run using sudo!" >&2; exit; }
set -e -x

sudo -u "${SUDO_USER}" bash -c "
    set -e -x
    curl -o linux-6.10.tar.xz https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.10.tar.xz
    unxz linux-6.10.tar.xz # we keep this file for Busybox benchmark
    tar xf linux-6.10.tar
    mv linux-6.10 linux_kernel
"
chown -R "${SUDO_USER}:${SUDO_USER}" linux_kernel

sudo -u "${SUDO_USER}" bash -c "
    set -e -x
    cd linux_kernel
    make mrproper
    patch -p1 < ../patches/kernel.patch
    cp ../patches/kernel.config .config
    make CC=\"gcc -std=gnu11\" \"-j$(nproc)\"
    make modules CC=\"gcc -std=gnu11\" \"-j$(nproc)\"
"

cd linux_kernel
make modules_install CC="gcc -std=gnu11" "-j$(nproc)"
cp -v arch/x86/boot/bzImage "/boot/vmlinuz-linux-6.10.0"
cp -v System.map "/boot/System.map-linux-6.10.0"
mkinitcpio -k 6.10.0 -g "/boot/initramfs-linux-6.10.0.img"
grub-mkconfig -o /boot/grub/grub.cfg
