#!/bin/bash
[ "$(id -u)" = 0 ] || { echo "This must be run as root!" >&2; exit; }
[ -n "${SUDO_USER}" ] || { echo "This must be run using sudo!" >&2; exit; }
set -e -x

# install necessary packages
pacman -Syu --noconfirm
pacman -S --needed --noconfirm base-devel gcc14 xmlto kmod inetutils bc libelf git cpio perl tar xz python3 nasm python-pip wget

# prepare python venv
sudo -u "${SUDO_USER}" bash -c "
    set -e -x
    python3 -m venv rbb_venv
    source rbb_venv/bin/activate
    pip3 install lief
    pip3 install capstone
    pip3 install tftpy
    pip3 install py-cpuinfo
    deactivate
"
