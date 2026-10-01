#!/bin/bash
set -e

cd ../hostapd
make clean
cp defconfig .config
make -j 2
