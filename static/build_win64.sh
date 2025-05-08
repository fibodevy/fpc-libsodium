#!/bin/bash
wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.20.tar.gz
tar -xvzf libsodium-1.0.20.tar.gz
rm -f libsodium-1.0.20.tar.gz
cd libsodium-1.0.20
export CFLAGS="-O3 -fomit-frame-pointer -m64 -march=westmere"
./configure --host=x86_64-w64-mingw32
make
cp -f src/libsodium/.libs/libsodium.a ../win64/libsodium.a
cd ..
rm -rf libsodium-1.0.20
