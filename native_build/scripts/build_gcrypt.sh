#!/bin/bash
set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/env_setup.sh"

GPG_Error_Ver="1.50"
Gcrypt_Ver="1.11.0"

EXTERNAL_DIR="$PROJECT_ROOT/native_build/external"

mkdir -p "$EXTERNAL_DIR"

# ================= libgpg-error =================
echo "[INFO] Building libgpg-error $GPG_Error_Ver..."
cd "$EXTERNAL_DIR"
if [ ! -d "libgpg-error-$GPG_Error_Ver" ]; then
    wget -c "https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-$GPG_Error_Ver.tar.bz2"
    tar -xf "libgpg-error-$GPG_Error_Ver.tar.bz2"
fi
cd "libgpg-error-$GPG_Error_Ver"

# The pinned source archive includes the Android lock-object definitions.
if [ ! -f src/syscfg/lock-obj-pub.aarch64-linux-android.h ]; then
    echo "Missing Android lock-object header; use the pinned native source archive." >&2
    exit 1
fi

# Fix weak threads issue (Termux hack)
sed -i 's/\<USE_POSIX_THREADS_WEAK\>/DONT_USE_POSIX_THREADS_WEAK/g' configure

if [ ! -f "Makefile" ]; then
    ./configure --host=$TARGET_HOST --prefix=$INSTALL_DIR \
        --disable-doc --disable-tests --disable-nls --disable-languages
fi

make -j$(nproc)
make install

# ================= libgcrypt =================
echo "[INFO] Building libgcrypt $Gcrypt_Ver..."
cd "$EXTERNAL_DIR"
if [ ! -d "libgcrypt-$Gcrypt_Ver" ]; then
    wget -c "https://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-$Gcrypt_Ver.tar.bz2"
    tar -xf "libgcrypt-$Gcrypt_Ver.tar.bz2"
fi
cd "libgcrypt-$Gcrypt_Ver"

# Patch: potentially needed for hardcoded paths, but we try standard first
# We link against our libgpg-error

if [ ! -f "Makefile" ]; then
    ./configure --host=$TARGET_HOST --prefix=$INSTALL_DIR \
        --with-libgpg-error-prefix=$INSTALL_DIR \
        --disable-doc --disable-tests \
        --disable-asm  # Disable asm to avoid potential NDK assembler issues for now
fi

make -j$(nproc)
make install
