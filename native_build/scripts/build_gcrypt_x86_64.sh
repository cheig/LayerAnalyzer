#!/bin/bash
# 任务2: x86_64 安全库编译 (libgpg-error + libgcrypt)
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source "$SCRIPT_DIR/env_setup_x86_64.sh"

GPG_Error_Ver="1.50"
Gcrypt_Ver="1.11.0"

EXTERNAL_DIR="$PROJECT_ROOT/native_build/external"

# ================= libgpg-error =================
echo "================================================================"
echo "[TASK2] Building libgpg-error $GPG_Error_Ver for x86_64..."
echo "================================================================"
cd "$EXTERNAL_DIR/libgpg-error-$GPG_Error_Ver"

# 清理之前的构建
make distclean || make clean || true

# 创建 x86_64 Android 的 lock-obj 文件
# 从 x86_64-unknown-linux-gnu.h 复制，结构兼容
# 需要创建所有可能的文件名变体
echo "Creating lock-obj-pub files for x86_64-linux-android..."
cp src/syscfg/lock-obj-pub.x86_64-unknown-linux-gnu.h src/syscfg/lock-obj-pub.x86_64-linux-android.h
cp src/syscfg/lock-obj-pub.x86_64-unknown-linux-gnu.h src/syscfg/lock-obj-pub.x86_64-pc-linux-android.h
cp src/syscfg/lock-obj-pub.x86_64-unknown-linux-gnu.h src/syscfg/lock-obj-pub.linux-android.h
cp src/syscfg/lock-obj-pub.x86_64-unknown-linux-gnu.h src/syscfg/lock-obj-pub.android.h

# Fix weak threads issue (Termux hack)
sed -i 's/\<USE_POSIX_THREADS_WEAK\>/DONT_USE_POSIX_THREADS_WEAK/g' configure

./configure \
  --host=$TARGET_HOST \
  --prefix=$INSTALL_DIR \
  --enable-shared \
  --disable-static \
  --disable-doc \
  --disable-tests \
  --disable-nls \
  --disable-languages

make -j$(nproc)
make install

echo "[OK] libgpg-error installed to $INSTALL_DIR"

# ================= libgcrypt =================
echo "================================================================"
echo "[TASK2] Building libgcrypt $Gcrypt_Ver for x86_64..."
echo "================================================================"
cd "$EXTERNAL_DIR/libgcrypt-$Gcrypt_Ver"

# 清理之前的构建
make distclean || make clean || true

./configure \
  --host=$TARGET_HOST \
  --prefix=$INSTALL_DIR \
  --enable-shared \
  --disable-static \
  --with-libgpg-error-prefix=$INSTALL_DIR \
  --disable-doc \
  --disable-asm

make -j$(nproc)
make install

echo "[OK] libgcrypt installed to $INSTALL_DIR"

# ================= 验证 =================
echo "================================================================"
echo "[TASK2] Verification..."
echo "================================================================"
echo "--- libgpg-error.so ---"
file $INSTALL_DIR/lib/libgpg-error.so* || echo "libgpg-error.so not found"
echo ""
echo "--- libgcrypt.so ---"
file $INSTALL_DIR/lib/libgcrypt.so* || echo "libgcrypt.so not found"
echo ""
echo "================================================================"
echo "[TASK2] Security libraries build complete!"
echo "================================================================"
