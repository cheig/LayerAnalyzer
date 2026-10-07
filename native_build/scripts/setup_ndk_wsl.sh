#!/bin/bash
set -e

NDK_VER="r27"
NDK_FULL_VER="27.0.12077973"
NDK_ZIP="android-ndk-$NDK_VER-linux.zip"
NDK_URL="https://dl.google.com/android/repository/$NDK_ZIP"

cd ~
if [ ! -d "android-ndk-$NDK_VER" ]; then
    echo "Downloading Linux NDK $NDK_VER..."
    wget -q --show-progress "$NDK_URL"
    echo "Extracting NDK..."
    unzip -q "$NDK_ZIP"
    rm "$NDK_ZIP"
fi

echo "Linux NDK is ready at: $HOME/android-ndk-$NDK_VER"
