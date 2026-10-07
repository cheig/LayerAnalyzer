#!/bin/bash
set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

echo "Starting Build for all Task 1.2 dependencies..."

bash "$SCRIPT_DIR/build_libiconv.sh"
bash "$SCRIPT_DIR/build_libffi.sh"
bash "$SCRIPT_DIR/build_zlib.sh"
bash "$SCRIPT_DIR/build_pcre2.sh"

echo "All Task 1.2 dependencies built successfully!"
