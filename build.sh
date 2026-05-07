#!/bin/bash
# Configure + build qemu-fuzz-aarch64 in a QEMU tree that has already
# had this repo's files applied (run apply.sh first, or copy by hand).
#
# Usage:
#   ./build.sh                       # default: build in ~/qemu/build-fuzz
#   ./build.sh /path/to/qemu         # build in <qemu>/build-fuzz
#   ./build.sh /path/to/qemu /path/to/build  # custom build dir
#
# Honors these env vars:
#   LLVM_PREFIX   path to LLVM (default: /opt/homebrew/opt/llvm)
#   BREW_PREFIX   path to Homebrew     (default: /opt/homebrew)
#   LPM_ROOT      path to a built libprotobuf-mutator
#                 (default: $HOME/libprotobuf-mutator)
#
# All three are also propagated into meson via the environment so the
# parameterized meson.build picks them up on first configure AND on any
# later reconfigure triggered by editing meson.build.

set -e

QEMU_DIR="${1:-$HOME/qemu}"
BUILD_DIR="${2:-$QEMU_DIR/build-fuzz}"
LLVM_PREFIX="${LLVM_PREFIX:-/opt/homebrew/opt/llvm}"
export BREW_PREFIX="${BREW_PREFIX:-/opt/homebrew}"
export LPM_ROOT="${LPM_ROOT:-$HOME/libprotobuf-mutator}"

if [[ ! -d "$QEMU_DIR" ]]; then
    echo "ERROR: $QEMU_DIR does not exist" >&2
    exit 1
fi
if [[ ! -f "$QEMU_DIR/configure" ]]; then
    echo "ERROR: $QEMU_DIR/configure missing -- not a QEMU tree?" >&2
    exit 1
fi
if [[ ! -d "$LLVM_PREFIX/bin" ]]; then
    echo "ERROR: LLVM_PREFIX=$LLVM_PREFIX has no bin/ dir." >&2
    echo "       Install with: brew install llvm" >&2
    echo "       Or override with: LLVM_PREFIX=/your/llvm $0 ..." >&2
    exit 1
fi
if [[ ! -f "$LPM_ROOT/build/src/libprotobuf-mutator.a" ]]; then
    echo "ERROR: $LPM_ROOT/build/src/libprotobuf-mutator.a not found." >&2
    echo "       Build it first:" >&2
    echo "         git clone https://github.com/google/libprotobuf-mutator.git $LPM_ROOT" >&2
    echo "         cd $LPM_ROOT && mkdir -p build && cd build" >&2
    echo "         cmake .. -GNinja -DCMAKE_BUILD_TYPE=Release \\" >&2
    echo "                  -DLIB_PROTO_MUTATOR_TESTING=OFF" >&2
    echo "         ninja" >&2
    echo "       Or set LPM_ROOT=/path/to/built/libprotobuf-mutator" >&2
    exit 1
fi

export PATH="$LLVM_PREFIX/bin:$PATH"
# CC / CXX are needed even on reconfigure (when meson re-detects the
# compiler). Without them the cached -fsanitize=fuzzer support test
# fails against Apple /usr/bin/clang.
export CC="$LLVM_PREFIX/bin/clang"
export CXX="$LLVM_PREFIX/bin/clang++"

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

if [[ ! -f build.ninja ]]; then
    echo "Configuring (first build) in $BUILD_DIR ..."
    echo "  LLVM_PREFIX=$LLVM_PREFIX"
    echo "  BREW_PREFIX=$BREW_PREFIX"
    echo "  LPM_ROOT=$LPM_ROOT"
    "$QEMU_DIR/configure" \
        --enable-fuzzing \
        --enable-asan \
        --target-list=aarch64-softmmu \
        --cc="$CC" \
        --cxx="$CXX"
fi

echo "Building qemu-fuzz-aarch64 ..."
ninja qemu-fuzz-aarch64

echo
echo "Built: $BUILD_DIR/qemu-fuzz-aarch64"
echo
echo "Quick test:"
echo "  python3 $QEMU_DIR/scripts/oss-fuzz/gen_virtio_net_corpus.py \\"
echo "    -o /tmp/corpus_net --clean"
echo "  $BUILD_DIR/qemu-fuzz-aarch64 \\"
echo "    --fuzz-target=proto-fuzz-virtio-net \\"
echo "    -close_fd_mask=2 /tmp/corpus_net"
