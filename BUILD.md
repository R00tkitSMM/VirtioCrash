# Build & run

End-to-end recipe to take a fresh QEMU clone, drop in this repo, and
get fuzzing.

## 1. Prerequisites

### 1a. System packages

#### macOS (arm64 -- Apple Silicon)

```sh
brew install llvm protobuf abseil pixman glib gnutls capstone \
             pkg-config zstd ninja meson
```

`meson.build` uses Homebrew's stable `opt/<formula>` symlinks (e.g.
`/opt/homebrew/opt/llvm`, `/opt/homebrew/opt/protobuf`), so a routine
`brew upgrade` won't break the build. If your Homebrew lives somewhere
other than `/opt/homebrew` (Intel mac → `/usr/local`; linuxbrew →
`/home/linuxbrew/.linuxbrew`), set `BREW_PREFIX`:

```sh
export BREW_PREFIX=/usr/local                # Intel mac example
```

#### Linux (x86_64 / aarch64)

```sh
sudo apt install clang lld llvm-dev libprotobuf-dev protobuf-compiler \
                 libabsl-dev libpixman-1-dev libglib2.0-dev \
                 libgnutls28-dev libcapstone-dev ninja-build meson \
                 pkg-config zstd python3
```

If your distro splits abseil into separate packages, you may also need
`libabsl-log-dev` etc. -- protobuf 7.34+ inlines abseil-logging into its
headers.

### 1b. libprotobuf-mutator (from source)

The `meson.build` expects LPM as **static archives** built from source --
not the Homebrew formula -- because we link against the exact `.a` files
LPM produces. Pick a directory and build:

```sh
git clone https://github.com/google/libprotobuf-mutator.git \
          ~/libprotobuf-mutator
cd ~/libprotobuf-mutator && mkdir -p build && cd build
cmake .. -GNinja -DCMAKE_BUILD_TYPE=Release \
         -DLIB_PROTO_MUTATOR_TESTING=OFF \
         -DLIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=OFF
ninja
# This produces:
#   ~/libprotobuf-mutator/build/src/libprotobuf-mutator.a
#   ~/libprotobuf-mutator/build/src/libfuzzer/libprotobuf-mutator-libfuzzer.a
```

Default location the build expects: `$HOME/libprotobuf-mutator`. Override
with `LPM_ROOT`:

```sh
export LPM_ROOT=/somewhere/else/libprotobuf-mutator
```

### 1c. Compiler

QEMU's build is configured against Homebrew clang/lld 22+ because Apple
`/usr/bin/clang` doesn't ship `libclang_rt.fuzzer_osx.a`. On Linux, the
distro `clang` package usually works -- if `clang -fsanitize=fuzzer-no-link`
fails, `apt install libclang-rt-dev` (or distro equivalent).

`build.sh` prepends `${LLVM_PREFIX}/bin` (default `/opt/homebrew/opt/llvm`)
to PATH automatically. Override with:

```sh
LLVM_PREFIX=/usr ~/qemu-virtio-protofuzz/build.sh ~/qemu     # Linux distro clang
```

## 2. Drop the files into a QEMU tree

```sh
git clone https://gitlab.com/qemu-project/qemu.git ~/qemu
~/qemu-virtio-protofuzz/apply.sh ~/qemu
```

`apply.sh` is a typed `cp -r`. It backs up the 5 files it overwrites
(fuzz.c / fuzz.h / meson.build / qtest_wrappers.c / libqtest.c) into
`~/qemu/.proto-fuzz-backup-<unix-timestamp>/` so you can roll back.

`apply.sh ~/qemu --dry-run` lists what would be copied without writing.

## 3. Build

```sh
~/qemu-virtio-protofuzz/build.sh ~/qemu
```

This configures `~/qemu/build-fuzz/` for `aarch64-softmmu` only with
`--enable-fuzzing`, then runs `ninja qemu-fuzz-aarch64`. First build is
~5 minutes; subsequent rebuilds are seconds.

If your LLVM lives somewhere other than `/opt/homebrew/opt/llvm`:

```sh
LLVM_PREFIX=/your/llvm/prefix ~/qemu-virtio-protofuzz/build.sh ~/qemu
```

## 4. Generate a seed corpus

```sh
python3 ~/qemu/scripts/oss-fuzz/gen_virtio_net_corpus.py \
        -o /tmp/corpus_net --clean              # all 26 base seeds
python3 ~/qemu/scripts/oss-fuzz/gen_virtio_gpu_corpus.py \
        -o /tmp/corpus_gpu --clean -n 100       # 13 base + 87 perturbations
python3 ~/qemu/scripts/oss-fuzz/gen_virtio_blk_corpus.py \
        -o /tmp/corpus_blk --clean
```

Each generator writes text-format proto seeds. The harness loads them
with `LoadProtoInput(binary=false, ...)` so they're directly mutatable
by LPM at the proto level.

## 5. Run

```sh
~/qemu/build-fuzz/qemu-fuzz-aarch64 \
    --fuzz-target=proto-fuzz-virtio-net \
    -close_fd_mask=2 -max_len=65536 \
    /tmp/corpus_net
```

Useful libFuzzer flags:

| Flag                  | What it does |
|--|--|
| `-runs=N`             | cap iterations (default: forever) |
| `-max_total_time=S`   | wall-clock cap, seconds |
| `-jobs=N -workers=N`  | parallel processes that share the corpus dir |
| `-print_funcs=N`      | print up to N new-PC function names per coverage event |
| `-rss_limit_mb=N`     | OOM threshold (default 2048) |
| `-artifact_prefix=P`  | filename prefix for crash files |

## 6. Verify the harness is hitting device code

A rising `cov:` counter is not enough -- some of that comes from the
proto parser and the harness itself. Set a breakpoint on a known
device-side function and confirm it fires:

```sh
lldb -b \
  -o "process handle -p true -s false SIGUSR2" \
  -o "br set -n virtio_net_handle_ctrl" \
  -o "run --fuzz-target=proto-fuzz-virtio-net -close_fd_mask=2 \
          -runs=20 /tmp/corpus_net" \
  ~/qemu/build-fuzz/qemu-fuzz-aarch64
```

You should see `stop reason = breakpoint 1.1` inside the first ~20
runs of any seed that contains a `ctrl_cmd` op. (If it never fires,
see ARCHITECTURE.md Section 13 for the three classic harness bugs --
all three are already fixed in this repo.)

## 7. macOS only -- copying the binary elsewhere

Plain `cp` on this machine drags `com.apple.FinderInfo` and
`com.apple.ResourceFork` xattrs onto the destination, which invalidates
the ad-hoc signature and makes the kernel SIGKILL the binary at exec.
After every `cp` of `qemu-fuzz-aarch64`:

```sh
xattr -c                  ~/somewhere/qemu-fuzz-aarch64
codesign --force --sign - ~/somewhere/qemu-fuzz-aarch64
```

## 8. Building a crash reproducer

When the fuzzer drops a `crash-<sha1>` file, you can replay it under a
clean qemu-system-aarch64 by serializing the qtest commands:

```sh
FUZZ_SERIALIZE_QTEST=1 QTEST_LOG=1 \
    ~/qemu/build-fuzz/qemu-fuzz-aarch64 \
        --fuzz-target=proto-fuzz-virtio-blk \
        ./crash-<sha1>  &> /tmp/trace
~/qemu/scripts/oss-fuzz/reorder_fuzzer_qtest_trace.py /tmp/trace \
    > /tmp/reproducer
qemu-system-aarch64 <args from top of /tmp/trace> \
    -qtest stdio < /tmp/reproducer
```

Every line in `/tmp/reproducer` is a write to the same MMIO register
a Linux `virtio_mmio.c` driver would write -- one step from a
guest-driver reproducer.

## 9. Rolling back

If something is wrong and you want to revert to upstream:

```sh
cd ~/qemu
git checkout -- tests/qtest/fuzz/{fuzz.c,fuzz.h,meson.build,qtest_wrappers.c} \
                 tests/qtest/libqtest.c
rm -f tests/qtest/fuzz/proto_fuzz_virtio_*.{cc,proto}
rm -f tests/qtest/fuzz/PROTO_FUZZ_ARCHITECTURE.md
rm -f scripts/oss-fuzz/gen_virtio_*_corpus.py
```

Or restore from the timestamped backup `apply.sh` made for you:

```sh
ls ~/qemu/.proto-fuzz-backup-*/         # list backups
cp -R ~/qemu/.proto-fuzz-backup-<ts>/*  ~/qemu/
```
