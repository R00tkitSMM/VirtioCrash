if not get_option('fuzzing')
  subdir_done()
endif

specific_fuzz_ss.add(files('fuzz.c', 'qos_fuzz.c',
                           'qtest_wrappers.c'), qos)

# Targets
specific_fuzz_ss.add(when: 'CONFIG_I440FX', if_true: files('i440fx_fuzz.c'))
specific_fuzz_ss.add(when: 'CONFIG_VIRTIO_NET', if_true: files('virtio_net_fuzz.c'))
specific_fuzz_ss.add(when: 'CONFIG_VIRTIO_SCSI', if_true: files('virtio_scsi_fuzz.c'))
specific_fuzz_ss.add(when: 'CONFIG_VIRTIO_BLK', if_true: files('virtio_blk_fuzz.c'))
specific_fuzz_ss.add(files('generic_fuzz.c'))

# Optional: structured (libprotobuf-mutator) fuzzer for virtio-blk on arm
# virt. Enabled if protoc + brewed protobuf are available and the LPM
# static archives exist at the hardcoded paths below.
protoc      = find_program('protoc', required: false)
fs_mod      = import('fs')
# libprotobuf-mutator: built from source. Override location with the
# LPM_ROOT env var: `LPM_ROOT=/path/to/lpm ../configure ...`
lpm_root    = run_command('sh', '-c',
                          'echo "${LPM_ROOT:-$HOME/libprotobuf-mutator}"',
                          check: true).stdout().strip()
lpm_lib     = lpm_root / 'build/src/libfuzzer/libprotobuf-mutator-libfuzzer.a'
lpm_core    = lpm_root / 'build/src/libprotobuf-mutator.a'
# Homebrew prefix. Override via BREW_PREFIX (Intel mac: /usr/local;
# linuxbrew: /home/linuxbrew/.linuxbrew).
brew_prefix = run_command('sh', '-c',
                          'echo "${BREW_PREFIX:-/opt/homebrew}"',
                          check: true).stdout().strip()
brew_libdir = brew_prefix / 'lib'
brew_incdir = brew_prefix / 'include'

if protoc.found() and \
    fs_mod.exists(lpm_lib) and fs_mod.exists(lpm_core) and \
    fs_mod.exists(brew_libdir / 'libprotobuf.dylib') and \
    add_languages('cpp', native: false, required: false)

  proto_pb = custom_target('proto_fuzz_virtio_blk_pb',
    input: 'proto_fuzz_virtio_blk.proto',
    output: ['proto_fuzz_virtio_blk.pb.cc', 'proto_fuzz_virtio_blk.pb.h'],
    command: [protoc,
              '--cpp_out=@OUTDIR@',
              '--proto_path=' + meson.current_source_dir(),
              meson.current_source_dir() / 'proto_fuzz_virtio_blk.proto'])

  # We compile the C++ harness with a dedicated clang++ invocation rather
  # than letting meson manage the flags. This is to avoid `-I..` (the
  # QEMU source root) appearing on the C++ command line: macOS APFS is
  # case-insensitive, so libc++'s `<version>` header collides with the
  # QEMU root `VERSION` file. With our own command we control the include
  # search order precisely (libc++ first, no QEMU root).
  # Use Homebrew's version-stable opt/ symlinks rather than versioned
  # Cellar/ paths so the recipe survives `brew upgrade`.
  clangxx       = brew_prefix / 'opt/llvm/bin/clang++'
  glib_includes = run_command('pkg-config', '--cflags', 'glib-2.0',
                              check: true).stdout().strip().split()
  # Note: `-fsanitize=fuzzer-no-link` is deliberately NOT in this list.
  # The flag enables SanCov edge instrumentation in any object built
  # with it. We don't want our harness or the auto-generated proto
  # serializer/deserializer code contributing to the `cov:` number --
  # those edges saturate quickly with mutated proto inputs and add
  # noise that makes it hard to tell whether new coverage represents
  # real progress in QEMU's device emulation.
  #
  # QEMU's C code IS still instrumented (the main meson build adds
  # -fsanitize=fuzzer-no-link to qemu_common_flags). ASAN stays on
  # here so allocation bugs in our harness still trip the sanitizer.
  cxx_common = [clangxx, '-c', '-std=c++17', '-O2', '-g',
                '-fPIC', '-fno-omit-frame-pointer',
                '-fsanitize=address',
                '-isysroot', run_command('xcrun', '--show-sdk-path',
                                          check: true).stdout().strip(),
                '-I' + brew_prefix / 'opt/llvm/include/c++/v1',
                '-I' + lpm_root,
                '-I' + lpm_root / 'src',  # for "libfuzzer/libfuzzer_macro.h"
                '-I' + brew_incdir,
                '-I' + meson.current_build_dir()]   # for proto_fuzz_virtio_blk.pb.h
  cxx_common += glib_includes
  cxx_common += ['-Wno-deprecated-declarations',
                 '-Wno-unused-parameter',
                 '-Wno-missing-field-initializers',
                 '-Wno-unused-variable']

  proto_pb_o = custom_target('proto_fuzz_virtio_blk_pb_o',
    input: proto_pb,
    output: 'proto_fuzz_virtio_blk.pb.o',
    command: cxx_common + ['-o', '@OUTPUT@', '@INPUT0@'])

  proto_cc_o = custom_target('proto_fuzz_virtio_blk_cc_o',
    input: ['proto_fuzz_virtio_blk.cc', proto_pb],
    output: 'proto_fuzz_virtio_blk.cc.o',
    command: cxx_common + ['-o', '@OUTPUT@', '@INPUT0@'])

  # virtio-net target: same toolchain, different proto + harness.
  proto_net_pb = custom_target('proto_fuzz_virtio_net_pb',
    input: 'proto_fuzz_virtio_net.proto',
    output: ['proto_fuzz_virtio_net.pb.cc', 'proto_fuzz_virtio_net.pb.h'],
    command: [protoc,
              '--cpp_out=@OUTDIR@',
              '--proto_path=' + meson.current_source_dir(),
              meson.current_source_dir() / 'proto_fuzz_virtio_net.proto'])

  proto_net_pb_o = custom_target('proto_fuzz_virtio_net_pb_o',
    input: proto_net_pb,
    output: 'proto_fuzz_virtio_net.pb.o',
    command: cxx_common + ['-o', '@OUTPUT@', '@INPUT0@'])

  proto_net_cc_o = custom_target('proto_fuzz_virtio_net_cc_o',
    input: ['proto_fuzz_virtio_net.cc', proto_net_pb],
    output: 'proto_fuzz_virtio_net.cc.o',
    command: cxx_common + ['-o', '@OUTPUT@', '@INPUT0@'])

  # virtio-gpu target.
  proto_gpu_pb = custom_target('proto_fuzz_virtio_gpu_pb',
    input: 'proto_fuzz_virtio_gpu.proto',
    output: ['proto_fuzz_virtio_gpu.pb.cc', 'proto_fuzz_virtio_gpu.pb.h'],
    command: [protoc,
              '--cpp_out=@OUTDIR@',
              '--proto_path=' + meson.current_source_dir(),
              meson.current_source_dir() / 'proto_fuzz_virtio_gpu.proto'])

  proto_gpu_pb_o = custom_target('proto_fuzz_virtio_gpu_pb_o',
    input: proto_gpu_pb,
    output: 'proto_fuzz_virtio_gpu.pb.o',
    command: cxx_common + ['-o', '@OUTPUT@', '@INPUT0@'])

  proto_gpu_cc_o = custom_target('proto_fuzz_virtio_gpu_cc_o',
    input: ['proto_fuzz_virtio_gpu.cc', proto_gpu_pb],
    output: 'proto_fuzz_virtio_gpu.cc.o',
    command: cxx_common + ['-o', '@OUTPUT@', '@INPUT0@'])

  # virtio-scsi target.
  proto_scsi_pb = custom_target('proto_fuzz_virtio_scsi_pb',
    input: 'proto_fuzz_virtio_scsi.proto',
    output: ['proto_fuzz_virtio_scsi.pb.cc', 'proto_fuzz_virtio_scsi.pb.h'],
    command: [protoc,
              '--cpp_out=@OUTDIR@',
              '--proto_path=' + meson.current_source_dir(),
              meson.current_source_dir() / 'proto_fuzz_virtio_scsi.proto'])

  proto_scsi_pb_o = custom_target('proto_fuzz_virtio_scsi_pb_o',
    input: proto_scsi_pb,
    output: 'proto_fuzz_virtio_scsi.pb.o',
    command: cxx_common + ['-o', '@OUTPUT@', '@INPUT0@'])

  proto_scsi_cc_o = custom_target('proto_fuzz_virtio_scsi_cc_o',
    input: ['proto_fuzz_virtio_scsi.cc', proto_scsi_pb],
    output: 'proto_fuzz_virtio_scsi.cc.o',
    command: cxx_common + ['-o', '@OUTPUT@', '@INPUT0@'])

  # virtio-fs target (vhost-user, with in-process mock backend).
  proto_fs_pb = custom_target('proto_fuzz_virtio_fs_pb',
    input: 'proto_fuzz_virtio_fs.proto',
    output: ['proto_fuzz_virtio_fs.pb.cc', 'proto_fuzz_virtio_fs.pb.h'],
    command: [protoc,
              '--cpp_out=@OUTDIR@',
              '--proto_path=' + meson.current_source_dir(),
              meson.current_source_dir() / 'proto_fuzz_virtio_fs.proto'])

  proto_fs_pb_o = custom_target('proto_fuzz_virtio_fs_pb_o',
    input: proto_fs_pb,
    output: 'proto_fuzz_virtio_fs.pb.o',
    command: cxx_common + ['-o', '@OUTPUT@', '@INPUT0@'])

  proto_fs_cc_o = custom_target('proto_fuzz_virtio_fs_cc_o',
    input: ['proto_fuzz_virtio_fs.cc', proto_fs_pb],
    output: 'proto_fuzz_virtio_fs.cc.o',
    command: cxx_common + ['-o', '@OUTPUT@', '@INPUT0@'])

  # virtio-snd target.
  proto_snd_pb = custom_target('proto_fuzz_virtio_snd_pb',
    input: 'proto_fuzz_virtio_snd.proto',
    output: ['proto_fuzz_virtio_snd.pb.cc', 'proto_fuzz_virtio_snd.pb.h'],
    command: [protoc,
              '--cpp_out=@OUTDIR@',
              '--proto_path=' + meson.current_source_dir(),
              meson.current_source_dir() / 'proto_fuzz_virtio_snd.proto'])

  proto_snd_pb_o = custom_target('proto_fuzz_virtio_snd_pb_o',
    input: proto_snd_pb,
    output: 'proto_fuzz_virtio_snd.pb.o',
    command: cxx_common + ['-o', '@OUTPUT@', '@INPUT0@'])

  proto_snd_cc_o = custom_target('proto_fuzz_virtio_snd_cc_o',
    input: ['proto_fuzz_virtio_snd.cc', proto_snd_pb],
    output: 'proto_fuzz_virtio_snd.cc.o',
    command: cxx_common + ['-o', '@OUTPUT@', '@INPUT0@'])

  # virtio-vsock target (vhost-vsock-device, Linux only at runtime).
  proto_vsock_pb = custom_target('proto_fuzz_virtio_vsock_pb',
    input: 'proto_fuzz_virtio_vsock.proto',
    output: ['proto_fuzz_virtio_vsock.pb.cc', 'proto_fuzz_virtio_vsock.pb.h'],
    command: [protoc, '--cpp_out=@OUTDIR@',
              '--proto_path=' + meson.current_source_dir(),
              meson.current_source_dir() / 'proto_fuzz_virtio_vsock.proto'])
  proto_vsock_pb_o = custom_target('proto_fuzz_virtio_vsock_pb_o',
    input: proto_vsock_pb, output: 'proto_fuzz_virtio_vsock.pb.o',
    command: cxx_common + ['-o', '@OUTPUT@', '@INPUT0@'])
  proto_vsock_cc_o = custom_target('proto_fuzz_virtio_vsock_cc_o',
    input: ['proto_fuzz_virtio_vsock.cc', proto_vsock_pb],
    output: 'proto_fuzz_virtio_vsock.cc.o',
    command: cxx_common + ['-o', '@OUTPUT@', '@INPUT0@'])

  # virtio-console target.
  proto_console_pb = custom_target('proto_fuzz_virtio_console_pb',
    input: 'proto_fuzz_virtio_console.proto',
    output: ['proto_fuzz_virtio_console.pb.cc', 'proto_fuzz_virtio_console.pb.h'],
    command: [protoc, '--cpp_out=@OUTDIR@',
              '--proto_path=' + meson.current_source_dir(),
              meson.current_source_dir() / 'proto_fuzz_virtio_console.proto'])
  proto_console_pb_o = custom_target('proto_fuzz_virtio_console_pb_o',
    input: proto_console_pb, output: 'proto_fuzz_virtio_console.pb.o',
    command: cxx_common + ['-o', '@OUTPUT@', '@INPUT0@'])
  proto_console_cc_o = custom_target('proto_fuzz_virtio_console_cc_o',
    input: ['proto_fuzz_virtio_console.cc', proto_console_pb],
    output: 'proto_fuzz_virtio_console.cc.o',
    command: cxx_common + ['-o', '@OUTPUT@', '@INPUT0@'])

  # virtio-input target.
  proto_input_pb = custom_target('proto_fuzz_virtio_input_pb',
    input: 'proto_fuzz_virtio_input.proto',
    output: ['proto_fuzz_virtio_input.pb.cc', 'proto_fuzz_virtio_input.pb.h'],
    command: [protoc, '--cpp_out=@OUTDIR@',
              '--proto_path=' + meson.current_source_dir(),
              meson.current_source_dir() / 'proto_fuzz_virtio_input.proto'])
  proto_input_pb_o = custom_target('proto_fuzz_virtio_input_pb_o',
    input: proto_input_pb, output: 'proto_fuzz_virtio_input.pb.o',
    command: cxx_common + ['-o', '@OUTPUT@', '@INPUT0@'])
  proto_input_cc_o = custom_target('proto_fuzz_virtio_input_cc_o',
    input: ['proto_fuzz_virtio_input.cc', proto_input_pb],
    output: 'proto_fuzz_virtio_input.cc.o',
    command: cxx_common + ['-o', '@OUTPUT@', '@INPUT0@'])

  # virtio-balloon target.
  proto_balloon_pb = custom_target('proto_fuzz_virtio_balloon_pb',
    input: 'proto_fuzz_virtio_balloon.proto',
    output: ['proto_fuzz_virtio_balloon.pb.cc', 'proto_fuzz_virtio_balloon.pb.h'],
    command: [protoc, '--cpp_out=@OUTDIR@',
              '--proto_path=' + meson.current_source_dir(),
              meson.current_source_dir() / 'proto_fuzz_virtio_balloon.proto'])
  proto_balloon_pb_o = custom_target('proto_fuzz_virtio_balloon_pb_o',
    input: proto_balloon_pb, output: 'proto_fuzz_virtio_balloon.pb.o',
    command: cxx_common + ['-o', '@OUTPUT@', '@INPUT0@'])
  proto_balloon_cc_o = custom_target('proto_fuzz_virtio_balloon_cc_o',
    input: ['proto_fuzz_virtio_balloon.cc', proto_balloon_pb],
    output: 'proto_fuzz_virtio_balloon.cc.o',
    command: cxx_common + ['-o', '@OUTPUT@', '@INPUT0@'])

  # Resolve protobuf + abseil link flags via pkg-config (brewed protobuf
  # 7.34 inlines abseil logging into its headers, so the generated .pb.o
  # has direct references to absl_log_internal_* symbols).
  pb_libs = run_command('pkg-config', '--libs', 'protobuf',
                        check: true).stdout().strip().split()

  specific_fuzz_ss.add(declare_dependency(
    # `sources` lists the custom_target outputs; meson recognizes them
    # as object files and inserts them on the link command line. Don't
    # also list them in link_args or they'd appear twice.
    sources: [proto_pb_o, proto_cc_o,
              proto_net_pb_o, proto_net_cc_o,
              proto_gpu_pb_o, proto_gpu_cc_o,
              proto_scsi_pb_o, proto_scsi_cc_o,
              proto_fs_pb_o, proto_fs_cc_o,
              proto_snd_pb_o, proto_snd_cc_o,
              proto_vsock_pb_o, proto_vsock_cc_o,
              proto_console_pb_o, proto_console_cc_o,
              proto_input_pb_o, proto_input_cc_o,
              proto_balloon_pb_o, proto_balloon_cc_o],
    link_args: [lpm_lib, lpm_core] + pb_libs + [
                '-Wl,-rpath,' + brew_libdir,
                '-Wl,-rpath,' + brew_prefix / 'opt/protobuf/lib',
                '-Wl,-rpath,' + brew_prefix / 'opt/abseil/lib']))
endif

# The qtest I/O functions (qtest_inb/outb/readb/writeb/...) are defined as
# weak symbols in libqtest.c so qtest_wrappers.c can override them with
# strong definitions when linked into a fuzz binary. This replaces the
# previous -Wl,-wrap mechanism, which Apple's ld and ld64.lld do not
# support.

fuzz_link_args = fuzz_exe_ldflags
if host_os == 'darwin'
  # Mach-O note: plugins/meson.build adds -Wl,-exported_symbols_list which
  # demotes every non-listed symbol to private_extern. That hides
  # LLVMFuzzer* entry points, so libFuzzer's weak-extern lookup for
  # LLVMFuzzerInitialize resolves to NULL and the QEMU init never runs.
  # Re-export the libFuzzer entry points explicitly.
  fuzz_link_args += [
    '-Wl,-exported_symbol,_LLVMFuzzerInitialize',
    '-Wl,-exported_symbol,_LLVMFuzzerTestOneInput',
    '-Wl,-exported_symbol,_LLVMFuzzerCustomCrossOver',
    '-Wl,-exported_symbol,_LLVMFuzzerCustomMutator',
  ]
endif
fuzz_ld = declare_dependency(link_args: fuzz_link_args)

specific_fuzz_ss.add(fuzz_ld)
