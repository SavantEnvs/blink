#!/usr/bin/env bash
#
# mayhem/build.sh — build blink (x86-64 Linux emulator + blinkenlights debugger),
# its unit tests, and the Mayhem fuzz targets.
#
#  1. ./configure (re-run every time: blink's Makefile re-configures and stops when
#     config.mk was written on another hostname, which is always the case on a rebuild
#     in a fresh container). Fork, sockets and threads are disabled so the emulated
#     guest programs a fuzzer feeds to blink cannot spawn host processes or sockets.
#  2. Oracle build (MODE='' -> o//): upstream's normal flags; blink, blinkenlights and
#     the test/blink unit tests that mayhem/test.sh runs.
#  3. Fuzz build (MODE=fz -> o/fz/): the whole emulator with $SANITIZER_FLAGS +
#     SanCov + $DEBUG_FLAGS, with -DNOJIT -DUBSAN as upstream's own MODE=ubsan does
#     (the JIT copies compiled micro-op functions as raw machine code, which
#     sanitizer/coverage instrumentation breaks).
#  4. libFuzzer harnesses (+ -standalone reproducers) and the file-input binaries.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export CC CXX

cd "$SRC"

# 1) configure (writes the gitignored config.h / config.mk)
./configure --disable-fork --disable-sockets --disable-threads

# 2) oracle build, upstream flags (+ optional coverage)
make -j"$MAYHEM_JOBS" TARGET_ARCH="$COVERAGE_FLAGS" \
  o//blink/blink o//blink/blinkenlights \
  o//test/blink/disinst_test.com o//test/blink/divmul_test.com \
  o//test/blink/modrm_test.com o//test/blink/x86_test.com \
  o//test/blink/ldbl_test.com

# 3) instrumented emulator library. TARGET_ARCH is appended after CFLAGS on every
#    compile and link, so these flags win over upstream's (-g -> -gdwarf-3) without
#    discarding the per-file CFLAGS the makefiles add.
FZ="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link $DEBUG_FLAGS"
#    upstream main() (blink.c, blinkenlights.c) is renamed blink_original_main so the
#    input-delivery shim (mayhem/harnesses/exec_input_main.c) can run first; no other
#    object in the library is linked for it (blink.a members are pulled only on demand).
make -f Makefile -f mayhem/fuzz.mk -j"$MAYHEM_JOBS" MODE=fz TARGET_ARCH="$FZ -DNOJIT -DUBSAN -Dmain=blink_original_main" \
  o/fz/blink/blink.a o/fz/blink/blink.o o/fz/blink/blinkenlights.o

OUT="$SRC/o/fz/fuzz"
mkdir -p "$OUT"
LIBS="$SRC/o/fz/blink/blink.a -lz -lrt -lm"
CPP="-iquote $SRC -D_FILE_OFFSET_BITS=64 -D_DEFAULT_SOURCE -D_BSD_SOURCE -D_GNU_SOURCE -DNOJIT -DUBSAN"

$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$OUT/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c -x c "$STANDALONE_FUZZ_MAIN" -o "$OUT/standalone_main.o"

# 4a) libFuzzer harnesses + standalone reproducers
for h in disinst diself; do
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $CPP -c "$SRC/mayhem/harnesses/fuzz_$h.c" -o "$OUT/fuzz_$h.o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/fuzz_$h.o" "$OUT/lsan_off.o" $LIBS -o "$OUT/fuzz_$h"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/standalone_main.o" "$OUT/fuzz_$h.o" "$OUT/lsan_off.o" $LIBS -o "$OUT/fuzz_$h-standalone"
done

# 4b) the real CLIs, instrumented, for the file-input targets (upstream link flags)
LDF="-Wl,-z,noseparate-code -Wl,-z,norelro -Wl,-z,common-page-size=65536,-z,max-page-size=65536 -pie"
$CC $FZ -fpie $CPP -c "$SRC/mayhem/harnesses/exec_input_main.c" -o "$OUT/exec_input_main.o"
$CC $LDF $FZ "$OUT/exec_input_main.o" "$SRC/o/fz/blink/blink.o" "$OUT/lsan_off.o" $LIBS -o "$OUT/blink"
#    blink-flat and blinkenlights: their shim always names the input *.bin. blink loads a
#    file as a raw flat image, and blinkenlights -r loads a boot sector at all, only when
#    the name ends in .bin (IsBinFile() in blink/loader.c); a Mayhem @@ input has none.
$CC $FZ -fpie $CPP '-DBLINK_INPUT_EXT=".bin"' -c "$SRC/mayhem/harnesses/exec_input_main.c" -o "$OUT/exec_input_main_flat.o"
$CC $LDF $FZ "$OUT/exec_input_main_flat.o" "$SRC/o/fz/blink/blink.o" "$OUT/lsan_off.o" $LIBS -o "$OUT/blink-flat"
$CC $LDF $FZ "$OUT/exec_input_main_flat.o" "$SRC/o/fz/blink/blinkenlights.o" "$OUT/lsan_off.o" $LIBS -o "$OUT/blinkenlights"

ls -la "$OUT"
