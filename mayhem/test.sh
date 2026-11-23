#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# blink's functional suite, built by mayhem/build.sh with upstream's normal flags (o//):
#  - test/blink unit tests (decoder, disassembler, modrm, divmul, x87 long double):
#    each is a TEST() runner that exits non-zero on any failed EXPECT/ASSERT;
#  - known-answer runs of the emulator on committed guest programs
#    (mayhem/testdata/*.S sources): stdout and exit status must match exactly;
#  - the fuzz front end (o/fz/fuzz, mayhem/harnesses/exec_input_main.c): it runs an
#    extensionless input under the .bin name blink-flat needs, and jails the guest's
#    filesystem: a guest open("/tmp/blink-jail-probe", O_CREAT) must succeed inside
#    the per-run jail, create nothing on the host, and the jail must be removed.
B="$SRC/o/"
for t in disinst divmul modrm x86 ldbl; do
  [ -x "$B/test/blink/${t}_test.com" ] || { echo "missing $B/test/blink/${t}_test.com — run mayhem/build.sh" >&2; exit 2; }
done
for f in blink/blink fz/fuzz/blink fz/fuzz/blink-flat; do
  [ -x "$B/$f" ] || { echo "missing $B/$f — run mayhem/build.sh" >&2; exit 2; }
done

passed=0; failed=0
check() {  # check <name> <expected stdout> <expected rc> <cmd...>
  local name="$1" want="$2" wantrc="$3"; shift 3
  local got rc
  got="$(cd "$work" && timeout 60 "$@" 2>/dev/null)"; rc=$?
  if [ "$got" = "$want" ] && [ "$rc" = "$wantrc" ]; then
    echo "PASS $name"; passed=$((passed + 1))
  else
    echo "FAIL $name: rc=$rc (want $wantrc) stdout=$(printf %q "$got") (want $(printf %q "$want"))"
    failed=$((failed + 1))
  fi
}
work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
cp "$SRC/mayhem/testdata/hello-elf" "$SRC/mayhem/testdata/hello.bin" "$SRC/mayhem/testdata/jail-elf" "$work/"
cp "$SRC/mayhem/testdata/hello.bin" "$work/hello-noext"
chmod +x "$work/hello-elf" "$work/jail-elf"
chmod -x "$work/hello-noext"
mkdir "$work/tmp"

for t in disinst divmul modrm x86 ldbl; do
  # the runners print nothing on success; a failed expectation prints "error:" and exits 1
  out="$("$B/test/blink/${t}_test.com" 2>&1)"; rc=$?
  if [ $rc -eq 0 ] && ! grep -q "error:" <<<"$out"; then echo "PASS ${t}_test"; passed=$((passed+1)); else echo "FAIL ${t}_test (rc=$rc)"; echo "$out" | head -20; failed=$((failed+1)); fi
done

check elf-jit        "hello from blink" 42 "$B/blink/blink" ./hello-elf
check elf-interp     "hello from blink" 42 "$B/blink/blink" -j ./hello-elf
check elf-nolinear   "hello from blink" 42 "$B/blink/blink" -m ./hello-elf
check flat-bin       "hello from blink" 42 "$B/blink/blink" ./hello.bin
check flat-interp    "hello from blink" 42 "$B/blink/blink" -jm ./hello.bin

# fuzz front end: a non-executable, extensionless input still runs as a flat image
check shim-flat      "hello from blink" 42 env TMPDIR="$work/tmp" "$B/fz/fuzz/blink-flat" -m ./hello-noext
# filesystem jail: the guest's create succeeds in the jail, not on the host
rm -f /tmp/blink-jail-probe
check shim-jail-open "created" 0 env TMPDIR="$work/tmp" "$B/fz/fuzz/blink" -m ./jail-elf
if [ ! -e /tmp/blink-jail-probe ] && [ -z "$(ls -A "$work/tmp")" ]; then
  echo "PASS shim-jail-host-untouched"; passed=$((passed + 1))
else
  echo "FAIL shim-jail-host-untouched: /tmp/blink-jail-probe exists or the jail was left in $work/tmp: $(ls -A "$work/tmp")"
  failed=$((failed + 1)); rm -f /tmp/blink-jail-probe
fi

emit_ctrf "blink-test" "$passed" "$failed" 0
