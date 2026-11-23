// libFuzzer harness: blink's x86 instruction decoder + AT&T disassembler.
// First byte selects the decode mode (real / legacy / long), the rest is the
// instruction stream; mirrors test/blink/disinst_test.c (DecodeInstruction ->
// DisSpec -> DisInst), then walks the whole buffer instruction by instruction.
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "blink/dis.h"
#include "blink/high.h"
#include "blink/x86.h"

static struct Dis d[1];

// blink.a leaves TerminateSignal() to the front end (blink.c, blinkenlights.c);
// library users such as test/test.h supply this one. Never reached here: no
// guest code runs.
_Noreturn void TerminateSignal(struct Machine *m, int sig, int code) { abort(); }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char spec[128], out[256];
  int mode;
  size_t off;
  if (size < 2) return -1;
  mode = data[0] % 3;  // XED_MODE_REAL, XED_MODE_LEGACY, XED_MODE_LONG
  memset(d, 0, sizeof(d));
  d->notab = data[0] & 0x80;
  g_high.enabled = false;
  for (off = 1; off < size;) {
    size_t n = size - off;
    if (n > 15) n = 15;
    if (DecodeInstruction(d->xedd, data + off, n, mode)) {
      off += 1;
      continue;
    }
    d->addr = off;
    DisInst(d, out, DisSpec(d->xedd, spec));
    off += d->xedd->length ? d->xedd->length : 1;
  }
  return 0;
}
