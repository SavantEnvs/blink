// libFuzzer harness: blink's ELF debug-symbol loader (diself.c + elf.c).
// Mirrors LoadFileMapSymbols() in blink/debug2.c, which is how blink and
// blinkenlights read the symbols of a guest program file: the same three
// preconditions (size >= Elf64_Ehdr_, ELF magic, GetElfMemorySize() != -1),
// then DisLoadElf(), symbol lookups, DisFree().
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "blink/dis.h"
#include "blink/elf.h"
#include "blink/endian.h"

// blink.a leaves TerminateSignal() to the front end (blink.c, blinkenlights.c);
// library users such as test/test.h supply this one. Never reached here: no
// guest code runs.
_Noreturn void TerminateSignal(struct Machine *m, int sig, int code) { abort(); }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct Dis d;
  i64 base;
  u8 *map;
  long i;
  if (size < sizeof(Elf64_Ehdr_)) return -1;
  // heap copy: aligned like the mmap()ed file blink passes, and ASan-bounded
  if (!(map = (u8 *)malloc(size))) return -1;
  memcpy(map, data, size);
  if (Read32(map) == Read32((const u8 *)"\177ELF") &&
      GetElfMemorySize((Elf64_Ehdr_ *)map, size, &base) != -1) {
    memset(&d, 0, sizeof(d));
    DisLoadElf(&d, (Elf64_Ehdr_ *)map, size, 0);
    for (i = 0; i < d.syms.i; ++i) {
      DisFindSym(&d, d.syms.p[i].addr);
      DisFindSymByName(&d, d.syms.p[i].name);
    }
    DisFindSym(&d, Read64(((Elf64_Ehdr_ *)map)->entry));
    DisIsText(&d, Read64(((Elf64_Ehdr_ *)map)->entry));
    DisFree(&d);
  }
  free(map);
  return 0;
}
