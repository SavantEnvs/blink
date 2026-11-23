# Extra makefile for the MODE=fz build (make -f Makefile -f mayhem/fuzz.mk ...).
# Relaxes single UBSan checks on single files where upstream code trips them
# unconditionally, so every input would "crash" on the same benign report. Each
# exemption covers one known upstream line (blink @ f006a4f); everything else in
# those files, and every other check, stays on:
#  - blink/biosrom.c:193-248, SetDefaultBiosIntVectors() and its helper: every
#    vector is built as `kBiosSeg << 16 | ...` in int (0xF000 << 16 overflows
#    int), on every real-mode boot, before any input byte is read
#    -> shift-base off. The value written is the intended F000:xxxx far pointer.
#  - blink/diself.c:120, DisSortSyms(): qsort(d->syms.p, d->syms.i, ...) with
#    d->syms.p == NULL and d->syms.i == 0 for any ELF that has no symbols
#    (called from diself.c:186) -> nonnull-attribute off. qsort of 0 elements
#    never touches the pointer.
#  - blink/buffer.c:84, AppendFmt(): vsnprintf(b->p + b->i, b->n - b->i, ...)
#    on a fresh, empty struct Buffer (p == NULL, i == n == 0); blinkenlights hits
#    it on every guest halt via PrintMessageBox() (blinkenlights.c:3348)
#    -> pointer-overflow off. NULL + 0 with size 0 writes nothing; the buffer
#    is realloc()ed on the next line.
# TARGET_ARCH is set on the make command line, hence `override`.
o/fz/blink/biosrom.o: override TARGET_ARCH += -fno-sanitize=shift-base
o/fz/blink/diself.o: override TARGET_ARCH += -fno-sanitize=nonnull-attribute
o/fz/blink/buffer.o: override TARGET_ARCH += -fno-sanitize=pointer-overflow

# The CLI front ends' TerminateSignal() (re-raises a guest's fatal signal on the
# host) is renamed so mayhem/harnesses/exec_input_main.c supplies the hook
# instead; see that file. Only these two objects define/use the renamed name.
o/fz/blink/blink.o o/fz/blink/blinkenlights.o: override TARGET_ARCH += -DTerminateSignal=FrontendTerminateSignal
