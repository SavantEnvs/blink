// Front end shim for the file-input targets (blink-elf, blink-flat,
// blinkenlights-metal). Upstream's main() and TerminateSignal() in
// blink/blink.c and blink/blinkenlights.c are compiled renamed
// (-Dmain=blink_original_main globally, -DTerminateSignal=... for those two
// objects only, see mayhem/fuzz.mk); everything else is upstream code.
//
// 1. Input delivery: blink refuses a program file that lacks an execute bit
//    unless its name ends in .bin (CheckExecutableFile() in blink/loader.c,
//    mirroring execve()). A fuzzer-staged input is never chmod +x, so every
//    input would be rejected before the loader runs; blink's own lookup of
//    the program (Commandv() -> access(X_OK)) needs that bit too. And blink's
//    loader (LoadProgram()/CanEmulateImpl() in blink/loader.c) reads the
//    program with mmap(), never read(): Mayhem delivers and tracks the input
//    through read(), so a target that only mmaps it "does not use the file
//    input" and the run fails its smoke test. So the input is always read()
//    into a 0700 copy that blink runs instead, and the fuzzer's own @@ file
//    is never modified.
//    Flat images: blink only loads a raw flat image, and blinkenlights -r
//    only loads a boot sector, when the program name ends in .bin
//    (IsBinFile() in blink/loader.c), and a Mayhem-staged @@ input has no
//    extension of its own. So when the input's own name ends in .bin, or the
//    binary is built with -DBLINK_INPUT_EXT='".bin"' (blink-flat and
//    blinkenlights), the copy is named input.bin; otherwise just input.
// 2. Guest filesystem jail: the fuzzed guest program runs with blink's file
//    syscalls enabled, and blink's default overlay (":o", blink/overlays.h)
//    is the host root, so a mutated guest could create, change or delete
//    host files that later inputs would see. The shim therefore makes a
//    fresh private directory per run with mkdtemp(), blink-input-<pid>-XXXXXX
//    under the first of $TMPDIR, /tmp, /dev/shm, . where that works, and sets
//    BLINK_OVERLAYS to it: with a single overlay blink treats it as the guest's
//    root and chdirs into it (SetOverlays() in blink/overlays.c), so a guest
//    open("/tmp/x", O_CREAT) lands in <dir>/tmp/x (the shim creates an empty
//    <dir>/tmp for guest scratch files), not the host's /tmp. The
//    input copy is <dir>/input[.bin] and blink is given the guest path
//    /input[.bin]. The copy must pass access(X_OK) (blink's program lookup);
//    on a noexec mount a regular file fails it, so there it is a symlink to an
//    anonymous memfd copy (/proc/self/fd/N, resolved by the host kernel).
//    The whole directory, including anything the guest created in it, is
//    removed when blink exits or the guest dies; directories left behind by a
//    process that was killed (sanitizer abort, timeout) are removed by the
//    next start, only those whose pid is no longer alive, so parallel workers
//    are not disturbed. If no copy can be staged the shim aborts with a
//    message: running the input any other way would either measure only
//    blink's reject path or let the guest see the host filesystem.
// 3. Guest death: TerminateSignal() is the hook blink.a leaves to each front
//    end (blink/signal.h; test/test.h supplies its own). The CLI's version
//    re-raises the GUEST's fatal signal (SIGILL for ud2, SIGTRAP for int3,
//    SIGSEGV for a bad guest pointer...) on the host process, which a fuzzer
//    would count as a crash of blink for nearly every random program. This
//    front end ends the process with a normal exit status 128+signal instead,
//    so only real faults in the emulator itself (ASan/UBSan reports, host
//    SIGSEGV inside blink) are crashes. Status: 64 + guest signal number
//    (<= 128, so it never reads as "killed by signal N").
// 4. Rejected inputs: blink exits with EXIT_FAILURE_EXEC_FAILED (127, the
//    shell's "command not found") for every program it refuses to load (empty
//    file, bad ELF header, ...). Fuzzing tools read 127 as "target binary not
//    runnable", so an on_exit() hook reports that status as 1 instead. Any
//    other status passes through unchanged.
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define DIR_PREFIX "blink-input-"

struct Machine;
int blink_original_main(int, char **);

static char g_fdpath[32];
static char g_dir[PATH_MAX];
static char g_guestpath[16];

static int RemoveEntry(const char *path, const struct stat *st, int type,
                       struct FTW *ftw) {
  (void)st, (void)ftw;
  if (type == FTW_DP) {
    chmod(path, 0700);  // a guest may have made it unwritable
    rmdir(path);
  } else {
    unlink(path);
  }
  return 0;
}

// Removes the directory tree at `path` without following symlinks.
static void RemoveTree(const char *path) {
  chmod(path, 0700);
  nftw(path, RemoveEntry, 16, FTW_DEPTH | FTW_PHYS);
}

static void RemoveJail(void) {
  if (g_dir[0]) RemoveTree(g_dir);
}

_Noreturn void TerminateSignal(struct Machine *m, int sig, int code) {
  fprintf(stderr, "blink: guest terminated by signal %d (code=%d)\n", sig, code);
  fflush(stdout);
  RemoveJail();
  _exit(64 + (sig & 63));
}

static void RemapExecFailed(int status, void *arg) {
  (void)arg;
  if (status == 127) _exit(1);
}

static void RemoveJailOnExit(int status, void *arg) {
  (void)status, (void)arg;
  RemoveJail();
}

// Removes <tmp>/blink-input-<pid>-XXXXXX/ directories whose process no
// longer exists.
static void RemoveStaleDirs(const char *tmp) {
  char path[PATH_MAX + 300];
  struct dirent *e;
  char *end;
  long pid;
  DIR *d;
  if (!(d = opendir(tmp))) return;
  while ((e = readdir(d))) {
    if (strncmp(e->d_name, DIR_PREFIX, strlen(DIR_PREFIX))) continue;
    pid = strtol(e->d_name + strlen(DIR_PREFIX), &end, 10);
    if (end == e->d_name + strlen(DIR_PREFIX) || *end != '-' || pid <= 0) continue;
    if (kill(pid, 0) == 0 || errno != ESRCH) continue;
    snprintf(path, sizeof(path), "%s/%s", tmp, e->d_name);
    RemoveTree(path);
  }
  closedir(d);
}

// read()s everything from `in` and writes it to `out`; returns 0 on success.
static int CopyFd(int in, int out) {
  char buf[65536];
  ssize_t n;
  while ((n = read(in, buf, sizeof(buf))) > 0) {
    if (write(out, buf, n) != n) return -1;
  }
  return n ? -1 : fchmod(out, 0700);
}

// read()s the file at `path` into a 0700 memfd and returns /proc/self/fd/N,
// or NULL.
static char *CopyToMemfd(const char *path) {
  int in, out, rc;
  if (g_fdpath[0]) return g_fdpath;
  if ((in = open(path, O_RDONLY)) == -1) return 0;
  if ((out = memfd_create("blink-input", MFD_CLOEXEC)) == -1) {
    close(in);
    return 0;
  }
  rc = CopyFd(in, out);
  close(in);
  if (rc) {
    close(out);
    return 0;
  }
  // out stays open: /proc/self/fd/N names it until the process ends.
  snprintf(g_fdpath, sizeof(g_fdpath), "/proc/self/fd/%d", out);
  if (access(g_fdpath, R_OK | X_OK)) {
    g_fdpath[0] = 0;
    close(out);
    return 0;
  }
  return g_fdpath;
}

// Makes the jail <tmp>/blink-input-<pid>-XXXXXX (absolute) and read()s the
// input into <jail>/input<ext>; returns 0 on success, or -1 with g_dir
// cleared. The copy must pass access(X_OK): blink looks the program up that
// way. On a noexec mount a regular file fails it, so there input<ext> is
// instead a symlink to a memfd copy (/proc/self/fd/N).
static int StageIn(const char *tmp, const char *path, const char *ext) {
  char dir[PATH_MAX], copy[PATH_MAX + 16];
  int in, out, rc;
  RemoveStaleDirs(tmp);
  snprintf(dir, sizeof(dir), "%s/%s%ld-XXXXXX", tmp, DIR_PREFIX,
           (long)getpid());
  if (!mkdtemp(dir)) return -1;
  if (!realpath(dir, g_dir)) {
    rmdir(dir);
    g_dir[0] = 0;
    return -1;
  }
  // an empty /tmp, so guest code that writes scratch files still runs
  snprintf(copy, sizeof(copy), "%s/tmp", g_dir);
  if (mkdir(copy, 0700)) goto fail;
  snprintf(copy, sizeof(copy), "%s/input%s", g_dir, ext);
  if ((in = open(path, O_RDONLY)) == -1) goto fail;
  if ((out = open(copy, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0700)) == -1) {
    close(in);
    goto fail;
  }
  rc = CopyFd(in, out);
  close(in);
  if (close(out) || rc) goto fail;
  if (!access(copy, R_OK | X_OK)) return 0;
  // noexec mount: name a memfd copy through a symlink in the jail.
  unlink(copy);
  if (CopyToMemfd(path) && !symlink(g_fdpath, copy) &&
      !access(copy, R_OK | X_OK))
    return 0;
fail:
  RemoveJail();
  g_dir[0] = 0;
  return -1;
}

// Stages the input at `path` in a fresh jail and returns the guest path
// blink should load it under. Aborts if it cannot.
static char *Stage(const char *path) {
  const char *dirs[] = {getenv("TMPDIR"), "/tmp", "/dev/shm", "."};
  const char *base = strrchr(path, '/');
  const char *ext = strrchr(base ? base + 1 : path, '.');
  size_t i;
  if (!ext || strcmp(ext, ".bin")) ext = "";
#ifdef BLINK_INPUT_EXT
  ext = BLINK_INPUT_EXT;
#endif
  for (i = 0; i < sizeof(dirs) / sizeof(*dirs); ++i) {
    if (!dirs[i] || !*dirs[i]) continue;
    if (!StageIn(dirs[i], path, ext)) {
      snprintf(g_guestpath, sizeof(g_guestpath), "/input%s", ext);
      return g_guestpath;
    }
    fprintf(stderr, "blink input shim: cannot stage %s under %s\n", path, dirs[i]);
  }
  fprintf(stderr, "blink input shim: cannot stage %s in a private directory\n",
          path);
  abort();
}

int main(int argc, char *argv[]) {
  struct stat st;
  on_exit(RemapExecFailed, 0);
  if (argc >= 2 && !stat(argv[argc - 1], &st) && S_ISREG(st.st_mode)) {
    argv[argc - 1] = Stage(argv[argc - 1]);
    on_exit(RemoveJailOnExit, 0);
    // blink reads BLINK_OVERLAYS before its options; this front end's
    // Mayhemfiles pass no -C, so the jail is the guest's whole filesystem.
    if (setenv("BLINK_OVERLAYS", g_dir, 1)) abort();
  }
  return blink_original_main(argc, argv);
}
