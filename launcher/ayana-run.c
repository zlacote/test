/*
 * ayana-run: in-process launcher prototype.
 *
 * Usage: ayana-run [--root DIR] FILE [ARGS...]
 *
 * FILE is an ELF that is mapped into this process and entered as if the
 * kernel had executed it: a dynamic linker (glibc ld.so, Android linker64)
 * or a static program. argv seen by FILE is "FILE ARGS...". The kernel never
 * execs FILE, so no exec permission on FILE is needed, only mmap.
 *
 * Always installed: a SIGSYS handler. Syscalls killed by the platform
 * seccomp filter become -ENOSYS (a few are emulated instead), which is the
 * answer libc fallbacks expect. AYANA_TRACE=1 reports each such syscall once.
 *
 * With --fakeroot (or AYANA_FAKEROOT=1): uid/gid queries report root, uid
 * and gid changes and chown succeed without effect (credentials are tracked
 * per process), and files owned by the app uid are reported as owned by root.
 *
 * With --root DIR (or AYANA_ROOT=DIR): an own seccomp filter traps path
 * syscalls made outside the launcher's syscall gate. The handler rewrites
 * absolute paths under the mapped prefixes to DIR/..., performs the call
 * through the gate, and re-routes execve through this launcher so that the
 * whole process tree keeps the handler. The filter is inherited by children
 * and stays valid because the launcher is linked at a fixed address.
 *
 * Freestanding: no libc. Every syscall goes through ayana_gate().
 */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <elf.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/ucontext.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#define E_NOSYS 38
#define E_NOENT 2
#define E_NOEXEC 8
#define E_NAMETOOLONG 36
#define E_LOOP 40
#define AYANA_TAG 0x3a7
#define PATH_CAP 4096
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif
#ifndef AT_EXECFN
#define AT_EXECFN 31
#endif

/* ------------------------------------------------------------------ */
/* arch                                                               */
/* ------------------------------------------------------------------ */
long ayana_gate(long nr, long a, long b, long c, long d, long e, long f);
long ayana_rawsvc(long nr, long a, long b, long c, long d, long e, long f);
extern char ayana_gate_start[], ayana_gate_end[];

#if defined(__aarch64__)
#define AYANA_ARCH AUDIT_ARCH_AARCH64
#define UC_ARG(uc, i) ((uc)->uc_mcontext.regs[i])
#define UC_RET(uc) ((uc)->uc_mcontext.regs[0])
__asm__(
    ".section .text.ayana_gate,\"ax\",%progbits\n"
    ".globl ayana_gate_start\n.globl ayana_gate_end\n.globl ayana_gate\n"
    "ayana_gate_start:\n"
    "ayana_gate:\n"
    "  mov x8, x0\n  mov x0, x1\n  mov x1, x2\n  mov x2, x3\n"
    "  mov x3, x4\n  mov x4, x5\n  mov x5, x6\n  svc #0\n  ret\n"
    "ayana_gate_end:\n"
    ".text\n"
    ".globl ayana_rawsvc\n"
    "ayana_rawsvc:\n"
    "  mov x8, x0\n  mov x0, x1\n  mov x1, x2\n  mov x2, x3\n"
    "  mov x3, x4\n  mov x4, x5\n  mov x5, x6\n  svc #0\n  ret\n"
    ".globl _start\n"
    "_start:\n"
    "  mov x0, sp\n  bl ayana_main\n  brk #0\n");
static void __attribute__((noreturn)) jump_to(void *sp, void *entry) {
  register void *s __asm__("x16") = sp;
  register void *e __asm__("x17") = entry;
  __asm__ volatile("mov sp, x16\n mov x0, xzr\n mov x29, xzr\n mov x30, xzr\n br x17\n"
                   :: "r"(s), "r"(e) : "memory");
  __builtin_unreachable();
}
#define NEED_RESTORER 0
#elif defined(__x86_64__)
#define AYANA_ARCH AUDIT_ARCH_X86_64
static const int XARG[6] = {REG_RDI, REG_RSI, REG_RDX, REG_R10, REG_R8, REG_R9};
#define UC_ARG(uc, i) ((uc)->uc_mcontext.gregs[XARG[i]])
#define UC_RET(uc) ((uc)->uc_mcontext.gregs[REG_RAX])
__asm__(
    ".section .text.ayana_gate,\"ax\",@progbits\n"
    ".globl ayana_gate_start\n.globl ayana_gate_end\n.globl ayana_gate\n"
    "ayana_gate_start:\n"
    "ayana_gate:\n"
    "  mov %rdi, %rax\n  mov %rsi, %rdi\n  mov %rdx, %rsi\n  mov %rcx, %rdx\n"
    "  mov %r8, %r10\n  mov %r9, %r8\n  mov 8(%rsp), %r9\n  syscall\n  ret\n"
    "ayana_gate_end:\n"
    ".text\n"
    ".globl ayana_rawsvc\n"
    "ayana_rawsvc:\n"
    "  mov %rdi, %rax\n  mov %rsi, %rdi\n  mov %rdx, %rsi\n  mov %rcx, %rdx\n"
    "  mov %r8, %r10\n  mov %r9, %r8\n  mov 8(%rsp), %r9\n  syscall\n  ret\n"
    ".globl ayana_restorer\n"
    "ayana_restorer:\n  mov $15, %rax\n  syscall\n  hlt\n"
    ".globl _start\n"
    "_start:\n  mov %rsp, %rdi\n  and $-16, %rsp\n  call ayana_main\n  hlt\n");
extern char ayana_restorer[];
static void __attribute__((noreturn)) jump_to(void *sp, void *entry) {
  __asm__ volatile("mov %%rsi, %%rsp\n xor %%edx, %%edx\n xor %%ebp, %%ebp\n jmp *%%rdi\n"
                   :: "S"(sp), "D"(entry) : "memory");
  __builtin_unreachable();
}
#define NEED_RESTORER 1
#else
#error "unsupported architecture"
#endif

#define SC(nr, a, b, c, d, e, f) ayana_gate((nr), (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), (long)(f))

/* ------------------------------------------------------------------ */
/* tiny runtime                                                       */
/* ------------------------------------------------------------------ */
void *memcpy(void *d, const void *s, size_t n) {
  unsigned char *dd = d;
  const unsigned char *ss = s;
  while (n--) { *dd++ = *ss++; __asm__ volatile("" ::: "memory"); }
  return d;
}
void *memset(void *d, int c, size_t n) {
  unsigned char *dd = d;
  while (n--) { *dd++ = (unsigned char)c; __asm__ volatile("" ::: "memory"); }
  return d;
}
static size_t slen(const char *s) { size_t n = 0; while (s[n]) n++; return n; }
static int sprefix(const char *s, const char *p) { while (*p) if (*s++ != *p++) return 0; return 1; }
static int seq(const char *a, const char *b) { while (*a && *a == *b) { a++; b++; } return *a == *b; }

static void out(const char *s) { SC(__NR_write, 2, s, slen(s), 0, 0, 0); }
static void out_num(long v) {
  char b[24];
  int i = 23;
  int neg = v < 0;
  unsigned long u = neg ? -(unsigned long)v : (unsigned long)v;
  b[i] = 0;
  do { b[--i] = (char)('0' + u % 10); u /= 10; } while (u);
  if (neg) b[--i] = '-';
  out(b + i);
}
static void __attribute__((noreturn)) die(const char *msg, long code) {
  out("ayana-run: ");
  out(msg);
  if (code) { out(" ("); out_num(code); out(")"); }
  out("\n");
  SC(__NR_exit_group, 127, 0, 0, 0, 0, 0);
  __builtin_unreachable();
}

/* ------------------------------------------------------------------ */
/* reality: path map                                                  */
/* ------------------------------------------------------------------ */
static char g_root[PATH_CAP];
static size_t g_rootlen;
static char g_kroot[PATH_CAP]; /* the same directory as the kernel names it in getcwd/readlink */
static size_t g_krootlen;
static int g_map_on;
static char g_self[PATH_CAP];

/* fake root: [0] uids, [1] gids; each real, effective, saved */
static int g_fake;
static long g_fid[2][3];
static long g_real_uid, g_real_gid;

static const char *const MAPPED[] = {"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/var",
                                     "/opt", "/root", "/home", "/tmp", "/srv", "/run", "/mnt",
                                     "/media", "/boot", 0};

/* Returns 1 and fills out if the path is remapped, 0 if unchanged, <0 on error. */
static int map_path(const char *in, char *out_buf) {
  if (!g_map_on || !in || in[0] != '/') return 0;
  int hit = (in[1] == 0);
  for (int i = 0; !hit && MAPPED[i]; i++) {
    size_t n = slen(MAPPED[i]);
    if (sprefix(in, MAPPED[i]) && (in[n] == '/' || in[n] == 0)) hit = 1;
  }
  if (!hit) return 0;
  size_t n = slen(in);
  if (g_rootlen + n + 1 > PATH_CAP) return -E_NAMETOOLONG;
  memcpy(out_buf, g_root, g_rootlen);
  memcpy(out_buf + g_rootlen, in, n + 1);
  return 1;
}

/* Reverse of map_path for paths the kernel hands back (readlink, getcwd):
 * strips the root prefix in place. n is the string length; returns the new one. */
static long unmap_with(char *buf, long n, const char *root, size_t len) {
  if (!len || n < (long)len) return -1;
  for (size_t k = 0; k < len; k++) if (buf[k] != root[k]) return -1;
  if (n == (long)len) { buf[0] = '/'; return 1; }
  if (buf[len] != '/') return -1;
  for (long k = (long)len; k < n; k++) buf[k - len] = buf[k];
  return n - (long)len;
}
static long unmap_inplace(char *buf, long n) {
  if (!g_map_on) return n;
  long r = unmap_with(buf, n, g_root, g_rootlen);
  if (r < 0) r = unmap_with(buf, n, g_kroot, g_krootlen);
  return r < 0 ? n : r;
}

/* ------------------------------------------------------------------ */
/* ELF loading                                                        */
/* ------------------------------------------------------------------ */
static long g_pg = 4096;

struct image {
  uintptr_t entry, phdr;
  long phnum, phent;
};

static long pread_all(int fd, void *buf, long n, long off) {
  long r = SC(__NR_pread64, fd, buf, n, off, 0, 0);
  return r == n ? 0 : (r < 0 ? r : -E_NOEXEC);
}

static long load_elf(const char *path, struct image *im) {
  long fd = SC(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0, 0, 0);
  if (fd < 0) return fd;
  Elf64_Ehdr eh;
  Elf64_Phdr ph[64];
  long r = pread_all(fd, &eh, sizeof eh, 0);
  if (r) goto fail;
  r = -E_NOEXEC;
  if (eh.e_ident[0] != 0x7f || eh.e_ident[1] != 'E' || eh.e_ident[2] != 'L' || eh.e_ident[3] != 'F' ||
      eh.e_ident[EI_CLASS] != ELFCLASS64 || eh.e_phentsize != sizeof(Elf64_Phdr) || eh.e_phnum > 64 ||
      (eh.e_type != ET_DYN && eh.e_type != ET_EXEC))
    goto fail;
  r = pread_all(fd, ph, (long)eh.e_phnum * sizeof(Elf64_Phdr), eh.e_phoff);
  if (r) goto fail;

  uintptr_t mask = (uintptr_t)g_pg - 1, lo = ~(uintptr_t)0, hi = 0;
  for (int i = 0; i < eh.e_phnum; i++) {
    if (ph[i].p_type != PT_LOAD) continue;
    if ((ph[i].p_vaddr & mask) != (ph[i].p_offset & mask)) goto fail; /* not mappable at this page size */
    uintptr_t s = ph[i].p_vaddr & ~mask, e = (ph[i].p_vaddr + ph[i].p_memsz + mask) & ~mask;
    if (s < lo) lo = s;
    if (e > hi) hi = e;
  }
  if (hi <= lo) goto fail;

  uintptr_t base = 0;
  int fixed = MAP_FIXED;
  if (eh.e_type == ET_DYN) {
    long m = SC(__NR_mmap, 0, hi - lo, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m < 0 && m > -4096) { r = m; goto fail; }
    base = (uintptr_t)m - lo;
  } else {
    fixed = MAP_FIXED_NOREPLACE;
  }

  uintptr_t phdr = 0;
  for (int i = 0; i < eh.e_phnum; i++) {
    if (ph[i].p_type == PT_PHDR) phdr = base + ph[i].p_vaddr;
    if (ph[i].p_type != PT_LOAD) continue;
    int prot = ((ph[i].p_flags & PF_R) ? PROT_READ : 0) | ((ph[i].p_flags & PF_W) ? PROT_WRITE : 0) |
               ((ph[i].p_flags & PF_X) ? PROT_EXEC : 0);
    uintptr_t seg = base + (ph[i].p_vaddr & ~mask);
    uintptr_t fend = base + ph[i].p_vaddr + ph[i].p_filesz;
    uintptr_t mend = (base + ph[i].p_vaddr + ph[i].p_memsz + mask) & ~mask;
    uintptr_t fpage_end = (fend + mask) & ~mask;
    if (ph[i].p_filesz) {
      long m = SC(__NR_mmap, seg, fend - seg, prot, MAP_PRIVATE | fixed, fd, ph[i].p_offset & ~mask);
      if (m < 0 && m > -4096) { r = m; goto fail; }
    } else {
      fpage_end = seg;
    }
    if (ph[i].p_memsz > ph[i].p_filesz) {
      if (ph[i].p_filesz && (prot & PROT_WRITE) && fend < fpage_end) memset((void *)fend, 0, fpage_end - fend);
      if (mend > fpage_end) {
        long m = SC(__NR_mmap, fpage_end, mend - fpage_end, prot, MAP_PRIVATE | MAP_ANONYMOUS | fixed, -1, 0);
        if (m < 0 && m > -4096) { r = m; goto fail; }
      }
    }
    if (!phdr && ph[i].p_offset == 0) phdr = base + ph[i].p_vaddr + eh.e_phoff;
  }
  SC(__NR_close, fd, 0, 0, 0, 0, 0);
  im->entry = base + eh.e_entry;
  im->phdr = phdr;
  im->phnum = eh.e_phnum;
  im->phent = eh.e_phentsize;
  return 0;
fail:
  SC(__NR_close, fd, 0, 0, 0, 0, 0);
  return r;
}

/* ------------------------------------------------------------------ */
/* execve re-routing                                                  */
/* ------------------------------------------------------------------ */
enum { K_OTHER, K_SCRIPT, K_DYNAMIC, K_STATIC };

/* Classify a (virtual) path. For K_SCRIPT fills interp/arg, for K_DYNAMIC fills interp. */
static int classify(const char *vpath, char *interp, char *arg) {
  char real[PATH_CAP];
  int m = map_path(vpath, real);
  if (m < 0) return m;
  long fd = SC(__NR_openat, AT_FDCWD, m ? real : vpath, O_RDONLY | O_CLOEXEC, 0, 0, 0);
  if (fd < 0) return (int)fd;
  unsigned char h[256];
  long n = SC(__NR_pread64, fd, h, sizeof h - 1, 0, 0, 0);
  int kind = K_OTHER;
  if (n >= 2 && h[0] == '#' && h[1] == '!') {
    h[n] = 0;
    long i = 2, j = 0;
    while (h[i] == ' ' || h[i] == '\t') i++;
    while (h[i] && h[i] != ' ' && h[i] != '\t' && h[i] != '\n' && j < 255) interp[j++] = (char)h[i++];
    interp[j] = 0;
    while (h[i] == ' ' || h[i] == '\t') i++;
    j = 0;
    while (h[i] && h[i] != '\n' && j < 255) arg[j++] = (char)h[i++];
    while (j > 0 && (arg[j - 1] == ' ' || arg[j - 1] == '\t' || arg[j - 1] == '\r')) j--;
    arg[j] = 0;
    kind = interp[0] ? K_SCRIPT : K_OTHER;
  } else if (n >= (long)sizeof(Elf64_Ehdr) && h[0] == 0x7f && h[1] == 'E' && h[2] == 'L' && h[3] == 'F') {
    Elf64_Ehdr *eh = (Elf64_Ehdr *)h;
    kind = K_STATIC;
    for (int i = 0; i < eh->e_phnum && i < 64; i++) {
      Elf64_Phdr ph;
      if (pread_all((int)fd, &ph, sizeof ph, eh->e_phoff + (long)i * sizeof ph)) break;
      if (ph.p_type == PT_INTERP && ph.p_filesz > 1 && ph.p_filesz < 256) {
        if (!pread_all((int)fd, interp, ph.p_filesz, ph.p_offset)) {
          interp[ph.p_filesz - 1] = 0;
          kind = K_DYNAMIC;
        }
        break;
      }
    }
  }
  SC(__NR_close, fd, 0, 0, 0, 0, 0);
  return kind;
}

static long emu_execve(const char *path, char *const *argv, char *const *envp) {
  enum { MAXARG = 16384, ARENA = 1 << 20 };
  long m = SC(__NR_mmap, 0, ARENA, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (m < 0 && m > -4096) return m;
  char **list = (char **)m;                      /* working argv */
  char *str = (char *)m + MAXARG * sizeof(char *); /* string arena */
  char **vec = (char **)(str + 4 * PATH_CAP);     /* final argv */
  char *interp = str, *arg = str + 512, *target = str + 1024; /* target: 5 slots of 1024 */
  char *dyn_interp = str + 7168, *real = str + 8192;
  long cnt = 0;
  long r = 0;
  if (argv)
    while (argv[cnt] && cnt < MAXARG / 2 - 16) { list[cnt] = argv[cnt]; cnt++; }
  if (cnt == 0) list[cnt++] = (char *)path;
  list[cnt] = 0;

  const char *cur = path;
  int kind = 0;
  for (int depth = 0;; depth++) {
    if (depth > 4) { r = -E_LOOP; goto fail; }
    kind = classify(cur, interp, arg);
    if (kind < 0) { r = kind; goto fail; }
    if (kind != K_SCRIPT) break;
    /* argv becomes: interp [arg] script argv[1..] */
    long shift = arg[0] ? 2 : 1;
    for (long i = cnt; i >= 1; i--) list[i + shift] = list[i];
    char *ip = target + depth * 1024; /* one slot per level: earlier strings stay referenced */
    memcpy(ip, interp, slen(interp) + 1);
    list[0] = ip;
    if (arg[0]) { char *ap = ip + 512; memcpy(ap, arg, slen(arg) + 1); list[1] = ap; }
    list[shift] = (char *)cur;
    cnt += shift;
    cur = ip;
  }

  long v = 0;
  if (kind == K_DYNAMIC || kind == K_STATIC) {
    vec[v++] = g_self;
    if (g_map_on) { vec[v++] = "--root"; vec[v++] = g_root; }
    if (g_fake) {
      char *id = str + 7680; /* "uid,gid" of the exec'ing process */
      char tmp[24];
      long k = 0;
      for (int w = 0; w < 2; w++) {
        unsigned long u = (unsigned long)g_fid[w][1];
        int t = 0;
        do { tmp[t++] = (char)('0' + u % 10); u /= 10; } while (u);
        while (t) id[k++] = tmp[--t];
        id[k++] = w ? 0 : ',';
      }
      vec[v++] = "--fakeid";
      vec[v++] = id;
    }
    if (kind == K_DYNAMIC) {
      char *ip = dyn_interp;
      memcpy(ip, interp, slen(interp) + 1);
      vec[v++] = ip;
      if (sprefix(ip, "/lib/ld-linux") || sprefix(ip, "/lib64/ld-linux")) { vec[v++] = "--argv0"; vec[v++] = list[0]; }
    }
    vec[v++] = (char *)cur;
    for (long i = 1; i < cnt; i++) vec[v++] = list[i];
    vec[v] = 0;
    r = SC(__NR_execve, g_self, vec, envp, 0, 0, 0);
  } else {
    int mm = map_path(cur, real);
    r = SC(__NR_execve, mm > 0 ? real : cur, list, envp, 0, 0, 0);
  }
fail:
  SC(__NR_munmap, m, ARENA, 0, 0, 0, 0);
  return r;
}

/* ------------------------------------------------------------------ */
/* SIGSYS handler                                                     */
/* ------------------------------------------------------------------ */
struct pathcall { int nr; signed char p1, p2; };
static const struct pathcall PATHCALLS[] = {
#ifdef __NR_open
    {__NR_open, 0, -1},
#endif
#ifdef __NR_creat
    {__NR_creat, 0, -1},
#endif
#ifdef __NR_stat
    {__NR_stat, 0, -1},
#endif
#ifdef __NR_lstat
    {__NR_lstat, 0, -1},
#endif
#ifdef __NR_access
    {__NR_access, 0, -1},
#endif
#ifdef __NR_readlink
    {__NR_readlink, 0, -1},
#endif
#ifdef __NR_mkdir
    {__NR_mkdir, 0, -1},
#endif
#ifdef __NR_rmdir
    {__NR_rmdir, 0, -1},
#endif
#ifdef __NR_unlink
    {__NR_unlink, 0, -1},
#endif
#ifdef __NR_rename
    {__NR_rename, 0, 1},
#endif
#ifdef __NR_link
    {__NR_link, 0, 1},
#endif
#ifdef __NR_symlink
    {__NR_symlink, 1, -1},
#endif
#ifdef __NR_chmod
    {__NR_chmod, 0, -1},
#endif
#ifdef __NR_chown
    {__NR_chown, 0, -1},
#endif
#ifdef __NR_lchown
    {__NR_lchown, 0, -1},
#endif
    {__NR_openat, 1, -1},
    {__NR_faccessat, 1, -1},
#ifdef __NR_faccessat2
    {__NR_faccessat2, 1, -1},
#endif
    {__NR_newfstatat, 1, -1},
#ifdef __NR_statx
    {__NR_statx, 1, -1},
#endif
    {__NR_readlinkat, 1, -1},
    {__NR_mkdirat, 1, -1},
    {__NR_mknodat, 1, -1},
    {__NR_unlinkat, 1, -1},
#ifdef __NR_renameat
    {__NR_renameat, 1, 3},
#endif
    {__NR_renameat2, 1, 3},
    {__NR_linkat, 1, 3},
    {__NR_symlinkat, 2, -1},
    {__NR_fchmodat, 1, -1},
    {__NR_fchownat, 1, -1},
    {__NR_utimensat, 1, -1},
    {__NR_chdir, 0, -1},
    {__NR_statfs, 0, -1},
    {__NR_truncate, 0, -1},
    {__NR_getxattr, 0, -1},
    {__NR_lgetxattr, 0, -1},
    {__NR_setxattr, 0, -1},
    {__NR_lsetxattr, 0, -1},
    {__NR_listxattr, 0, -1},
    {__NR_llistxattr, 0, -1},
    {__NR_inotify_add_watch, 1, -1},
#ifdef __NR_openat2
    {__NR_openat2, 1, -1},
#endif
};
#define NPATHCALLS ((int)(sizeof PATHCALLS / sizeof PATHCALLS[0]))

struct ksigaction { void *handler; unsigned long flags; void *restorer; unsigned long mask; };
#define SIGSYS_BIT (1UL << (SIGSYS - 1))

static unsigned char g_seen[1024];
static int g_trace; /* AYANA_TRACE set: report platform-blocked syscalls once */
static volatile int g_probe_hit;

/* struct stat / struct statx owner fields (kernel layout). */
#if defined(__aarch64__)
#define STAT_UID_OFF 24
#define STAT_GID_OFF 28
#else
#define STAT_UID_OFF 28
#define STAT_GID_OFF 32
#endif
#define STATX_UID_OFF 20
#define STATX_GID_OFF 24

static void fix_owner(long buf, int uoff, int goff) {
  if (!g_fake || !buf) return;
  unsigned int *u = (unsigned int *)(buf + uoff), *g = (unsigned int *)(buf + goff);
  if (*u == (unsigned int)g_real_uid) *u = 0;
  if (*g == (unsigned int)g_real_gid) *g = 0;
}

#define NOCHANGE(x) ((unsigned int)(x) == 0xffffffffu)

/* Credential calls under fake root. Sets *handled when nr is one of them. */
static long emulate_ids(long nr, long *a, int *handled) {
  *handled = 1;
  switch (nr) {
  case __NR_getuid: return g_fid[0][0];
  case __NR_geteuid: return g_fid[0][1];
  case __NR_getgid: return g_fid[1][0];
  case __NR_getegid: return g_fid[1][1];
  case __NR_getresuid:
  case __NR_getresgid: {
    int w = nr == __NR_getresgid;
    for (int k = 0; k < 3; k++) if (a[k]) *(unsigned int *)a[k] = (unsigned int)g_fid[w][k];
    return 0;
  }
  case __NR_setuid:
  case __NR_setgid: {
    int w = nr == __NR_setgid;
    g_fid[w][0] = g_fid[w][1] = g_fid[w][2] = (unsigned int)a[0];
    return 0;
  }
  case __NR_setreuid:
  case __NR_setregid: {
    int w = nr == __NR_setregid;
    if (!NOCHANGE(a[0])) g_fid[w][0] = (unsigned int)a[0];
    if (!NOCHANGE(a[1])) g_fid[w][1] = g_fid[w][2] = (unsigned int)a[1];
    return 0;
  }
  case __NR_setresuid:
  case __NR_setresgid: {
    int w = nr == __NR_setresgid;
    for (int k = 0; k < 3; k++) if (!NOCHANGE(a[k])) g_fid[w][k] = (unsigned int)a[k];
    return 0;
  }
  case __NR_setfsuid: return g_fid[0][1];
  case __NR_setfsgid: return g_fid[1][1];
  case __NR_setgroups: return 0;
  case __NR_fchown: return 0;
  }
  *handled = 0;
  return 0;
}

static long on_blocked(long nr, long *a) {
  if (g_fake) {
    int h;
    long r = emulate_ids(nr, a, &h);
    if (h) return r;
  }
#ifdef __NR_accept
  if (nr == __NR_accept) return SC(__NR_accept4, a[0], a[1], a[2], 0, 0, 0);
#endif
  if (g_trace && nr >= 0 && nr < 1024 && !g_seen[nr]) {
    g_seen[nr] = 1;
    out("[ayana] blocked by platform: syscall ");
    out_num(nr);
    out(" -> ENOSYS\n");
  }
  return -E_NOSYS;
}

static long on_trapped(long nr, long *a) {
  if (nr == __NR_execve) return emu_execve((const char *)a[0], (char *const *)a[1], (char *const *)a[2]);
  if (nr == __NR_faccessat && a[1] == 0 && a[2] == 0x3a7) { g_probe_hit = 1; return 0; }
  /* Invariant: SIGSYS is never blocked and never loses our handler. A trap
   * that arrives while SIGSYS is blocked kills the process (glibc's fork
   * child blocks all signals and then calls set_robust_list, which the
   * platform filter traps). */
  if (nr == __NR_rt_sigprocmask) {
    if (a[1] && (a[0] == SIG_BLOCK || a[0] == SIG_SETMASK)) {
      unsigned long set = *(const unsigned long *)a[1] & ~SIGSYS_BIT;
      return ayana_gate(nr, a[0], (long)&set, a[2], a[3], 0, 0);
    }
    return ayana_gate(nr, a[0], a[1], a[2], a[3], 0, 0);
  }
  if (nr == __NR_rt_sigaction) {
    if (a[0] == SIGSYS) { /* report default disposition, change nothing */
      if (a[2]) memset((void *)a[2], 0, sizeof(struct ksigaction));
      return 0;
    }
    if (a[1]) {
      struct ksigaction k;
      memcpy(&k, (const void *)a[1], sizeof k);
      k.mask &= ~SIGSYS_BIT;
      return ayana_gate(nr, a[0], (long)&k, a[2], a[3], 0, 0);
    }
    return ayana_gate(nr, a[0], a[1], a[2], a[3], 0, 0);
  }
  if (g_fake) {
    int h;
    long r = emulate_ids(nr, a, &h);
    if (h) return r;
  }
  if (nr == __NR_getcwd) {
    long r = ayana_gate(nr, a[0], a[1], 0, 0, 0, 0);
    if (r > 1) {
      r = unmap_inplace((char *)a[0], r - 1);
      ((char *)a[0])[r++] = 0;
    }
    return r;
  }
  if (nr == __NR_fstat) {
    long r = ayana_gate(nr, a[0], a[1], 0, 0, 0, 0);
    if (!r) fix_owner(a[1], STAT_UID_OFF, STAT_GID_OFF);
    return r;
  }
  for (int i = 0; i < NPATHCALLS; i++) {
    if (PATHCALLS[i].nr != nr) continue;
    if (g_fake && (nr == __NR_fchownat
#ifdef __NR_chown
                   || nr == __NR_chown
#endif
#ifdef __NR_lchown
                   || nr == __NR_lchown
#endif
                   ))
      return 0;
    char b1[PATH_CAP], b2[PATH_CAP];
    long x[6];
    for (int k = 0; k < 6; k++) x[k] = a[k];
    int m = map_path((const char *)a[PATHCALLS[i].p1], b1);
    if (m < 0) return m;
    if (m) x[PATHCALLS[i].p1] = (long)b1;
    if (PATHCALLS[i].p2 >= 0) {
      m = map_path((const char *)a[PATHCALLS[i].p2], b2);
      if (m < 0) return m;
      if (m) x[PATHCALLS[i].p2] = (long)b2;
    }
    /* An absolute symlink target is stored with the root prefix, so the
     * kernel resolves it inside the rootfs; readlink strips it again. */
    int tgt = -1;
    if (nr == __NR_symlinkat) tgt = 0;
#ifdef __NR_symlink
    if (nr == __NR_symlink) tgt = 0;
#endif
    if (tgt >= 0) {
      m = map_path((const char *)a[tgt], b2);
      if (m < 0) return m;
      if (m) x[tgt] = (long)b2;
    }
    int rl = -1; /* index of the readlink output buffer */
    if (nr == __NR_readlinkat) rl = 2;
#ifdef __NR_readlink
    if (nr == __NR_readlink) rl = 1;
#endif
    if (rl >= 0) {
      /* Read the whole target, strip the prefix, then truncate to the
       * caller's size: a prefixed target that the kernel cut short must not
       * come back as a short, seemingly complete answer. */
      char *full = b2; /* free here: readlink calls have no second path */
      long cap = x[rl + 1];
      x[rl] = (long)full;
      x[rl + 1] = PATH_CAP;
      long r = ayana_gate(nr, x[0], x[1], x[2], x[3], x[4], x[5]);
      if (r <= 0) return r;
      r = unmap_inplace(full, r);
      if (r > cap) r = cap;
      memcpy((void *)a[rl], full, (size_t)r);
      return r;
    }
    long r = ayana_gate(nr, x[0], x[1], x[2], x[3], x[4], x[5]);
    if (nr == __NR_newfstatat && !r) fix_owner(a[2], STAT_UID_OFF, STAT_GID_OFF);
#ifdef __NR_stat
    if ((nr == __NR_stat || nr == __NR_lstat) && !r) fix_owner(a[1], STAT_UID_OFF, STAT_GID_OFF);
#endif
#ifdef __NR_statx
    if (nr == __NR_statx && !r) fix_owner(a[4], STATX_UID_OFF, STATX_GID_OFF);
#endif
    return r;
  }
  return ayana_gate(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
}

static void on_sigsys(int sig, siginfo_t *si, void *ctx) {
  (void)sig;
  ucontext_t *uc = ctx;
  long a[6];
  for (int i = 0; i < 6; i++) a[i] = (long)UC_ARG(uc, i);
  long nr = si->si_syscall;
  long r = (si->si_errno == AYANA_TAG) ? on_trapped(nr, a) : on_blocked(nr, a);
  UC_RET(uc) = (unsigned long)r;
}

static void install_handler(void) {
  struct ksigaction sa;
  memset(&sa, 0, sizeof sa);
  sa.handler = (void *)on_sigsys;
  /* No SA_ONSTACK: programs may install tiny alternate stacks (Rust does).
   * SA_NODEFER: execve emulated inside the handler must not hand a blocked
   * SIGSYS to the new image, a blocked trap kills the process. */
  sa.flags = SA_SIGINFO | SA_NODEFER;
#if NEED_RESTORER
  sa.flags |= 0x04000000; /* SA_RESTORER */
  sa.restorer = ayana_restorer;
#endif
  long r = SC(__NR_rt_sigaction, SIGSYS, &sa, 0, 8, 0, 0);
  if (r) die("cannot install SIGSYS handler", r);
  unsigned long set = 1UL << (SIGSYS - 1); /* the mask survives execve */
  SC(__NR_rt_sigprocmask, SIG_UNBLOCK, &set, 0, 8, 0, 0);
}

/* ------------------------------------------------------------------ */
/* own seccomp filter                                                 */
/* ------------------------------------------------------------------ */
#define DATA_NR offsetof(struct seccomp_data, nr)
#define DATA_ARCH offsetof(struct seccomp_data, arch)
#define DATA_IP_LO offsetof(struct seccomp_data, instruction_pointer)
#define DATA_IP_HI (offsetof(struct seccomp_data, instruction_pointer) + 4)
#define DATA_ARG_LO(i) offsetof(struct seccomp_data, args[i])
#define DATA_ARG_HI(i) (offsetof(struct seccomp_data, args[i]) + 4)

static long install_filter(void) {
  struct sock_filter f[256];
  int n = 0;
  uintptr_t lo = (uintptr_t)ayana_gate_start, hi = (uintptr_t)ayana_gate_end;
  if ((lo >> 32) != (hi >> 32)) return -1;
  f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, DATA_ARCH);
  f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AYANA_ARCH, 1, 0);
  f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
  f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, DATA_IP_HI);
  f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)(lo >> 32), 0, 4);
  f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, DATA_IP_LO);
  f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, (uint32_t)lo, 0, 2);
  f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, (uint32_t)hi, 1, 0);
  f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
  f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, DATA_NR);
  static const int EXTRA[] = {__NR_execve, __NR_getcwd};
  static const int FAKE[] = {__NR_getuid, __NR_geteuid, __NR_getgid, __NR_getegid, __NR_getresuid,
                             __NR_getresgid, __NR_setuid, __NR_setgid, __NR_setreuid, __NR_setregid,
                             __NR_setresuid, __NR_setresgid, __NR_setfsuid, __NR_setfsgid,
                             __NR_setgroups, __NR_fchown, __NR_fstat};
  int list[NPATHCALLS + 32], cnt = 0;
  for (int i = 0; i < NPATHCALLS; i++) list[cnt++] = PATHCALLS[i].nr;
  for (unsigned i = 0; i < sizeof EXTRA / sizeof EXTRA[0]; i++) list[cnt++] = EXTRA[i];
  if (g_fake)
    for (unsigned i = 0; i < sizeof FAKE / sizeof FAKE[0]; i++) list[cnt++] = FAKE[i];
  for (int i = 0; i < cnt; i++) {
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, list[i], 0, 1);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP | AYANA_TAG);
  }
  /* clone3 from outside the gate answers ENOSYS without a signal: glibc then
   * falls back to clone(). clone3 can carry CLONE_CLEAR_SIGHAND (posix_spawn,
   * system(), popen() use it), which would start the child without our
   * handler, and a stack-switching clone cannot be replayed from a handler. */
#ifdef __NR_clone3
  f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1);
  f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | E_NOSYS);
#endif
  /* Signal mask and disposition changes go through the handler, see on_trapped. */
  f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigprocmask, 0, 1);
  f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP | AYANA_TAG);
  f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigaction, 0, 5);
  f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, DATA_ARG_LO(1));
  f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 2);
  f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, DATA_ARG_HI(1));
  f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0);
  f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP | AYANA_TAG);
  f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

  struct sock_fprog prog = {(unsigned short)n, f};
  long r = SC(__NR_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0, 0);
  if (r) return r;
  return SC(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog, 0, 0, 0);
}

/* A faccessat from outside the gate reaches the handler only if our
 * filter is already active (inherited from a parent launcher). */
static int filter_active(void) {
  g_probe_hit = 0;
  ayana_rawsvc(__NR_faccessat, AT_FDCWD, 0, 0x3a7, 0, 0, 0);
  return g_probe_hit;
}

/* ------------------------------------------------------------------ */
/* entry                                                              */
/* ------------------------------------------------------------------ */
static const char *getenv_in(char **envp, const char *key) {
  size_t n = slen(key);
  for (; *envp; envp++)
    if (sprefix(*envp, key) && (*envp)[n] == '=') return *envp + n + 1;
  return 0;
}

__attribute__((used)) void ayana_main(uintptr_t *sp) {
  long argc = (long)sp[0];
  char **argv = (char **)(sp + 1);
  char **envp = argv + argc + 1;
  char **e = envp;
  while (*e) e++;
  uintptr_t *auxv = (uintptr_t *)(e + 1);
  for (uintptr_t *a = auxv; a[0] != AT_NULL; a += 2)
    if (a[0] == AT_PAGESZ) g_pg = (long)a[1];

  int i = 1;
  const char *root = 0, *fakeid = 0;
  while (i < argc && argv[i][0] == '-' && argv[i][1] == '-') {
    if (seq(argv[i], "--root") && i + 1 < argc) { root = argv[i + 1]; i += 2; }
    else if (seq(argv[i], "--fakeroot")) { g_fake = 1; i++; }
    else if (seq(argv[i], "--fakeid") && i + 1 < argc) { g_fake = 1; fakeid = argv[i + 1]; i += 2; }
    else break;
  }
  if (!root) root = getenv_in(envp, "AYANA_ROOT");
  if (getenv_in(envp, "AYANA_FAKEROOT")) g_fake = 1;
  if (g_fake) {
    g_real_uid = SC(__NR_getuid, 0, 0, 0, 0, 0, 0);
    g_real_gid = SC(__NR_getgid, 0, 0, 0, 0, 0, 0);
    long v[2] = {0, 0};
    for (int w = 0; fakeid && w < 2 && *fakeid; w++) {
      while (*fakeid >= '0' && *fakeid <= '9') v[w] = v[w] * 10 + (*fakeid++ - '0');
      if (*fakeid == ',') fakeid++;
    }
    for (int k = 0; k < 3; k++) { g_fid[0][k] = v[0]; g_fid[1][k] = v[1]; }
  }
  g_trace = getenv_in(envp, "AYANA_TRACE") != 0;
  if (i >= argc) die("usage: ayana-run [--root DIR] [--fakeroot] FILE [ARGS...]", 0);

  long n = SC(__NR_readlinkat, AT_FDCWD, "/proc/self/exe", g_self, PATH_CAP - 1, 0, 0);
  if (n <= 0) die("cannot read /proc/self/exe", n);
  g_self[n] = 0;

  install_handler();
  if (root && root[0]) {
    g_rootlen = slen(root);
    while (g_rootlen > 1 && root[g_rootlen - 1] == '/') g_rootlen--;
    if (g_rootlen + 2 > PATH_CAP) die("root path too long", 0);
    memcpy(g_root, root, g_rootlen);
    g_root[g_rootlen] = 0;
    g_map_on = 1;
    long dfd = SC(__NR_openat, AT_FDCWD, g_root, O_PATH | O_DIRECTORY | O_CLOEXEC, 0, 0, 0);
    if (dfd >= 0) {
      char fdp[32] = "/proc/self/fd/";
      int p = 14;
      char d[12];
      int t = 0;
      long v = dfd;
      do { d[t++] = (char)('0' + v % 10); v /= 10; } while (v);
      while (t) fdp[p++] = d[--t];
      fdp[p] = 0;
      long kn = SC(__NR_readlinkat, AT_FDCWD, fdp, g_kroot, PATH_CAP - 1, 0, 0);
      if (kn > 0) { g_kroot[kn] = 0; g_krootlen = (size_t)kn; }
      SC(__NR_close, dfd, 0, 0, 0, 0, 0);
    }
    if (!filter_active()) {
      long r = install_filter();
      if (r) { out("ayana-run: own seccomp filter not installed, path mapping off ("); out_num(r); out(")\n"); g_map_on = 0; }
    }
  }

  const char *file = argv[i];
  char real[PATH_CAP];
  int m = map_path(file, real);
  if (m < 0) die("path too long", m);
  struct image im = {0, 0, 0, 0};
  long r = load_elf(m ? real : file, &im);
  if (r) { out("ayana-run: cannot load "); out(file); die("", r); }

  /* New initial stack: argc, argv[i..], NULL, envp minus LD_PRELOAD, NULL, auxv. */
  enum { VEC = 8192 };
  uintptr_t vec_store[VEC + 2];
  uintptr_t *vec = (uintptr_t *)(((uintptr_t)vec_store + 15) & ~(uintptr_t)15);
  long k = 0;
  vec[k++] = (uintptr_t)(argc - i);
  for (long j = i; j < argc && k < VEC - 64; j++) vec[k++] = (uintptr_t)argv[j];
  vec[k++] = 0;
  for (char **ep = envp; *ep && k < VEC - 160; ep++)
    if (!sprefix(*ep, "LD_PRELOAD=")) vec[k++] = (uintptr_t)*ep;
  vec[k++] = 0;
  for (uintptr_t *a = auxv; k < VEC - 4; a += 2) {
    uintptr_t t = a[0], v = a[1];
    if (t == AT_PHDR) v = im.phdr;
    else if (t == AT_PHNUM) v = (uintptr_t)im.phnum;
    else if (t == AT_PHENT) v = (uintptr_t)im.phent;
    else if (t == AT_ENTRY) v = im.entry;
    else if (t == AT_BASE) v = 0;
    vec[k++] = t;
    vec[k++] = v;
    if (t == AT_NULL) break;
  }
  jump_to(vec, (void *)im.entry);
}
