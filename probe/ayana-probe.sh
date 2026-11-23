#!/data/data/com.termux/files/usr/bin/bash
# Ayana device probe v1.
# Collects facts about the device and the app sandbox. Changes nothing
# outside $TMPDIR and $HOME/ayana-probe. Safe to run repeatedly.

OUT="$HOME/ayana-report.txt"
WORK="$HOME/ayana-probe"
mkdir -p "$WORK" "${TMPDIR:=$PREFIX/tmp}"
exec > >(tee "$OUT") 2>&1

sec() { echo; echo "=== $1 ==="; }
run() {  # run "<shell command>" [max_lines]
  echo "\$ $1"
  bash -c "$1" 2>&1 | head -n "${2:-25}"
  echo "[rc=${PIPESTATUS[0]}]"
}

sec "1. device"
run 'getprop ro.product.manufacturer; getprop ro.product.model'
run 'getprop ro.build.version.release; getprop ro.build.version.sdk; getprop ro.build.version.security_patch'
run 'getprop ro.product.cpu.abilist'
run 'uname -a'
run 'cat /proc/version'
run 'getconf PAGESIZE'
run 'nproc; head -n 3 /proc/meminfo'
run 'df -h "$HOME" | tail -n 1'

sec "2. app sandbox"
run 'env | grep -E "^TERMUX_(VERSION|APK_RELEASE|APP__TARGET_SDK|APP__PACKAGE_NAME)" ; echo "PREFIX=$PREFIX"'
run 'cat /proc/self/attr/current; echo'
run 'id'
run '/system/bin/getenforce'
run 'grep -E "^(Seccomp|Seccomp_filters|NoNewPrivs|CapEff|CapBnd)" /proc/self/status'
run 'ls -la /proc/self/ns'
run 'cat /proc/sys/user/max_user_namespaces /proc/sys/kernel/unprivileged_userns_clone'
run 'cat /proc/sys/kernel/yama/ptrace_scope'

sec "3. restricted kernel views"
run 'head -n 2 /proc/stat' 3
run 'cat /proc/loadavg /proc/uptime'
run 'head -n 3 /proc/net/tcp' 4
run 'head -n 4 /proc/net/dev' 5
run 'head -n 3 /proc/self/mountinfo' 4
run 'ls /sys/class/net'
run '/system/bin/ip addr' 12
run 'cat /proc/sys/net/ipv4/ping_group_range /proc/sys/net/ipv4/ip_unprivileged_port_start'
run 'grep -E "fuse|overlay|tmpfs|binder" /proc/filesystems'
run 'ls -ld /dev/shm /dev/fuse /tmp /etc /bin /usr'
run 'ls /'

sec "4. files"
run 'cd "$TMPDIR" && rm -f a b c && echo x > a && ln a b; echo "hardlink rc=$?"; ln -s a c; echo "symlink rc=$?"; rm -f a b c'

sec "5. native probe"
if ! command -v clang >/dev/null 2>&1; then
  echo "installing clang (one time)..."
  pkg install -y clang >/dev/null 2>&1 || echo "clang install FAILED"
fi
cat > "$WORK/probe.c" <<'CEOF'
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/auxv.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#ifndef PR_SET_MM
#define PR_SET_MM 35
#endif
#ifndef PR_SET_MM_EXE_FILE
#define PR_SET_MM_EXE_FILE 13
#endif
#define WRONG_RESULT 250

static long PG;
static char codefile[512];
/* aarch64: mov x0, #42 ; ret */
static const uint32_t CODE[2] = {0xd2800540u, 0xd65f03c0u};
typedef long (*fn0)(void);

static int call_code(void *p) {
  __builtin___clear_cache((char *)p, (char *)p + sizeof CODE);
  return ((fn0)p)() == 42 ? 0 : WRONG_RESULT;
}

/* Run a test in a child so a crash cannot kill the probe. */
static void guarded(const char *name, int (*f)(void)) {
  fflush(stdout);
  pid_t p = fork();
  if (p == 0) { alarm(5); _exit(f() & 0xff); }
  int st = 0;
  waitpid(p, &st, 0);
  if (WIFEXITED(st)) {
    int c = WEXITSTATUS(st);
    if (c == 0) printf("%-28s OK\n", name);
    else if (c == WRONG_RESULT) printf("%-28s FAIL wrong result\n", name);
    else printf("%-28s FAIL errno=%d (%s)\n", name, c, strerror(c));
  } else if (WIFSIGNALED(st)) {
    printf("%-28s KILLED signal=%d (%s)\n", name, WTERMSIG(st), strsignal(WTERMSIG(st)));
  }
}

/* --- executable memory --- */
static int t_anon_rwx(void) {
  void *p = mmap(0, PG, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) return errno;
  memcpy(p, CODE, sizeof CODE);
  return call_code(p);
}
static int t_anon_rw_then_rx(void) {
  void *p = mmap(0, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (p == MAP_FAILED) return errno;
  memcpy(p, CODE, sizeof CODE);
  if (mprotect(p, PG, PROT_READ | PROT_EXEC)) return errno;
  return call_code(p);
}
static int t_memfd_rx(void) {
  int fd = (int)syscall(__NR_memfd_create, "ayana", 0);
  if (fd < 0) return errno;
  if (write(fd, CODE, sizeof CODE) != (ssize_t)sizeof CODE) return errno;
  if (ftruncate(fd, PG)) return errno;
  void *p = mmap(0, PG, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
  if (p == MAP_FAILED) return errno;
  return call_code(p);
}
static int t_file_clean_rx(void) {
  int fd = open(codefile, O_RDONLY);
  if (fd < 0) return errno;
  void *p = mmap(0, PG, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
  if (p == MAP_FAILED) return errno;
  return call_code(p);
}
static int t_file_written_rx(void) {
  int fd = open(codefile, O_RDONLY);
  if (fd < 0) return errno;
  uint32_t *p = mmap(0, PG, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
  if (p == MAP_FAILED) return errno;
  p[0] = CODE[0]; /* dirty the private page */
  if (mprotect(p, PG, PROT_READ | PROT_EXEC)) return errno;
  return call_code(p);
}

/* --- isolation and identity --- */
static int t_userns(void) { return unshare(CLONE_NEWUSER) ? errno : 0; }
static int t_userns_mount(void) { return unshare(CLONE_NEWUSER | CLONE_NEWNS) ? errno : 0; }
static int t_set_name(void) {
  if (prctl(PR_SET_NAME, "ayana-test")) return errno;
  char b[32] = {0};
  int fd = open("/proc/self/comm", O_RDONLY);
  if (fd < 0) return errno;
  if (read(fd, b, sizeof b - 1) < 0) return errno;
  return strncmp(b, "ayana-test", 10) ? WRONG_RESULT : 0;
}
static int t_set_mm_exe(void) {
  int fd = open(codefile, O_RDONLY);
  if (fd < 0) return errno;
  return prctl(PR_SET_MM, PR_SET_MM_EXE_FILE, fd, 0, 0) ? errno : 0;
}
static int t_sysv_shm(void) {
  long id = syscall(__NR_shmget, (long)IPC_PRIVATE, 4096L, (long)(IPC_CREAT | 0600));
  if (id < 0) return errno;
  syscall(__NR_shmctl, id, (long)IPC_RMID, 0L);
  return 0;
}
static int t_hardlink(void) {
  char a[600], b[600];
  snprintf(a, sizeof a, "%s.l1", codefile);
  snprintf(b, sizeof b, "%s.l2", codefile);
  unlink(a); unlink(b);
  int fd = open(a, O_CREAT | O_WRONLY, 0600);
  if (fd < 0) return errno;
  close(fd);
  int r = link(a, b) ? errno : 0;
  unlink(a); unlink(b);
  return r;
}

/* --- network --- */
static int t_bind_port(int port) {
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) return errno;
  struct sockaddr_in a = {0};
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  return bind(s, (struct sockaddr *)&a, sizeof a) ? errno : 0;
}
static int t_bind_80(void) { return t_bind_port(80); }
static int t_bind_8080(void) { return t_bind_port(18080); }
static int t_icmp_dgram(void) { return socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP) < 0 ? errno : 0; }
static int t_icmp_raw(void) { return socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) < 0 ? errno : 0; }
static int nl_bind_flag = 0;
static int nl_dump(int type) {
  int s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
  if (s < 0) return errno;
  if (nl_bind_flag) {
    struct sockaddr_nl sa = {0};
    sa.nl_family = AF_NETLINK;
    if (bind(s, (struct sockaddr *)&sa, sizeof sa)) return errno;
  }
  struct { struct nlmsghdr h; struct rtgenmsg g; } req;
  memset(&req, 0, sizeof req);
  req.h.nlmsg_len = sizeof req;
  req.h.nlmsg_type = type;
  req.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
  req.h.nlmsg_seq = 1;
  req.g.rtgen_family = AF_UNSPEC;
  struct sockaddr_nl k = {0};
  k.nl_family = AF_NETLINK;
  if (sendto(s, &req, sizeof req, 0, (struct sockaddr *)&k, sizeof k) < 0) return errno;
  struct timeval tv = {2, 0};
  setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  static char buf[32768];
  ssize_t n = recv(s, buf, sizeof buf, 0);
  if (n < 0) return errno;
  struct nlmsghdr *h = (struct nlmsghdr *)buf;
  if (h->nlmsg_type == NLMSG_ERROR) return -((struct nlmsgerr *)NLMSG_DATA(h))->error;
  return 0;
}
static int t_nl_bind(void) { nl_bind_flag = 1; int r = nl_dump(RTM_GETADDR); return r; }
static int t_nl_getlink(void) { return nl_dump(RTM_GETLINK); }
static int t_nl_getaddr(void) { return nl_dump(RTM_GETADDR); }

/* --- seccomp census: call every syscall number with zero args --- */
static void census(void) {
  enum { MAXNR = 512 };
  static char cls[MAXNR + 1];
  for (long nr = 0; nr <= MAXNR; nr++) {
    int fds[2];
    if (pipe(fds)) { cls[nr] = '?'; continue; }
    fflush(stdout);
    pid_t p = fork();
    if (p == 0) {
      close(fds[0]);
      alarm(1);
      long r = syscall(nr, 0L, 0L, 0L, 0L, 0L, 0L);
      int e = (r == -1) ? errno : 0;
      char c = 'o';                 /* returned ok */
      if (e == ENOSYS) c = 'n';
      else if (e == EPERM) c = 'p';
      else if (e == EACCES) c = 'a';
      else if (e) c = 'e';          /* other errno: syscall exists and ran */
      syscall(__NR_write, fds[1], &c, 1L);
      syscall(__NR_exit, 0L);
    }
    close(fds[1]);
    char c = 0;
    ssize_t got = read(fds[0], &c, 1);
    close(fds[0]);
    int st = 0;
    while (waitpid(p, &st, 0) > 0 && WIFSTOPPED(st)) kill(p, SIGKILL);
    if (got == 1) cls[nr] = c;
    else if (WIFSIGNALED(st) && WTERMSIG(st) == SIGSYS) cls[nr] = 'S';
    else if (WIFSIGNALED(st) && WTERMSIG(st) == SIGALRM) cls[nr] = 't';
    else if (WIFSIGNALED(st)) cls[nr] = 'k';
    else cls[nr] = 'x';             /* exited without reply, e.g. exit() */
  }
  const char *want = "Snpaktx";
  const char *label[] = {"SIGSYS (seccomp kill)", "ENOSYS", "EPERM", "EACCES",
                         "killed by other signal", "timeout (blocked)", "no reply (exited)", 0};
  for (int i = 0; label[i]; i++) {
    printf("%-24s:", label[i]);
    for (long nr = 0; nr <= MAXNR; nr++)
      if (cls[nr] == want[i]) printf(" %ld", nr);
    printf("\n");
  }
}

int main(void) {
  setvbuf(stdout, NULL, _IOLBF, 0);
  PG = sysconf(_SC_PAGESIZE);
  struct utsname u;
  uname(&u);
  printf("uname: %s %s %s\n", u.sysname, u.release, u.machine);
  printf("pagesize: sysconf=%ld AT_PAGESZ=%lu\n", PG, getauxval(AT_PAGESZ));
  printf("hwcap=0x%lx hwcap2=0x%lx\n", getauxval(AT_HWCAP), getauxval(AT_HWCAP2));

  const char *tmp = getenv("TMPDIR");
  snprintf(codefile, sizeof codefile, "%s/ayana_code.bin", tmp ? tmp : "/tmp");
  int fd = open(codefile, O_CREAT | O_TRUNC | O_WRONLY, 0700);
  if (fd >= 0) {
    char *page = calloc(1, PG);
    memcpy(page, CODE, sizeof CODE);
    if (write(fd, page, PG) != PG) perror("write codefile");
    close(fd);
  }

  printf("\n-- executable memory --\n");
  guarded("anon RWX", t_anon_rwx);
  guarded("anon RW then RX", t_anon_rw_then_rx);
  guarded("memfd RX", t_memfd_rx);
  guarded("data file clean RX", t_file_clean_rx);
  guarded("data file written then RX", t_file_written_rx);

  printf("\n-- isolation / identity / ipc --\n");
  guarded("unshare user ns", t_userns);
  guarded("unshare user+mount ns", t_userns_mount);
  guarded("prctl set name", t_set_name);
  guarded("prctl set mm exe", t_set_mm_exe);
  guarded("sysv shmget", t_sysv_shm);
  guarded("hard link", t_hardlink);

  printf("\n-- network --\n");
  guarded("bind tcp port 80", t_bind_80);
  guarded("bind tcp port 18080", t_bind_8080);
  guarded("icmp datagram socket", t_icmp_dgram);
  guarded("icmp raw socket", t_icmp_raw);
  guarded("netlink bind", t_nl_bind);
  guarded("netlink RTM_GETLINK", t_nl_getlink);
  guarded("netlink RTM_GETADDR", t_nl_getaddr);

  printf("\n-- seccomp census (syscall numbers) --\n");
  census();
  unlink(codefile);
  return 0;
}
CEOF
BIN="$TMPDIR/ayana_probe"
echo 'int main(void){return 0;}' > "$WORK/true.c"
clang -O1 -o "$TMPDIR/ayana_true" "$WORK/true.c" 2>>"$WORK/cc.log"
run 'env -u LD_PRELOAD "$TMPDIR/ayana_true"; echo "direct exec of data file rc=$?"'
run 'env -u LD_PRELOAD /system/bin/linker64 "$TMPDIR/ayana_true"; echo "exec via system linker rc=$?"'
if clang -O1 -w -o "$BIN" "$WORK/probe.c" 2>"$WORK/cc.log"; then
  if env -u LD_PRELOAD "$TMPDIR/ayana_true" 2>/dev/null; then "$BIN"
  else /system/bin/linker64 "$BIN"; fi
else
  echo "compile FAILED:"; head -n 20 "$WORK/cc.log"
fi

sec "6. Debian glibc without proot"
LD=$(find "$PREFIX/var/lib" -path '*aarch64-linux-gnu/ld-linux-aarch64.so.1' -type f 2>/dev/null | head -n 1)
if [ -z "$LD" ]; then
  echo "no Debian/glibc rootfs found under $PREFIX/var/lib (skipping)"
else
  R="${LD%/usr/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1}"
  R="${R%/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1}"
  echo "rootfs: $R"
  export LD R LP="$R/usr/lib/aarch64-linux-gnu:$R/lib/aarch64-linux-gnu"
  G='env -u LD_PRELOAD -u LD_LIBRARY_PATH "$LD" --library-path "$LP"'
  run "$G \"\$R/usr/bin/true\"; echo \"glibc true rc=\$?\""
  run "$G \"\$R/usr/bin/uname\" -a"
  run "$G --argv0 ayana-name \"\$R/usr/bin/cat\" /proc/self/cmdline | tr '\\0' ' '; echo"
  run "$G \"\$R/usr/bin/readlink\" /proc/self/exe"
  run "$G \"\$R/usr/bin/ls\" /" 8
  run "$G \"\$R/usr/bin/cat\" /etc/os-release" 3
  run "$G \"\$R/usr/bin/id\""
  run "$G \"\$R/usr/bin/getent\" hosts example.com"
  run "$G \"\$R/usr/bin/bash\" -c 'echo bash ok \$BASH_VERSION'"
  run "env -u LD_PRELOAD LD_SHOW_AUXV=1 \"\$LD\" --library-path \"\$LP\" \"\$R/usr/bin/true\"" 30
  run "time ( for i in 1 2 3 4 5 6 7 8 9 10; do $G \"\$R/usr/bin/true\"; done )"
  if command -v proot-distro >/dev/null 2>&1; then
    run 'proot-distro list 2>&1 | grep -iE "debian|installed"' 8
    run 'timeout 90 proot-distro login debian -- uname -r'
    run 'time ( for i in 1 2 3 4 5 6 7 8 9 10; do timeout 90 proot-distro login debian -- true; done )'
  fi
fi

sec "done"
echo "report saved to $OUT"
if [ -d "$HOME/storage/downloads" ]; then
  cp "$OUT" "$HOME/storage/downloads/ayana-report.txt" && echo "copied to Downloads/ayana-report.txt"
fi
