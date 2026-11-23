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
