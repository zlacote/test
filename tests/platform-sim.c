/* Emulates the Android app seccomp behaviour on a desktop Linux host:
 * set_robust_list and rseq are trapped with SIGSYS (data 0), like the
 * platform filter observed on the target phone. Then execs argv[1..]. */
#define _GNU_SOURCE
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

int main(int argc, char **argv) {
  struct sock_filter f[] = {
      BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_set_robust_list, 2, 0),
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rseq, 1, 0),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRAP),
  };
  struct sock_fprog prog = {sizeof f / sizeof f[0], f};
  if (argc < 2) return 2;
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) || syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &prog)) {
    perror("seccomp");
    return 1;
  }
  execv(argv[1], argv + 1);
  perror("execv");
  return 1;
}
