/* Reproduces the glibc fork pattern: block all signals, then call a
 * syscall that the platform filter traps. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/wait.h>

int main(void) {
  sigset_t all, old;
  sigfillset(&all);
  sigprocmask(SIG_BLOCK, &all, &old);
  long r = syscall(__NR_set_robust_list, 0, 0);
  sigprocmask(SIG_SETMASK, &old, 0);
  printf("survived blocked trap, r=%ld\n", r);
  pid_t p = fork();
  if (p == 0) { execl("/usr/bin/true", "true", (char *)0); _exit(99); }
  int st; waitpid(p, &st, 0);
  printf("fork+exec child status=%d\n", st);
  return 0;
}
