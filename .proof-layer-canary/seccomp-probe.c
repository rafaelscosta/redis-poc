#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__x86_64__)
#define CANARY_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define CANARY_ARCH AUDIT_ARCH_AARCH64
#else
#error unsupported architecture
#endif

int main(void) {
  struct sock_filter filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, CANARY_ARCH, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog program = {
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
  };
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    perror("PR_SET_NO_NEW_PRIVS");
    return 125;
  }
#ifdef SYS_seccomp
  if (syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) != 0) {
    perror("seccomp");
    return 125;
  }
#else
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) {
    perror("PR_SET_SECCOMP");
    return 125;
  }
#endif
  errno = 0;
  long result = syscall(SYS_getppid);
  if (result == -1 && errno == EPERM) {
    puts("seccomp=enforced");
    return 0;
  }
  fputs("seccomp probe syscall was not denied\n", stderr);
  return 1;
}
