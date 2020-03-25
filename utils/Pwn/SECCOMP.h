/*Some seccomp constructor macros for pwn problems*/

#include<stddef.h>
#include<sys/prctl.h>
#include<linux/filter.h>
#include<linux/seccomp.h>
#include<linux/audit.h>
#include<linux/unistd.h>

#define ArchField offsetof(struct seccomp_data, arch)
#define SyscallNum offsetof(struct seccomp_data, nr)
#define SyscallArg(x) offsetof(struct seccomp_data, args[x])

#define Allow(syscall) \
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##syscall, 0, 1),\
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

#define Disallow(syscall) \
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##syscall, 0, 1),\
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL)
