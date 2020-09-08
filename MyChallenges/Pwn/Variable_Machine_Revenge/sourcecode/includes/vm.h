#include <stdint.h>

#ifndef VM_
#define VM_

// #define DEBUG 1

#define SETOPCODE(r, op) r = (op << 24) + (r & 0x00ffffff)
#define SETARG1(r, arg1) r = (arg1 << 16) + (r & 0xff00ffff)
#define SETARG2(r, arg2) r = (arg2 << 8) + (r & 0xffff00ff)
#define SETARG3(r, arg3) r = arg3 + (r & 0xffffff00)

#define GETOPCODE(r) ((r & 0xff000000) >> 24)
#define GETARG1(r) ((r & 0x00ff0000) >> 16)
#define GETARG2(r) ((r & 0x0000ff00) >> 8)
#define GETARG3(r) ((r & 0x000000ff))

int initVm(char *c, int length);
size_t fetch();
int execute(size_t opcode);
int allocate(size_t opcode);
int delete(size_t opcode);
int edit(size_t opcode);
int print(size_t opcode);
int operate(size_t opcode);
int concat(size_t opcode);

#endif