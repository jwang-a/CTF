#!/usr/bin/env python2

import sys
import os
from unicorn import *
from unicorn.x86_const import *
from threading import Thread
from Queue import Queue as queue
from elftools.elf.elffile import ELFFile

kernel_queue = Queue(1)
user_queue = Queue(1)

KERNEL_ADDRESS = 0xFFFFFFFF81000000
KERNEL_STACK =   0xFFFF8801FFFFF000

KERNEL_SYSCALL_HANDLER = KERNEL_ADDRESS + 7
KERNEL_SEGFAULT_HANDLER = KERNEL_ADDRESS + 14

USER_ADDRESS = 0x4000000
USER_STACK = 0x7ffffffff000

MAPPING_SIZE = 0x100000

USER_TEXT_MEM = "\x00" * MAPPING_SIZE
USER_DATA_MEM = "\x00" * MAPPING_SIZE
USER_STACK_MEM = "\x00" * MAPPING_SIZE

def get_syscall_regs(uc):
    return {
        "rax": uc.reg_read(UC_X86_REG_RAX),
        "rdi": uc.reg_read(UC_X86_REG_RDI),
        "rsi": uc.reg_read(UC_X86_REG_RSI),
        "rdx": uc.reg_read(UC_X86_REG_RDX),
        "r10": uc.reg_read(UC_X86_REG_R10),
        "r8" : uc.reg_read(UC_X86_REG_R8),
        "r9" : uc.reg_read(UC_X86_REG_R9)
    }

def set_syscall_regs(uc, regs):
    uc.reg_write(UC_X86_REG_RAX, regs["rax"])
    uc.reg_write(UC_X86_REG_RDI, regs["rdi"])
    uc.reg_write(UC_X86_REG_RSI, regs["rsi"])
    uc.reg_write(UC_X86_REG_RDX, regs["rdx"])
    uc.reg_write(UC_X86_REG_R10, regs["r10"])
    uc.reg_write(UC_X86_REG_R8, regs["r8"])
    uc.reg_write(UC_X86_REG_R9, regs["r9"])

def handle_syscall(uc, user_data):
    kernel_queue.put(get_syscall_regs(uc))
    set_syscall_regs(uc, user_queue.get())

def handle_userland_invalid(uc, access, address, size, value, user_data):
    kernel_queue.put("SEGV")
    return False

def handle_kernel(uc, address, size, user_data):
    inst = uc.mem_read(address, size)
    
    if inst == "\xcf":
        user_queue.put(get_syscall_regs(uc))
        
    if inst == "\xcf" or inst == "\xF3\x90":
        msg = kernel_queue.get()
        if msg == "SEGV":
            uc.reg_write(UC_X86_REG_RIP, KERNEL_SEGFAULT_HANDLER)
        else:
            set_syscall_regs(uc, msg)
            uc.reg_write(UC_X86_REG_RIP, KERNEL_SYSCALL_HANDLER)

def handle_kernel_interrupt(uc, intno, data):    
    if intno == 0x70:
        rax = uc.reg_read(UC_X86_REG_RAX)
        if rax == 0:
            rdi = uc.reg_read(UC_X86_REG_RDI)
            rsi = uc.reg_read(UC_X86_REG_RSI)
            rdx = uc.reg_read(UC_X86_REG_RDX)
            uc.mem_protect(rdi, rsi, rdx)
        elif rax == 7:
            rdi = uc.reg_read(UC_X86_REG_RDI)
            rsi = uc.reg_read(UC_X86_REG_RSI)
            rdx = uc.reg_read(UC_X86_REG_RDX)
            buf = str(eval(str(uc.mem_read(rdi, rdx))))
            uc.mem_write(rsi, buf)
            uc.reg_write(UC_X86_REG_RAX, len(buf))

def handle_kernel_in(uc, port, size, user_data):
    if port == 0x3f8 and size == 1:
        c = sys.stdin.read(1)
        if not c:
            os._exit(-1)
        return ord(c)

def handle_kernel_out(uc, port, size, value, user_data):
    if port == 0x3f8 and size == 1:
        sys.stdout.write(chr(value))
        sys.stdout.flush()

def handle_kernel_invalid(uc, access, address, size, value, user_data):
    log.info("handle_kernel_invalid: 0x{:x}".format(address))
    uc.reg_write(UC_X86_REG_RIP, KERNEL_SEGFAULT_HANDLER)
    return True

def read(file):
    with open(file, 'rb') as f:
        return f.read()

def start_userland():
    with open("/home/ctf/userland", 'rb') as f:
        userland = ELFFile(f).get_segment(0).data()
    flag1 = read("/flag1.txt")

    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    mu.mem_map_ptr(USER_ADDRESS, MAPPING_SIZE, UC_PROT_READ | UC_PROT_EXEC, USER_TEXT_MEM)
    mu.mem_map_ptr(USER_ADDRESS + MAPPING_SIZE, MAPPING_SIZE, UC_PROT_READ | UC_PROT_WRITE, USER_DATA_MEM)
    mu.mem_map_ptr(USER_STACK - MAPPING_SIZE, MAPPING_SIZE, UC_PROT_READ | UC_PROT_WRITE, USER_STACK_MEM)

    mu.mem_write(USER_ADDRESS, userland)
    mu.hook_add(UC_HOOK_INSN, handle_syscall, None, 1, 0, UC_X86_INS_SYSCALL)
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, handle_userland_invalid)

    mu.reg_write(UC_X86_REG_RSP, USER_STACK-0x1000)
    mu.reg_write(UC_X86_REG_RIP, USER_ADDRESS)

    mu.mem_write(USER_ADDRESS + MAPPING_SIZE, flag1)

    mu.emu_start(USER_ADDRESS, USER_ADDRESS + len(userland))

    regs = get_syscall_regs(mu)
    regs["rax"] = 60
    kernel_queue.put(regs)

def start_kernel():
    kernel = read("/home/ctf/kernel")
    flag2 = read("/flag2.txt")

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map_ptr(USER_ADDRESS, MAPPING_SIZE, UC_PROT_READ, USER_TEXT_MEM)
    mu.mem_map_ptr(USER_ADDRESS + MAPPING_SIZE, MAPPING_SIZE, UC_PROT_READ | UC_PROT_WRITE, USER_DATA_MEM)
    mu.mem_map_ptr(USER_STACK - MAPPING_SIZE, MAPPING_SIZE, UC_PROT_READ | UC_PROT_WRITE, USER_STACK_MEM)

    mu.mem_map(KERNEL_ADDRESS, MAPPING_SIZE, UC_PROT_READ | UC_PROT_EXEC)
    mu.mem_map(KERNEL_STACK - MAPPING_SIZE, MAPPING_SIZE, UC_PROT_READ | UC_PROT_WRITE)

    mu.mem_write(KERNEL_ADDRESS, kernel)
    mu.hook_add(UC_HOOK_CODE, handle_kernel, None, KERNEL_ADDRESS, KERNEL_ADDRESS+MAPPING_SIZE)
    mu.hook_add(UC_HOOK_INSN, handle_kernel_in, None, 1, 0, UC_X86_INS_IN)
    mu.hook_add(UC_HOOK_INSN, handle_kernel_out, None, 1, 0, UC_X86_INS_OUT)
    mu.hook_add(UC_HOOK_INTR, handle_kernel_interrupt)
    mu.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED, handle_kernel_invalid)

    mu.reg_write(UC_X86_REG_RSP, KERNEL_STACK-0x1000)
    mu.reg_write(UC_X86_REG_RIP, KERNEL_ADDRESS)

    mu.mem_write(KERNEL_ADDRESS + 0x5000, flag2)

    mu.emu_start(KERNEL_ADDRESS, KERNEL_ADDRESS + len(kernel))

if __name__ == '__main__':
    kernel = Thread(target=start_kernel)
    userland = Thread(target=start_userland)

    kernel.start()
    userland.start()

    kernel.join()
    userland.join(1)
    os._exit(0)
