###Split numbers into groups by their bitmap
###Works as long as N<2^C

from pwn import *

r = remote('pwnable.kr', 9008)
r.recvuntil('... -\n\t\n')

for i in range(100):
    res = r.recvline().strip().split(b' C=')
    N = int(res[0][2:])
    C = int(res[1])
    groups = []
    for j in range(C):
        entry = ' '.join([str(k) for k in range(N) if k&(1<<j)])
        groups.append(entry)
    r.sendline('-'.join(groups))
    res = r.recvline().strip().split(b'-')
    bits = ''
    for j in res:
        if int(j)%10==0:
            bits+='0'
        else:
            bits+='1'
    r.sendline(str(int(bits[::-1], 2)))
    r.recvline()

r.interactive()
