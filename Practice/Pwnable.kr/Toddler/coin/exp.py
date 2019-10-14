from pwn import *

mes = ' '.join([str(i) for i in range(10000)])
ind = [-1]
mes = ' '+mes
for i in range(1,10001):
    ind.append(mes[ind[i-1]+1:].find(' ')+ind[i-1]+1)
mes = mes[1:]
ind = ind[1:]

def get_set():
    mes = r.recvline().strip().decode('utf-8').split(' ')
    n = mes[0].split('=')[1]
    c = mes[1].split('=')[1]
    return int(n)-1,int(c)

def weigh(start,end):
    mid = (end+start)//2+(end+start)%2
    qry = mes[ind[start]:ind[mid]-1]
    r.sendline(qry)
    res = int(r.recvline().strip())
    if res!=(mid-start)*10:
        return start,mid-1
    else:
        return mid,end

r = remote('pwnable.kr',9007)
r.recv()
for i in range(100):
    N,C = get_set()
    S,E = 0,N
    for j in range(C):
        nS,nE = weigh(S,E)
        S = nS
        E = nE
        if nE-nS==0:
            for k in range(j+1,C):
                r.sendline('0')
                r.recvline()
            break
    r.sendline(str(S))
    res = r.recvline()
    if b'Correct!' not in res:
        i-=1

r.interactive()
