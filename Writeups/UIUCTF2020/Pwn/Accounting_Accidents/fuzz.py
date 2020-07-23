from pwn import *
import os
import sys
import subprocess

def patch():
    if 'accounting_patched' not in subprocess.getoutput('ls'):
        f = open('accounting','rb').read()
        f = f.replace(b'usleep',b'isnan\x00')
        f2 = open(os.open('accounting_patched',os.O_CREAT|os.O_WRONLY,0o700),'wb')
        f2.write(f)
        f2.close()

def printtree():
    r.recvuntil('=====TREE=====')
    print(f'TREE : ')
    print(r.recvuntil('==============').decode())

patch()
r = process(['gdb','-ex','source gdbscript.py'])
r.sendlineafter('Item: ','M30W')
for i in range(len(sys.argv)-1):
    printtree()
    r.sendlineafter('Cost: ',sys.argv[1+i])
printtree()
