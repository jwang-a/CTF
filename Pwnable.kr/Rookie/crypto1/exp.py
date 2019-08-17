###padding oracle

from pwn import *
import hashlib

def login(usr,pwd,interactive=False):
    r = remote('pwnable.kr',9006)
    r.sendlineafter('ID\n',usr)
    r.sendlineafter('PW\n',pwd)
    if interactive is True:
        r.interactive()
    else:
        res = r.recvline().decode().strip().split('(')[1][:-1]
        r.close()
        return res

charset = '1234567890abcdefghijklmnopqrstuvwxyz-_'

max_cookie_len = len(login('',''))//2
cookie = ''
for i in range(0,max_cookie_len,0x10):
    flag = 0
    cur_blk = ''
    cur_blk_len = 0x10
    if i==0:
        cur_blk_len-=2
    for j in range(cur_blk_len-1,-1,-1):
        payload = '-'*j
        target = login(payload,'')[:i*2+32]
        print('%2d %2d %s'%(i,j,cookie+cur_blk),end=' ')
        for k in charset:
            payload = (cookie+cur_blk).rjust(i+15,'-')+k
            print('\b'+k,end='')
            res = login(payload,'')[:i*2+32]
            if res==target:
                cur_blk+=k
                print('')
                break
            if k==charset[-1]:
                flag=1
                break
        if flag==1:
            break
    if flag==1:
        break
    cookie+=cur_blk

pwd = hashlib.sha256(('admin'+cookie).encode()).hexdigest()
login('admin',pwd,interactive=True)
