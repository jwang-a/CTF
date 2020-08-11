#!/usr/sbin/python3

from pwn import *
import binascii

###Util
def get_token():
    r.sendlineafter('choice : ','1')
    return binascii.unhexlify(r.recvline()[:-1].split(b' : ')[1])

def login(token):
    r.sendlineafter('choice : ','2')
    r.sendlineafter('(hex encoded) : ',binascii.hexlify(token))
    return r.recvline()

def create_user(user,desc):
    r.sendlineafter('choice : ','2')
    r.sendlineafter('Username : ',user)
    r.sendlineafter('Description : ',desc)
    return binascii.unhexlify(r.recvline()[:-1].split(b' : ')[1])

def get_secret():
    r.sendlineafter('choice : ','3')
    return r.recvline()

def logout():
    r.sendlineafter('choice : ','4')

def xorbytes(s1,s2):
    r = b''
    for c1,c2 in zip(s1,s2):
        r+=p8(c1^c2)
    return r

def padding_oracle(orig_cipher):
    orig_cipher = list(orig_cipher)
    cipher = orig_cipher[:]
    P = []
    LEN = len(orig_cipher)
    for i in range(LEN//0x10-1):
        for j in range(1,0x11):
            cur = cipher[-0x10-j]
            for k in range(1,j):
                cipher[-0x10-k] = P[j-1-k]^j
            for k in range(0x100):
                if k==cur:
                    continue
                print('\b\b\b\b\b\b\b\b\b%2d %2d %3d'%(i,j,k),end='')
                cipher[-0x10-j] = k
                res = login(b''.join(map(p8,cipher)))
                if b'Padding' not in res and b'padding' not in res:
                    P = [k^j]+P
                    if b'menu' in res:
                        logout()
                    break
            if len(P)!=0x10*i+j:
                P = [cur^j]+P
            print(P,'\n         ',end='')
        cipher = orig_cipher[:-0x10*(i+1)]
    plain = b''
    for i in range(len(P)):
        plain+=p8(P[i]^orig_cipher[i])
    return plain

def probe_by_login(token,plain):
    CNT = 0
    iv, orig_cipher = token[:0x10], token[0x10:]
    orig_cipher = list(orig_cipher)
    cipher = orig_cipher[:]
    for i in range(0x80):
        cipher[0x10] = orig_cipher[0x10]^plain[0x20]^i
        for j in range(0x80):
            cipher[0x11] = orig_cipher[0x11]^plain[0x21]^j
            for k in range(0x80):
                cipher[0x12] = orig_cipher[0x12]^plain[0x22]^k
                for l in range(0x80):
                    cipher[0x13] = orig_cipher[0x13]^plain[0x23]^l
                    CNT+=1
                    if CNT%10000==0:
                        print(CNT)
                    res = login(iv+b''.join(map(p8,cipher)))
                    if b'Unicode Decode Error' not in res:
                        return iv+b''.join(map(p8,cipher))

def probe_by_create(target_idx_range,fixed):
    CNT = 0
    name = list(b'king of the'.ljust(0xf,b'\x00'))
    for i in range(0x80):
        name[0xb] = i
        for j in range(0x80):
            name[0xc] = j
            for k in range(0x80):
                name[0xd] = k
                for l in range(0x80):
                    name[0xe] = l
                    CNT+=1
                    if CNT%10000==0:
                        print(CNT)
                    if 0xa in name:
                        continue
                    res = create_user(b''.join(map(p8,name)),'\x00'*0xf)
                    plain = xorbytes(res[target_idx_range[0]:target_idx_range[1]],fixed)
                    try:
                        plain = plain.decode()
                        if len(plain)<=0xe and '\n' not in plain:
                            print(CNT)
                            return b''.join(map(p8,name)),plain
                    except:
                        pass

###Solve
r = process(['python3','server.py'])

token = get_token()
plain = padding_oracle(token)

token = token[:0x37]+p8(token[0x37]^ord('0')^ord('1'))+token[0x38:]
plain2 = padding_oracle(token[:0x40])

token = token[:0x24]+xorbytes(xorbytes(token[0x24:0x30],plain[0x24:0x30]),plain2[0x24:0x30])+token[0x30:]
token = token[:0x2c]+p8(token[0x2c]^ord('0')^ord('1'))+token[0x2d:]
plain3 = padding_oracle(token[:0x40])

privileged_token = probe_by_login(token,plain3)
print(f'privileged token : {privileged_token}')

token = create_user('king of the'.ljust(0xf,'\x00'),'\x00'*0xf)
master_token = token[:0x20]

name,desc = probe_by_create([0x30,0x40],xorbytes(token[0x10:0x20],b' cats||isvip:1||'))
token = create_user(name,'\x00'+desc)
master_token+=token[0x40:0x50]

name,desc = probe_by_create([0x30,0x40],xorbytes(token[0x40:0x50],b'isadmin:1||desc:'))
token = create_user(name,'\x00'+desc)
master_token+=token[0x40:0x60]
print(f'master token : {master_token}')

logout()
login(master_token)
print(get_secret())

'''
IVIVIVIVIVIVIVIV
name:king of the ->enc(IV^P0)=C0
xxxx||isvip:0||i ->enc(C0^P1)=C1 known
sadmin:0||desc:x ->enc(C1^P2)=C2 known
SSSSxxxxxxxxxxxx ->enc(C2^P3)=C3(=enc(C0^target) -> P3=C2^C0^target) C2 modifiable
padding_________

privileged token : b'your_everyday_iv\xc6\xd4\x91\x93Zb\xde\xa3\xd3\xf5X<\xdf\x1c\x8eW\x8c\xe5\xf1\x98\xe9\xf9RR\n\xca8\xe3\xf6l\xf6\xce\xb3~5\x13&\xd9\xd8\x12\x82o\x18\x86\xcb\x02\xbd\xb2b\xe5\x92\x19\xb8Ez\xfc)\xa2\x17\x93|\xf2 %\xe4\x11#:\x13D\\\x9e\x8a}?\x14\xfd\xde@\xde\x95\xc6\n\xc1\x95\xdfi\xcd\xf7\xbd\x1d\x00\xe3ve\xe4'

master token : b'your_everyday_iv\xef\x98hF\xc4j\xcb*\xd6I\xb0\xe0at\x1c\xa4\x9b\xbf_\x14\x1f\xa22mb\x1f<\xae\x8c\xa8\xac\xec\xcc3\x90\x81\x1e\x9b0\xa5\xc9X1@\x19\xa6\xc9\xac\xe3\x94\xb5U\\\xeb\x03 \x8d\x14K(\xeb9\xbeS'
'''
