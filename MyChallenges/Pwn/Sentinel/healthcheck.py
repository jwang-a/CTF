#!/usr/bin/python3
from pwn import *

def doPow():
    challenge = r.recvline()
    challenge,difficulty = challenge.split(b"'")[1], int(challenge.split(b'<< ')[1].split(b')')[0])
    r.sendlineafter(b'answer > ',b'dummySecret')
    return

def createInstance(secret):
    r.sendlineafter(b'Choice > ',b'1')
    doPow()
    if type(secret)==str:
        secret = secret.encode()
    r.sendlineafter(b'secret > ',secret)
    instanceId = r.recvuntil(b' (keep this for future reference)').split(b' ')[2].decode()
    r.recvuntil(b'done\r\n')
    return instanceId

def resumeInstance(instanceId,secret,reset=True):
    if reset is True:
        cmd = 3
    else:
        cmd = 2
    r.sendlineafter(b'Choice > ',str(cmd).encode())
    if type(instanceId)==str:
        instanceId = instanceId.encode()
    r.sendlineafter(b'instanceId > ',instanceId)
    if type(secret)==str:
        secret = secret.encode()
    r.sendlineafter(b'secret > ',secret)
    r.recvuntil(b'done\r\n')

def removeInstance(instanceId,secret):
    r.sendlineafter(b'Choice > ',b'4')
    if type(instanceId)==str:
        instanceId = instanceId.encode()
    r.sendlineafter(b'instanceId > ',instanceId)
    if type(secret)==str:
        secret = secret.encode()
    r.sendlineafter(b'secret > ',secret)

RETVAL_ALIVE = 0
RETVAL_CHALLENGE_NOT_GOOD = 1
RETVAL_SCRIPT_NOT_GOOD = 2
RETVAL_TIMEOUT = 3

DOMAIN = 'sentinel.balsnctf.com'

r = remote(DOMAIN,10101)
instanceId = createInstance('dummySecret')
print(instanceId)
r.sendline(b"echo 'a' > work/A")
r.sendline(b'exit')
r.close()

r = remote(DOMAIN,10101)
resumeInstance(instanceId,'dummySecret',reset=False)
r.sendline(b"ls work/ | grep A")
r.sendline(b'echo "aaaaa"')
res = r.recvuntil(b'aaaaa',timeout=20)
print(f'[+] persist recv {res}')
if res==b'':
    print('recv timeout, might be iosync problem',file=sys.stderr)
    exit(RETVAL_TIMEOUT)
if b'A' not in res:
    print('persist failed',file=sys.stderr)
    exit(RETVAL_CHALLENGE_NOT_GOOD)
r.sendline(b'exit')
r.close()

r = remote(DOMAIN,10101)
resumeInstance(instanceId,'dummySecret')
r.sendline(b"ls work/ | grep A")
r.sendline(b'echo "aaaaa"')
res = r.recvuntil(b'aaaaa',timeout=20)
print(f'[+] reset recv {res}')
if res==b'':
    print('recv timeout, might be iosync problem',file=sys.stderr)
    exit(RETVAL_TIMEOUT)
if b'A' in res:
    print('reset failed',file=sys.stderr)
    exit(RETVAL_CHALLENGE_NOT_GOOD)
r.sendline(b'ls -li | grep "flag"')
res = r.recvuntil(b'flag')
origInode = int(res.split(b'\n')[-1].strip().split(b' ')[0])
print(f'[+] origInode {origInode}')
r.sendline(b'ln flag work/F')
r.sendline(b'ls -li | grep "flag"')
res = r.recvuntil(b'flag')
newInode = int(res.split(b'\n')[-1].strip().split(b' ')[0])
print(f'[+] newInode {newInode}')
if origInode==newInode:
    print('up copy failed on ln',file=sys.stderr)
    exit(RETVAL_CHALLENGE_NOT_GOOD)
r.sendline(b'exit')
r.close()

r = remote(DOMAIN,10101)
removeInstance(instanceId,'dummySecret')
r.close()

print('succeeded',file=sys.stderr)
exit(RETVAL_ALIVE)
