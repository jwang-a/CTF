###Simple Calculations###

from pwn import *
flag = [233, 129, 9, 5, 130, 194, 195, 39, 75, 229]

inp = ''
for i in flag:
	char = bin(i)[2:].rjust(8,'0')
	char = ((int(char[3:],2)^15)<<3) + (int(char[:3],2)^3)
	print(char)
	inp+=chr(char)
print(inp)
