###Resolve gdb x/gx result to hexdump format

import binascii

print('filename : ',end = '')
name = input()
file = open(name).read().split('\n')
str = ''
for i in file:
	i = i[i.find('\t')+1:].split('\t')
	for j in i:
		for k in range(16,0,-2):
			str+=j[k:k+2]+' '
str = str.strip()
output = name+'.hex'
f = open(output,'w')
f.write(str)
f.close()
