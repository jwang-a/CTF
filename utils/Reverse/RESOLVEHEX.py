###Resolve hexdumped file back to binary

import binascii

print('filename : ',end = '')
name = input()
file = ' '.join(open(name).read().split('\n')).strip().split(' ')
str = ''
for i in file:
	if len(i)==2:
		str+=i
output = name+'.bin'
f = open(output,'wb')
f.write(binascii.unhexlify(str.encode('utf-8')))
f.close()
