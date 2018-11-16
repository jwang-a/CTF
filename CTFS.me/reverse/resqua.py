###Encodes partial binary with self function###
#####Patch binary with gdb x/gx hex after unlock function

import math

for i in range(10000,1110,-1):
    if '0' in str(i):
        continue
    num = math.sqrt(i)
    if num//1==num:
        print(num**2)
