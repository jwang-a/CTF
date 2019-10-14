###Brute force search small random space###

crypt = open("rubyflag").read()[1:-2]
length = len(crypt)
crypt = crypt[length//15:2*length//15]
length = len(crypt)
a = int('1'+'0'*(length),2)
for i in range(8):
    crypt = crypt[1:]+crypt[0]
    flag = []
    for j in range(0,length,8):
        flag.append(int(crypt[j:j+8],2))
    print(''.join(list(map(chr,flag))))
