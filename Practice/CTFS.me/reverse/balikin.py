###Simple XOR decode###

from Crypto.Cipher import XOR
import base64

key = "RENDANGBASOGULING"
cipher = XOR.new(key)
crypt = 'Dof99eGO8erh6/nvnfPn9eGX6/j84fzv5fLh8u/t5/fzh+P79PTj8vfq/fXa3M0='
mid = cipher.encrypt(base64.b64decode(crypt))
fin = ''
kr = 0
for i in mid:
    fin+=chr(int(i)-ord(key[kr%len(key)]))
    kr+=1
print(fin[::-1])
