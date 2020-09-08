all:
	wget https://raw.githubusercontent.com/jwang-a/CTF/master/utils/Pwn/SECCOMP.h
	gcc -Wl,-z,now -fpie -fstack-protector-all grocery_shop.c -o grocery_shop
	strip grocery_shop
	rm SECCOMP.h

clean:
	rm grocery_shop
