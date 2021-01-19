all:
	wget https://raw.githubusercontent.com/jwang-a/CTF/master/utils/Pwn/SECCOMP.h
	gcc -Wl,-z,now -fpie -fstack-protector-all babyheap.c -o babyheap
	strip babyheap
	rm SECCOMP.h

clean:
	rm babyheap
