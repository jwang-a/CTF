all:
	wget https://raw.githubusercontent.com/jwang-a/CTF/master/utils/Pwn/SECCOMP.h
	gcc -Wl,-z,now -fpie -fstack-protector-all shelllab.c -o shelllab
	strip shelllab
	rm SECCOMP.h

clean:
	rm shelllab
