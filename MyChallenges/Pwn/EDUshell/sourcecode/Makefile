all:
	wget https://raw.githubusercontent.com/jwang-a/CTF/master/utils/Pwn/SECCOMP.h
	gcc -Wl,-z,now -fpie -fstack-protector-all EDUshell.c -o EDUshell
	strip EDUshell
	rm SECCOMP.h

clean:
	rm EDUshell
