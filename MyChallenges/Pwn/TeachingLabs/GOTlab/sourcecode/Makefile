all:
	gcc -Wl,-z,relro -no-pie -fstack-protector-all GOTlab.c -o GOTlab
	strip GOTlab

clean:
	rm GOTlab
