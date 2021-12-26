all:
	gcc -Wl,-z,now -fpie -fstack-protector-all sandbox.c -o sandbox
	strip sandbox

clean:
	rm sandbox
