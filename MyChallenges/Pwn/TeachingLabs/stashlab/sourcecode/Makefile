all:
	gcc -Wl,-z,now -fpie -fstack-protector-all stashlab.c -o stashlab
	strip stashlab

clean:
	rm stashlab
