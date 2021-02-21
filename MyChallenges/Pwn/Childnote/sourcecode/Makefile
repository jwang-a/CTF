all:
	gcc -Wl,-z,now -fpie -fstack-protector-all childnote.c -o childnote
	strip childnote

clean:
	rm childnote
