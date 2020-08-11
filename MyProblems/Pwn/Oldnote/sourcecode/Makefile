all:
	gcc -Wl,-z,now -fpie -fstack-protector-all oldnote.c -o oldnote
	strip oldnote

clean:
	rm oldnote
