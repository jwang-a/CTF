all:
	gcc -Wl,-z,now -fpie -fstack-protector-all babynote.c -o babynote
	strip babynote

clean:
	rm babynote
