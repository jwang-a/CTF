all:
	gcc -Wl,-z,now -fpie -fstack-protector-all STACK_armoured.c -o STACK
	strip STACK

clean:
	rm STACK
