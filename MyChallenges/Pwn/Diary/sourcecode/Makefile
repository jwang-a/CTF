all:
	gcc -Wl,-z,now -fpie -fstack-protector-all diary.c -o diary
	strip diary

clean:
	rm diary
