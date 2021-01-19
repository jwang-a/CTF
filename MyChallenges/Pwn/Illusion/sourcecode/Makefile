all:
	gcc -Wl,-z,lazy -fpie -fstack-protector-all -fno-builtin-printf illusion.c -o illusion
	python3 illusion.py illusion

clean:
	rm illusion
