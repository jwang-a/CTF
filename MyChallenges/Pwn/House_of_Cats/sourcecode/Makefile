all:
	gcc -Wl,-z,now -fpie -fstack-protector-all house_of_cats_armoured.c -o house_of_cats
	strip house_of_cats

clean:
	rm house_of_cats
