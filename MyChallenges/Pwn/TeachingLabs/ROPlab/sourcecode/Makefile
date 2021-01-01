all:
	gcc -Wl,-z,now -fpie -fstack-protector-all ROPlab.c -o ROPlab
	strip ROPlab

clean:
	rm ROPlab
