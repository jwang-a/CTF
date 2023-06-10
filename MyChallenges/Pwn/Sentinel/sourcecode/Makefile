original:
	gcc -Wl,-z,now -fpie -fstack-protector-all -DDO_LOG sentinel.c -o sentinel
	strip sentinel

revenge:
	patch -p0 sentinel.c source.diff -o sentinelRevenge.c
	gcc -Wl,-z,now -fpie -fstack-protector-all -DDO_LOG sentinelRevenge.c -o sentinelRevenge
	strip sentinelRevenge
	rm sentinelRevenge.c

all: original revenge

clean:
	rm sentinel sentinelRevenge
