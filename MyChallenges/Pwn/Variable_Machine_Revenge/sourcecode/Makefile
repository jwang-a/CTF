all:
	patch -t -p0 <source.diff
	cd src; make; mv variable_machine_revenge ../; rm *.o
	strip variable_machine_revenge
	patch -tR -p0 <source.diff

clean:
	rm variable_machine_revenge
