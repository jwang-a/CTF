#!/bin/sh

gcc main.c -o notepad \
    -fno-stack-protector \
    -s

gcc wrapper.c -o wrapper \
    -s

strip -s notepad
strip -s wrapper

rm -rf dumps


