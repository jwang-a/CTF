#!/bin/bash

#mkdir -p dumps

cd /home/ctf

ulimit -c unlimited

segfault_handler() {
    mv cores/core.notepad.* dumps/
    cat dumps/*
    rm -rf dumps/*
}

./wrapper 2>&1

if [[ $? -eq 139 ]]
then
    segfault_handler
fi
