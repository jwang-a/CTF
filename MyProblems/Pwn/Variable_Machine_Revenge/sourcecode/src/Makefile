CC=clang
OBJS=vm.o gc.o main.o
TARGET=main
CFLAGS=-std=c99 -fPIC


all: $(TARGET) 

$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) -pie -lpthread