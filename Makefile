KRNL_SRC=linux-2.6.32.68/
PWD=$(shell pwd)
obj-m = ptrace_fix.o

all:
	make ARCH=mips CROSS_COMPILE=../mips-buildroot-linux-uclibc-gcc/usr/bin/mips-linux- -C $(KRNL_SRC) M=$(PWD) modules
	
clean:
	make ARCH=mips CROSS_COMPILE=../mips-buildroot-linux-uclibc-gcc/usr/bin/mips-linux- -C $(KRNL_SRC) M=$(PWD) clean