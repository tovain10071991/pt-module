KDIR = /lib/modules/`uname -r`/build
obj-m := pt-module.o
M := make -C ${KDIR} M=`pwd`

CFLAGS_simple-pt.o := -DTRACE_INCLUDE_PATH=${M}

all:
	${M} modules

modules_install:
	${M} modules_install

clean: kernel-clean

kernel-clean:
	${M} clean
