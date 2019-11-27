
all: default main

# Comment/uncomment the following line to disable/enable debugging
#DEBUG = y

# Add your debugging flag (or not) to CFLAGS
ifeq ($(DEBUG),y)
  DEBFLAGS = -O -g # "-O" is needed to expand inlines
else
  DEBFLAGS = -O2
endif

#ccflags-y += $(DEBFLAGS) -I$(LDDINCDIR)
EXTRA_CFLAGS+=-Wno-unused-variable
#CFLAGS +=-DMMAP_FILE=./mmap-test.txt
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD       := $(shell pwd)
my-dev-objs := misc-mmap-dev.o kmmap.o
obj-m := my-dev.o

default:
	$(MAKE) -C $(KERNELDIR) SUBDIRS=$(PWD)  modules




clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions modules.order  Module.symvers main 

depend .depend dep:
	$(CC) $(CFLAGS) -M *.c > .depend


ifeq (.depend,$(wildcard .depend))
include .depend
endif


main:main.c
	gcc -o  main -g main.c
