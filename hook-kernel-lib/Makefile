
# Comment/uncomment the following line to enable/disable debugging
#DEBUG = y

unexport ARCH
PWD = $(shell pwd)/

ifeq ($(DEBUG),y)
  DEBFLAGS = -O -g -DSCULLP_DEBUG # "-O" is needed to expand inlines
else
  DEBFLAGS = -O2
endif

disasm-OBJECTS = ./mhook/disasm-lib/cpu.o ./mhook/disasm-lib/disasm.o \
				 ./mhook/disasm-lib/disasm_x86.o ./mhook/disasm-lib/misc.o \
				 ./mhook/mhook-lib/mhook_linux.o
debuglog-OBJ = ./debug-log/compat_rtc_time.o ./debug-log/klog.o

lsm-OBJECTS = ./lsm/lsm.o ./lsm/probe.o ./lsm/securityhook.o 
#./lsm/securityhook_bprm_check.o
tpe-OBJECTS = ./tpe/symbols.o ./tpe/kernsymbol.o




#CFLAGS += $(DEBFLAGS) -I$(LDDINC) -I"../misc/"
VPATH = .:../misc
SRC_DIRS = ../common ../include ./lsm ./debug-log


vpath %.c ../common
vpath %.h $(SRC_DIRS) 

# $(xscanMatchine_OBJECTS)

total-OBJECTS =   $(lsm-OBJECTS)  \
				$(disasm-OBJECTS) $(tpe-OBJECTS)  $(debuglog-OBJ)

PRIVATE_INC = $(PWD)/
EXTRA_CFLAGS +=  -I$(SELF_PATH)   -Wno-unused-function -Wno-unused-variable -g -Wno-parentheses 
EXTRA_CFLAGS +=  -g -I$(INC)/../include -I$(INC)/lsm -I$(INC)/ -I$(INC)/debug-log
EXTRA_CFLAGS += $(KERNEL_CFLAGS)
TARGET = KTsgMod

ifneq ($(KERNELRELEASE),)

KTsgMod-objs := $(total-OBJECTS)
obj-m	:= KTsgMod.o
# obj-m 制定最后模块的名字？
else
#添加相应的头文件目录
__SELF = $(shell pwd)/
KERNELDIR ?= /lib/modules/$(shell uname -r)/build
#KERNELDIR ?= /lib/modules/3.7.10-1.32-desktop/build

modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) INC=$(PRIVATE_INC) SELF_PATH=$(__SELF) modules
	cp KTsgMod.ko ../bin
# M=$(PWD) : 指定模块编译之后的路径,同时也指定了内核的MAKEFILE第二次再次调用本MAKEFILE;
# INC=$(PRIVATE_INC) ：通知内核的MAKEFILE定义一个INC变量，初始值为$(PRIVATE_INC)，
# PRIVATE_INC不能够直接传给内核MAKEFILE给第二次经过这个文件的时候用；
#

endif


install:
	install -d $(INSTALLDIR)
	install -c $(TARGET).o $(INSTALLDIR)

clean:
	rm -rf *.o $(total-OBJECTS) *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions


depend .depend dep:
	$(CC) $(CFLAGS) -M *.c > .depend

ifeq (.depend,$(wildcard .depend))
include .depend
endif
