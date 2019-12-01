#ifndef __LINUX_KERNEL_PORT_H__
#define __LINUX_KERNEL_PORT_H__

#include <linux/module.h>
#include <linux/types.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/cdev.h>
#include <linux/wait.h>
#include <asm/io.h>
// -- #include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/atomic.h>
#include <linux/spinlock.h>
#include <linux/time.h>
#include <linux/slab.h>
// -- #define printf DbgPrint
#undef DbgPrint
// -- #define DbgPrint(fmt,arg...) printk("<1>"fmt, ##arg)
#define KPrint(x, y)	\
	do{	\
		if(x >= DISPLAY_PRINTK_LEVEL){ \
			printk y; \
		}	\
	}while(0)
// -- #define DbgPrint(fmt,arg...) printk("<7>"fmt, ##arg)
#define DbgPrint(fmt,arg...) KPrint(DBG_LEVEL, (fmt, ##arg))

#ifndef BOOLEAN 
#define BOOLEAN char
#endif
 
#endif
