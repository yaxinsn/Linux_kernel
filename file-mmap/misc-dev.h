#ifndef MISC_DEV_H
#define MISC_DEV_H

#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/mman.h>
#include <linux/random.h>
#include <linux/init.h>
#include <linux/raw.h>
#include <linux/tty.h>
#include <linux/capability.h>
#include <linux/ptrace.h>
#include <linux/device.h>
#include <linux/highmem.h>

#include <linux/pfn.h>
//#include <asm/io.h> 
#include <linux/io.h> 
#include <linux/module.h>

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/miscdevice.h>
#include <linux/fcntl.h>
#include <linux/init.h>
//#include <linux/smp_lock.h>
#include <asm/uaccess.h>
//#include <asm/nvram.h>

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/sockios.h>
#include <linux/jiffies.h>
#include <linux/times.h>
#include <linux/types.h>
#include <linux/string.h>

#include <linux/slab.h>


#define VMD_VMALLOCED 0x1	/* vmalloc'd rather than kmalloc'd */

#define NVRAM_SIZE	8192
struct my_mem_ctx{
    unsigned long size;
    void* ptr;
    int flag;
    atomic_t refcnt;
    spinlock_t lock;
};
struct my_misc_dev_extern{
	void* msg_buf;
    char name[64];
    int  code;
    struct my_mem_ctx mem_ctx;


	//msg list
	int max_type;
};

#endif // MISC_DEV_H
