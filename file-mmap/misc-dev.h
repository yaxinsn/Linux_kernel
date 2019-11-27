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

#include <linux/mutex.h>
#include <linux/uaccess.h>
#include <linux/bitops.h>
#include <linux/poll.h>

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


	wait_queue_head_t	wait;
	int wait_flag;
	//msg list
	int max_type;
};
static __inline__ int  __release_mem_ctx( struct my_misc_dev_extern* t)
{
    if(t->mem_ctx.ptr)
    {
        if(t->mem_ctx.flag == VMD_VMALLOCED)
            vfree(t->mem_ctx.ptr);
        else
            kfree(t->mem_ctx.ptr);

    }
    t->mem_ctx.ptr = NULL;
    t->mem_ctx.flag  = 0;
    t->mem_ctx.size = 0;
	return 0;
}

#endif // MISC_DEV_H
