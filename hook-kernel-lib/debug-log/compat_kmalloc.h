#ifndef  _COMPAT_KMALLOC_H
#define  _COMPAT_KMALLOC_H

#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/highmem.h>


extern void *kmalloc(size_t, gfp_t);


#endif //_COMPAT_KMALLOC_H
