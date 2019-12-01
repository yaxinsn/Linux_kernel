#ifndef __KTSG_LOG_H
#define __KTSG_LOG_H

#include <linux/proc_fs.h>
#include <linux/kernel.h>
#include "klog.h"
#include "compat_kmalloc.h"

typedef struct __GLOBAL_LOGS
{
            struct proc_dir_entry  *proc_dir;
            struct klog_ctx        *klogCtx;
}GLOBAL_LOGS;
#if 0
extern GLOBAL_LOGS     g_globalLog;

#define KTsgDebug(fmt, args...)     do {   \
                                        if(g_globalLog.klogCtx){ \
                                        klog_printk_time(g_globalLog.klogCtx,"[%s:%d] "fmt,__func__,__LINE__,## args); \
                                    }   \
                                    else \
                                    {   \
                                        printk(KERN_DEBUG "[%s:%d] "fmt,__func__,__LINE__,## args); \
                                    }   \
                                    }while(0);







#else

#define KTsgDebug(fmt, args...)  	do { \
    printk(KERN_DEBUG "[%s:%d] "fmt,__func__,__LINE__,## args);  \
    }while(0);
#endif

#endif //
