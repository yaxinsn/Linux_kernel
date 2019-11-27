
#include <linux/timer.h>
#include <linux/timex.h>
#include <linux/rtc.h>


#include "common.h"

#include "misc-dev.h"

int __ioctl_set_function_name( struct my_misc_dev_extern* t, void * arg)
{
    ictl_set_funct_name msg;
    int retval = 0;
    if(unlikely(0 != copy_from_user(&msg, arg, sizeof(msg)))){
            retval = -EINVAL;
            goto DONE;
        }

    strncpy(t->name ,msg.name,sizeof(t->name));
    t->code = msg.code;
    printk("%s:%d t->name <%s> t->code <%d>\n",__func__,__LINE__,t->name,t->code);

DONE:
    return retval;
}


int __ioctl_alloc_mem( struct my_misc_dev_extern* t, void * arg)
{
    unsigned long size;
    int retval = 0;
    int flags = 0;
    void* vdata = NULL;
    size = ( unsigned long)arg;
    if (size <= PAGE_SIZE*16)
		vdata = kzalloc(size, GFP_KERNEL);
	else {
		vdata = vzalloc(size);
		flags = VMD_VMALLOCED;
	}
	if(vdata)
	{
	    if(t->mem_ctx.ptr)
	    {
	       __release_mem_ctx(t);

	    }
        t->mem_ctx.ptr = vdata;
        t->mem_ctx.flag =flags;
        t->mem_ctx.size = size;
    }
    else
    {
         retval = -ENOMEM;
    }
    printk("%s:%d ptr <%p> size <%lu>\n",__func__,__LINE__,t->mem_ctx.ptr,t->mem_ctx.size);

//DONE:
    return retval;
}
int __ioctl_test_mem( struct my_misc_dev_extern* t, void * arg)
{
    unsigned long offset;
    char* p;
    offset = ( unsigned long)arg;

    if(t->mem_ctx.ptr)
    {
        p = (char*)t->mem_ctx.ptr+offset;
        printk("%s:%d ptr <%s> \n",__func__,__LINE__,p);
        strcpy(p,"5667cfgg");
    }

//DONE:
    return 0;
}
char* get_time(void)
{
#if 0
	struct rtc_time tm;
	struct timex tmx;
	static char  time[128];

	do_gettimeofday(&(tmx.time));
	rtc_time_to_tm(tmx.time.tv_sec, &tm);


	snprintf(time, sizeof(time) - 1, "%d-%02d-%02d %02d:%02d:%02d",
		tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
		return time;
#else
    static char time[128];
    static int i;
    sprintf(time,"%s-%d","abc",i);
    i++;
    return time;
#endif
}

int __ioctl_test_poll_wark_up( struct my_misc_dev_extern* t, void * arg)
{

    char* tc = get_time();
    int up = (int)arg;
	printk("%s:%d wakup %s \n",__func__,__LINE__,tc);
	if(up)
	{
	    t->wait_flag = 1;
	    wake_up(&t->wait);
	}
	else
	{
	     t->wait_flag = 0;
	     wait_event_interruptible(t->wait, t->wait_flag);
	}
	if(t->mem_ctx.ptr)
	{
        sprintf(t->mem_ctx.ptr,"%s",tc);
     }
//DONE:
    return 0;

}

long my_ioctl( struct file *file,unsigned int cmd, unsigned long arg)
{
    int ret;

    struct my_misc_dev_extern* t = ( struct my_misc_dev_extern *)file->private_data;

    printk("%s:%d file->private_data %p \n",__func__,__LINE__,file->private_data);

	switch(cmd) {

	case IOCTL_CODE_SET_FUNCTION_NAME:
    	printk("%s:%d IOCTL_CODE_SET_FUNCTION_NAME \n",__func__,__LINE__);
    	return __ioctl_set_function_name(t,(void*)arg);
		break;
	case IOCTL_CODE_ALLOC_MEM:
    	printk("%s:%d IOCTL_CODE_ALLOC_MEM \n",__func__,__LINE__);
    	return __ioctl_alloc_mem(t,(void*)arg);
		break;

        case IOCTL_CODE_TEST_MEM:
            printk("%s:%d IOCTL_CODE_test_MEM \n",__func__,__LINE__);
            return __ioctl_test_mem(t,(void*)arg);
            break;

        case IOCTL_CODE_TEST_POLL_WAITER_WAKE_UP:
            printk("%s:%d IOCTL_CODE_test_MEM \n",__func__,__LINE__);
            return __ioctl_test_poll_wark_up(t,(void*)arg);
            break;

	default:
		return -EINVAL;
	}

	return 0;
}


