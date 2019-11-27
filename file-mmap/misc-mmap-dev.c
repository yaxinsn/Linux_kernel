/*
说明：

open 一个 dev.然后可以mmap,可以发ioctl.


------------------------------
*/





#include "common.h"

#include "misc-dev.h"




static ssize_t nvram_len;
char* test_str="abcd";
static ssize_t read_nvram(struct file *file, char __user *buf,
			  size_t count, loff_t *ppos)
{
	unsigned int i;
	char __user *p = buf;
	if (!access_ok(VERIFY_WRITE, buf, count))
		return -EFAULT;

	printk("%s:%d \n",__func__,__LINE__);
	if(unlikely(copy_to_user(p,test_str,4)))
	{
			return -EFAULT;
	}

	printk("%s:%d \n",__func__,__LINE__);
#if 0
	for (i = *ppos; count > 0 && i < nvram_len; ++i, ++p, --count)
		if (__put_user(nvram_read_byte(i), p))
			return -EFAULT;
#endif

	return 4;
}
#if 0
static ssize_t write_nvram(struct file *file, const char __user *buf,
			   size_t count, loff_t *ppos)
{
	unsigned int i;
	const char __user *p = buf;
	char c;

	if (!access_ok(VERIFY_READ, buf, count))
		return -EFAULT;
	if (*ppos >= nvram_len)
		return 0;
	for (i = *ppos; count > 0 && i < nvram_len; ++i, ++p, --count) {
		if (__get_user(c, p))
			return -EFAULT;
		nvram_write_byte(c, i);
	}
	*ppos = i;
	return p - buf;
}

#endif
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
int __release_mem_ctx( struct my_misc_dev_extern* t)
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

static long my_ioctl( struct file *file,unsigned int cmd, unsigned long arg)
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


	default:
		return -EINVAL;
	}

	return 0;
}
extern int my_mmap (struct file *file , struct vm_area_struct * vm);

static int my_release(struct inode *inode, struct file *file)
{
    struct my_misc_dev_extern* t = ( struct my_misc_dev_extern *)file->private_data;
    if(t)
    {

        __release_mem_ctx(t);
        kfree(t);
        file->private_data = NULL;
        printk("%s:%d \n",__func__,__LINE__);

    }
    return 0;
}

static int my_open(struct inode *inode, struct file *file)
{
    struct my_misc_dev_extern* t= (struct my_misc_dev_extern*)kmalloc(sizeof(struct my_misc_dev_extern),GFP_KERNEL);
    memset(t,0,sizeof(struct my_misc_dev_extern));


	file->private_data = (void*)t;
    printk("%s:%d file->private_data %p \n",__func__,__LINE__,file->private_data);
	return 0;
}
const static struct file_operations my_cdev_fops = {
	.owner		= THIS_MODULE,
	.open       = my_open,
	//.llseek		= nvram_llseek,
	.read		= read_nvram,
	//.write		= write_nvram, 不让写。没有写操作。
	.unlocked_ioctl		= my_ioctl,
	.release      =  my_release,
	.mmap           = my_mmap,
};

struct miscdevice my_misc_dev =
{
	MISC_DYNAMIC_MINOR,
	"my_cdev",
	&my_cdev_fops,
};

int __init nvram_init(void)
{
	int ret = 0;

	printk(KERN_INFO "nvram_init: liudan ioctl and mmap test. compile at centos5.x centos7.x \n");
	ret = misc_register(&my_misc_dev);
	if (ret != 0)
		goto out;

out:
	return ret;
}

void __exit nvram_cleanup(void)
{
    printk(KERN_INFO "nvram_cleanup \n");
    misc_deregister( &my_misc_dev);

}

module_init(nvram_init);
module_exit(nvram_cleanup);
MODULE_LICENSE("GPL");
