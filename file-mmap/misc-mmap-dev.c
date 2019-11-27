/*
说明：

open 一个 dev.然后可以mmap,可以发ioctl.


------------------------------
*/




#include <linux/timer.h>
#include <linux/timex.h>
#include <linux/rtc.h>


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

extern long my_ioctl( struct file *file,unsigned int cmd, unsigned long arg);

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

	init_waitqueue_head(&t->wait);

	file->private_data = (void*)t;
    printk("%s:%d file->private_data %p \n",__func__,__LINE__,file->private_data);
	return 0;
}


static unsigned int
my_poll(struct file *file, poll_table * wait)
{
	unsigned int mask;
    struct my_misc_dev_extern* t = ( struct my_misc_dev_extern *)file->private_data;

    printk("%s:%d ############### \n",__func__,__LINE__);

	poll_wait(file, &t->wait, wait);
	mask = 0;
	//if (ENTROPY_BITS(&input_pool) >= random_read_wakeup_thresh)
		mask |= POLLIN | POLLRDNORM;
#if 0
	if (ENTROPY_BITS(&input_pool) < random_write_wakeup_thresh)
		mask |= POLLOUT | POLLWRNORM;
#endif
	return mask;
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
	.poll           = my_poll,
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
