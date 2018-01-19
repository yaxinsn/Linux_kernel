
//#include <linux/config.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>


/*
 *  * Module housekeeping.
 *   */
static int simple_init(void)
{
	printk("hello !!\n");
	return 0;
}


static void simple_cleanup(void)
{
	printk("Hello byebye\n");
}


module_init(simple_init);
module_exit(simple_cleanup);

