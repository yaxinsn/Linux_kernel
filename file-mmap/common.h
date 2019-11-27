/*
说明：

本文件只定义数据结构，用于应用程序与驱动之间的通信。


------------------------------
*/
#define IOCTL_CODE_MK(x) (0x99000000|(x))

#define IOCTL_CODE_SET_FUNCTION_NAME   	IOCTL_CODE_MK(1)
#define IOCTL_CODE_NOTIFY_DRV_READ   	IOCTL_CODE_MK(2)
#define IOCTL_CODE_NOTIFY_DRV_WRITE   	IOCTL_CODE_MK(3)
// //告诉驱动，我们要多少内存vmalloc，还是用kmalloc.
#define IOCTL_CODE_ALLOC_MEM            IOCTL_CODE_MK(4)
#define IOCTL_CODE_TEST_MEM            IOCTL_CODE_MK(5)


typedef struct ioctl_msg_set_func_name_st
{
    char name[64];
    int  code;
}ictl_set_funct_name;



