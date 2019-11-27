 #include <sys/socket.h>
       #include <netinet/in.h>
       #include <netinet/ip.h> /* superset of previous */
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>


#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <error.h>
 #include <sys/ioctl.h>



 #include "common.h"

#if 0
int mmap_read(char* filename)
{
	  struct stat sb;
	char *mapped;


	int fd = open(filename,O_RDONLY,0666);
	if(fd < 0  )
	{
		fprintf(stderr, "%s open error %s \n",__func__,strerror(errno));
		return -1;
	}

		  /* 获取文件的属性 */
	if ((fstat (fd, &sb)) == -1)
    {
      perror ("fstat");
    }

  /* 将文件映射至进程的地址空间 */
  if ((mapped = (char *) mmap (NULL, sb.st_size, PROT_READ , MAP_SHARED, fd, 0)) == (void *) -1)
    {
      perror ("mmap");
	  return -1;
    }
  /* 映射完后, 关闭文件也可以操纵内存 */
  close (fd);
	printf("%s ok mmapped: %s \n",__func__,mapped);

	  /* 释放存储映射区 */
  if ((munmap ((void *) mapped, sb.st_size)) == -1)
    {
      perror ("munmap");
	  return -1;
    }
	return 0;
}


#define MMAP_SIZE 10*1024
int mmap_write(char* filename,int flag)
{
	  struct stat sb;
	char *mapped;

	int fd = open(filename,O_RDWR,0666);//O_WRONLY
	if(fd < 0  )
	{
		fprintf(stderr, "%s open error %s \n",__func__,strerror(errno));
		return -1;
	}

	/* 获取文件的属性 */
	if ((fstat (fd, &sb)) == -1)
    {
      perror ("fstat");
	  return -1;
    }

  /* 将文件映射至进程的地址空间 */
  if ((mapped = (char *) mmap (NULL,MMAP_SIZE, PROT_READ|PROT_WRITE, flag, fd, 0)) == (void *) -1)
    {
      perror ("mmap");
	  return -1;
    }
  /* 映射完后, 关闭文件也可以操纵内存 */
  close (fd);

  mapped[0]='a';
	  /* 释放存储映射区 */
  if ((munmap ((void *) mapped, MMAP_SIZE)) == -1)
    {
      perror ("munmap");
	  return -1;
    }
	return 0;
}
#endif

int dev_ioctl_set_func_mem(int fd,char* name,int type)
{

    int ret;
    ictl_set_funct_name msg;
    strncpy(msg.name,name,sizeof(msg.name));
    msg.code=9;
    ret = ioctl(fd,IOCTL_CODE_SET_FUNCTION_NAME,&msg);
    printf("%s :%d ret %d \n",__FILE__,__LINE__,ret);
    return ret;
}
int dev_ioctl_test_mem(int fd,unsigned long offset)
{
    int ret;
    ret = ioctl(fd,IOCTL_CODE_TEST_MEM,offset);
    printf("%s :%d ret %d \n",__FILE__,__LINE__,ret);
    return ret;
}


int dev_ioctl_alloc_mem(int fd,unsigned long size)
{
    int ret;
    ret = ioctl(fd,IOCTL_CODE_ALLOC_MEM,size);
    printf("%s :%d ret %d \n",__FILE__,__LINE__,ret);
    return ret;
}
#define BUF_SIZE   1024*1024*16
int test_dev_mmap(int fd)
{

    char *addr = NULL;
    char *paddr = NULL;

    addr = mmap(NULL, BUF_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED , fd, 0);
	if( addr == NULL )
	{
			return -1;
	}

	
    paddr = addr+BUF_SIZE-32;

    printf("%s :%d  paddr %p  addr %p \n",__FILE__,__LINE__,paddr,addr);

    strcpy(paddr,"12345abcde");

    printf("%s :%d  \n",__FILE__,__LINE__);

    dev_ioctl_test_mem(fd,BUF_SIZE-32);

    printf("%s :%d modify memap content <%s> \n",__FILE__,__LINE__,paddr);


    if ((munmap ((void *) addr, BUF_SIZE)) == -1)
    {
      perror ("munmap");
	  return -1;
    }

    printf("%s :%d  \n",__FILE__,__LINE__);
    return 0;
}

void test_dev()
{
    int fd = open("/dev/my_cdev",O_RDWR);
    if(fd <0)
    {
        perror("/dev/my_cdev\n");
        exit(1);
    }
    dev_ioctl_set_func_mem(fd,"wlist",9);

    printf("%s :%d  \n",__FILE__,__LINE__);

    dev_ioctl_alloc_mem(fd,BUF_SIZE);

    printf("%s :%d  \n",__FILE__,__LINE__);


    test_dev_mmap(fd);

	sleep(5);
    close(fd);


}


int main(int argc, char* argv[] )
{

    test_dev();


		return 0;
}
