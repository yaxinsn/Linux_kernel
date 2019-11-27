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

#include <sys/inotify.h>
#include <sys/epoll.h>
 #include <stdio.h>

  #include <sys/types.h>
       #include <sys/stat.h>
       #include <fcntl.h>


#include <pthread.h>

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
int test_dev_mmap_for_poll(int fd)
{

    char *addr = NULL;
    char *paddr = NULL;


    printf("%s :%d modify memap content <%s> \n",__FILE__,__LINE__,paddr);




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

    printf("%s :%d  \n",__func__,__LINE__);

    dev_ioctl_alloc_mem(fd,BUF_SIZE);

    printf("%s :%d  \n",__func__,__LINE__);


    test_dev_mmap(fd);

	sleep(5);
    close(fd);


}
#define EPOLL_MAX_FD 255
int poll_loop(int fd)
{
	int iFdNum                                     = 0;
	int i                                         = 0;
	struct epoll_event astEvents[EPOLL_MAX_FD]     = {0};
    int iEpollFd;

    int j = 0;
    char* addr;


	iEpollFd = epoll_create(EPOLL_MAX_FD);
	if(iEpollFd < 0)
	{
	    int ret = 4;
		perror("main::epoll_create Fail!");
		pthread_exit(&ret);
	}
//
{
	struct epoll_event FdEvent              = {0};

    FdEvent.data.fd = fd;

	FdEvent.events = (EPOLLIN|EPOLLERR);

    epoll_ctl(iEpollFd, EPOLL_CTL_ADD, fd,&FdEvent);
}
{

addr = mmap(NULL, BUF_SIZE, PROT_READ|PROT_WRITE, MAP_SHARED , fd, 0);
if( addr == NULL )
{

		perror("main::addr Fail!");
    return -1;
}

}

printf("%s :%d  \n",__func__,__LINE__);

//
	for(;;)
	{
	    iFdNum = epoll_wait (iEpollFd,astEvents,EPOLL_MAX_FD,-1);
        for(i = 0;i < iFdNum;i++)
		{
			if(astEvents[i].events & EPOLLIN)
			{
                if(astEvents[i].data.fd == fd)
                {
                    printf("%s: %d [%d] addr <%s>  \n",__func__,__LINE__,j,addr);
                    j++;
                    ioctl(fd,IOCTL_CODE_TEST_POLL_WAITER_WAKE_UP,0);
                }
#if 0
{
struct epoll_event FdEvent              = {0};

FdEvent.data.fd = fd;

FdEvent.events = (EPOLLIN|EPOLLERR);
epoll_ctl(iEpollFd, EPOLL_CTL_ADD, fd,&FdEvent);
}
#endif
			}
	    }
	}

}
static void* poll_pthread(void* arg)
{
    int fd = (int)(arg);
    printf("%s :%d  \n",__func__,__LINE__);
    poll_loop(fd);
    printf("%s :%d  \n",__func__,__LINE__);
}
static void* wakeup_pthread(void* arg)
{
    int fd = (int)(arg);
    int i = 0;
    int up;
    while(i<10)
    {
        int ret;
        if(i%2 == 0)
        {
            up =1;
        }
        else
            up = 0;
        ret = ioctl(fd,IOCTL_CODE_TEST_POLL_WAITER_WAKE_UP,1);
        printf("%s :%d ret %d \n",__func__,__LINE__,ret);
        sleep(1);
        i++;

    }
    return;

}

int main(int argc, char* argv[] )
{
	pthread_t tid;
    pthread_t tid2;
    int fd = open("/dev/my_cdev",O_RDWR);
    if(fd <0)
    {
        perror("/dev/my_cdev\n");
        exit(1);
    }

    dev_ioctl_set_func_mem(fd,"wlist",9);
    dev_ioctl_alloc_mem(fd,BUF_SIZE);

	if(pthread_create(&tid,NULL,poll_pthread,(void*)(unsigned long)fd))
	{
        printf("pthread creat poll_pthread Failed  \n");
		return 0;
	}

	if(pthread_create(&tid2,NULL,wakeup_pthread,(void*)(unsigned long)fd))
	{
        printf("pthread creat wakeup_pthread Failed  \n");
		return 0;
	}




	pthread_join(tid,NULL);

	pthread_join(tid2,NULL);

//    test_dev();


		return 0;
}
