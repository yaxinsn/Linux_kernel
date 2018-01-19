 #include <sys/socket.h>
       #include <netinet/in.h>
       #include <netinet/ip.h> /* superset of previous */
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include "hello_sock_opt.h"


int common_set_sock_opt(int id,void* msg,int len)
{
	int sock;
	int ret;
	sock = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
	if(sock <=0){
		printf("socket error\n");
		return -1;	
	}
	ret=setsockopt(sock,0,id,msg,len);

	close(sock);
	return ret;
}
int common_get_sock_opt(int id,void* msg,int* len)
{
	int sock;
	int ret;
	sock = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
	if(sock <=0){
		printf("socket error\n");
		return -1;	
	}
	ret=getsockopt(sock,0,id,msg,len);
	close(sock);
	return ret;
}
int __set_lisa(char* s)
{
	return common_set_sock_opt(HELLO_LISA,s,strlen(s));
	
}

int __get_lisa(char* s,int *len)
{
	return common_get_sock_opt(HELLO_LISA,s,len);
	
	
}


void main(int argc,char* argv[])
{
	char ret[100]={0};
	int len=0;
	int t;
	if(argc ==2){
		printf("argv : %s :%s \n",argv[0],argv[1]);
		t = __set_lisa(argv[1]);
		if(t<0)
			perror("__set_lisa:");
		__get_lisa(ret,&len);
		if(t<0)
			perror("__GET_lisa:");
		else
		{
			printf("ret %s; len %d\n",ret,len);
		}
	}
}
