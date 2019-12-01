#ifndef __PRECOMPILE_H__
#define __PRECOMPILE_H__

#include <asm/byteorder.h>

#ifndef __LITTLE_ENDIAN
	#define __LITTLE_ENDIAN
#endif

// -- 头文件部分
#define DBG_LEVEL (1)
#define TEST_LEVEL (2)
#define MSG_LEVEL (3)
#define DISPLAY_PRINTK_LEVEL TEST_LEVEL

#ifdef WIN32
	#define __attribute__(x)
	#undef __LINUX__
#ifdef __IN_KERNEL_MOD__
	#define __LINUX_KERNEL__
	#define OS_FREE(x)  do{ if(x) wlKRFree(x);}while(0)
	#define OS_MALLOLC(x)  wlKRAlloc(NonPagedPool,(x))
    typedef KSPIN_LOCK OS_SPIN_LOCK_t;


#else

    #define OS_FREE(x)  do{ if(x) free(x);}while(0)
    #define OS_MALLOLC(x)  malloc((x))
#endif

#else

#ifndef __USE_GNU
	#define __USE_GNU
#endif
	#define __LINUX__
#endif

#ifdef __LINUX__
#ifdef __IN_KERNEL_MOD__
	#define __LINUX_KERNEL__

    #define OS_MOD_INIT __init
    #define OS_MOD_EXIT __exit
	#define OS_FREE(x)  do{ if(x) kfree(x);}while(0)
	#define OS_MALLOLC(x)  kmalloc((x), GFP_ATOMIC)
    typedef spinlock_t OS_SPIN_LOCK_t;
    #define OS_LOCK_INIT(x)    spin_lock_init(x)
    #define OS_LOCK(x)         spin_lock(x)
    #define OS_UNLOCK(x)       spin_unlock(x)
#else

    #define OS_FREE(x)  do{ if(x) free(x);}while(0)
    #define OS_MALLOLC(x)  malloc((x))

#endif

#endif

#ifdef __LINUX__ // -- linux
	#ifdef __IN_KERNEL_MOD__
		// -- kernel
		#include "linux_kernel_port.h"

	#else
	 // -- application
		#include "linux_app_port.h"
	#endif

#else
// -- windows

	#ifdef __cplusplus
		#define __inline__ inline
	#else
		#define __inline__
	#endif
	#define unlikely(x) (x)

#endif


	#define PATH_SEPERATOR_CHAR '/'
	#define PATH_SEPERATOR_STRING "/"



#undef DbgPrint

#ifndef WIN32
#define __xLogPrint(fmt, arg...)					\
	do {								\
		time_t t = time(NULL);					\
		struct tm * now = localtime(&t);			\
		printf("[%.4d-%.2d-%.2d %.2d:%.2d:%.2d]",		\
		1900 + now->tm_year,					\
		now->tm_mon+1,						\
		now->tm_mday,						\
		now->tm_hour,						\
		now->tm_min,						\
		now->tm_sec);						\
		printf("["__FILE__":%d] " fmt, __LINE__, ##arg);	\
		fflush(stdout);						\
	} while (0);
#endif


#ifndef WIN32

#define __int8 char
#define __int16 short
#define __int32 int
#define __int64 long long

#define BOOLEAN char
//#define UINT unsigned int
//#define LONG long
//#define PVOID void *
//#define LPVOID void *
//#define DWORD unsigned int
//#define LPDWORD DWORD *
//#define LONGLONG long long
//#define ULONGLONG unsigned long long
//#define THAR unsigned short
//#define TCHAR THAR
//#define WCHAR unsigned short
//typedef char  		BOOLEAN;
#ifndef __UINT_
#define __UINT_
typedef unsigned int 	UINT;
#endif
#ifndef __LONG_
#define __LONG_
typedef long  		LONG;
#endif
#ifndef __PVOID_
#define __PVOID_
typedef void *  		PVOID;
#endif
#ifndef __LPVOID_
#define __LPVOID_
typedef void *  		LPVOID;
#endif
#ifndef __DWORD_
#define __DWORD_
typedef unsigned int 	DWORD;
#endif
#ifndef __LPDWORD_
#define __LPDWORD_
typedef DWORD * 	LPDWORD;
#endif
#ifndef __LONGLONG_
#define __LONGLONG_
typedef long long 		LONGLONG;
#endif
#ifndef __ULONGLONG_
#define __ULONGLONG_
typedef unsigned long long 	ULONGLONG;
#endif
#ifndef __THAR_
#define __THAR_
typedef unsigned short 	THAR;
#endif
#ifndef __TCHAR_
#define __TCHAR_
typedef unsigned short 	TCHAR;
#endif
#ifndef __WCHAR_
#define __WCHAR_
typedef unsigned short 	WCHAR;
#endif
#ifndef __BOOL_
#define __BOOL_
#endif
#ifndef BOOL
typedef int 				BOOL;
#endif
/*
#ifndef BOOL
#define BOOL int
#endif
*/
#ifndef ULONG
#define ULONG unsigned long
#endif

#ifndef TRUE
#define TRUE (1)
#endif

#ifndef FALSE
#define FALSE (0)
#endif

#endif

#ifndef WIN32
//#define FALSE 0
//#define TRUE 1
#define Debug FALSE
#define DbgPrint(fmt,arg...) if(FALSE){KPrint(MSG_LEVEL, (fmt, ##arg));}
#endif

#define RET_OK              0
#define RET_ERR             -1
#define RET_ERR_EXIT_INPUT 101


#endif
