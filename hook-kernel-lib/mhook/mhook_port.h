#ifndef __MHOOK_PORT_H__
#define __MHOOK_PORT_H__


#ifdef WIN32

	#undef NDEBUG
	#include <windows.h>
	#include <stdio.h>
	#include <tchar.h>
	#include <stdarg.h>
	#include <assert.h>

	#include <windows.h>
	#include <tlhelp32.h>
	#include <stdio.h>

#else
	#ifndef __OS_KERNEL__
		#include <stdio.h>
		#include <stdlib.h>
	#else
		#define assert(x)

	#endif
	#include "linux_port.h"
#endif

// -- 体系结构相关
#define _M_IX86_X64

typedef signed char S8;
typedef unsigned char U8;
typedef signed short S16;
typedef unsigned short U16;

typedef signed int S32;
typedef unsigned int U32;

#ifdef WIN32
	typedef LONG64 S64;
	typedef ULONG64 U64;
#else
	// -- gcc long in 64 bit is 64 bit
	typedef unsigned long ULONG_PTR, *PULONG_PTR;
	// -- typedef unsigned int DWORD
	typedef long long S64;
	#define U64 unsigned long long
	typedef ULONG_PTR DWORD_PTR;
	typedef DWORD_PTR * PDWORD_PTR;
	#define INT32 int

	#ifndef HANDLE
	#define HANDLE void *
    #endif

	#ifndef PBYTE
	#define PBYTE unsigned char *
	#endif

	#ifndef DWORD
	#define DWORD unsigned int
	#endif

	#ifndef PDWORD
	#define PDWORD DWORD *
	#endif

	#ifndef BYTE
	#define BYTE unsigned char
	#endif

	#ifndef VOID
	#define VOID void
	#endif

	#ifndef CHAR
	#define CHAR char
	#endif

	#ifndef SIZE_T
	#define SIZE_T ULONG_PTR
	#endif
#endif


#ifdef WIN32
	#ifdef _WIN64
		#define __X86_64__
	#else
		#undef __X86_64__
	#endif
#else
	// -- linux 64 macro
	#ifdef __x86_64__
		#define _M_X64
		#define __X86_64__
	#else
		#define _M_IX86
		#undef __X86_64__
	#endif

#endif

#endif