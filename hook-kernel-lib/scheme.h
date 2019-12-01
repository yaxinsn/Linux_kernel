#ifndef __SCHEME_H__
#define __SCHEME_H__

#define __LINUX__
#define __IN_KERNEL_MOD__
#define __OS_KERNEL__
#define LINUX_DRIVER
/* all's *c in KtsgMod must include this scheme.h --liudan 2019-2-12. */
#include <linux/version.h>
#include <linux/security.h>

#include <linux/module.h>

#include <linux/proc_fs.h>
#include "precompile.h"

#include "./mhook/mhook_port.h"

#define __SCHEME_DEBUG__

#define NTSTATUS int
#define STATUS_SUCCESS (0)

#define STATUS_UNSUCCESSFUL (-1)
#define STATUS_INVALID_PARAMETER (-2)
#define STATUS_INSUFFICIENT_RESOURCES (-3)
#define STATUS_BUFFER_TOO_SMALL (-4)
#define NT_SUCCESS(x) (0 == (x))

// -- #define wlKRFree(x) ExFreePool(x)

#define malloc(x) kmalloc((x), GFP_ATOMIC)
#define free(x) kfree(x)

typedef struct __IOCTL_PARAM
{
	unsigned int uCode;
	unsigned int inputBufferLength;
	unsigned char * inputBuffer;

	unsigned int outputBufferLength;
	unsigned char * outputBuffer;
	int uRetValue; // -- BOOL value;
	unsigned int uRawMode;
}IOCTL_PARAM;


#endif
