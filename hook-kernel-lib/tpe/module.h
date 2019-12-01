#ifndef TPE_H_INCLUDED
#define TPE_H_INCLUDED

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/file.h>
#include <linux/mman.h>
#include <linux/binfmts.h>
#include <linux/version.h>
#include <linux/utsname.h>
#include <linux/kallsyms.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/jiffies.h>
#include <linux/sysctl.h>
#include <linux/err.h>
#include <linux/namei.h>
#include <linux/fs_struct.h>
#include <linux/mount.h>

#include <asm/uaccess.h>
// -- #include <asm/insn.h>

#ifndef BOOLEAN
#define BOOLEAN int
#endif
#ifndef bool
#define bool BOOLEAN
#endif
#ifndef false
#define false 0
#endif
#ifndef true
#define true 1
#endif


#define MODULE_NAME "tpe"
#define PKPRE "[" MODULE_NAME "] "
#define MAX_FILE_LEN 256
#define TPE_HARDCODED_PATH_LEN 1024

#define LOG_FLOODTIME 5
#define LOG_FLOODBURST 5
#define IN_ERR(x) (x < 0)
struct kernsym {
	void *addr; // orig addr
	void *end_addr;
	unsigned long size;
	const char *name;
	// -- bool name_alloc; // whether or not we alloc'd memory for char *name
	// -- u8 orig_start_bytes[OP_JMP_SIZE];
	// -- void *new_addr;
	unsigned long new_size;
	BOOLEAN found;
	// -- bool hijacked;
	void *run;
};
int find_symbol_address(struct kernsym *sym, const char *symbol_name);
#endif


