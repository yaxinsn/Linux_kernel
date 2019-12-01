#include <scheme.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 16, 0)
#include <linux/syscalls.h>
#endif

#include <linux/version.h>
#include "./tpe/module.h"
#include "kernsymbol.h"

void * kGetSymbol(const char * symbol)
{
	void * retval = NULL;
	#ifndef __USING_KALLSYMS_LOOKUP_NAME__
		int ret = 0;
		struct kernsym sym;
	#endif
	
	#ifdef __USING_KALLSYMS_LOOKUP_NAME__
		retval = (void *)kallsyms_lookup_name(symbol);
	#else
		memset(&sym, 0, sizeof(sym));
		ret = find_symbol_address(&sym, symbol);
		if (IN_ERR(ret)){
			goto DONE;
		}
		retval = sym.run;
	#endif
DONE:	
	return retval;
}

