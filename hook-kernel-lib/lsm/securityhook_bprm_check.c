#include <linux/elf.h>

#include <linux/a.out.h>

#include "securityhook_bprm_check.h"
#include "Ktsglog.h"

struct loc_st
{
    struct elfhdr elf_ex;
    struct elfhdr interp_elf_ex;
    struct exec interp_ex;
};

int wlSecMMapCheck(struct file * file, unsigned long reqprot,
			     unsigned long prot, unsigned long flags);


int securityhook_bprm_check_security_elf(struct linux_binprm *bprm)
{
    int retval = 0;


    return retval;
}


