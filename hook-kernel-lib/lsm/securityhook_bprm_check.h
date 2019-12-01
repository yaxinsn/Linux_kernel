#ifndef  __SECURITYHOOK_BPRM_CHECK_H__
#define  __SECURITYHOOK_BPRM_CHECK_H__
#include <linux/version.h>
#include <linux/security.h>
#include <linux/binfmts.h>
#include <linux/highmem.h>
#include <linux/file.h>
#include <linux/mman.h>

int securityhook_bprm_check_security_elf(struct linux_binprm *bprm);


#endif //__SECURITYHOOK_BPRM_CHECK_H__