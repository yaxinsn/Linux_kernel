//#include "internal.h"
#include "probe.h"
#include "../scheme.h"
#include "../../common/pid_ctx.h"
#include "../../common/genTable.h"
#include "../xHookProc.h"
#include "../xLsmHook.h"
#include "../ProtectFile.h"
#include "../scriptfilter.h"
#include "../iNodeCtxTable.h"
#include "securityhook.h"

static void ccs_cred_free(struct cred *cred)
{

}

static int ccs_cred_prepare(struct cred *new, const struct cred *old,
			    gfp_t gfp)
{
	return 0;
}

static int ccs_cred_alloc_blank(struct cred *new, gfp_t gfp)
{
    return 0;
}

int ccs_mmap_file(struct file *file, unsigned long reqprot,
			     unsigned long prot, unsigned long flags)
{
	int retval = -1;


	retval = securityhook_file_mmap(file, reqprot, prot, flags);
	if (retval)
	{
	    return retval;
	}

	return retval;
}


#define MY_HOOK_INIT(HEAD, HOOK)				    \
{                                                   \
    .head = &probe_dummy_security_hook_heads.HEAD,	\
    .hook = { .HEAD = HOOK }                        \
}

static struct security_hook_list akari_hooks[] = {

	/* Security context allocator. */
	MY_HOOK_INIT(cred_free, ccs_cred_free),
	MY_HOOK_INIT(cred_prepare, ccs_cred_prepare),
	MY_HOOK_INIT(cred_alloc_blank, ccs_cred_alloc_blank),
	MY_HOOK_INIT(mmap_file, ccs_mmap_file),

    MY_HOOK_INIT(path_truncate, securityhook_path_truncate),
#ifdef xCONFIG_SECURITY_PATH
    MY_HOOK_INIT(path_mkdir, securityhook_path_mkdir),
    MY_HOOK_INIT(path_rmdir, securityhook_path_rmdir),
    MY_HOOK_INIT(path_unlink, securityhook_path_unlink),
    MY_HOOK_INIT(path_rename, securityhook_path_rename),

    MY_HOOK_INIT(path_mknod, securityhook_path_mknod),
#endif

	MY_HOOK_INIT(inode_free_security, securityhook_inode_free_security),
	MY_HOOK_INIT(inode_alloc_security, securityhook_inode_alloc_security),
	MY_HOOK_INIT(inode_mkdir, securityhook_inode_mkdir),
	MY_HOOK_INIT(inode_rmdir, securityhook_inode_rmdir),
    //MY_HOOK_INIT(inode_permission, smack_inode_permission),
	MY_HOOK_INIT(inode_unlink, securityhook_inode_unlink),
	MY_HOOK_INIT(inode_mknod, securityhook_inode_mknod),
	MY_HOOK_INIT(inode_create, securityhook_inode_create),

    MY_HOOK_INIT(inode_rename,securityhook_inode_rename),
    MY_HOOK_INIT(inode_symlink,securityhook_inode_symlink),
    MY_HOOK_INIT(inode_link,securityhook_inode_link),

    MY_HOOK_INIT(inode_permission, securityhook_inode_permission),
    MY_HOOK_INIT(file_permission, securityhook_file_permission),
    MY_HOOK_INIT(file_open, securityhook_file_open),

	MY_HOOK_INIT(bprm_set_creds, securityhook_bprm_set_creds),
	MY_HOOK_INIT(bprm_check_security, securityhook_bprm_check_security),
};

static inline void add_hook(struct security_hook_list *hook)
{
	list_add_tail_rcu(&hook->list, hook->head);
}

/*
static void __init swap_hook(
                        struct security_hook_list *hook,
                        union security_list_options *original)
{
	struct list_head *list = hook->head;

    if (list_empty(list))
    {
        add_hook(hook);
    }
    else
    {
        struct security_hook_list *shp =
            list_last_entry(list, struct security_hook_list, list);
        *original = shp->hook;
        smp_wmb();
        shp->hook = hook->hook;
    }
}
*/

#include <linux/rculist.h>

#if 0
static inline void xx__list_del(struct list_head * prev, struct list_head * next)
{
    smp_wmb();
	next->prev = prev;
    smp_wmb();
    prev->next = next;
	//WRITE_ONCE(prev->next, next);
}

/**
 * list_del - deletes entry from list.
 * @entry: the element to delete from the list.
 * Note: list_empty() on entry does not return true after this, the entry is
 * in an undefined state.
 */
static inline void xx__list_del_entry(struct list_head *entry)
{
	//if (!__list_del_entry_valid(entry))
	//	return;

	xx__list_del(entry->prev, entry->next);
}
#endif

int ccs_destroy(void)
{
    int idx;

    KTsgDebug(KERN_INFO "rmmod ccs_destroy\n");

    for (idx = 3; idx < ARRAY_SIZE(akari_hooks); idx++)
        __list_del_entry(&akari_hooks[idx].list);

    return 0;
}

/**
 * ccs_init - Initialize this module.
 *
 * Returns 0 on success, negative value otherwise.
 */
int ccs_init(void)
{
	int idx;
	struct security_hook_heads *hooks = probe_security_hook_heads();

	if (!hooks)
		goto out;

    for (idx = 0; idx < ARRAY_SIZE(akari_hooks); idx++)
        akari_hooks[idx].head = ((void *) hooks)
        + ((unsigned long)akari_hooks[idx].head)
        - ((unsigned long)&probe_dummy_security_hook_heads);

	if (ARRAY_SIZE(akari_hooks) > 0)
    {
        for (idx = 3; idx < ARRAY_SIZE(akari_hooks); idx++)
            add_hook(&akari_hooks[idx]);

        KTsgDebug(KERN_INFO "AKARI: 1.0.35   2015/11/11\n");
        KTsgDebug(KERN_INFO
        "Access Keeping And Regulating Instrument registered.\n");
    }

	return 0;
out:
	return -EINVAL;
}

// -- module_init(ccs_init);
// -- MODULE_LICENSE("GPL");


