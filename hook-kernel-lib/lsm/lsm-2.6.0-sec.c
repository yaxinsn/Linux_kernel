/*
 * lsm.c
 *
 * Copyright (C) 2010-2015  Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
 *
 * Version: 1.0.35   2015/11/11
 */

#include "internal.h"
#include "probe.h"
#include "../scheme.h"
//#include "../../common/pid_ctx.h"
//#include "../../common/genTable.h"
//#include "../xHookProc.h"
//#include "../xLsmHook.h"
//#include "../ProtectFile.h"
//#include "../scriptfilter.h"
//#include "../iNodeCtxTable.h"
#include "securityhook.h"
#include "hook.h"
#include "klog.h"

//#include "../globals.h"

/* Prototype definition. */

/* Function pointers originally registered by register_security(). */
static struct security_operations original_security_ops /* = *security_ops; */;
static struct security_operations *ops_orig;


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)

#if 0
/**
 * ccs_open - Check permission for open().
 *
 * @f: Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_open(struct file *f)
{
    return ccs_open_permission(f->f_path.dentry, f->f_path.mnt,
                   f->f_flags + 1);
}

#endif

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)

/**
 * ccs_dentry_open - Check permission for open().
 *
 * @f: Pointer to "struct file".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_dentry_open(struct file *f)
{
#if 0
    int rc = ccs_open(f);
    if (rc)
        return rc;
#endif
    int ret;

    while (!original_security_ops.dentry_open);

    ret = securityhook_file_open(f, cred);

    if (ret)
    {
        return ret;
    }

    return original_security_ops.dentry_open(f);
}

#else


/**
 * ccs_open - Check permission for open().
 *
 * @inode: Pointer to "struct inode".
 * @mask:  Open mode.
 * @nd:    Pointer to "struct nameidata".
 *
 * Returns 0 on success, negative value otherwise.
 */
 #if 0
static int ccs_open(struct inode *inode, int mask, struct nameidata *nd)
{
    int flags;
    if (!nd || !nd->dentry)
        return 0;
    /* open_exec() passes MAY_EXEC . */
    if (mask == MAY_EXEC && inode && S_ISREG(inode->i_mode) &&
        (ccs_current_flags() & CCS_TASK_IS_IN_EXECVE))
        mask = MAY_READ;
    /*
     * This flags value is passed to ACC_MODE().
     * ccs_open_permission() for older versions uses old ACC_MODE().
     */
    switch (mask & (MAY_READ | MAY_WRITE)) {
    case MAY_READ:
        flags = 01;
        break;
    case MAY_WRITE:
        flags = 02;
        break;
    case MAY_READ | MAY_WRITE:
        flags = 03;
        break;
    default:
        return 0;
    }
    return ccs_open_permission(nd->dentry, nd->mnt, flags);
}
#endif

static int  ccs_file_permission(struct file *file, int mask)
{
     int ret;

     while (!original_security_ops.file_permission);

     ret =  securityhook_file_permission(file, mask);

    //printk("ccs_file_permission ret:(%d)\n", ret);

     if (ret)
     {
         return ret;
     }
#if 0
     if (privilege_task2(current))
     {
         return 0;
     }
     if (privilege_task2(current->parent))
     {
         return 0;
     }
#endif
     ret = original_security_ops.file_permission(file, mask);
     return ret;

}


/**
 * ccs_inode_permission - Check permission for open().
 *
 * @inode: Pointer to "struct inode".
 * @mask:  Open mode.
 * @nd:    Pointer to "struct nameidata".
 *
 * Returns 0 on success, negative value otherwise.
 *
 * Note that this hook is called from permission(), and may not be called for
 * open(). Maybe it is better to use security_file_permission().
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
    int ccs_inode_permission (struct inode *inode, int mask)
#else
    int ccs_inode_permission (struct inode *inode, int mask, struct nameidata *nd)
#endif
     {
         int ret;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
        ret = securityhook_inode_permission(inode, mask);

#else
        ret = securityhook_inode_permission(inode, mask, nd);

#endif
          if (ret)
          {
              return ret;
          }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
         return original_security_ops.inode_permission(inode, mask);
#else
#if 0
         if (privilege_task2(current))
         {
             return 0;
         }
         if (privilege_task2(current->parent))
         {
             return 0;
         }
#endif
          ret = original_security_ops.inode_permission(inode, mask,nd);
          return ret;
#endif
}

#endif

int ccs_inode_alloc_security(struct inode *inode)
{
	int retval = 0;
	while (!original_security_ops.inode_alloc_security);
	retval = original_security_ops.inode_alloc_security(inode);
#if 0
	if(0==retval){
		insert_sys_inode(inode);

	}
#endif
	return retval;
}

void ccs_inode_free_security(struct inode *inode)
{
	while (!original_security_ops.inode_free_security);

	//remove_sys_inode_ctx(inode);

	return original_security_ops.inode_free_security(inode);
}



/**
 * ccs_inode_mknod - Check permission for mknod().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 * @mode:   Create mode.
 * @dev:    Device major/minor number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_mknod(struct inode *dir, struct dentry *dentry, int mode,
               dev_t dev)
{
#if 0
    int rc = ccs_mknod_permission(dentry, NULL, mode, dev);
    if (rc)
        return rc;
#endif
    int ret;

    while (!original_security_ops.inode_mknod);

    ret = securityhook_inode_mknod(dir, dentry, mode, dev);

    //printk("securityhook_inode_mknod ret:(%d)\n", ret);

    if (ret)
    {
        return ret;
    }

    return original_security_ops.inode_mknod(dir, dentry, mode, dev);
}

/**
 * ccs_inode_mkdir - Check permission for mkdir().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 * @mode:   Create mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
#if 0
    int rc = ccs_mkdir_permission(dentry, NULL, mode);
    if (rc)
        return rc;
#endif
    int ret;

    while (!original_security_ops.inode_mkdir);


    ret = securityhook_inode_mkdir(dir, dentry, mode);

    //printk("securityhook_inode_mkdir ret:(%d)\n", ret);

    if (ret)
    {
        return ret;
    }

    return original_security_ops.inode_mkdir(dir, dentry, mode);
}

/**
 * ccs_inode_rmdir - Check permission for rmdir().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
#if 0
    int rc = ccs_rmdir_permission(dentry, NULL);
    if (rc)
        return rc;
#endif
    int ret;

    while (!original_security_ops.inode_rmdir);

    ret = securityhook_inode_rmdir(dir, dentry);

    //printk("securityhook_inode_rmdir ret:(%d)\n", ret);

    if (ret)
    {
        return ret;
    }

    return original_security_ops.inode_rmdir(dir, dentry);
}

/**
 * ccs_inode_unlink - Check permission for unlink().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_unlink(struct inode *dir, struct dentry *dentry)
{
#if 0
    int rc = ccs_unlink_permission(dentry, NULL);
    if (rc)
        return rc;
#endif
    int ret;

    while (!original_security_ops.inode_unlink);

    ret = securityhook_inode_unlink(dir, dentry);

    //printk("securityhook_inode_unlink ret:(%d)\n", ret);

    if (ret < 0)
    {
        return ret;
    }
#if 0
    if (privilege_task2(current))
    {
        return 0;
    }
    if (privilege_task2(current->parent))
    {
        return 0;
    }
#endif
    ret = original_security_ops.inode_unlink(dir, dentry);
    return ret;
}

/**
 * ccs_inode_symlink - Check permission for symlink().
 *
 * @dir:      Pointer to "struct inode".
 * @dentry:   Pointer to "struct dentry".
 * @old_name: Content of symbolic link.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_symlink(struct inode *dir, struct dentry *dentry,
                 const char *old_name)
{
#if 0
    int rc = ccs_symlink_permission(dentry, NULL, old_name);
    if (rc)
        return rc;
#endif
    int ret;

    while (!original_security_ops.inode_symlink);

    ret = securityhook_inode_symlink(dir, dentry, old_name);

    //printk("securityhook_inode_symlink ret:(%d)\n", ret);

     if (ret)
     {
         return ret;
     }

    return original_security_ops.inode_symlink(dir, dentry, old_name);
}

/**
 * ccs_inode_rename - Check permission for rename().
 *
 * @old_dir:    Pointer to "struct inode".
 * @old_dentry: Pointer to "struct dentry".
 * @new_dir:    Pointer to "struct inode".
 * @new_dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
                struct inode *new_dir, struct dentry *new_dentry)
{
#if 0
    int rc = ccs_rename_permission(old_dentry, new_dentry, NULL);
    if (rc)
        return rc;
#endif
    int ret;

    while (!original_security_ops.inode_rename);

    ret = securityhook_inode_rename(old_dir, old_dentry, new_dir, new_dentry);

    //printk("securityhook_inode_rename ret:(%d)\n", ret);

    if (ret)
    {
        return ret;
    }
#if 0
    if (privilege_task2(current))
    {
        return 0;
    }
    if (privilege_task2(current->parent))
    {
        return 0;
    }
#endif
    ret = original_security_ops.inode_rename(old_dir, old_dentry, new_dir,
                          new_dentry);
    return ret;
}

/**
 * ccs_inode_link - Check permission for link().
 *
 * @old_dentry: Pointer to "struct dentry".
 * @dir:        Pointer to "struct inode".
 * @new_dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_link(struct dentry *old_dentry, struct inode *dir,
              struct dentry *new_dentry)
{
#if 0
    int rc = ccs_link_permission(old_dentry, new_dentry, NULL);
    if (rc)
        return rc;
#endif
    int ret;
    while (!original_security_ops.inode_link);

    ret = securityhook_inode_link(old_dentry, dir, new_dentry);

    //printk("securityhook_inode_link ret:(%d)\n", ret);

     if (ret)
     {
         return ret;
     }

    return original_security_ops.inode_link(old_dentry, dir, new_dentry);
}

/**
 * ccs_inode_create - Check permission for creat().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 * @mode:   Create mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_create(struct inode *dir, struct dentry *dentry,
                int mode)
{
#if 0
    int rc = ccs_mknod_permission(dentry, NULL, mode, 0);
    if (rc)
        return rc;
#endif
    int ret;
    while (!original_security_ops.inode_create);

    ret = securityhook_inode_create(dir, dentry, mode);

    //printk("securityhook_inode_create ret:(%d)\n", ret);

    if (ret)
    {
        return ret;
    }

    return original_security_ops.inode_create(dir, dentry, mode);
}

 int ccs_bprm_set_security(struct linux_binprm *bprm)
{
	int ret;

    while (!original_security_ops.bprm_set_security);

    ret = securityhook_bprm_set_securit(bprm);

   // printk("securityhook_bprm_set_securit ret:(%d)\n", ret);

    if (ret)
    {
        return ret;
    }

    return original_security_ops.bprm_set_security(bprm);
}
int ccs_bprm_check_security(struct linux_binprm *bprm)
{
    int ret;

    while (!original_security_ops.bprm_check_security);

    ret = securityhook_bprm_check_security(bprm);

  //  printk("securityhook_bprm_check_security ret:(%d)\n", ret);

    if (ret < 0)
    {
        return ret;
    }

    return original_security_ops.bprm_check_security(bprm);
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 21) && defined(CONFIG_SYSCTL_SYSCALL)
int ccs_path_permission(struct ccs_request_info *r, u8 operation,
            const struct ccs_path_info *filename);

/**
 * ccs_prepend - Copy of prepend() in fs/dcache.c.
 *
 * @buffer: Pointer to "struct char *".
 * @buflen: Pointer to int which holds size of @buffer.
 * @str:    String to copy.
 *
 * Returns 0 on success, negative value otherwise.
 *
 * @buffer and @buflen are updated upon success.
 */
static int ccs_prepend(char **buffer, int *buflen, const char *str)
{
    int namelen = strlen(str);
    if (*buflen < namelen)
        return -ENOMEM;
    *buflen -= namelen;
    *buffer -= namelen;
    memcpy(*buffer, str, namelen);
    return 0;
}


#endif

/*
 * Why not to copy all operations by "original_security_ops = *ops" ?
 * Because copying byte array is not atomic. Reader checks
 * original_security_ops.op != NULL before doing original_security_ops.op().
 * Thus, modifying original_security_ops.op has to be atomic.
 */
#define swap_security_ops(op)                        \
    original_security_ops.op = ops->op; smp_wmb(); ops->op = ccs_##op;

#define rwap_security_ops(op)  ops_orig->op = original_security_ops.op;

/**
 * ccs_update_security_ops - Overwrite original "struct security_operations".
 *
 * @ops: Pointer to "struct security_operations".
 *
 * Returns nothing.
 */
static void ccs_update_security_ops(struct security_operations *ops)
{

    /* Various permission checker. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
    swap_security_ops(dentry_open);
#else
    swap_security_ops(file_permission);
    swap_security_ops(inode_permission);
#endif

    swap_security_ops(inode_alloc_security);
    swap_security_ops(inode_free_security);
    swap_security_ops(inode_mknod);
    swap_security_ops(inode_mkdir);
    swap_security_ops(inode_rmdir);
    swap_security_ops(inode_unlink);
    swap_security_ops(inode_symlink);
    swap_security_ops(inode_rename);
    swap_security_ops(inode_link);
    swap_security_ops(inode_create);


    //swap_security_ops();
    //swap_security_ops(bprm_apply_creds);
    //swap_security_ops(bprm_post_apply_creds);
    swap_security_ops(bprm_set_security);
    swap_security_ops(bprm_check_security);

}


static void ccs_restore_security_ops(void)
{
        /* Various permission checker. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
        rwap_security_ops(dentry_open);
#else
        rwap_security_ops(file_permission);
        rwap_security_ops(inode_permission);
#endif

        rwap_security_ops(inode_alloc_security);
        rwap_security_ops(inode_free_security);
        rwap_security_ops(inode_mknod);
        rwap_security_ops(inode_mkdir);
        rwap_security_ops(inode_rmdir);
        rwap_security_ops(inode_unlink);
        rwap_security_ops(inode_symlink);
        rwap_security_ops(inode_rename);
        rwap_security_ops(inode_link);
        rwap_security_ops(inode_create);


        //swap_security_ops();
        //swap_security_ops(bprm_apply_creds);
        //swap_security_ops(bprm_post_apply_creds);
        rwap_security_ops(bprm_set_security);
        rwap_security_ops(bprm_check_security);

    return;
}


#undef swap_security_ops
#undef rwap_security_ops


/**
 * ccs_init - Initialize this module.
 *
 * Returns 0 on success, negative value otherwise.
 */
 int ccs_init(void)
{
    printk(KERN_INFO "%s:%s:%d ----\n",__FILE__,__func__,__LINE__);

    struct security_operations *ops = probe_security_ops();

    ops_orig = ops;
    if (!ops)
        goto out;

    printk(KERN_INFO "AKARI: 1.0.35   2015/11/11 ----\n");

    ccs_update_security_ops(ops);

    printk("Access Keeping And Regulating Instrument registered.\n");
    return 0;

out:
    return -EINVAL;
}

 int ccs_destroy(void)
{
    ccs_restore_security_ops();
    printk(KERN_INFO "Unregister TsgMod and defender close!\n");

    return 0;
}

//module_init(ccs_init);
MODULE_LICENSE("GPL");

