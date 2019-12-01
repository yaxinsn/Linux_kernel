#include <linux/version.h>
#include <linux/security.h>
#include <linux/binfmts.h>
#include <linux/highmem.h>
#include <linux/file.h>
#include <linux/mman.h>
#include "probe.h"
#include "../scheme.h"
#include "../unifiedfs.h"
#include "securityhook.h"
//#include "../../include/wlSecMod.h"


//#include "../xKrnlMisc.h"

#include "securityhook_bprm_check.h"

//extern GLOBAL_CONTEXT  g_globals;







#if 0
//#ifdef CONFIG_SECURITY_PATH


#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
int securityhook_path_mkdir(struct path *dir, struct dentry *dentry,
				umode_t mode)
#else
int securityhook_path_mkdir(const struct path *dir, struct dentry *dentry,
				umode_t mode)
#endif
{
    int ret;
    ret =  macHookPathMkdir(dir,dentry);
    if(ret)
    {
        return ret;
    }
    ret = fileProtect_common2(dir->dentry->d_inode,dentry,AUDIT_MKDIR);

    if (is_user_process())
    {

        insert_self_protect_cfg(dir->dentry->d_inode, dentry);

    }
    return ret;

}

/**
 * ccs_path_rmdir - Check permission for rmdir().
 *
 * @dir:    Pointer to "struct path".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
int securityhook_path_rmdir(struct path *dir, struct dentry *dentry)
{
    int ret;
    ret =  macHookPathRmdir(dir,dentry);
    if(ret)
    {
        return ret;
    }
    ret = fileProtect_common(dentry,AUDIT_RMDIR);

    return ret;
}

/**
 * ccs_path_unlink - Check permission for unlink().
 *
 * @dir:    Pointer to "struct path".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
int securityhook_path_unlink(struct path *dir, struct dentry *dentry)
{

    int ret;
    ret =  macHookPathUnlink(dir,dentry);
    if(ret)
    {
        return ret;
    }

//    d_name.name
    return   fileProtect_common2(dir->dentry->d_inode, dentry,AUDIT_UNLINK);
}

/**
 * ccs_path_rename - Check permission for rename().
 *
 * @old_dir:    Pointer to "struct path".
 * @old_dentry: Pointer to "struct dentry".
 * @new_dir:    Pointer to "struct path".
 * @new_dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
int securityhook_path_rename(struct path *old_dir, struct dentry *old_dentry,
			   struct path *new_dir, struct dentry *new_dentry)
{
    int ret;
    ret = macHookPathRename(old_dir, old_dentry, new_dir, new_dentry);
    if (ret)
    {
        return ret;
    }
    return securityhook_inode_rename(old_dir->dentry->d_inode, old_dentry,
                new_dir->dentry->d_inode, new_dentry);
}

/**
* ccs_path_truncate - Check permission for truncate().
*
* @path: Pointer to "struct path".
*
* Returns 0 on success, negative value otherwise.
*/
int securityhook_path_truncate(struct path *path)
{
    int ret;
    ret = macHookPathTruncate(path);
    if(ret)
    {
        return ret;
    }
    return fileProtect_common(path->dentry,AUDIT_TRUNCATE);


    return ret;
}

int securityhook_path_link(struct dentry *old_dentry, struct path *new_dir,
		       struct dentry *new_dentry)
{
    int ret;

    ret =  macHookPathLink(old_dentry,new_dir,new_dentry);
    if(ret)
    {
        return ret;
    }

    return fileProtect_common2(new_dir->dentry->d_inode,new_dentry,AUDIT_LINK);

    return 0;
}
/* liudan add it for soft link  */
int  securityhook_path_symlink(struct path *path, struct dentry *dentry,
                                            const char *old_name)
{

    int ret;
    ret =  macHookPathSymLink(path,dentry,old_name);
    if(ret)
    {
        return ret;
    }

    return fileProtect_common2(path->dentry->d_inode,dentry,AUDIT_SYMLINK);

    return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
int securityhook_path_mknod(struct path *dir, struct dentry *dentry,
        umode_t mode, unsigned int dev)
#else
int securityhook_path_mknod(const struct path *dir, struct dentry *dentry,
        umode_t mode, unsigned int dev)
#endif
{
    int ret;
    ret =  macHookPathMknod(dir,dentry,mode,dev);
    if(ret)
    {
        return ret;
    }
    return securityhook_inode_mknod(dir->dentry->d_inode, dentry, mode, dev);
}

#endif //CONFIG_SECURITY_PATH

#define SECHOOKTABLE_SLOTNUM (sizeof(g_secHookTable_slot) / sizeof((g_secHookTable_slot)[0]))

secHookTable *g_secHookTable_slot[] =
{
//    &g_secHookTableMac,
//    &g_secHookTableFileProtect,
//    &g_secHookTableSelfProtect,
//    &g_secHookTableWlProtect,
//    &g_secHookTableUSBDisk,
};

int securityhook_inode_alloc_security(struct inode *inode)
{
//    insert_sys_inode(inode);

    return 0;
}

void securityhook_inode_free_security(struct inode *inode)
{
//    remove_sys_inode_ctx(inode);
}

int securityhook_file_mmap(struct file *file,
			  unsigned long reqprot, unsigned long prot,
			  unsigned long flags)
{
    int i;


    int iRet;
    for(i = 0;i<SECHOOKTABLE_SLOTNUM;i++)
    {
        if(g_secHookTable_slot[i]->file_mmap)
        {
            iRet = g_secHookTable_slot[i]->file_mmap(file,reqprot,prot,flags);
            if(iRet)
                return iRet;
        }
    }
    return 0;
}

int securityhook_inode_mkdir(struct inode *dir, struct dentry *dentry,
            umode_t mode)
{
    int iRet;
    int i;
    for(i = 0;i<SECHOOKTABLE_SLOTNUM;i++)
    {
        if(g_secHookTable_slot[i]->inode_mkdir)
        {
            iRet = g_secHookTable_slot[i]->inode_mkdir(dir,dentry,mode);
            if(iRet)
                return iRet;
        }
    }
	return 0;
}


int securityhook_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
    int iRet;
    int i;
    for(i = 0;i<SECHOOKTABLE_SLOTNUM;i++)
    {
        if(g_secHookTable_slot[i]->inode_rmdir)
        {
            iRet = g_secHookTable_slot[i]->inode_rmdir(dir,dentry);
            if(iRet)
                return iRet;
        }
    }
    return 0;
}


int securityhook_inode_unlink(struct inode *dir, struct dentry *dentry)
{
    int iRet;
    int i;
    for(i = 0;i<SECHOOKTABLE_SLOTNUM;i++)
    {
        if(g_secHookTable_slot[i]->inode_unlink)
        {
            iRet = g_secHookTable_slot[i]->inode_unlink(dir,dentry);
            if(iRet)
                return iRet;
        }
    }
    return 0;

}

int securityhook_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
            struct inode *new_dir,
            struct dentry *new_dentry
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
            ,unsigned int flags
#endif
            )
{
    int iRet;
    int i;
    for(i = 0;i<SECHOOKTABLE_SLOTNUM;i++)
    {
        if(g_secHookTable_slot[i]->inode_rename)
        {
            iRet = g_secHookTable_slot[i]->inode_rename(old_dir,old_dentry,new_dir,new_dentry);
            if(iRet)
                return iRet;
        }
    }
    return 0;
#if 0
    int ret;

    ret = fileProtect_common2(old_dir,old_dentry,AUDIT_RENAME);
    if(ret)
        return ret;

    ret =  macHookInodeCommon(old_dentry,MAC_EXT_OP_RENAME);
    if(ret)
        return ret;


    ret = fileProtect_common2(new_dir,new_dentry,AUDIT_RENAME);
    if(ret)
        return ret;

    ret =  macHookInodeCommon(new_dentry,MAC_EXT_OP_RENAME);
    if(ret)
        return ret;


    if (is_user_process())
    {
        rm_self_protect_cfg(old_dir, old_dentry);
        insert_self_protect_cfg(new_dir, new_dentry);
    }

    return 0;
#endif
}
#if 0
int securityhook_inode_permission(struct inode *inode, int mask)
{
    if (!(mask & MAY_WRITE))
    {
        return 0;
    }

    if (is_self_protect_inode(inode))
    {
        //audit_fs_detry_operation(dentry, AUDIT_UNLINK);
        KTsgDebug(KERN_INFO"[-] securityhook_inode_permission is_self_protect_inode\n");
        return -EPERM;
    }

    if (!file_protect_enable())
    {
        return 0;
    }

    if (lookup_protect_inode(inode))
    {
        KTsgDebug(KERN_INFO"[-] securityhook_inode_permission lookup_protect_inode\n");
        return -EPERM;
    }

    return 0;
}
#endif
int securityhook_dentry_permission( struct dentry* d, int mask)
{

#if 0

    int iRet;
    if(((mask&MAY_WRITE) ||(mask&MAY_APPEND)))
    {
        iRet = fileProtect_common(d, AUDIT_WRITE);
        if(iRet)
            return iRet;
    }

    return macHookInodeOpen(d, mask, MAC_EXT_OP_OPEN);
#endif
    int iRet;
    int i;
    for(i = 0;i<SECHOOKTABLE_SLOTNUM;i++)
    {
        if(g_secHookTable_slot[i]->_dentry_permission)
        {
            iRet = g_secHookTable_slot[i]->_dentry_permission(d,mask);
            if(iRet)
                return iRet;
        }
    }
    return 0;

}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
int securityhook_inode_permission (struct inode *inode, int mask)
#else
int securityhook_inode_permission (struct inode *inode, int mask, struct nameidata *nd)
#endif
{
    int iRet;
    int i;
    for(i = 0;i<SECHOOKTABLE_SLOTNUM;i++)
    {
        if(g_secHookTable_slot[i]->inode_permission)
        {

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
            iRet = g_secHookTable_slot[i]->inode_permission(inode,mask);
#else
            iRet = g_secHookTable_slot[i]->inode_permission(inode,mask,nd);
#endif
            if(iRet)
                return iRet;
        }
    }
    return 0;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0)
int securityhook_inode_permission_by_nameidata( struct nameidata *nd, int mask)
{
    int iRet;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 25)
    struct dentry* d = nd->path.dentry;
#else
    struct dentry* d = nd->dentry;
#endif
    return securityhook_dentry_permission(d,mask);
//    return 0;
}
#endif
int securityhook_inode_mknod(struct inode *dir, struct dentry *dentry,
				umode_t mode, dev_t dev)
{
    int iRet;
    int i;
    for(i = 0;i<SECHOOKTABLE_SLOTNUM;i++)
    {
        if(g_secHookTable_slot[i]->inode_mknod)
        {
            iRet = g_secHookTable_slot[i]->inode_mknod(dir,dentry,mode,dev);
            if(iRet)
                return iRet;
        }
    }
    return 0;

}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 16)

int  securityhook_file_permission(struct file *file, int mask)
{
    int iRet;
    int i;
    for(i = 0;i<SECHOOKTABLE_SLOTNUM;i++)
    {
        if(g_secHookTable_slot[i]->file_permission)
        {
            iRet = g_secHookTable_slot[i]->file_permission(file,mask);
            if(iRet)
                return iRet;
        }
    }
    return 0;


}
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
int securityhook_file_open(struct file *file, const struct cred *cred)
#else
int securityhook_file_open(struct file *file)
#endif
{
    int iRet;
    int i;
    for(i = 0;i<SECHOOKTABLE_SLOTNUM;i++)
    {
        if(g_secHookTable_slot[i]->dentry_open)
        {
            iRet = g_secHookTable_slot[i]->dentry_open(file);
            if(iRet)
                return iRet;
        }
    }
    return 0;


}

#endif


int securityhook_inode_create(struct inode *dir,
        struct dentry *dentry,
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
        umode_t mode
    #else
        int mode
    #endif
        )
{
    int iRet;
    int i;
    for(i = 0;i<SECHOOKTABLE_SLOTNUM;i++)
    {
        if(g_secHookTable_slot[i]->inode_create)
        {
            iRet = g_secHookTable_slot[i]->inode_create(dir,dentry,mode);
            if(iRet)
                return iRet;
        }
    }
    return 0;


}

int    securityhook_inode_symlink(struct inode *dir, struct dentry *dentry,
			    const char *old_name)
{
    int iRet;
    int i;
    //cycles_t a;

    //cycles_t b;
    for(i = 0;i<SECHOOKTABLE_SLOTNUM;i++)
    {
        if(g_secHookTable_slot[i]->inode_symlink)
        {
            //a = 1;
            iRet = g_secHookTable_slot[i]->inode_symlink(dir,dentry,old_name);
            //b = 3;

            if(iRet)
                return iRet;
        }
    }
    return 0;


}

int securityhook_inode_link(struct dentry *old_dentry, struct inode *dir,
             struct dentry *new_dentry)
{
    int i;


    int iRet;
    for(i = 0;i<SECHOOKTABLE_SLOTNUM;i++)
    {
        if(g_secHookTable_slot[i]->inode_link)
        {
            iRet = g_secHookTable_slot[i]->inode_link(old_dentry,dir,new_dentry);
            if(iRet)
                return iRet;
        }
    }
    return 0;
}
#ifdef CONFIG_SECURITY_PATH

int securityhook_path_truncate(struct path *path, loff_t length,
                   unsigned int time_attrs)
{
    int i;
    int iRet;
    for(i = 0;i<SECHOOKTABLE_SLOTNUM;i++)
    {
        if(g_secHookTable_slot[i]->path_truncate)
        {
            iRet = g_secHookTable_slot[i]->path_truncate(path,length,time_attrs);
            if(iRet)
                return iRet;
        }
    }
    return 0;
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32) || !defined (CONFIG_SECURITY_PATH)
int securityhook_do_truncate_hook(struct dentry *dentry, loff_t length,
                   unsigned int time_attrs,struct file *filp)
{
    int i;
    int iRet;
    for(i = 0;i<SECHOOKTABLE_SLOTNUM;i++)
    {
        if(g_secHookTable_slot[i]->do_truncate_hook)
        {
            iRet = g_secHookTable_slot[i]->do_truncate_hook(dentry,length,time_attrs,filp);
            if(iRet)
                return iRet;
        }
    }
    return 0;
}
#endif

/************************************************************************************************/

/*
securityhook_bprm_set_creds
securityhook_bprm_set_securit

securityhook_bprm_check_security
用来控制程序白名单的。


*/
int securityhook_bprm_set_creds(struct linux_binprm *bprm)
{
	int retval = 0;

	return retval;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 28) // check-linux-src haozelong for redhat5.4

int securityhook_bprm_set_securit(struct linux_binprm *bprm)
{
	int retval = 0;

	return retval;
}

#endif

ssize_t __xkernel_write(struct file *file, const char *buf, size_t count,
			    loff_t pos)
{
	mm_segment_t old_fs;
	ssize_t res;

	old_fs = get_fs();
	set_fs(get_ds());
	/* The cast to a user pointer is valid due to the set_fs() */
	res = vfs_write(file, (const char __user *)buf, count, &pos);
	set_fs(old_fs);

	return res;
}



int securityhook_bprm_check_security(struct linux_binprm *bprm)
{
    return 0;
}


