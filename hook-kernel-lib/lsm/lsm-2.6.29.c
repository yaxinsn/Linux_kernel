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
#include "../../common/pid_ctx.h"
#include "../../common/genTable.h"
#include "../xHookProc.h"
#include "../xLsmHook.h" 
#include "../ProtectFile.h" 
#include "../scriptfilter.h"
#include "../iNodeCtxTable.h"
#include "securityhook.h"
#include "../hook.h" 

#include "../globals.h" 
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
#define USE_UMODE_T
#else
// -- #include "check_umode_t.h"
#endif 
/* Function pointers originally registered by register_security(). */
static struct security_operations original_security_ops /* = *security_ops; */;
static struct security_operations *ops_orig;
  
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)

/**
 * ccs_file_open - Check permission for open().
 *
 * @f:    Pointer to "struct file".
 * @cred: Pointer to "struct cred".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_file_open(struct file *f, const struct cred *cred)
{
    int ret;
    
	//while (!original_security_ops.file_open);
    //return original_security_ops.file_open(f, cred);

    ret = securityhook_file_open(f, cred);

    if (ret)
    {
        return ret;
    }
    
	return original_security_ops.file_open(f, cred);
}

#else

/**
 * ccs_dentry_open - Check permission for open().
 *
 * @f:    Pointer to "struct file".
 * @cred: Pointer to "struct cred".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_dentry_open(struct file *f, const struct cred *cred)
{
    int ret;
    
	while (!original_security_ops.dentry_open);

    ret = securityhook_file_open(f, cred);

    if (ret)
    {
        return ret;
    }
    
	return original_security_ops.dentry_open(f, cred);
}

#endif

#if defined(CONFIG_SECURITY_PATH)

#if 0
int prepare_path(struct path *dir, struct dentry *dentry, char *buffer, int buflen)
{
    int ret;
    char *path;
    int dlen;
    char *buf;

    buf = buffer;
    
    path = d_path(dir, buf, buflen);

    if (IS_ERR(path))
    {
        ret = PTR_ERR(path);
        goto out;
    }

    if (path == buf ||
        (dentry->d_name.len + 1) > (path - buf))
    {
        ret = -ENAMETOOLONG;
        goto out;
    }

    dlen = buf + buflen - path;
    memmove(buf, path, dlen);  
    buf += dlen - 1;

    if (buf[-1] != '/')
    {
        *buf++ = '/';
    }
    
    memcpy(buf, dentry->d_name.name, dentry->d_name.len + 1);
    ret = 0;
    
out:
    return ret;
}
#endif

/**
 * ccs_path_truncate - Check permission for truncate().
 *
 * @path: Pointer to "struct path".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_truncate(
        #if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
            struct path *path
        #else
            struct path *path,
            loff_t length,
            unsigned int time_attrs
        #endif
    )
{
    int ret;

	while (!original_security_ops.path_truncate);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)

    ret = securityhook_path_truncate(path,0,0);
#else

ret = securityhook_path_truncate(path,length,time_attrs);

#endif
    if (ret)
    {
        return ret;
    }
    
    return original_security_ops.path_truncate(
            #if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
                path
            #else
                path,
                length,
                time_attrs
            #endif
                );
}
#endif
#if 0
/**
 * ccs_path_rmdir - Check permission for rmdir().
 *
 * @dir:    Pointer to "struct path".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_rmdir(struct path *dir, struct dentry *dentry)
{
    int ret;

	while (!original_security_ops.path_rmdir);

    ret = securityhook_path_rmdir(dir, dentry);

    if (ret)
    {
        return ret;
    }
    
	return original_security_ops.path_rmdir(dir, dentry);
}

/**
 * ccs_path_unlink - Check permission for unlink().
 *
 * @dir:    Pointer to "struct path".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_path_unlink(struct path *dir, struct dentry *dentry)
{
    int ret;
    
	while (!original_security_ops.path_unlink);

    ret = securityhook_path_unlink(dir, dentry);

    if (ret)
    {
        return ret;
    }
        
	return original_security_ops.path_unlink(dir, dentry);
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
static int ccs_path_rename(struct path *old_dir, struct dentry *old_dentry,
			   struct path *new_dir, struct dentry *new_dentry)
{
    int ret;

	while (!original_security_ops.path_rename);

    ret = securityhook_path_rename(old_dir, old_dentry, new_dir, new_dentry);

    if (ret)
    {
        return ret;
    }
    
	return original_security_ops.path_rename(old_dir, old_dentry, new_dir,
						 new_dentry);                      
}

static int ccs_path_mkdir(struct path *dir, struct dentry *dentry,
            #if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
                umode_t mode
            #else
                int mode
            #endif
                )
{
    int ret;

	while (!original_security_ops.path_mkdir);

    ret = securityhook_path_mkdir(dir, dentry, mode);

    if (ret)
    {
        return ret;
    }
    
	return original_security_ops.path_mkdir(dir, dentry, mode);                      
}         

static int ccs_path_mknod(struct path *dir, struct dentry *dentry,
                #if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
                    umode_t mode,
                #else
                    int mode,
                #endif
				    unsigned int dev)
{
    int ret;

    while (!original_security_ops.path_mknod);

    ret = securityhook_path_mknod(dir, dentry, mode, dev);

    if (ret)
    {
        return ret;
    }
    
    return original_security_ops.path_mknod(dir, dentry, mode, dev);                      
} 
static int ccs_path_link(struct dentry *old_dentry,
         struct path *new_dir,
         struct dentry *new_dentry)
{
    int ret;

    //while (!original_security_ops.path_link);

    ret = securityhook_path_link(old_dentry, new_dir, new_dentry);

    if (ret)
    {
        return ret;
    }
    
    return original_security_ops.path_link(old_dentry, new_dir, new_dentry); 
}

static int ccs_path_symlink(struct path *path, struct dentry *dentry,
     const char *old_name)

{
    int ret;

    //while (!original_security_ops.path_symlink);


    ret = securityhook_path_symlink(path, dentry, old_name);

    if (ret)
    {
        return ret;
    }

    return original_security_ops.path_link(path, dentry, old_name);
}
/* liudan add file_permission for mac */
static int  ccs_file_permission(struct file *file, int mask)
{
     int ret;
     
     
     ret =  securityhook_file_permission(file, mask);
     
     
     if (ret)
     {
         return ret;
     }
     ret = original_security_ops.file_permission(file, mask);
     return ret;

}
#endif  //defined(CONFIG_SECURITY_PATH)

int wlSecMMapCheck(struct file * file, unsigned long reqprot,
			     unsigned long prot, unsigned long flags);
				 
int ccs_inode_alloc_security(struct inode *inode)
{
	int retval = 0;
	while (!original_security_ops.inode_alloc_security);
	retval = original_security_ops.inode_alloc_security(inode);  
	
	if(0==retval){
		insert_sys_inode(inode);
	}
	
	return retval;
}

void ccs_inode_free_security(struct inode *inode)
{
	while (!original_security_ops.inode_free_security);
	
	remove_sys_inode_ctx(inode);
	
	return original_security_ops.inode_free_security(inode); 
}

int ccs_inode_unlink(struct inode *dir, struct dentry *dentry)
{
    int ret;
    
	while (!original_security_ops.inode_unlink);
    
    ret = securityhook_inode_unlink(dir, dentry);
    
    if (ret < 0)
    {
        return ret;
    }
    
	return original_security_ops.inode_unlink(dir, dentry); 
}

int ccs_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
    int ret;
    
	while (!original_security_ops.inode_rmdir);
	
    ret = securityhook_inode_rmdir(dir, dentry);

    if (ret)
    {
        return ret;
    }
    
	return original_security_ops.inode_rmdir(dir, dentry); 
}

int ccs_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
            struct inode *new_dir,
            struct dentry *new_dentry)
{
    int ret;
    
	while (!original_security_ops.inode_rename);
	
    ret = securityhook_inode_rename(old_dir, old_dentry, new_dir, new_dentry);

    if (ret)
    {
        return ret;
    }
    
	return original_security_ops.inode_rename(old_dir, old_dentry, new_dir, new_dentry); 
}

int ccs_inode_mkdir(struct inode *dir, struct dentry *dentry,
                        #if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
                            umode_t mode
                        #else
                            int mode
                        #endif
                            )
{
    int ret;

    while (!original_security_ops.inode_mkdir);

    ret = securityhook_inode_mkdir(dir, dentry, mode);

    if (ret)
    {
        return ret;
    }

    return original_security_ops.inode_mkdir(dir, dentry, mode); 
}

int ccs_inode_mknod(struct inode *dir, struct dentry *dentry,
                       #if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
                           umode_t mode,
                       #else
                           int mode,
                       #endif
				           dev_t dev)
{
    int ret;

    while (!original_security_ops.inode_mknod);

    ret = securityhook_inode_mknod(dir, dentry, mode, dev);

    if (ret)
    {
        return ret;
    }

    return original_security_ops.inode_mknod(dir, dentry, mode, dev); 
}

int ccs_inode_create(struct inode *dir,
                             struct dentry *dentry,  
                         #if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 0, 0)
                             umode_t mode
                         #else
                             int mode
                        #endif
                             )
{
    int ret;
    
    ret = securityhook_inode_create(dir, dentry, mode);

    if (ret)
    {
        return ret;
    }

    return original_security_ops.inode_create(dir, dentry, mode); 
}     
/* soft link */
int ccs_inode_symlink(struct inode *dir, struct dentry *dentry,
			    const char *old_name)
{
    int ret;
 
    ret = securityhook_inode_symlink(dir, dentry, old_name);

     if (ret)
     {
         return ret;
     }

    return original_security_ops.inode_symlink(dir, dentry, old_name); 
} 
/* hardlink */
int ccs_inode_link(struct dentry *old_dentry, struct inode *dir,
			 struct dentry *new_dentry)
{
    int ret;
 
    ret = securityhook_inode_link(old_dentry, dir, new_dentry);

     if (ret)
     {
         return ret;
     }

    return original_security_ops.inode_link(old_dentry, dir, new_dentry); 
} 
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
    return original_security_ops.inode_permission(inode, nd);
#endif
 }
int ccs_file_permission (struct file *file, int mask)
{
    int ret;

    ret = securityhook_file_permission(file, mask);

    if (ret)
    {
      return ret;
    }

    return original_security_ops.file_permission(file, mask);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
		static int ccs_mmap_file(struct file *file,
			  unsigned long reqprot, unsigned long prot,
			  unsigned long flags)	
	#else
		static int ccs_file_mmap(struct file *file, unsigned long reqprot, unsigned long prot,
					  unsigned long flags, unsigned long addr,
					  unsigned long addr_only)		
	#endif
#else			  
static int ccs_file_mmap(struct file * file, unsigned long reqprot,
			     unsigned long prot, unsigned long flags)
#endif	
{
	int retval = 0;
	
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
		while (!original_security_ops.mmap_file);
	#else
		while (!original_security_ops.file_mmap);
	#endif
    {
          retval = securityhook_file_mmap(file, reqprot, prot, flags);

        if (retval)
        {
            return retval;
        }
    }
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 30)
	
		/*
		3.4
		int (*file_mmap) (struct file *file,
			  unsigned long reqprot, unsigned long prot,
			  unsigned long flags, unsigned long addr,
			  unsigned long addr_only);
		
		3.16
		int (*mmap_file) (struct file *file,
			  unsigned long reqprot, unsigned long prot,
			  unsigned long flags);
		*/  
		#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
			retval = original_security_ops.mmap_file(file, reqprot, prot, flags); 
		#else
			retval = original_security_ops.file_mmap(file, reqprot, prot, flags, addr, addr_only); 
		#endif
	#else
		retval = original_security_ops.file_mmap(file, reqprot, prot, flags);
	#endif	

	return retval;
}

#include <linux/mman.h>

 int ccs_bprm_set_creds(struct linux_binprm *bprm)
{
	int ret;

    ret = securityhook_bprm_set_creds(bprm);

    if (ret)
    {
        return ret;
    }

	return original_security_ops.bprm_set_creds(bprm);
}

 static ssize_t __xkernel_write(struct file *file, const char *buf, size_t count,
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

/*
void dump_user_page(char *page)
{
    struct file * fp = NULL;
    
    fp = __filp_open_ptr("/var/log/tsg_page", O_SYNC | O_RDWR | O_CREAT | O_TRUNC, 0);
    
    if (IS_ERR(fp)) {
        KTsgDebug(KERN_INFO "[-] ccs_bprm_check_security argv_exec failure\n");
        return;
    }

    __xkernel_write(fp, page, PAGE_SIZE, 0);
    
    filp_close(fp, NULL);
}


static inline int arg_len(char *argv, int maxlen)
{
    int len = 0;

    while (*argv++ && len < maxlen)
    {
        len++;
    }

    return len;
}
*/

int ccs_bprm_check_security(struct linux_binprm *bprm)
{
    int ret;
    
    ret = securityhook_bprm_check_security(bprm);

    if (ret < 0)
    {
        return ret;
    }

    return original_security_ops.bprm_check_security(bprm);
}
#if 0

#define ccs_inode_permission __hk_inode_permission
extern int __hk_inode_permission(struct inode *inode, int mask);


int ccs_inode_permission(struct inode *inode, int mask)
{
    int retval = 0;
    
    /*
        tsg_task_path ??????????????
        ?????¡§??i_ino????????
        ?¡À???????????¡À?¨°????????????inode??????????????????????????¡À¨ª
    */

    char *task_ptr ,*task_buf;
    char inod_num[256];

    memset(inod_num, 0 , 256);
    int2str(inode->i_ino,inod_num);
    if(getSelfProtectionFlag()){
        if(xProtectLookupFile(inod_num)){
            task_buf = (char *)kmalloc(PAGE_SIZE ,GFP_KERNEL);
            if(!task_buf){
                goto out;
            }

            memset(task_buf ,0x00 ,PAGE_SIZE);
    
            task_ptr = tsg_task_path(current ,task_buf ,PAGE_SIZE);
            if(!task_ptr){
                goto out;   
            }
            if(!strcmp(task_ptr ,"/TSG/TsgService") ||
                !strcmp(task_ptr ,"/TSG/tsg")){
                goto out;
            }
        
            if(!(mask & MAY_WRITE) && (mask & MAY_EXEC)){
                goto out;
            }
            if(!((mask & MAY_WRITE) || (mask & MAY_EXEC))){
                goto out;
            }
            retval = -1;
        }
    }

    if ((mask & MAY_WRITE) && 
        S_ISDIR(inode->i_mode) &&
        lookup_protect_inode(inode))
    {
        retval = -EACCES;
    }

out:
    if(task_buf){
        kfree(task_buf);
    }
    return retval;
}
#endif

/*
 * Why not to copy all operations by "original_security_ops = *ops" ?
 * Because copying byte array is not atomic. Reader checks
 * original_security_ops.op != NULL before doing original_security_ops.op().
 * Thus, modifying original_security_ops.op has to be atomic.
 */
#define swap_security_ops(op)				\
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
#if 1
	/* Various permission checker. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	swap_security_ops(file_open);
#else   //LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0)
	swap_security_ops(dentry_open);
#endif
#endif
#if defined(CONFIG_SECURITY_PATH)
    swap_security_ops(path_truncate);
#endif
#if 1
#if defined(xCONFIG_SECURITY_PATH)
	swap_security_ops(path_rmdir);
	swap_security_ops(path_unlink); 
	swap_security_ops(path_rename); 
    swap_security_ops(path_mkdir);
    swap_security_ops(path_mknod);
/* liudan add it for mac symlink  */    
    swap_security_ops(path_link);
    swap_security_ops(path_symlink);

    
#endif  //defined(CONFIG_SECURITY_PATH)

    //swap_security_ops(inode_permission);
    swap_security_ops(file_permission);

    swap_security_ops(inode_rmdir);
    swap_security_ops(inode_unlink);
    
    swap_security_ops(inode_rename);
    swap_security_ops(inode_mkdir);
    swap_security_ops(inode_mknod);
    swap_security_ops(inode_create);
 
    swap_security_ops(inode_symlink);
    swap_security_ops(inode_link);
    swap_security_ops(inode_permission);
//	swap_security_ops(inode_alloc_security);
//	swap_security_ops(inode_free_security);

#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
	swap_security_ops(mmap_file);
#else   //LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
	swap_security_ops(file_mmap);
#endif
#if 1
    swap_security_ops(bprm_set_creds);
    swap_security_ops(bprm_check_security);    
#endif
	return;
}

static void ccs_restore_security_ops(void)
{
#if 1
	/* Various permission checker. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0)
	rwap_security_ops(file_open);
#else   //LINUX_VERSION_CODE < KERNEL_VERSION(3, 5, 0)
	rwap_security_ops(dentry_open);
#endif
#endif

#if defined(CONFIG_SECURITY_PATH)
    rwap_security_ops(path_truncate);
#endif
#if 1
#if defined(xCONFIG_SECURITY_PATH)
	rwap_security_ops(path_rmdir);
	rwap_security_ops(path_unlink); 
	rwap_security_ops(path_rename); 
    rwap_security_ops(path_mkdir);
    rwap_security_ops(path_mknod);

    
/* liudan add it for mac symlink  */    
    rwap_security_ops(path_link);
    rwap_security_ops(path_symlink);

    
#endif  //defined(CONFIG_SECURITY_PATH)

    //rwap_security_ops(inode_permission);
    rwap_security_ops(file_permission);

    rwap_security_ops(inode_rmdir);
    rwap_security_ops(inode_unlink);
    rwap_security_ops(inode_rename);
    rwap_security_ops(inode_mkdir);
    rwap_security_ops(inode_mknod);
    rwap_security_ops(inode_create);
 
    rwap_security_ops(inode_symlink);
    rwap_security_ops(inode_link);
    rwap_security_ops(inode_permission);

 
//    rwap_security_ops(inode_alloc_security);
//    rwap_security_ops(inode_free_security);
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 7, 0)
	rwap_security_ops(mmap_file);
#else   //LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
	rwap_security_ops(file_mmap);
#endif  //LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)

#if 1
    rwap_security_ops(bprm_set_creds);
    rwap_security_ops(bprm_check_security);
#endif
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
	struct security_operations *ops = probe_security_ops();
	//struct security_operations *ops = __get_security_ops_ptr();
    KTsgDebug(KERN_INFO "probe_security_ops ccs_init %p\n", ops);
	ops_orig = ops;
	if (!ops)
		goto out;
    
	ccs_update_security_ops(ops);
	KTsgDebug(KERN_INFO "AKARI: 1.0.35   2015/11/11\n");
	KTsgDebug(KERN_INFO
	       "Access Keeping And Regulating Instrument registered.\n");
	return 0;
out:
	KTsgDebug(KERN_INFO
	       "Can't get security_operations-----------------------------\n");
	return -EINVAL;
}

int ccs_destroy(void)
{
	ccs_restore_security_ops();
	KTsgDebug(KERN_INFO "Unregister TsgMod and defender close!\n");

	return 0;
}


// -- module_init(ccs_init);
// -- MODULE_LICENSE("GPL");
 
