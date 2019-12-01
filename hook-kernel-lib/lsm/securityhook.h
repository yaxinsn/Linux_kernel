#ifndef _SECURITYHOOK_H_
#define _SECURITYHOOK_H_
#include <linux/version.h>
#include <linux/security.h>

#ifdef CONFIG_SECURITY_PATH
int securityhook_path_truncate(struct path *path, loff_t length,
                   unsigned int time_attrs);

#endif
#if 0
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)

extern int securityhook_path_mkdir(struct path *dir, struct dentry *dentry,
                umode_t mode);
extern int securityhook_path_mknod(struct path *dir, struct dentry *dentry,
				      umode_t mode, unsigned int dev);
#else
extern int securityhook_path_mkdir(const struct path *dir, struct dentry *dentry,
				umode_t mode);
extern int securityhook_path_mknod(const struct path *dir, struct dentry *dentry,
				      umode_t mode, unsigned int dev);
#endif

extern int securityhook_path_rmdir(struct path *dir, struct dentry *dentry);
extern int securityhook_path_unlink(struct path *dir, struct dentry *dentry);
extern int securityhook_path_rename(struct path *old_dir, struct dentry *old_dentry,
			   struct path *new_dir, struct dentry *new_dentry);

/* liudan add for mac: */
extern int securityhook_path_link(struct dentry *old_dentry, struct path *new_dir,
		       struct dentry *new_dentry);
extern int  securityhook_path_symlink(struct path *path, struct dentry *dentry,
                            const char *old_name);
/* liudan add for mac: */

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
extern  int  securityhook_file_permission(struct file *file, int mask);
#endif



extern int securityhook_inode_alloc_security(struct inode *inode);
extern void securityhook_inode_free_security(struct inode *inode);
int securityhook_inode_mkdir(struct inode *dir, struct dentry *dentry,
            umode_t mode);
extern int securityhook_inode_rmdir(struct inode *dir, struct dentry *dentry);
extern int securityhook_inode_unlink(struct inode *dir, struct dentry *dentry);
extern int securityhook_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
                struct inode *new_dir,
                struct dentry *new_dentry
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
                ,unsigned int flags
#endif
);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
extern int securityhook_inode_permission(struct inode *inode, int mask);
#else
extern  int securityhook_inode_permission (struct inode *inode, int mask, struct nameidata *nd);
#endif

extern int securityhook_inode_permission_by_nameidata( struct nameidata *nd, int mask);

extern int securityhook_inode_mknod(struct inode *dir, struct dentry *dentry,
				umode_t mode, dev_t dev);
extern int securityhook_inode_create(struct inode *dir,
                struct dentry *dentry,
            #if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
                umode_t mode
            #else
                int mode
            #endif
        );
extern int securityhook_inode_symlink(struct inode *dir, struct dentry *dentry,
			    const char *old_name);

extern int securityhook_inode_link(struct dentry *old_dentry, struct inode *dir,
             struct dentry *new_dentry);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
extern int securityhook_file_open(struct file *file, const struct cred *cred);
#else
extern int securityhook_file_open(struct file *file);

#endif
extern int securityhook_bprm_set_creds(struct linux_binprm *bprm);
extern int securityhook_bprm_check_security(struct linux_binprm *bprm);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 28) // check-linux-src haozelong for redhat5.4
extern int securityhook_bprm_set_securit(struct linux_binprm *bprm);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32) || !defined (CONFIG_SECURITY_PATH)
int securityhook_do_truncate_hook(struct dentry *dentry, loff_t length,
                   unsigned int time_attrs,struct file *filp);
#endif


int securityhook_file_mmap(struct file *file,
			  unsigned long reqprot, unsigned long prot,
			  unsigned long flags);
typedef struct secHookStat_st
{
    unsigned long maxCycle;
    unsigned long averageCycle;
}secHookStat;
typedef struct secHookTable_st
{

    int (*inode_alloc_security) (struct inode *inode);
    void (*inode_free_security) (struct inode *inode);
    int (*inode_init_security) (struct inode *inode, struct inode *dir,
                    char **name, void **value, size_t *len);


int (*inode_create) (struct inode *dir, struct dentry *dentry,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
        umode_t
#else
        int
#endif
        mode);



    int (*inode_link) (struct dentry *old_dentry,
               struct inode *dir, struct dentry *new_dentry);
    int (*inode_unlink) (struct inode *dir, struct dentry *dentry);
    int (*inode_symlink) (struct inode *dir,
                  struct dentry *dentry, const char *old_name);


    int (*inode_mkdir) (struct inode *dir, struct dentry *dentry,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
        umode_t
#else
        int
#endif
    mode);

    int (*inode_rmdir) (struct inode *dir, struct dentry *dentry);


int (*inode_mknod) (struct inode *dir, struct dentry *dentry,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 3, 0)
            umode_t
#else
            int
#endif
             mode,  dev_t dev);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 27)
    int (*inode_permission) (struct inode *inode, int mask);
#else
    int (*inode_permission) (struct inode *inode, int mask, struct nameidata *nd);
#endif


    int (*inode_rename) (struct inode *old_dir, struct dentry *old_dentry,
                 struct inode *new_dir, struct dentry *new_dentry);



	int (*file_permission) (struct file *file, int mask);
	int (*dentry_open) (struct file *file);

    int (*_dentry_permission)( struct dentry* d, int mask); //不是security_operations的标准回调函数。
#ifdef CONFIG_SECURITY_PATH
    int (*path_unlink)(struct path *dir, struct dentry *dentry);
    int (*path_mkdir)(struct path *dir, struct dentry *dentry, int mode);
    int (*path_rmdir)(struct path *dir, struct dentry *dentry);
    int (*path_mknod)(struct path *dir, struct dentry *dentry, int mode,
                unsigned int dev);
    int (*path_truncate)(struct path *path, loff_t length,
                   unsigned int time_attrs);
    int (*path_symlink)(struct path *dir, struct dentry *dentry,
                  const char *old_name);
    int (*path_link)(struct dentry *old_dentry, struct path *new_dir,
                   struct dentry *new_dentry);
    int (*path_rename)(struct path *old_dir, struct dentry *old_dentry,
                 struct path *new_dir, struct dentry *new_dentry);
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 32) || !defined (CONFIG_SECURITY_PATH)
    int (*do_truncate_hook)(struct dentry *dentry, loff_t length,
                   unsigned int time_attrs,struct file *filp);
#endif
    int (*file_mmap)(struct file *file,
                  unsigned long reqprot, unsigned long prot,
                  unsigned long flags);

    char *HookName;

    //secHookStat	secHookStatic[30];
}secHookTable;

extern secHookTable g_secHookTableMac;

extern secHookTable g_secHookTableFileProtect;
extern  secHookTable g_secHookTableSelfProtect;
extern  secHookTable g_secHookTableUSBDisk;
extern  secHookTable g_secHookTableWlProtect;

#endif
