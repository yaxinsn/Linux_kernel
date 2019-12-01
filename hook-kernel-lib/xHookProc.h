#ifndef __XHOOKPROC_H__
#define __XHOOKPROC_H__

#include "tsg_mount_kernel.h"
#include "kernsymbol.h"
#include "linux/genhd.h"

typedef long (* do_rmdir_ptr)(int dfd, const char __user *pathname);
typedef int (* vfs_unlink_ptr)(struct inode *dir, struct dentry *dentry);
typedef long (* do_unlinkat_ptr)(int dfd, const char __user * pathname);
typedef asmlinkage long (* sys_link_ptr)(const char __user *oldname, const char __user *newname);
typedef asmlinkage long (* sys_unlink_ptr)(const char __user *pathname);
typedef asmlinkage long (* sys_linkat_ptr)(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, int flags);
typedef asmlinkage long (* sys_renameat_ptr)(int olddfd, const char __user * oldname, int newdfd, const char __user * newname);
typedef asmlinkage long (* sys_rename_ptr)(const char __user * oldname, const char __user * newname);
typedef asmlinkage long (* sys_renameat2_ptr)(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, unsigned int flags);

typedef asmlinkage long (* sys_kill_ptr)(int pid, int sig);
typedef asmlinkage long (* sys_tgkill_ptr)(int tgid, int pid, int sig);
typedef asmlinkage long (* sys_tkill_ptr)(int pid, int sig);
typedef asmlinkage int (*vfs_write_ptr)(struct file *file, const char __user *buf, size_t count, loff_t *pos);

// -- _do_fork
typedef long (* xdo_fork_ptr)(unsigned long clone_flags,
	      unsigned long stack_start,
	      unsigned long stack_size,
	      int __user *parent_tidptr,
	      int __user *child_tidptr,
	      unsigned long tls);

typedef long (* do_fork_ptr)(unsigned long clone_flags, unsigned long stack_start, struct pt_regs *regs, unsigned long stack_size, int __user *parent_tidptr, int __user *child_tidptr);
typedef void (* do_exit_ptr)(long code);

typedef int (* do_execve_ptr)(const char *filename,
	const char __user *const __user *__argv,
	const char __user *const __user *__envp,
	struct pt_regs *regs);


typedef int (* bprm_mm_init_ptr)(struct linux_binprm *bprm); // -- vs do_execve;
typedef struct task_struct * (* copy_process_ptr)(unsigned long clone_flags,
					unsigned long stack_start,
					struct pt_regs *regs,
					unsigned long stack_size,
					int __user *child_tidptr,
					struct pid *pid,
					int trace); // -- vs do_fork

typedef int (*do_mmap_file_ptr)(struct file *file, unsigned long rqprot ,unsigned long prot,
                        unsigned long flags);
typedef void (* exit_signals_ptr) (struct task_struct *tsk); // -- vs do_exit

typedef int ( *do_truncate_ptr)(struct dentry *dentry, loff_t length, unsigned int time_attrs,
	struct file *filp);


typedef struct file * (*do_filp_open_ptr)(int dfd, const char *pathname, int open_flag, int mode, int acc_mode);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
typedef struct file * (*filp_open_ptr)(const char *filename, int flags, umode_t mode);
#else
typedef struct file * (*filp_open_ptr)(const char *filename, int flags, int mode);
#endif

typedef long ( * do_sys_open_ptr)(int dfd, const char __user *filename, int flags, int mode);
typedef int (* filp_close_ptr)(struct file *filp, fl_owner_t id);

// -- fsnotify在 2.6.21中不存在
typedef void (* fsnotify_ptr)(struct inode *to_tell, __u32 mask, void *data, int data_is, const char *file_name, u32 cookie);

typedef asmlinkage long (* sys_init_module_ptr)(void __user *umod, unsigned long len, const char __user *uargs);
// -- asmlinkage long sys_init_module(void __user *umod, unsigned long len, const char __user *uargs);

typedef asmlinkage long (* sys_getcwd_ptr)(char __user *buf, unsigned long size);
asmlinkage long sys_getcwd(char __user *buf, unsigned long size);


typedef long (*sys_mount_ptr)(char *dev_name, char *dir_name, char *type_page,
		  unsigned long flags, void *data_page);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 27)
typedef struct gendisk *(*get_gendisk_ptr)(dev_t dev, int *part);
extern get_gendisk_ptr  __get_gendisk_ptr;

#endif

typedef int (*sys_inode_permission_ptr)(struct inode *inode, int mask);
typedef asmlinkage long (*sys_readlink_ptr)(const char __user *path,
				char __user *buf, int bufsiz);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
typedef struct file *(*get_mm_exe_file_ptr)(struct mm_struct *mm);
#endif

#if 0
typedef asmlinkage long (*sys_link_ptr)(const char __user *oldname,
                const char __user *newname);
typedef asmlinkage long (*sys_creat_ptr)(const char __user *pathname, umode_t mode);
typedef asmlinkage long (*sys_access_ptr)(const char __user *filename, int mode);
typedef asmlinkage long (*sys_truncate_ptr)(const char __user *path, long length);
typedef asmlinkage long (*sys_ftruncate_ptr)(unsigned int fd, unsigned long length);
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 2, 0)
typedef char *(*dentry_path_ptr)(struct dentry *dentry, char *buf, int buflen);
typedef void (*put_mnt_ns_ptr)(struct mnt_namespace *ns);

#endif
void wlHooksModuleDestroy(void);
int wlHooksModuleInit(void);

extern do_unlinkat_ptr __do_unlinkat_ptr;
extern do_fork_ptr __do_fork_ptr; // -- &do_fork; // -- do_fork 没有输出
extern do_exit_ptr __do_exit_ptr;
extern do_execve_ptr __do_execve_ptr; // = do_execve;
extern xdo_fork_ptr __xdo_fork_ptr;

extern bprm_mm_init_ptr __bprm_mm_init_ptr;
extern exit_signals_ptr __exit_signals_ptr;
extern copy_process_ptr __copy_process_ptr;

// -- do_filp_open_ptr __do_filp_open_ptr = do_filp_open;
extern filp_open_ptr __filp_open_ptr;
extern do_sys_open_ptr __do_sys_open_ptr; // -- &do_sys_open;
// -- fsnotify_ptr __fsnotify_ptr = &fsnotify;
extern filp_close_ptr __filp_close_ptr;
extern sys_init_module_ptr __sys_init_module_ptr;// -- &sys_init_module;
extern sys_renameat_ptr __sys_renameat_ptr;
extern sys_rename_ptr __sys_rename_ptr;
extern sys_kill_ptr __sys_kill_ptr;
extern sys_tgkill_ptr __sys_tgkill_ptr;
extern sys_tkill_ptr __sys_tkill_ptr;
extern do_unlinkat_ptr __do_unlinkat_ptr;
extern filp_open_ptr __filp_open_ptr;
extern do_sys_open_ptr __do_sys_open_ptr; // -- &do_sys_open;
extern filp_close_ptr __filp_close_ptr;
extern sys_renameat_ptr __sys_renameat_ptr;
extern sys_getcwd_ptr __sys_getcwd_ptr;
extern do_truncate_ptr __do_truncate_ptr;
extern do_rmdir_ptr __do_rmdir_ptr;
extern vfs_write_ptr __vfs_write_ptr;
extern sys_readlink_ptr __readlink_ptr;

#if 0
extern sys_link_ptr __sys_link_ptr;
extern sys_creat_ptr __sys_creat_ptr;
extern sys_access_ptr __sys_access_ptr;
extern sys_truncate_ptr __sys_truncate_ptr;
extern sys_ftruncate_ptr __sys_ftruncate_ptr;
#endif
//mount
extern sys_mount_ptr __sys_mount_ptr;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
extern get_mm_exe_file_ptr __get_mm_exe_file_ptr;
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(3, 2, 0)
extern dentry_path_ptr __dentry_path_ptr;
extern put_mnt_ns_ptr  __put_mnt_ns_ptr;

#endif
extern int privilege_task(void);
extern int privilege_task2(struct task_struct *task);
void load_symbol_log(void *ptr, char *symbol);

#define load_kernel_symbol_ptr(ptr, type, symbol) \
    ptr = (type)kGetSymbol(symbol);    \
    load_symbol_log(ptr, symbol)

#endif
