/*
 * lsm.c
 *
 * Copyright (C) 2010-2015  Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
 *
 * Version: 1.0.35   2015/11/11
 */

#include "internal.h"
#include "probe.h"

/* Prototype definition. */

 
/* Function pointers originally registered by register_security(). */
static struct security_operations original_security_ops /* = *security_ops; */;

 

/**
 * ccs_inode_mknod - Check permission for mknod().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount". Maybe NULL.
 * @mode:   Create mode.
 * @dev:    Device major/minor number.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_mknod(struct inode *dir, struct dentry *dentry,
			   struct vfsmount *mnt, int mode, dev_t dev)
{
	int rc = ccs_mknod_permission(dentry, mnt, mode, dev);
	if (rc)
		return rc;
	while (!original_security_ops.inode_mknod);
	return original_security_ops.inode_mknod(dir, dentry, mnt, mode, dev);
}

/**
 * ccs_inode_mkdir - Check permission for mkdir().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount". Maybe NULL.
 * @mode:   Create mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_mkdir(struct inode *dir, struct dentry *dentry,
			   struct vfsmount *mnt, int mode)
{
	int rc = ccs_mkdir_permission(dentry, mnt, mode);
	if (rc)
		return rc;
	while (!original_security_ops.inode_mkdir);
	return original_security_ops.inode_mkdir(dir, dentry, mnt, mode);
}

/**
 * ccs_inode_rmdir - Check permission for rmdir().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount". Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_rmdir(struct inode *dir, struct dentry *dentry,
			   struct vfsmount *mnt)
{
	int rc = ccs_rmdir_permission(dentry, mnt);
	if (rc)
		return rc;
	while (!original_security_ops.inode_rmdir);
	return original_security_ops.inode_rmdir(dir, dentry, mnt);
}

/**
 * ccs_inode_unlink - Check permission for unlink().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount". Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_unlink(struct inode *dir, struct dentry *dentry,
			    struct vfsmount *mnt)
{
	int rc = ccs_unlink_permission(dentry, mnt);
	if (rc)
		return rc;
	while (!original_security_ops.inode_unlink);
	return original_security_ops.inode_unlink(dir, dentry, mnt);
}

/**
 * ccs_inode_symlink - Check permission for symlink().
 *
 * @dir:      Pointer to "struct inode".
 * @dentry:   Pointer to "struct dentry".
 * @mnt:      Pointer to "struct vfsmount". Maybe NULL.
 * @old_name: Content of symbolic link.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_symlink(struct inode *dir, struct dentry *dentry,
			     struct vfsmount *mnt, const char *old_name)
{
	int rc = ccs_symlink_permission(dentry, mnt, old_name);
	if (rc)
		return rc;
	while (!original_security_ops.inode_symlink);
	return original_security_ops.inode_symlink(dir, dentry, mnt, old_name);
}

/**
 * ccs_inode_rename - Check permission for rename().
 *
 * @old_dir:    Pointer to "struct inode".
 * @old_dentry: Pointer to "struct dentry".
 * @old_mnt:    Pointer to "struct vfsmount". Maybe NULL.
 * @new_dir:    Pointer to "struct inode".
 * @new_dentry: Pointer to "struct dentry".
 * @new_mnt:    Pointer to "struct vfsmount". Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_rename(struct inode *old_dir, struct dentry *old_dentry,
			    struct vfsmount *old_mnt, struct inode *new_dir,
			    struct dentry *new_dentry,
			    struct vfsmount *new_mnt)
{
	int rc = ccs_rename_permission(old_dentry, new_dentry, new_mnt);
	if (rc)
		return rc;
	while (!original_security_ops.inode_rename);
	return original_security_ops.inode_rename(old_dir, old_dentry, old_mnt,
						  new_dir, new_dentry,
						  new_mnt);
}

/**
 * ccs_inode_link - Check permission for link().
 *
 * @old_dentry: Pointer to "struct dentry".
 * @old_mnt:    Pointer to "struct vfsmount". Maybe NULL.
 * @dir:        Pointer to "struct inode".
 * @new_dentry: Pointer to "struct dentry".
 * @new_mnt:    Pointer to "struct vfsmount". Maybe NULL.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_link(struct dentry *old_dentry, struct vfsmount *old_mnt,
			  struct inode *dir, struct dentry *new_dentry,
			  struct vfsmount *new_mnt)
{
	int rc = ccs_link_permission(old_dentry, new_dentry, new_mnt);
	if (rc)
		return rc;
	while (!original_security_ops.inode_link);
	return original_security_ops.inode_link(old_dentry, old_mnt, dir,
						new_dentry, new_mnt);
}

/**
 * ccs_inode_create - Check permission for creat().
 *
 * @dir:    Pointer to "struct inode".
 * @dentry: Pointer to "struct dentry".
 * @mnt:    Pointer to "struct vfsmount". Maybe NULL.
 * @mode:   Create mode.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_inode_create(struct inode *dir, struct dentry *dentry,
			    struct vfsmount *mnt, int mode)
{
	int rc = ccs_mknod_permission(dentry, mnt, mode, 0);
	if (rc)
		return rc;
	while (!original_security_ops.inode_create);
	return original_security_ops.inode_create(dir, dentry, mnt, mode);
}
 

/*
 * Why not to copy all operations by "original_security_ops = *ops" ?
 * Because copying byte array is not atomic. Reader checks
 * original_security_ops.op != NULL before doing original_security_ops.op().
 * Thus, modifying original_security_ops.op has to be atomic.
 */
#define swap_security_ops(op)						\
	original_security_ops.op = ops->op; smp_wmb(); ops->op = ccs_##op;

/**
 * ccs_update_security_ops - Overwrite original "struct security_operations".
 *
 * @ops: Pointer to "struct security_operations".
 *
 * Returns nothing.
 */
static void ccs_update_security_ops(struct security_operations *ops)
{
 
	swap_security_ops(inode_mknod);
	swap_security_ops(inode_mkdir);
	swap_security_ops(inode_rmdir);
	swap_security_ops(inode_unlink);
	swap_security_ops(inode_symlink);
	swap_security_ops(inode_rename);
	swap_security_ops(inode_link);
	swap_security_ops(inode_create);
}

#undef swap_security_ops

/**
 * ccs_init - Initialize this module.
 *
 * Returns 0 on success, negative value otherwise.
 */
static int ccs_init(void)
{
	struct security_operations *ops = probe_security_ops();
	if (!ops)
		goto out;
 
	ccs_update_security_ops(ops);
	KTsgDebug(KERN_INFO "AKARI: 1.0.35   2015/11/11\n");
	KTsgDebug(KERN_INFO
	       "Access Keeping And Regulating Instrument registered.\n");
	return 0;
out:
	return -EINVAL;
}

module_init(ccs_init);
MODULE_LICENSE("GPL");
 