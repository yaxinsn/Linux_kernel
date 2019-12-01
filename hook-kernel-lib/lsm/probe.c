/*
 * probe.c
 *
 * Copyright (C) 2010-2013  Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
 *
 * Functions in this file are doing runtime address resolution based on byte
 * code comparison in order to allow LKM-based LSM modules to access built-in
 * functions and variables which are not exported to LKMs.
 * Since functions in this file are assuming that using identical source code,
 * identical kernel config and identical compiler generates identical byte code
 * output, functions in this file may not work on some architectures and/or
 * environments.
 *
 * This file is used by AKARI and CaitSith. This file will become unnecessary
 * when LKM-based LSM module comes back and TOMOYO 2.x becomes a LKM-based LSM
 * module.
 */

#include "probe.h"
#ifndef WIN32
#include <linux/spinlock.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24) || LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 19) // no check-linux-src haozelong for redhat5.4

/**
 * probe_kernel_read - Wrapper for kernel_read().
 *
 * @file:   Pointer to "struct file".
 * @offset: Starting position.
 * @addr:   Buffer.
 * @count:  Size of @addr.
 *
 * Returns return value from kernel_read().
 */
static int probe_kernel_read(struct file *file, unsigned long offset,
				    char *addr, unsigned long count)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 8)
	/*
	 * I can't use kernel_read() because seq_read() returns -EPIPE
	 * if &pos != &file->f_pos .
	 */
	mm_segment_t old_fs;
	unsigned long pos = file->f_pos;
	int result;
	file->f_pos = offset;
	old_fs = get_fs();
	set_fs(get_ds());
	result = vfs_read(file, (void __user *)addr, count, &file->f_pos);
	set_fs(old_fs);
	file->f_pos = pos;
	return result;
#else
	return kernel_read(file, offset, addr, count);
#endif
}

/**
 * probe_find_symbol - Find function's address from /proc/kallsyms .
 *
 * @keyline: Function to find.
 *
 * Returns address of specified function on success, NULL otherwise.
 */
static void *probe_find_symbol(const char *keyline)
{
	struct file *file = NULL;
	char *buf;
	unsigned long entry = 0;
	{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18)
		struct file_system_type *fstype = get_fs_type("proc");
		struct vfsmount *mnt = vfs_kern_mount(fstype, 0, "proc", NULL);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
		struct file_system_type *fstype = NULL;
		struct vfsmount *mnt = do_kern_mount("proc", 0, "proc", NULL);
#else
		struct file_system_type *fstype = get_fs_type("proc");
		struct vfsmount *mnt = kern_mount(fstype);
#endif
		struct dentry *root;
		struct dentry *dentry;
		/*
		 * We embed put_filesystem() here because it is not exported.
		 */
		if (fstype)
			module_put(fstype->owner);
		if (IS_ERR(mnt))
			goto out;
		root = dget(mnt->mnt_root);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
    inode_lock(root->d_inode);
//        down_write(&root->d_inode->i_rwsem);
        dentry = lookup_one_len("kallsyms", root, 8);
          inode_unlock(root->d_inode);
        //up_write(&root->d_inode->i_rwsem);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 16)
		mutex_lock(&root->d_inode->i_mutex);
		dentry = lookup_one_len("kallsyms", root, 8);
		mutex_unlock(&root->d_inode->i_mutex);
#else
		down(&root->d_inode->i_sem);
		dentry = lookup_one_len("kallsyms", root, 8);
		up(&root->d_inode->i_sem);
#endif
		dput(root);
		if (IS_ERR(dentry))
			mntput(mnt);
		else {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 6, 0)
			//struct path path = { mnt, dentry };
			struct path path;

            path.mnt = mnt;
            path.dentry = dentry;
			file = dentry_open(&path, O_RDONLY, current_cred());
#else
			file = dentry_open(dentry, mnt, O_RDONLY
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 29)
					   , current_cred()
#endif
					   );
#endif
		}
	}
	if (IS_ERR(file) || !file)
		goto out;
	buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (buf) {
		int len;
		int offset = 0;
		while ((len = probe_kernel_read(file, offset, buf,
						PAGE_SIZE - 1)) > 0) {
			char *cp;
			buf[len] = '\0';
			cp = strrchr(buf, '\n');
			if (!cp)
				break;
			*(cp + 1) = '\0';
			offset += strlen(buf);
			cp = strstr(buf, keyline);
			if (!cp)
				continue;
			*cp = '\0';
			while (cp > buf && *(cp - 1) != '\n')
				cp--;
			entry = simple_strtoul(cp, NULL, 16);
			break;
		}
		kfree(buf);
	}
	filp_close(file, NULL);
out:
	return (void *) entry;
}

#endif

#if defined(LSM_HOOK_INIT)

/*
 * Dummy variable for finding location of
 * "struct security_hook_heads security_hook_heads".
 */
struct security_hook_heads probe_dummy_security_hook_heads;

/**
 * probe_security_bprm_committed_creds - Dummy function which does identical to security_bprm_committed_creds() in security/security.c.
 *
 * @bprm: Pointer to "struct linux_binprm".
 *
 * Returns nothing.
 */
void probe_security_bprm_committed_creds(struct linux_binprm *bprm)
{
	do {
		struct security_hook_list *p;
		list_for_each_entry(p, &probe_dummy_security_hook_heads.
				    bprm_committed_creds, list)
			p->hook.bprm_committed_creds(bprm);
	} while (0);
}

#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24) && defined(CONFIG_SECURITY)

/*
 * Dummy variable for finding address of
 * "struct security_operations *security_ops".
 */
#include <linux/security.h>
static struct security_operations *probe_dummy_security_ops;

/**
 * probe_security_file_alloc - Dummy function which does identical to security_file_alloc() in security/security.c.
 *
 * @file: Pointer to "struct file".
 *
 * Returns return value from security_file_alloc().
 */
static int probe_security_file_alloc(struct file *file)
{
	return probe_dummy_security_ops->file_alloc_security(file);
}

#if defined(CONFIG_ARM)

/**
 * probe_security_ops_on_arm - Find security_ops on ARM.
 *
 * @base: Address of security_file_alloc().
 *
 * Returns address of security_ops on success, NULL otherwise.
 */
static void * probe_security_ops_on_arm(unsigned int *base)
{
	static unsigned int *ip4ret;
	int i;
	const unsigned long addr = (unsigned long) &probe_dummy_security_ops;
	unsigned int *ip = (unsigned int *) probe_security_file_alloc;
	for (i = 0; i < 32; ip++, i++) {
		if (*(ip + 2 + ((*ip & 0xFFF) >> 2)) != addr)
			continue;
		ip = base + i;
		ip4ret = (unsigned int *) (*(ip + 2 + ((*ip & 0xFFF) >> 2)));
		return &ip4ret;
	}
	ip = (unsigned int *) probe_security_file_alloc;
	for (i = 0; i < 32; ip++, i++) {
		/*
		 * Find
		 *   ldr r3, [pc, #offset1]
		 *   ldr r3, [r3, #offset2]
		 * sequence.
		 */
		if ((*ip & 0xFFFFF000) != 0xE59F3000 ||
		    (*(ip + 1) & 0xFFFFF000) != 0xE5933000)
			continue;
		ip4ret = (unsigned int *) (*(ip + 2 + ((*ip & 0xFFF) >> 2)));
		ip4ret += (*(ip + 1) & 0xFFF) >> 2;
		if ((unsigned long) ip4ret != addr)
			continue;
		ip = base + i;
		ip4ret = (unsigned int *) (*(ip + 2 + ((*ip & 0xFFF) >> 2)));
		ip4ret += (*(ip + 1) & 0xFFF) >> 2;
		return &ip4ret;
	}
	return NULL;
}

#endif

#endif

#if defined(CONFIG_ARM) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
/**
 * probe_find_vfsmount_lock_on_arm - Find vfsmount_lock spinlock on ARM.
 *
 * @ip:   Address of dummy function's entry point.
 * @addr: Address of the variable which is used within @function.
 * @base: Address of function's entry point.
 *
 * Returns address of vfsmount_lock on success, NULL otherwise.
 */
static void * probe_find_vfsmount_lock_on_arm(unsigned int *ip,
						     unsigned long addr,
						     unsigned int *base)
{
	int i;
	for (i = 0; i < 32; ip++, i++) {
		static unsigned int *ip4ret;
		if (*(ip + 2 + ((*ip & 0xFFF) >> 2)) != addr)
			continue;
		ip = base + i;
		ip4ret = (unsigned int *) (*(ip + 2 + ((*ip & 0xFFF) >> 2)));
		return &ip4ret;
	}
	return NULL;
}
#endif

/**
 * probe_find_variable - Find variable's address using dummy.
 *
 * @function: Pointer to dummy function's entry point.
 * @addr:     Address of the variable which is used within @function.
 * @symbol:   Name of symbol to resolve.
 *
 * This trick depends on below assumptions.
 *
 * (1) @addr is found within 128 bytes from @function, even if additional
 *     code (e.g. debug symbols) is added.
 * (2) It is safe to read 128 bytes from @function.
 * (3) @addr != Byte code except @addr.
 */
static void *probe_find_variable(void *function, unsigned long addr,
					 const char *symbol)
{
	int i;
	u8 *base;
	u8 *cp = function;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24) || LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 3)
	if (*symbol == ' ')
		base = probe_find_symbol(symbol);
	else
#endif
		base = __symbol_get(symbol);
	if (!base)
		return NULL;
#if defined(CONFIG_ARM) && LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24) && !defined(LSM_HOOK_INIT)
	if (function == probe_security_file_alloc)
		return probe_security_ops_on_arm((unsigned int *) base);
#endif
#if defined(CONFIG_ARM) && LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	return probe_find_vfsmount_lock_on_arm(function, addr,
					       (unsigned int *) base);
#endif
	/* First, assume absolute adressing mode is used. */
	for (i = 0; i < 128; i++) {
		if (*(unsigned long *) cp == addr)
			return base + i;
		cp++;
	}

	/* Next, assume PC-relative addressing mode is used. */
#if defined(CONFIG_S390)
	cp = function;
	for (i = 0; i < 128; i++) {
		if ((unsigned long) (cp + (*(int *) cp) * 2 - 2) == addr) {
			static void *cp4ret;
			cp = base + i;
			cp += (*(int *) cp) * 2 - 2;
			cp4ret = cp;
			return &cp4ret;
		}
		cp++;
	}
#endif

	cp = function;

	for (i = 0; i < 128; i++) {
		if ((unsigned long) (cp + sizeof(int) + *(int *) cp) == addr) {
			static void *cp4ret;
			cp = base + i;
			cp += sizeof(int) + *(int *) cp;
			cp4ret = cp;
			return &cp4ret;
		}
		cp++;
	}

	cp = function;

	for (i = 0; i < 128; i++) {
		if ((unsigned long) (long) (*(int *) cp) == addr) {
			static void *cp4ret;
			cp = base + i;
			cp = (void *) (long) (*(int *) cp);
			cp4ret = cp;
			return &cp4ret;
		}
		cp++;
	}
	return NULL;
}

#if defined(LSM_HOOK_INIT)

/**
 * probe_security_hook_heads - Find address of "struct security_hook_heads security_hook_heads".
 *
 * Returns pointer to "struct security_hook_heads" on success, NULL otherwise.
 */
struct security_hook_heads * probe_security_hook_heads(void)
{
	const unsigned int offset = offsetof(struct security_hook_heads,
					     bprm_committed_creds);
	void *cp;
	/* Guess "struct security_hook_heads security_hook_heads;". */
	cp = probe_find_variable(probe_security_bprm_committed_creds,
				 ((unsigned long)
				  &probe_dummy_security_hook_heads) + offset,
				 " security_bprm_committed_creds\n");
	if (!cp) {
		printk(KERN_ERR
		       "Can't resolve security_bprm_committed_creds().\n");
		return NULL;
	}
	/* This should be "struct security_hook_heads security_hook_heads;". */
	cp = ((void *) (*(unsigned long *) cp)) - offset;
	printk(KERN_INFO "security_hook_heads=%p\n", cp);
	return cp;
}

#else
struct security_operations *__probe_security_ops_find_symbol(void)
{
	struct security_operations **ptr;
	struct security_operations *ops;

	struct security_operations * (*__get_security_ops)(void) = NULL;

	__get_security_ops = (struct security_operations * (*)(void))probe_find_symbol(" get_security_ops\n");

	if(__get_security_ops){
		ops = __get_security_ops();
		if(ops){
			return ops;
		}
	}

	return NULL;
}

/**
 * probe_security_ops - Find address of "struct security_operations *security_ops".
 *
 * Returns pointer to "struct security_operations" on success, NULL otherwise.
 */
#if defined(CONFIG_SECURITY)
#ifdef ROCKY42_KERNEL
struct security_operations *probe_security_ops(void)
{
    // struct security_operations **ptr;
    struct security_operations *ops;

    struct security_operations * (*__get_security_ops)(void) = NULL;

    __get_security_ops = (struct security_operations * (*)(void))probe_find_symbol(" get_security_ops\n");

    if(__get_security_ops)
    {
        ops = __get_security_ops();
        if(ops)
        {
            printk(KERN_INFO "[%s:%d] security_ops=%p I am ROcky42.----\n",__func__,__LINE__, ops);
            return ops;
        }
    }

    return NULL;
}
#else
 struct security_operations *probe_security_ops(void)
{
	struct security_operations **ptr;
	struct security_operations *ops = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
	void *cp;
	/* Guess "struct security_operations *security_ops;". */
	cp = probe_find_variable(probe_security_file_alloc, (unsigned long)
				 &probe_dummy_security_ops,
				 " security_file_alloc\n");
	if (!cp) {
		printk(KERN_ERR "Can't resolve security_file_alloc().\n");
		return NULL;
	}
	/* This should be "struct security_operations *security_ops;". */
	ptr = *(struct security_operations ***) cp;
#else
	/* This is "struct security_operations *security_ops;". */
	ptr = (struct security_operations **) __symbol_get("security_ops");
#endif
	if (!ptr)
	{
		printk(KERN_ERR "Can't resolve security_ops structure.\n");
		printk(KERN_ERR "call __probe_security_ops_find_symbol.\n");
        ops = __probe_security_ops_find_symbol();
		if(ops == NULL)
		{

		printk(KERN_ERR "call __probe_security_ops_find_symbol failed .\n");
		    return NULL;
		}
	}
	else
	{
    	printk(KERN_INFO "[%s:%d] security_ops=%p\n",__func__,__LINE__, ptr);
    	ops = *ptr;
    	if (!ops) {
    		printk(KERN_ERR "No security_operations registered.\n");
    		return NULL;
    	}
	}
	return ops;
}

#endif
#else
struct security_operations *probe_security_ops(void)
{
    return NULL;
}

#endif

#endif
#if 0
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)

/**
 * probe_find_task_by_vpid - Find address of find_task_by_vpid().
 *
 * Returns address of find_task_by_vpid() on success, NULL otherwise.
 */
void * probe_find_task_by_vpid(void)
{
	void *ptr;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
	ptr = probe_find_symbol(" find_task_by_vpid\n");
#else
	ptr = __symbol_get("find_task_by_vpid");
#endif
	if (!ptr) {
		printk(KERN_ERR "Can't resolve find_task_by_vpid().\n");
		return NULL;
	}
	printk(KERN_INFO "find_task_by_vpid=%p\n", ptr);
	return ptr;
}

/**
 * probe_find_task_by_pid_ns - Find address of find_task_by_pid().
 *
 * Returns address of find_task_by_pid_ns() on success, NULL otherwise.
 */
void * probe_find_task_by_pid_ns(void)
{
	void *ptr;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 31)
	ptr = probe_find_symbol(" find_task_by_pid_ns\n");
#else
	ptr = __symbol_get("find_task_by_pid_ns");
#endif
	if (!ptr) {
		printk(KERN_ERR "Can't resolve find_task_by_pid_ns().\n");
		return NULL;
	}
	printk(KERN_INFO "find_task_by_pid_ns=%p\n", ptr);
	return ptr;
}

#endif
#endif
#if 0
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)

#if defined(CONFIG_SMP) || defined(CONFIG_DEBUG_SPINLOCK)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 3)

/* Dummy variable for finding address of "spinlock_t vfsmount_lock". */
static spinlock_t probe_dummy_vfsmount_lock __cacheline_aligned_in_smp =
	SPIN_LOCK_UNLOCKED;

static struct list_head *probe_mount_hashtable;
static int probe_hash_mask, probe_hash_bits;

/**
 * hash - Copy of hash() in fs/namespace.c.
 *
 * @mnt: Pointer to "struct vfsmount".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns hash value.
 */
static inline unsigned long hash(struct vfsmount *mnt, struct dentry *dentry)
{
	unsigned long tmp = ((unsigned long) mnt / L1_CACHE_BYTES);
	tmp += ((unsigned long) dentry / L1_CACHE_BYTES);
	tmp = tmp + (tmp >> probe_hash_bits);
	return tmp & probe_hash_mask;
}

/**
 * probe_lookup_mnt - Dummy function which does identical to lookup_mnt() in fs/namespace.c.
 *
 * @mnt:    Pointer to "struct vfsmount".
 * @dentry: Pointer to "struct dentry".
 *
 * Returns pointer to "struct vfsmount".
 */
static struct vfsmount *probe_lookup_mnt(struct vfsmount *mnt,
					 struct dentry *dentry)
{
	struct list_head *head = probe_mount_hashtable + hash(mnt, dentry);
	struct list_head *tmp = head;
	struct vfsmount *p, *found = NULL;

	spin_lock(&probe_dummy_vfsmount_lock);
	for (;;) {
		tmp = tmp->next;
		p = NULL;
		if (tmp == head)
			break;
		p = list_entry(tmp, struct vfsmount, mnt_hash);
		if (p->mnt_parent == mnt && p->mnt_mountpoint == dentry) {
			found = mntget(p);
			break;
		}
	}
	spin_unlock(&probe_dummy_vfsmount_lock);
	return found;
}

/**
 * probe_vfsmount_lock - Find address of "spinlock_t vfsmount_lock".
 *
 * Returns address of vfsmount_lock on success, NULL otherwise.
 */
void * probe_vfsmount_lock(void)
{
	void *cp;
	spinlock_t *ptr;
	/* Guess "spinlock_t vfsmount_lock;". */
	cp = probe_find_variable(probe_lookup_mnt, (unsigned long)
				 &probe_dummy_vfsmount_lock, " lookup_mnt\n");
	if (!cp) {
		printk(KERN_ERR "Can't resolve lookup_mnt().\n");
		return NULL;
	}
	/* This should be "spinlock_t *vfsmount_lock;". */
	ptr = *(spinlock_t **) cp;
	if (!ptr) {
		printk(KERN_ERR "Can't resolve vfsmount_lock .\n");
		return NULL;
	}
	printk(KERN_INFO "vfsmount_lock=%p\n", ptr);
	return ptr;
}

#elif LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 15)

/* Dummy variable for finding address of "spinlock_t vfsmount_lock". */
static spinlock_t probe_dummy_vfsmount_lock;

/**
 * probe_follow_up - Dummy function which does identical to follow_up() in fs/namei.c.
 *
 * @mnt:    Pointer to "struct vfsmount *".
 * @dentry: Pointer to "struct dentry *".
 *
 * Returns 1 if followed up, 0 otehrwise.
 */
static int probe_follow_up(struct vfsmount **mnt, struct dentry **dentry)
{
	struct vfsmount *parent;
	struct dentry *mountpoint;
	spin_lock(&probe_dummy_vfsmount_lock);
	parent = (*mnt)->mnt_parent;
	if (parent == *mnt) {
		spin_unlock(&probe_dummy_vfsmount_lock);
		return 0;
	}
	mntget(parent);
	mountpoint = dget((*mnt)->mnt_mountpoint);
	spin_unlock(&probe_dummy_vfsmount_lock);
	dput(*dentry);
	*dentry = mountpoint;
	mntput(*mnt);
	*mnt = parent;
	return 1;
}

/**
 * probe_vfsmount_lock - Find address of "spinlock_t vfsmount_lock".
 *
 * Returns address of vfsmount_lock on success, NULL otherwise.
 */
void * probe_vfsmount_lock(void)
{
	void *cp;
	spinlock_t *ptr;
	/* Guess "spinlock_t vfsmount_lock;". */
	cp = probe_find_variable(probe_follow_up, (unsigned long)
				 &probe_dummy_vfsmount_lock, "follow_up");
	if (!cp) {
		printk(KERN_ERR "Can't resolve follow_up().\n");
		return NULL;
	}
	/* This should be "spinlock_t *vfsmount_lock;". */
	ptr = *(spinlock_t **) cp;
	if (!ptr) {
		printk(KERN_ERR "Can't resolve vfsmount_lock .\n");
		return NULL;
	}
	printk(KERN_INFO "vfsmount_lock=%p\n", ptr);
	return ptr;
}

#else

/* Dummy variable for finding address of "spinlock_t vfsmount_lock". */
static spinlock_t probe_dummy_vfsmount_lock;

/**
 * probe_mnt_pin - Dummy function which does identical to mnt_pin() in fs/namespace.c.
 *
 * @mnt: Pointer to "struct vfsmount".
 *
 * Returns nothing.
 */
static void probe_mnt_pin(struct vfsmount *mnt)
{
	spin_lock(&probe_dummy_vfsmount_lock);
	mnt->mnt_pinned++;
	spin_unlock(&probe_dummy_vfsmount_lock);
}

/**
 * probe_vfsmount_lock - Find address of "spinlock_t vfsmount_lock".
 *
 * Returns address of vfsmount_lock on success, NULL otherwise.
 */
void * probe_vfsmount_lock(void)
{
	void *cp;
	spinlock_t *ptr;
	/* Guess "spinlock_t vfsmount_lock;". */
	cp = probe_find_variable(probe_mnt_pin, (unsigned long)
				 &probe_dummy_vfsmount_lock, "mnt_pin");
	if (!cp) {
		printk(KERN_ERR "Can't resolve mnt_pin().\n");
		return NULL;
	}
	/* This should be "spinlock_t *vfsmount_lock;". */
	ptr = *(spinlock_t **) cp;
	if (!ptr) {
		printk(KERN_ERR "Can't resolve vfsmount_lock .\n");
		return NULL;
	}
	printk(KERN_INFO "vfsmount_lock=%p\n", ptr);
	return ptr;
}

#endif

#else

/*
 * Never mark this variable as __initdata , for this variable might be accessed
 * by caller of probe_find_vfsmount_lock().
 */
static spinlock_t probe_dummy_vfsmount_lock;

/**
 * probe_vfsmount_lock - Find address of "spinlock_t vfsmount_lock".
 *
 * Returns address of vfsmount_lock.
 */
void * probe_vfsmount_lock(void)
{
	return &probe_dummy_vfsmount_lock;
}

#endif

#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 36) && LINUX_VERSION_CODE < KERNEL_VERSION(3, 2, 0)

/**
 * probe___d_path - Find address of "__d_path()".
 *
 * Returns address of __d_path() on success, NULL otherwise.
 */
void * probe___d_path(void)
{
	void *ptr = probe_find_symbol(" __d_path\n");
	if (!ptr) {
		printk(KERN_ERR "Can't resolve __d_path().\n");
		return NULL;
	}
	printk(KERN_INFO "__d_path=%p\n", ptr);
	return ptr;
}

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 2, 0)

/**
 * probe_d_absolute_path - Find address of "d_absolute_path()".
 *
 * Returns address of d_absolute_path() on success, NULL otherwise.
 */
void * probe_d_absolute_path(void)
{
	void *ptr = probe_find_symbol(" d_absolute_path\n");
	if (!ptr) {
		printk(KERN_ERR "Can't resolve d_absolute_path().\n");
		return NULL;
	}
	printk(KERN_INFO "d_absolute_path=%p\n", ptr);
	return ptr;
}

#endif

#endif// disable the code 2019-7-9 liudan
