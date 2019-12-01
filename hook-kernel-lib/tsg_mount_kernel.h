#ifndef __TSG_MOUNT_HEAD_
#define __TSG_MOUNT_HEAD_

#include <linux/version.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
#include <linux/nsproxy.h>
#include <linux/sched.h>
#include <linux/path.h>
#include <linux/mnt_namespace.h>

#if (LINUX_VERSION_CODE <= KERNEL_VERSION(3,5,7)) && (LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32))
#include <linux/mount.h>

/*For 2,6,32 < k <= 3.5.0 */
struct mnt_namespace {
        atomic_t                count;
        struct mount *  root;
        struct list_head        list;
        wait_queue_head_t poll;
        int event;
};
struct mount {
        struct list_head mnt_hash;
        struct mount *mnt_parent;
        struct dentry *mnt_mountpoint;
        struct vfsmount mnt;
#ifdef CONFIG_SMP
        struct mnt_pcp __percpu *mnt_pcp;
        atomic_t mnt_longterm;          /* how many of the refs are longterm */
#else
        int mnt_count;
        int mnt_writers;
#endif
        struct list_head mnt_mounts;    /* list of children, anchored here */
        struct list_head mnt_child;     /* and going through their mnt_child */
        struct list_head mnt_instance;  /* mount instance on sb->s_mounts */
        const char *mnt_devname;        /* Name of device e.g. /dev/dsk/hda1 */
        struct list_head mnt_list;
        struct list_head mnt_expire;    /* link in fs-specific expiry list */
        struct list_head mnt_share;     /* circular list of shared mounts */
        struct list_head mnt_slave_list;/* list of slave mounts */
        struct list_head mnt_slave;     /* slave list entry */
        struct mount *mnt_master;       /* slave is on master->mnt_slave_list */
        struct mnt_namespace *mnt_ns;   /* containing namespace */
#ifdef CONFIG_FSNOTIFY
        struct hlist_head mnt_fsnotify_marks;
        __u32 mnt_fsnotify_mask;
#endif
        int mnt_id;                     /* mount identifier */
        int mnt_group_id;               /* peer group identifier */
        int mnt_expiry_mark;            /* true if marked for expiry */
        int mnt_pinned;
        int mnt_ghosts;
};
/*End of 3.5.x */
#else
#include <linux/mount.h>
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(4,9,0))

struct mnt_namespace {
    atomic_t        count;
    unsigned int        proc_inum;
    struct mount *  root;
    struct list_head    list;
    struct user_namespace   *user_ns;
    u64         seq;    /* Sequence number to prevent loops */
    wait_queue_head_t poll;
    int event;
};
#else
#include <linux/mount.h>
#include <linux/seq_file.h>
#include <linux/poll.h>
#include <linux/ns_common.h>
#include <linux/fs_pin.h>

struct mnt_namespace {
	atomic_t		count;
	struct ns_common	ns;
	struct mount *	root;
	struct list_head	list;
	struct user_namespace	*user_ns;
	struct ucounts		*ucounts;
	u64			seq;	/* Sequence number to prevent loops */
	wait_queue_head_t poll;
	u64 event;
	unsigned int		mounts; /* # of mounts in the namespace */
	unsigned int		pending_mounts;
};
#endif //4.9.0
struct mount {
    struct hlist_node mnt_hash;
    struct mount *mnt_parent;
    struct dentry *mnt_mountpoint;
    struct vfsmount mnt;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0) 
    //Addby shenjunwei+20140915 for 3.10.X kernel version
    struct rcu_head mnt_rcu;
#endif
#ifdef CONFIG_SMP
    struct mnt_pcp __percpu *mnt_pcp;
#else
    int mnt_count;
    int mnt_writers;
#endif
    struct list_head mnt_mounts;    /* list of children, anchored here */
    struct list_head mnt_child; /* and going through their mnt_child */
    struct list_head mnt_instance;  /* mount instance on sb->s_mounts */
    const char *mnt_devname;    /* Name of device e.g. /dev/dsk/hda1 */
    struct list_head mnt_list;
    struct list_head mnt_expire;    /* link in fs-specific expiry list */
    struct list_head mnt_share; /* circular list of shared mounts */
    struct list_head mnt_slave_list;/* list of slave mounts */
    struct list_head mnt_slave; /* slave list entry */
    struct mount *mnt_master;   /* slave is on master->mnt_slave_list */
    struct mnt_namespace *mnt_ns;   /* containing namespace */
    struct mountpoint *mnt_mp;  /* where is it mounted */
#ifdef CONFIG_FSNOTIFY
    struct hlist_head mnt_fsnotify_marks;
    __u32 mnt_fsnotify_mask;
#endif
    int mnt_id;         /* mount identifier */
    int mnt_group_id;       /* peer group identifier */
    int mnt_expiry_mark;        /* true if marked for expiry */
    int mnt_pinned;
    struct path mnt_ex_mountpoint;
};
#endif//
#endif//

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
#include <linux/mm_types.h>
#include <linux/mm.h>
#else
//for GLH 2.6.16.25 --liudan
#include <linux/mount.h>
struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
};

#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
#include <linux/binfmts.h>
#include <linux/mm.h>
#include <linux/namespace.h>
#endif

#if (LINUX_VERSION_CODE == KERNEL_VERSION(2,6,32))
#include <linux/nsproxy.h>
#include <linux/mnt_namespace.h>
#include <linux/fs_struct.h>
#include <linux/path.h>
#endif

#endif

