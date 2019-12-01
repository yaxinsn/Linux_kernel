/*
 * lsm.c
 *
 * Copyright (C) 2010-2015  Tetsuo Handa <penguin-kernel@I-love.SAKURA.ne.jp>
 *
 * Version: 1.0.35   2015/11/11
 */

//#include "internal.h"
//#include "probe.h"


#include "../mhook/mhook-lib/mhook.h"
#include "xHookProc.h"
#include "hook.h"
#include "securityhook.h"
#include "xLsmHook.h"

#include "Ktsglog.h"
#include "kernsymbol.h"

//#include "globals.h"

/*

要控制的HOOK点与对应的caller.

	HOOK										        CALLER
	security_inode_permission   				                 int permission(struct inode *inode, int mask, struct nameidata *nd)
												static int exec_permission_lite(struct inode *inode,struct nameidata *nd)

	 
 	security_inode_mknod						int vfs_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
	security_inode_mkdir						int vfs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
	security_inode_rmdir						int vfs_rmdir(struct inode *dir, struct dentry *dentry)
	security_inode_unlink						int vfs_unlink(struct inode *dir, struct dentry *dentry)
	security_inode_symlink						int vfs_symlink(struct inode *dir, struct dentry *dentry, const char *oldname, int mode)
	security_inode_rename			int vfs_rename(struct inode *old_dir, struct dentry *old_dentry,
	       							struct inode *new_dir, struct dentry *new_dentry)
	       
	       							static int vfs_rename_dir(struct inode *old_dir, struct dentry *old_dentry,
			  							struct inode *new_dir, struct dentry *new_dentry)
			  
	security_inode_link				int vfs_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
	
	security_inode_create 			int vfs_create(struct inode *dir, struct dentry *dentry, int mode,
		                                        struct nameidata *nd)

      security_file_mmap            unsigned long do_mmap_pgoff(struct file * file, unsigned long addr,
                                                    			unsigned long len, unsigned long prot,
                                    			unsigned long flags, unsigned long pgoff)
---------------------------------------------------------------------------------------------------
      int security_bprm_check              int search_binary_handler(struct linux_binprm *bprm,struct pt_regs *regs)
                                                                			
*/


typedef struct LSM_HOOK_ST
{
    HOOK_STUB stub;
    void*     origFunction;
    void*     hookFunction;
    
}LSMHOOK_ST;
#define  LSMHOOK_MAX 16
LSMHOOK_ST g_LSMHOOK[LSMHOOK_MAX];

int g_hook_new_count = 0;
int __hook_one(char* origFuncName,void* newFunction, LSMHOOK_ST* p)
{
    hookStubInitialize(&p->stub,origFuncName);
    load_kernel_symbol_ptr(p->origFunction, void* ,origFuncName);
    hookStubSetEx(&p->stub,newFunction,(void **)&p->origFunction);
    return 0;    
}

int hook_one(char* origFuncName,void* newFunction)
{

    if(g_hook_new_count >= LSMHOOK_MAX)
        return -1;
        
    __hook_one(origFuncName,newFunction,&g_LSMHOOK[g_hook_new_count++]);   
    return 0;
}




int _hook_new_permission(struct inode *inode, int mask, struct nameidata *nd)
{
    int ret;
    if(nd)
    {
        ret = securityhook_inode_permission(inode, mask,nd);
        if(ret)
            return ret;
    }
    return ( (typeof(&permission) )g_LSMHOOK[0].origFunction)(inode,mask,nd);
}
int _hook_new_exec_permission_lite(struct inode *inode,struct nameidata *nd)
{

    if(g_LSMHOOK[1].origFunction)
    {
        return ( (int (*)(struct inode *inode,struct nameidata *nd))g_LSMHOOK[1].origFunction)(inode,nd);    
    }
    return 0;
}
int _hook_new_vfs_mknod(struct inode *dir, struct dentry *dentry, int mode, dev_t dev)
{

    int ret;
    
    ret =  securityhook_inode_mknod(dir,dentry,mode,dev);
    if(ret)
        return ret;
        
    return ( ( typeof(&vfs_mknod) )g_LSMHOOK[2].origFunction)(dir,dentry,mode,dev);
}
int _hook_new_vfs_mkdir(struct inode *dir, struct dentry *dentry, int mode)
{
    int ret;
    ret =  securityhook_inode_mkdir(dir,dentry,mode);
    if(ret)
        return ret;
        
    return ( ( typeof(&vfs_mkdir)  )g_LSMHOOK[3].origFunction)(dir,dentry,mode);
}

int _hook_new_vfs_rmdir(struct inode *dir, struct dentry *dentry)
{    
    int ret;
    ret =  securityhook_inode_rmdir(dir,dentry );
    if(ret)
        return ret;
        
    return ( ( typeof(&vfs_rmdir)  )g_LSMHOOK[4].origFunction)(dir,dentry);
}
int _hook_new_vfs_unlink    (struct inode *dir, struct dentry *dentry)
{   
    int ret;
    ret =  securityhook_inode_unlink(dir,dentry);
    if(ret)
        return ret;
        
    return ( ( typeof(&vfs_unlink)  )g_LSMHOOK[5].origFunction)(dir,dentry);
}
int _hook_new_vfs_symlink    (struct inode *dir, struct dentry *dentry, const char *oldname, int mode)
{
    int ret;
    ret =  securityhook_inode_symlink(dir,dentry,oldname);
    if(ret)
        return ret;

    return ( ( typeof(&vfs_symlink)  )g_LSMHOOK[6].origFunction)
        (dir,dentry,oldname,mode);
    
}
int _hook_new_vfs_rename    (struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry)
{

    int ret;
    ret =  securityhook_inode_rename(old_dir,old_dentry,new_dir,new_dentry);
    if(ret)
        return ret;

    return ( ( typeof(&vfs_rename)  )g_LSMHOOK[7].origFunction)
            (old_dir,old_dentry,new_dir,new_dentry);
    
}
int _hook_new_vfs_link    (struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
    
    int ret;
    ret =  securityhook_inode_link(old_dentry,dir,new_dentry);
    if(ret)
        return ret;
    return ( ( typeof(&vfs_link)  )g_LSMHOOK[8].origFunction)
            (old_dentry,dir,new_dentry);
    
}
int _hook_new_vfs_create    (struct inode *dir, struct dentry *dentry, int mode,struct nameidata *nd)
{
    
    int ret;
    ret =  securityhook_inode_create(dir,dentry,mode);
    if(ret)
        return ret;

    return ( ( typeof(&vfs_create)  )g_LSMHOOK[9].origFunction)
        (dir,dentry,mode,nd);
    
}

unsigned long _hook_new_do_mmap_pgoff(struct file * file, unsigned long addr,
                                                                    unsigned long len, unsigned long prot,
                                                    unsigned long flags, unsigned long pgoff)

{
    int ret;
    ret = wlSecMMapCheck(file, prot, prot, flags);
	if (ret)
	{
	//	KTsgDebug(KERN_INFO "[-]  wlImageCheck failure\n");
	    return ret;
	}
	ret = securityhook_file_mmap(file, prot, prot, flags);
	if (ret)
	{
	    return ret;
	}
    return ( ( typeof(&do_mmap_pgoff)  )g_LSMHOOK[10].origFunction)
        (file,addr,len,prot,flags,pgoff);
        
}
                                                    
int _hook_new_search_binary_handler(struct linux_binprm *bprm,struct pt_regs *regs)
{
    int ret;
    ret = securityhook_bprm_check_security(bprm);
    if(ret)
    {
		KTsgDebug(KERN_INFO "[-]  wlImageCheck failure---\n");
	    return ret;
    }
    return ( ( typeof(&search_binary_handler)  )g_LSMHOOK[11].origFunction)(bprm,regs);
}
int _hook_new_vfs_rw(int read_write, struct file *file, loff_t *ppos, size_t count)
//(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
    int ret;
    if(read_write == 0)
        ret = securityhook_file_permission(file,MAY_READ);
    else
        ret = securityhook_file_permission(file,MAY_WRITE);
    if(ret)
    {
		KTsgDebug(KERN_INFO "[-]   failure---\n");
	    return ret;
    }
    return ( ( typeof(&rw_verify_area)  )g_LSMHOOK[12].origFunction)(read_write,file,ppos,count);
}

int _hook_new_vfs_readdir(struct file *file, filldir_t filler, void *buf)
{
    int ret;

    ret = securityhook_file_permission(file,MAY_READ);
    if(ret)
    {
        KTsgDebug(KERN_INFO "[-]  failure---\n");
        return ret;
    }
    return ( ( typeof(&vfs_readdir)  )g_LSMHOOK[13].origFunction)(file,filler,buf);
}


int lsm_hooks_init()
{
    hook_one("permission",_hook_new_permission);
    hook_one("exec_permission_lite",_hook_new_exec_permission_lite);
    hook_one("vfs_mknod",_hook_new_vfs_mknod);
    hook_one("vfs_mkdir",_hook_new_vfs_mkdir);
    hook_one("vfs_rmdir",_hook_new_vfs_rmdir);
    hook_one("vfs_unlink",_hook_new_vfs_unlink);
    hook_one("vfs_symlink",_hook_new_vfs_symlink);
    
    hook_one("vfs_rename",_hook_new_vfs_rename);    
    hook_one("vfs_link",_hook_new_vfs_link);
    hook_one("vfs_create",_hook_new_vfs_create);
    hook_one("do_mmap_pgoff",_hook_new_do_mmap_pgoff);
    hook_one("search_binary_handler",_hook_new_search_binary_handler);
    hook_one("rw_verify_area",_hook_new_vfs_rw);
    hook_one("vfs_readdir",_hook_new_vfs_readdir);
    return 0;
}

void _destrory_one_hook(LSMHOOK_ST* p)
{
    hookStubDestroy(&p->stub);
    p->origFunction = NULL;
    p->hookFunction = NULL;

}
void lsm_hooks_destory(void)
{
    int i;
    for(i = 0;i<=g_hook_new_count;i++)
    {
        _destrory_one_hook(&g_LSMHOOK[i]);   
    }
}



__init int ccs_init(void)
{

    lsm_hooks_init();
	printk(KERN_INFO "LiuDan : 1.0.0   2018/10/25\n");
	printk(KERN_INFO
	       "Access Keeping And Regulating Instrument registered.\n");
	return 0;
//out:
	return -EINVAL;
}


 int ccs_destroy(void)
{

    lsm_hooks_destory();
	printk(KERN_INFO "Unregister TsgMod and defender close!----------\n");

	return 0;
}
MODULE_LICENSE("GPL");
 
