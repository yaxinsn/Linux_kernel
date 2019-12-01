#ifndef  _COMPAT_PROC_FS_H
#define  _COMPAT_PROC_FS_H


#include <linux/proc_fs.h>
#include <linux/seq_file.h>

#include <linux/version.h>


 #if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
 static __inline__ struct proc_dir_entry *proc_create_data(const char *name,
     mode_t mode, struct proc_dir_entry *parent,
     const struct file_operations *proc_fops, void *data)
 {
     struct proc_dir_entry *ent;
     ent = create_proc_entry(name,mode,parent);
     if(!ent)
     {
         printk("create proc enty %s failed \n",name);
         return NULL;
     }
     ent->proc_fops = proc_fops;
     ent->data = data;
     return ent;
 }
#endif


#endif ///_COMPAT_PROC_FS_H

