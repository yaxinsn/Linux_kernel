





#include "misc-dev.h"		/* local definitions */





void my_vma_open(struct vm_area_struct *vma)
{
	struct my_misc_dev_extern *dev = vma->vm_private_data;
    atomic_inc(&dev->mem_ctx.refcnt);
}

void my_vma_close(struct vm_area_struct *vma)
{
	struct my_misc_dev_extern *dev = vma->vm_private_data;
    atomic_dec(&dev->mem_ctx.refcnt);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
struct page *my_vma_nopage(struct vm_area_struct *vma,
                                unsigned long address, int *type)
{
	unsigned long offset;
	
    
    struct my_misc_dev_extern *t = ( struct my_misc_dev_extern *)vma->vm_private_data;
	
    struct my_mem_ctx *p = &t->mem_ctx;

	printk("%s:%d ############# p %p\n",__func__,__LINE__,p);
	struct page *page = NOPAGE_SIGBUS;
	void *pageptr = NULL; /* default to "missing" */

        printk("%s:%d vma->vm_pgoff %d (address - vma->vm_start) %d \n",__func__,__LINE__,vma->vm_pgoff,(address - vma->vm_start));
	offset = (address - vma->vm_start) + (vma->vm_pgoff << PAGE_SHIFT);
	//offset = (address - vma->vm_start);// + (vma->vm_pgoff << PAGE_SHIFT);
	if (offset >= p->size)
	    goto out; /* out of range */

	printk("%s:%d ############# offset %d \n",__func__,__LINE__,offset);
	/*
	 * Now retrieve the scullv device from the list,then the page.
	 * If the device has holes, the process receives a SIGBUS when
	 * accessing the hole.
	 */
	//offset >>= PAGE_SHIFT; /* offset is a number of pages */

    pageptr = ((char*)p->ptr+offset);

	page = vmalloc_to_page(pageptr);

    printk("%s:%d mspec_mmap############# paddr %p ppage %x \n",__func__,__LINE__,pageptr,page);
	/* got it, now increment the count */
	get_page(page);
	if (type)
		*type = VM_FAULT_MINOR;
  out:
	return page;
}

#else
static int
my_vma_fault(struct vm_area_struct *vma, struct vm_fault *vmf)
{
    void* paddr;
    struct page *ppage; //pfn;
	pgoff_t index = vmf->pgoff;
    unsigned long offset = index*PAGE_SIZE;
    struct my_misc_dev_extern *t = ( struct my_misc_dev_extern *)vma->vm_private_data;
    struct my_mem_ctx *p = &t->mem_ctx;

    if(p->ptr == NULL)
        return VM_FAULT_NOPAGE;

	if (offset >= p->size)
		return VM_FAULT_SIGBUS;


    paddr = ((char*)p->ptr + offset);

    ppage = vmalloc_to_page(paddr);
    get_page(ppage);
    vmf->page = ppage;

    printk("%s:%d mspec_mmap############# paddr %p ppage %p \n",__func__,__LINE__,paddr,ppage);

	return 0;
}

#endif

static const struct vm_operations_struct mspec_vm_ops = {
	.open = my_vma_open,
	.close = my_vma_close,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
    .nopage = my_vma_nopage,
#else
	.fault = my_vma_fault,
#endif
};
static int
vmalloc_mmap(struct file *file, struct vm_area_struct *vma)
                    //enum mspec_page_type type)
{
#if 0
    //vma->vm_flags |= (VM_IO  | VM_DONTEXPAND); //| VM_RESERVED |VM_PFNMAP
	vma->vm_flags |= VM_RESERVED;
#endif	
    vma->vm_ops = &mspec_vm_ops;
	vma->vm_private_data = file->private_data;
    my_vma_open(vma);

    printk("%s:%d ############# \n",__func__,__LINE__);
    return 0;
}


/********************************************************************************************/
/* 两种mmap方式,
1：在mmap中使用remap_pfn_range直接完成全部页面的映射
2：使用nopage（fault)方式，在使用时再进行映射。

*/

static int remap_pfn_mmap(struct file *file, struct vm_area_struct *vma)
{


    struct my_misc_dev_extern* t = ( struct my_misc_dev_extern *)file->private_data;
    void* kbuff = t->mem_ctx.ptr;


    unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
    unsigned long pfn_start = (virt_to_phys(kbuff) >> PAGE_SHIFT) + vma->vm_pgoff;
    unsigned long virt_start = (unsigned long)kbuff + offset;
    unsigned long size = vma->vm_end - vma->vm_start;
    int ret = 0;

    if(kbuff == NULL)
    {
        return -ENOMEM;
    }
	
        printk("%s:%d size %lu t->mem_ctx.size %lu\n",__func__,__LINE__,size,t->mem_ctx.size);
    if(size > t->mem_ctx.size)
    {

        return -ENOMEM;
    }

 //   printk("remap_pfn_mmap phy: 0x%lx, offset: 0x%lx, size: 0x%lx\n", pfn_start << PAGE_SHIFT, offset, size);
#if 0
    ret = remap_pfn_range(vma, vma->vm_start, pfn_start, size, vma->vm_page_prot);
    if (ret)
        printk("%s: remap_pfn_range failed at [0x%lx  0x%lx]\n",
            __func__, vma->vm_start, vma->vm_end);
    else
        printk("%s: map 0x%lx to 0x%lx, size: 0x%lx\n", __func__, virt_start,
            vma->vm_start, size);
#endif
    return ret;
}

int my_mmap (struct file *file , struct vm_area_struct * vm)
{

    struct my_misc_dev_extern* t = ( struct my_misc_dev_extern *)file->private_data;
	
	printk(KERN_INFO "my_mmap\n");
    if(t->mem_ctx.flag != VMD_VMALLOCED)
    {

    /* 由于使用了kmalloc来申请内存，所以可以直接使用remap_pfn_range来直接把 连续的
     物理页面直接进行映射。
    */
        return remap_pfn_mmap(file,vm);//
    }
    else
    {


    printk("%s:%d ############# \n",__func__,__LINE__);
        return vmalloc_mmap(file,vm);
    }
}

