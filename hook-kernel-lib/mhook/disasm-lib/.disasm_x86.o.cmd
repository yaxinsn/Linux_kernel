cmd_/mnt/hgfs/dd-edit-code/KTsgMod/./mhook/disasm-lib/disasm_x86.o := gcc -Wp,-MD,/mnt/hgfs/dd-edit-code/KTsgMod/./mhook/disasm-lib/.disasm_x86.o.d  -nostdinc -isystem /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include -D__KERNEL__ -Iinclude  -include include/linux/autoconf.h  -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Wstrict-prototypes -Wundef -Werror-implicit-function-declaration -fno-delete-null-pointer-checks -fwrapv -Os  -mtune=generic -m64 -mno-red-zone -mcmodel=kernel -pipe -fno-reorder-blocks -Wno-sign-compare -fno-asynchronous-unwind-tables -funit-at-a-time -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -fomit-frame-pointer -g  -fno-stack-protector -Wdeclaration-after-statement -Wno-pointer-sign -I/mnt/hgfs/dd-edit-code/KTsgMod/   -Wno-unused-function -Wno-unused-variable -g -Wno-parentheses  -g -I/mnt/hgfs/dd-edit-code/KTsgMod///../include -I/mnt/hgfs/dd-edit-code/KTsgMod///lsm -I/mnt/hgfs/dd-edit-code/KTsgMod/// -I/mnt/hgfs/dd-edit-code/KTsgMod///debug-log   -DMODULE -D"KBUILD_STR(s)=\#s" -D"KBUILD_BASENAME=KBUILD_STR(disasm_x86)"  -D"KBUILD_MODNAME=KBUILD_STR(KTsgMod)" -c -o /mnt/hgfs/dd-edit-code/KTsgMod/./mhook/disasm-lib/.tmp_disasm_x86.o /mnt/hgfs/dd-edit-code/KTsgMod/./mhook/disasm-lib/disasm_x86.c

deps_/mnt/hgfs/dd-edit-code/KTsgMod/./mhook/disasm-lib/disasm_x86.o := \
  /mnt/hgfs/dd-edit-code/KTsgMod/./mhook/disasm-lib/disasm_x86.c \
  /mnt/hgfs/dd-edit-code/KTsgMod/scheme.h \
  include/linux/version.h \
  include/linux/security.h \
    $(wildcard include/config/security.h) \
    $(wildcard include/config/security/network.h) \
    $(wildcard include/config/security/network/xfrm.h) \
    $(wildcard include/config/keys.h) \
  include/linux/fs.h \
    $(wildcard include/config/dnotify.h) \
    $(wildcard include/config/sysfs.h) \
    $(wildcard include/config/smp.h) \
    $(wildcard include/config/quota.h) \
    $(wildcard include/config/inotify.h) \
    $(wildcard include/config/preempt.h) \
    $(wildcard include/config/epoll.h) \
    $(wildcard include/config/auditsyscall.h) \
    $(wildcard include/config/fs/xip.h) \
    $(wildcard include/config/migration.h) \
  include/linux/limits.h \
  include/linux/ioctl.h \
  include/asm/ioctl.h \
  include/asm-generic/ioctl.h \
  include/linux/linkage.h \
  include/asm/linkage.h \
  include/linux/wait.h \
    $(wildcard include/config/lockdep.h) \
  include/linux/list.h \
    $(wildcard include/config/debug/list.h) \
  include/linux/stddef.h \
  include/linux/compiler.h \
  include/linux/compiler-gcc4.h \
    $(wildcard include/config/forced/inlining.h) \
  include/linux/compiler-gcc.h \
  include/linux/poison.h \
  include/linux/prefetch.h \
  include/linux/types.h \
    $(wildcard include/config/uid16.h) \
    $(wildcard include/config/resources/64bit.h) \
  include/linux/posix_types.h \
  include/asm/posix_types.h \
  include/asm/types.h \
  include/asm/processor.h \
    $(wildcard include/config/x86/vsmp.h) \
  include/asm/segment.h \
  include/asm/cache.h \
    $(wildcard include/config/x86/l1/cache/shift.h) \
  include/asm/page.h \
    $(wildcard include/config/flatmem.h) \
  include/asm/const.h \
  include/asm/bug.h \
    $(wildcard include/config/bug.h) \
  include/linux/stringify.h \
  include/asm-generic/bug.h \
  include/asm-generic/memory_model.h \
    $(wildcard include/config/discontigmem.h) \
    $(wildcard include/config/sparsemem.h) \
    $(wildcard include/config/out/of/line/pfn/to/page.h) \
  include/asm-generic/page.h \
  include/asm/sigcontext.h \
  include/asm/cpufeature.h \
  include/linux/threads.h \
    $(wildcard include/config/nr/cpus.h) \
    $(wildcard include/config/base/small.h) \
  include/asm/msr.h \
  include/asm/current.h \
  include/asm/pda.h \
  include/linux/cache.h \
  include/linux/kernel.h \
    $(wildcard include/config/preempt/voluntary.h) \
    $(wildcard include/config/debug/spinlock/sleep.h) \
    $(wildcard include/config/printk.h) \
  /usr/lib/gcc/x86_64-redhat-linux/4.1.2/include/stdarg.h \
  include/linux/bitops.h \
  include/asm/bitops.h \
  include/asm/alternative.h \
  include/asm-generic/bitops/sched.h \
  include/asm-generic/bitops/hweight.h \
  include/asm-generic/bitops/ext2-non-atomic.h \
  include/asm-generic/bitops/le.h \
  include/asm/byteorder.h \
  include/linux/byteorder/little_endian.h \
  include/linux/byteorder/swab.h \
  include/linux/byteorder/generic.h \
  include/asm-generic/bitops/minix.h \
  include/linux/log2.h \
    $(wildcard include/config/arch/has/ilog2/u32.h) \
    $(wildcard include/config/arch/has/ilog2/u64.h) \
  include/asm/system.h \
    $(wildcard include/config/unordered/io.h) \
  include/linux/irqflags.h \
    $(wildcard include/config/trace/irqflags.h) \
    $(wildcard include/config/trace/irqflags/support.h) \
    $(wildcard include/config/x86.h) \
  include/asm/irqflags.h \
  include/asm/mmsegment.h \
  include/asm/percpu.h \
  include/linux/personality.h \
  include/linux/cpumask.h \
    $(wildcard include/config/hotplug/cpu.h) \
  include/linux/bitmap.h \
  include/linux/string.h \
  include/asm/string.h \
  include/linux/spinlock.h \
    $(wildcard include/config/debug/spinlock.h) \
    $(wildcard include/config/debug/lock/alloc.h) \
  include/linux/preempt.h \
    $(wildcard include/config/debug/preempt.h) \
    $(wildcard include/config/preempt/notifiers.h) \
  include/linux/thread_info.h \
  include/asm/thread_info.h \
    $(wildcard include/config/debug/stack/usage.h) \
  include/linux/spinlock_types.h \
  include/asm/spinlock_types.h \
  include/linux/lockdep.h \
    $(wildcard include/config/lock/stat.h) \
    $(wildcard include/config/generic/hardirqs.h) \
    $(wildcard include/config/prove/locking.h) \
  include/linux/debug_locks.h \
    $(wildcard include/config/debug/locking/api/selftests.h) \
  include/linux/stacktrace.h \
    $(wildcard include/config/stacktrace.h) \
  include/asm/spinlock.h \
  include/asm/atomic.h \
  include/asm-generic/atomic.h \
  include/asm/rwlock.h \
  include/linux/spinlock_api_smp.h \
  include/linux/kdev_t.h \
  include/linux/dcache.h \
    $(wildcard include/config/profiling.h) \
  include/linux/rcupdate.h \
  include/linux/percpu.h \
    $(wildcard include/config/modules.h) \
  include/linux/slab.h \
    $(wildcard include/config/slob.h) \
    $(wildcard include/config/debug/slab.h) \
    $(wildcard include/config/numa.h) \
  include/linux/gfp.h \
    $(wildcard include/config/dma/is/dma32.h) \
  include/linux/mmzone.h \
    $(wildcard include/config/force/max/zoneorder.h) \
    $(wildcard include/config/memory/hotplug.h) \
    $(wildcard include/config/flat/node/mem/map.h) \
    $(wildcard include/config/have/memory/present.h) \
    $(wildcard include/config/need/node/memmap/size.h) \
    $(wildcard include/config/need/multiple/nodes.h) \
    $(wildcard include/config/have/arch/early/pfn/to/nid.h) \
    $(wildcard include/config/sparsemem/extreme.h) \
    $(wildcard include/config/nodes/span/other/nodes.h) \
  include/linux/numa.h \
    $(wildcard include/config/nodes/shift.h) \
  include/linux/init.h \
    $(wildcard include/config/hotplug.h) \
    $(wildcard include/config/acpi/hotplug/memory.h) \
    $(wildcard include/config/acpi/hotplug/memory/module.h) \
  include/linux/seqlock.h \
  include/linux/nodemask.h \
  include/linux/memory_hotplug.h \
    $(wildcard include/config/have/arch/nodedata/extension.h) \
  include/linux/notifier.h \
  include/linux/errno.h \
  include/asm/errno.h \
  include/asm-generic/errno.h \
  include/asm-generic/errno-base.h \
  include/linux/mutex.h \
    $(wildcard include/config/debug/mutexes.h) \
  include/linux/rwsem.h \
    $(wildcard include/config/rwsem/generic/spinlock.h) \
  include/linux/rwsem-spinlock.h \
  include/linux/topology.h \
    $(wildcard include/config/sched/smt.h) \
    $(wildcard include/config/sched/mc.h) \
  include/linux/smp.h \
  include/asm/smp.h \
    $(wildcard include/config/x86/local/apic.h) \
    $(wildcard include/config/x86/io/apic.h) \
  include/asm/fixmap.h \
  include/asm/apicdef.h \
  include/asm/vsyscall.h \
  include/asm/vsyscall32.h \
  include/asm/mpspec.h \
    $(wildcard include/config/acpi.h) \
  include/asm/io_apic.h \
    $(wildcard include/config/pci/msi.h) \
    $(wildcard include/config/xen.h) \
  include/asm/apic.h \
    $(wildcard include/config/x86/good/apic.h) \
  include/linux/pm.h \
    $(wildcard include/config/pm.h) \
  include/asm/topology.h \
    $(wildcard include/config/acpi/numa.h) \
  include/asm-generic/topology.h \
  include/asm/mmzone.h \
  include/asm/sparsemem.h \
  include/linux/kmalloc_sizes.h \
    $(wildcard include/config/ppc/64k/pages.h) \
    $(wildcard include/config/mmu.h) \
    $(wildcard include/config/large/allocs.h) \
  include/linux/stat.h \
  include/asm/stat.h \
  include/linux/time.h \
  include/linux/kobject.h \
  include/linux/sysfs.h \
  include/linux/kref.h \
  include/linux/radix-tree.h \
  include/linux/sched.h \
    $(wildcard include/config/detect/softlockup.h) \
    $(wildcard include/config/detect/hung/task.h) \
    $(wildcard include/config/split/ptlock/cpus.h) \
    $(wildcard include/config/mmu/notifier.h) \
    $(wildcard include/config/bsd/process/acct.h) \
    $(wildcard include/config/taskstats.h) \
    $(wildcard include/config/audit.h) \
    $(wildcard include/config/inotify/user.h) \
    $(wildcard include/config/schedstats.h) \
    $(wildcard include/config/task/delay/acct.h) \
    $(wildcard include/config/utrace.h) \
    $(wildcard include/config/rt/mutexes.h) \
    $(wildcard include/config/task/xacct.h) \
    $(wildcard include/config/cpusets.h) \
    $(wildcard include/config/compat.h) \
    $(wildcard include/config/ptrace.h) \
  include/linux/auxvec.h \
  include/asm/auxvec.h \
  include/asm/param.h \
    $(wildcard include/config/hz.h) \
  include/linux/capability.h \
  include/linux/timex.h \
    $(wildcard include/config/time/interpolation.h) \
  include/asm/timex.h \
  include/asm/8253pit.h \
  include/asm/hpet.h \
    $(wildcard include/config/hpet/emulate/rtc.h) \
  include/linux/jiffies.h \
    $(wildcard include/config/tick/divider.h) \
  include/linux/math64.h \
  include/asm/div64.h \
  include/asm-generic/div64.h \
  include/linux/rbtree.h \
  include/asm/semaphore.h \
  include/asm/ptrace.h \
  include/asm/mmu.h \
  include/asm/cputime.h \
  include/asm-generic/cputime.h \
  include/linux/sem.h \
    $(wildcard include/config/sysvipc.h) \
  include/linux/ipc.h \
  include/asm/ipcbuf.h \
  include/asm/sembuf.h \
  include/linux/signal.h \
  include/asm/signal.h \
  include/asm-generic/signal.h \
  include/asm/siginfo.h \
  include/asm-generic/siginfo.h \
  include/linux/securebits.h \
  include/linux/fs_struct.h \
  include/linux/completion.h \
  include/linux/pid.h \
  include/linux/seccomp.h \
    $(wildcard include/config/seccomp.h) \
  include/linux/futex.h \
    $(wildcard include/config/futex.h) \
  include/linux/rtmutex.h \
    $(wildcard include/config/debug/rt/mutexes.h) \
  include/linux/plist.h \
    $(wildcard include/config/debug/pi/list.h) \
  include/linux/param.h \
  include/linux/resource.h \
  include/asm/resource.h \
  include/asm-generic/resource.h \
  include/linux/timer.h \
  include/linux/hrtimer.h \
    $(wildcard include/config/no/idle/hz.h) \
  include/linux/ktime.h \
    $(wildcard include/config/ktime/scalar.h) \
  include/linux/task_io_accounting.h \
    $(wildcard include/config/task/io/accounting.h) \
  include/linux/aio.h \
  include/linux/workqueue.h \
  include/linux/aio_abi.h \
  include/linux/sysdev.h \
  include/linux/prio_tree.h \
  include/linux/fiemap.h \
  include/linux/quota.h \
  include/linux/dqblk_xfs.h \
  include/linux/dqblk_v1.h \
  include/linux/dqblk_v2.h \
  include/linux/nfs_fs_i.h \
  include/linux/nfs.h \
  include/linux/sunrpc/msg_prot.h \
  include/linux/fcntl.h \
  include/asm/fcntl.h \
  include/asm-generic/fcntl.h \
    $(wildcard include/config/64bit.h) \
  include/linux/err.h \
  include/linux/binfmts.h \
  include/linux/shm.h \
  include/asm/shmparam.h \
  include/asm/shmbuf.h \
  include/linux/mm.h \
    $(wildcard include/config/sysctl.h) \
    $(wildcard include/config/stack/growsup.h) \
    $(wildcard include/config/ia64.h) \
    $(wildcard include/config/highmem.h) \
    $(wildcard include/config/shmem.h) \
    $(wildcard include/config/have/get/user/pages/fast.h) \
    $(wildcard include/config/proc/fs.h) \
    $(wildcard include/config/debug/pagealloc.h) \
  include/linux/backing-dev.h \
  include/asm/pgtable.h \
  include/asm/mm_track.h \
    $(wildcard include/config/track/dirty/pages.h) \
  include/asm-generic/pgtable.h \
  include/linux/page-flags.h \
    $(wildcard include/config/s390.h) \
    $(wildcard include/config/swap.h) \
    $(wildcard include/config/x86/64.h) \
  include/linux/vmstat.h \
    $(wildcard include/config/vm/event/counters.h) \
    $(wildcard include/config/dma/is/normal.h) \
  include/linux/msg.h \
  include/asm/msgbuf.h \
  include/linux/key.h \
  include/linux/sysctl.h \
    $(wildcard include/config/tux/debug/blocking.h) \
  include/linux/xfrm.h \
  include/net/flow.h \
  include/linux/in6.h \
  include/linux/module.h \
    $(wildcard include/config/modversions.h) \
    $(wildcard include/config/unused/symbols.h) \
    $(wildcard include/config/module/unload.h) \
    $(wildcard include/config/kallsyms.h) \
  include/linux/kmod.h \
    $(wildcard include/config/kmod.h) \
  include/linux/elf.h \
  include/linux/elf-em.h \
  include/asm/elf.h \
  include/asm/user.h \
  include/asm/compat.h \
  include/linux/moduleparam.h \
  include/linux/tracepoint.h \
    $(wildcard include/config/tracepoints.h) \
  include/linux/marker.h \
    $(wildcard include/config/markers.h) \
  include/asm/local.h \
  include/asm/module.h \
  include/linux/proc_fs.h \
    $(wildcard include/config/proc/devicetree.h) \
    $(wildcard include/config/proc/kcore.h) \
  /mnt/hgfs/dd-edit-code/KTsgMod/precompile.h \
  /mnt/hgfs/dd-edit-code/KTsgMod/linux_kernel_port.h \
  include/linux/vmalloc.h \
  include/linux/cdev.h \
  include/asm/io.h \
  include/asm-generic/iomap.h \
  include/asm/uaccess.h \
  /mnt/hgfs/dd-edit-code/KTsgMod/./mhook/mhook_port.h \
  /mnt/hgfs/dd-edit-code/KTsgMod/./mhook/linux_port.h \
  /mnt/hgfs/dd-edit-code/KTsgMod/./mhook/disasm-lib/disasm.h \
  /mnt/hgfs/dd-edit-code/KTsgMod/./mhook/disasm-lib/misc.h \
  /mnt/hgfs/dd-edit-code/KTsgMod/./mhook/disasm-lib/disasm_x86.h \
  /mnt/hgfs/dd-edit-code/KTsgMod/./mhook/disasm-lib/cpu.h \
  /mnt/hgfs/dd-edit-code/KTsgMod///debug-log/ktsglog.h \
  /mnt/hgfs/dd-edit-code/KTsgMod///debug-log/klog.h \
  include/linux/seq_file.h \
  /mnt/hgfs/dd-edit-code/KTsgMod///debug-log/compat_proc_fs.h \
  /mnt/hgfs/dd-edit-code/KTsgMod///debug-log/compat_rtc_time.h \
    $(wildcard include/config/rtc/lib.h) \
  include/linux/rtc.h \
    $(wildcard include/config/rtc/intf/dev/uie/emul.h) \
  include/linux/interrupt.h \
    $(wildcard include/config/have/irq/ignore/unhandled.h) \
    $(wildcard include/config/generic/irq/probe.h) \
  include/linux/irqreturn.h \
  include/linux/hardirq.h \
    $(wildcard include/config/preempt/bkl.h) \
    $(wildcard include/config/virt/cpu/accounting.h) \
  include/linux/smp_lock.h \
    $(wildcard include/config/lock/kernel.h) \
  include/asm/hardirq.h \
  include/linux/irq.h \
    $(wildcard include/config/irq/per/cpu.h) \
    $(wildcard include/config/irq/release/method.h) \
    $(wildcard include/config/generic/pending/irq.h) \
    $(wildcard include/config/irqbalance.h) \
    $(wildcard include/config/auto/irq/affinity.h) \
  include/asm/irq.h \
  include/asm/hw_irq.h \
  include/linux/profile.h \
  include/trace/irq.h \
  include/linux/device.h \
    $(wildcard include/config/debug/devres.h) \
  include/linux/ioport.h \
  include/linux/klist.h \
  include/linux/poll.h \
  include/asm/poll.h \
  /mnt/hgfs/dd-edit-code/KTsgMod///debug-log/compat_kmalloc.h \
  include/linux/highmem.h \
  include/asm/cacheflush.h \
    $(wildcard include/config/debug/rodata.h) \
  /mnt/hgfs/dd-edit-code/KTsgMod/./mhook/disasm-lib/disasm_x86_tables.h \

/mnt/hgfs/dd-edit-code/KTsgMod/./mhook/disasm-lib/disasm_x86.o: $(deps_/mnt/hgfs/dd-edit-code/KTsgMod/./mhook/disasm-lib/disasm_x86.o)

$(deps_/mnt/hgfs/dd-edit-code/KTsgMod/./mhook/disasm-lib/disasm_x86.o):
