#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/cpu.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/gfp.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/kprobes.h>
#include <linux/dcache.h>
#include <linux/ctype.h>
#include <linux/syscore_ops.h>
#include <trace/events/sched.h>
#include <asm/msr.h>
#include <asm/processor.h>

#include <linux/kdebug.h>

static int tracked_pid = -1;
static int start;

static u64 pt_buffer;
static u64* topa;

#define TOPA_STOP	BIT_ULL(4)
#define TOPA_INT	BIT_ULL(2)
#define TOPA_END	BIT_ULL(0)

#define TRACE_EN	BIT_ULL(0)
#define CYC_EN		BIT_ULL(1)
#define CTL_OS		BIT_ULL(2)
#define CTL_USER	BIT_ULL(3)
#define CTL_PEWOR   BIT_ULL(4)
#define FUP_PTW     BIT_ULL(5)
#define FABRIC_EN   BIT_ULL(6)
#define CR3_FILTER	BIT_ULL(7)
#define TO_PA		BIT_ULL(8)
#define MTC_EN		BIT_ULL(9)
#define TSC_EN		BIT_ULL(10)
#define DIS_RETC	BIT_ULL(11)
#define PTW_EN		BIT_ULL(12)
#define BRANCH_EN	BIT_ULL(13)
#define MTC_MASK	(0xf << 14)
#define CYC_MASK	(0xf << 19)
#define PSB_MASK	(0xf << 24)

#define PT_ERROR	BIT_ULL(4)
#define STATUS_STOP		BIT_ULL(5)

static void wrmsr64_safe_on_cpu(int cpu, u32 reg, u64 val) {
    wrmsr_safe_on_cpu(cpu, reg, 
            (u32)((u64)(unsigned long)val),
            (u32)((u64)(unsigned long)val >> 32));
}

static void rdmsr64_safe_on_cpu(int cpu, u32 reg, u64* val) {
    rdmsr_safe_on_cpu(cpu, reg, (u32*)val, (u32*)val+1);
}

static int init_mask_ptrs(void) {
    // config ToPA
    wrmsr64_safe_on_cpu(0, MSR_IA32_RTIT_OUTPUT_BASE, __pa(topa));
    wrmsr64_safe_on_cpu(0, MSR_IA32_RTIT_OUTPUT_MASK, 0ULL);
    // config pt
    wrmsr64_safe_on_cpu(0, MSR_IA32_RTIT_STATUS, 0ULL);
    return 0;
}

static int pt_start(void) {
    struct task_struct* task = NULL;
    u64 cr3, ctl;
    rdmsr64_safe_on_cpu(0, MSR_IA32_RTIT_CTL, &ctl);
    if(ctl & TRACE_EN) {
        pr_err("pt have started\n");
        return -EINVAL;
    }
    if(tracked_pid == -1) {
        pr_err("tracked pid not set\n");
        return -EINVAL;
    }
    // set cr3 filtering
    task = pid_task(find_vpid(tracked_pid), PIDTYPE_PID);
    if(!task) {
        pr_err("pid %d task not found\n", tracked_pid);
        return -EINVAL;
    }
    pr_err("pid %d find task succeeded\n", tracked_pid);
    cr3 = (u64)__pa(task->mm->pgd);
    wrmsr64_safe_on_cpu(0, MSR_IA32_RTIT_CR3_MATCH, cr3);
    pr_err("set cr3 succeeded: %llx\n", cr3);
    // write pt ctl
    init_mask_ptrs();
    ctl |= TRACE_EN;
    wrmsr64_safe_on_cpu(0, MSR_IA32_RTIT_CTL, ctl);
    pr_err("pt contorl succeeded\n");
    pr_info("start pt succeed, ctl: %llx\n", ctl);
    return 0;
}

static int pt_stop(void) {
    u64 ctl;
    rdmsr64_safe_on_cpu(0, MSR_IA32_RTIT_CTL, &ctl);
    if(!(ctl & TRACE_EN)) {
        pr_err("pt have stoped\n");
        return -EINVAL;
    }
    ctl &= ~TRACE_EN;
    wrmsr64_safe_on_cpu(0, MSR_IA32_RTIT_CTL, ctl);
    pr_info("stop pt succeed\n");
    return 0;
}

static int start_set(const char *val, const struct kernel_param *kp)
{
    int ret;
    ret = param_set_int(val, kp);
    pr_info("reach start_set, val: %d\n", start);
    if(start == 1)
        pt_start();
    else
        pt_stop();
    return ret;
}

static int pid_set(const char *val, const struct kernel_param *kp)
{
    int ret;
    ret = param_set_int(val, kp);
    pr_info("reach pid_set, val: %d\n", tracked_pid);
    return ret;
}

static struct kernel_param_ops start_ops = {
	.set = start_set,
	.get = param_get_int,
};

static struct kernel_param_ops pid_ops = {
	.set = pid_set,
	.get = param_get_int,
};

module_param_cb(start, &start_ops, &start, 0644);
MODULE_PARM_DESC(start, "Set to 1 to start trace, or 0 to stop");
module_param_cb(pid, &pid_ops, &tracked_pid, 0644);
MODULE_PARM_DESC(pid, "Set to pid to be tracked");

static int init_buffer(void) {
    pt_buffer = __get_free_pages(GFP_KERNEL|__GFP_ZERO, 0);
    if (!pt_buffer) {
        pr_warn("Cannot allocate pt buffer\n");
        return -ENOMEM;
	}
    pr_info("allocate pt_buffer succeed: %llx\n", pt_buffer);
    topa = (u64*)__get_free_page(GFP_KERNEL|__GFP_ZERO);
    if (!topa) {
        pr_warn("Cannot allocate topa\n");
        free_page(pt_buffer);
        pt_buffer = 0UL;
        return -ENOMEM;
	}
    pr_info("allocate topa succeed: %p\n", topa);
    topa[0] = (u64)__pa(pt_buffer) | (0 << 6) | TOPA_INT;
    // topa[1] = (u64)__pa(topa) | TOPA_END;
    return 0;
}

static int free_buffer(void) {
    if(pt_buffer) {
        free_page(pt_buffer);
        pt_buffer = 0UL;
    }
    if(topa) {
        free_page((u64)topa);
        topa = NULL;
    }
    return 0;
}

static int __kprobes pt_int_handler(struct notifier_block *self, unsigned long cmd, void *__args) {
    printk(KERN_INFO "reach pt PMI interrupt!!\n");
    pr_err("current cpu: %d\n", get_cpu());
    // apic_write(APIC_LVTPC,APIC_DM_NMI);
    pt_stop();

    return NOTIFY_STOP;
}

static __read_mostly struct notifier_block pt_int_notifier = {
    .notifier_call          = pt_int_handler,
    .next                   = NULL,
    .priority               = 0
};

static int register_pmi_handler(void) {
    u32 lvtpc = apic_read(APIC_LVTPC);
    pr_info("lvt pc: %x\n", lvtpc);
    apic_write(APIC_LVTPC,APIC_DM_NMI);
    register_die_notifier(&pt_int_notifier);
    return 0;
}

static int unregister_pmi_handler(void) {
    unregister_die_notifier(&pt_int_notifier);
    return 0;
}

/*
static const struct file_operations pt_fops = {
	.owner = THIS_MODULE,
	.mmap =	simple_pt_mmap,
	.unlocked_ioctl = simple_pt_ioctl,
	.llseek = noop_llseek,
};

static struct miscdevice simple_pt_miscdev = {
	MISC_DYNAMIC_MINOR,
	"pt-module",
	&pt_fops
};

static int register_device(void) {
    int err;
    err = misc_register(&pt_miscdev);	// register device
	if (err < 0) {
		pr_err("Cannot register simple-pt device\n");
		return err;
	}
}
*/
static int config_pt(void) {
    u64 ctl = 0;
    // rdmsr64_safe_on_cpu(0, MSR_IA32_RTIT_CTL, &ctl);
    ctl |= CTL_USER | TO_PA | DIS_RETC | BRANCH_EN;
    wrmsr64_safe_on_cpu(0, MSR_IA32_RTIT_CTL, ctl);
    return 0;
}

static int pt_init(void) {
    int err;
    printk("Hello init module\n");
    // allocate buffer
    err = init_buffer();
    if(err) {
        pr_err("init module failed when init buffer\n");
        return err;
    }
    // regiter pmi handler
    err = register_pmi_handler();
    if(err) {
        pr_err("init module failed when register pmi handler\n");
        free_buffer();
        return err;
    }
    err = config_pt();
    if(err) {
        pr_err("init module failed when config pt\n");
        free_buffer();
        unregister_pmi_handler();
        return err;
    }
    // init pota msr
    err = init_mask_ptrs();
    if(err) {
        pr_err("init module failed when init pota msr\n");
        free_buffer();
        unregister_pmi_handler();
        return err;
    }
    // register device
    // register_device();
    printk("init module done\n");
    
    return 0;
}

static void pt_exit(void) {
    u64 offset;
    printk("Goodbye init module\n");
    rdmsr64_safe_on_cpu(0, MSR_IA32_RTIT_OUTPUT_MASK, &offset);
    pr_info("buffer offset: %llx\n", offset >> 32);
    free_buffer();
    unregister_pmi_handler();
}

module_init(pt_init);
module_exit(pt_exit);
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("skyin");