/******************************************************************************
 *
 * Fix ptrace issue for MIPS architecture
 *
 *****************************************************************************/

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/unistd.h>
#include <asm/cacheflush.h>
#include <linux/ptrace.h>
#include <linux/smp_lock.h>
#include <linux/err.h>

/*****************************************************************************/
/*                               DEFINES                                     */
/*****************************************************************************/

#define NR_PTRACE (26)

/*****************************************************************************/
/*                                 TYPES                                     */
/*****************************************************************************/

long (*old_sys_ptrace)(long  request, long  pid, long  addr, long  data);
typedef struct task_struct *(*lkp_find_task_by_vpid_t)(pid_t vnr);
typedef int (* lkp_ptrace_check_attach_t)(struct task_struct *child, int kill);
typedef int (* lkp_ptrace_request_t)(struct task_struct *child, long request,
		   long addr, long data);
typedef int (*lkp_wake_up_state_t)(struct task_struct *p, unsigned int state);

typedef struct syscall_entry_t {
	void *addr;
	unsigned int argc;
} syscall_entry;

lkp_find_task_by_vpid_t lkp_find_task_by_vpid;
lkp_ptrace_check_attach_t lkp_ptrace_check_attach;
lkp_ptrace_request_t lkp_ptrace_request;
lkp_wake_up_state_t lkp_wake_up_state;

/*****************************************************************************/
/*                               LOCAL FUNCTIONS                             */
/*****************************************************************************/

static int lookup_func(void *data, const char *sym, struct module *mod, unsigned long addr)
{
	if(0 == strcmp((char*)data, sym))
	{
		return addr;
	}
	else
	{
		return 0;
	}
}

static unsigned int find_name(const char *name)
{
	return kallsyms_on_each_symbol(lookup_func, (void *)name);
}

static struct task_struct *ptrace_get_task_struct(pid_t pid)
{
	struct task_struct *child;

	rcu_read_lock();
	child = lkp_find_task_by_vpid(pid);
	if (child)
		get_task_struct(child);
	rcu_read_unlock();

	if (!child)
		return ERR_PTR(-ESRCH);
	return child;
}

static void ptrace_unfreeze_traced(struct task_struct *task)
{
	if (task->state != __TASK_TRACED)
		return;

	WARN_ON(!task->ptrace || task->parent != current);

	spin_lock_irq(&task->sighand->siglock);
	if (__fatal_signal_pending(task))
		lkp_wake_up_state(task, __TASK_TRACED);
	else
		task->state = TASK_TRACED;
	spin_unlock_irq(&task->sighand->siglock);
}

static long new_sys_ptrace(long request, long pid, long addr, long data)
{
	struct task_struct *child;
	long ret = 0;

	switch (request) {
	case PTRACE_SYSCALL:
	case PTRACE_CONT:
	case PTRACE_KILL:
		lock_kernel();
		child = ptrace_get_task_struct(pid);
		if (IS_ERR(child)) {
			ret = PTR_ERR(child);
			goto unlock;
		}
		ret = lkp_ptrace_check_attach(child, request == PTRACE_KILL);
		if (ret < 0)
			goto out_put_task_struct;
		ret = lkp_ptrace_request(child, request, addr, data);
		if (ret)
			ptrace_unfreeze_traced(child);
		break;
	default:
		ret = old_sys_ptrace(request, pid, addr, data);
		goto out;
		break;
	}

out_put_task_struct:
	put_task_struct(child);
unlock:
	unlock_kernel();
out:
	return ret;
}

static int ptrace_fix_init(void)
{
	long ret = 0;

	syscall_entry *sys_call_table = (syscall_entry *)find_name("sys_call_table");
	printk("sys_call_table = %p\n", sys_call_table);

	if (NULL != sys_call_table)
	{
		lkp_find_task_by_vpid = (lkp_find_task_by_vpid_t)find_name("find_task_by_vpid");
		if (NULL == lkp_find_task_by_vpid)
		{
			printk("Failed to find find_task_by_vpid\n");
			ret = -EFAULT;
			goto out;
		}
		lkp_ptrace_check_attach = (lkp_ptrace_check_attach_t)find_name("ptrace_check_attach");
		if (NULL == lkp_ptrace_check_attach)
		{
			printk("Failed to find ptrace_check_attach\n");
			ret = -EFAULT;
			goto out;
		}
		lkp_ptrace_request = (lkp_ptrace_request_t)find_name("ptrace_request");
		if (NULL == lkp_ptrace_request)
		{
			printk("Failed to find ptrace_request\n");
			ret = -EFAULT;
			goto out;
		}
		lkp_wake_up_state = (lkp_wake_up_state_t)find_name("wake_up_state");
		if (NULL == lkp_wake_up_state)
		{
			printk("Failed to find wake_up_state\n");
			ret = -EFAULT;
			goto out;
		}

		old_sys_ptrace = sys_call_table[NR_PTRACE].addr;
		sys_call_table[NR_PTRACE].addr = new_sys_ptrace;
		printk("New ptrace addr = %p\n", sys_call_table[NR_PTRACE].addr);
	}
	else
	{
		printk("Failed to find sys_call_table\n");
		ret = -EFAULT;
	}
out:
	return ret;
}

static void ptrace_fix_fini(void)
{
	if (NULL != old_sys_ptrace)
	{
		syscall_entry *sys_call_table = (syscall_entry *)find_name("sys_call_table");
		if (NULL != sys_call_table)
		{
			sys_call_table[NR_PTRACE].addr = old_sys_ptrace;
		}
		else
		{
			printk("Failed to find sys_call_table\n");
		}
	}
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xklts 0xklts@protonmain.com");
MODULE_DESCRIPTION("Fix ptrace bug for MIPS kernel 2.6.32. 55436c91652b45be576b91ec96a8d65f6b7447fa");

module_init(ptrace_fix_init);
module_exit(ptrace_fix_fini);
