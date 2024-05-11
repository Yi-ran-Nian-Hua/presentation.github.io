---
# try also 'default' to start simple
theme: default
# random image from a curated Unsplash collection by Anthony
# like them? see https://unsplash.com/collections/94734566/slidev
# background: https://cover.sli.dev
# some information about your slides, markdown enabled
title: 嵌入式系统设计
info: |
  ## Slidev Starter Template
  Presentation slides for developers.

  Learn more at [Sli.dev](https://sli.dev)
# apply any unocss classes to the current slide
class: text-center
# https://sli.dev/custom/highlighters.html
highlighter: shiki
# https://sli.dev/guide/drawing
drawings:
  persist: false
# slide transition: https://sli.dev/guide/animations#slide-transitions
transition: slide-left
# enable MDC Syntax: https://sli.dev/guide/syntax#mdc-syntax
mdc: true
hideInToc: true
lineNumbers: true
---

# 嵌入式系统设计小组汇报

尹彦江、高万胜、林秋霞

汇报人：尹彦江

<div class="pt-12">
  <span @click="$slidev.nav.next" class="px-2 py-1 rounded cursor-pointer" hover="bg-white bg-opacity-10">
    Press Space for next page <carbon:arrow-right class="inline"/>
  </span>
</div>



<!--
The last comment block of each slide will be treated as slide notes. It will be visible and editable in Presenter Mode along with the slide. [Read more in the docs](https://sli.dev/guide/syntax.html#notes)
-->

---
transition: fade-out
hideInToc: true
---

# Contents

<Toc columns="1" maxDepth="1"/>
<!--
You can have `style` tag in markdown to override the style for the current page.
Learn more: https://sli.dev/guide/syntax#embedded-styles
-->

<style>
h1 {
  background-color: #2B90B6;
  background-image: linear-gradient(45deg, #4EC5D4 10%, #146b8c 20%);
  background-size: 100%;
  -webkit-background-clip: text;
  -moz-background-clip: text;
  -webkit-text-fill-color: transparent;
  -moz-text-fill-color: transparent;
}
</style>

<!--
Here is another comment.
-->

---
transition: slide-up
title: 小组分工与实验环境
---

# 小组选题与分工

- 选题
  - 选题一
  - 选题四

- 分工
  - 尹彦江：完成选题四
  - 林秋霞：完成选题一基础结构搭建
  - 高万胜：完成选题一进程通信

---
layout: two-cols-header
layoutClass: gap-16
---

# 实验环境
<template v-slot:left>

### 选题一实验环境
- CPU：Apple Silicon M2 Pro
- Python版本：3.11
</template>

<template v-slot:right>

### 选题四实验环境
- x86实验环境
  - CPU: Intel Core i7-9750H
  - Ubuntu版本：22.04.4-amd64
  - Linux内核版本：6.5.0-28-generic
- ARM实验环境
  - CPU：Apple Silicon M2 Pro
  - Ubuntu版本：22.04.2-ARM64
  - Linux内核版本：5.15.0-105-generic
</template>

---
layout: section
title: 实验一设计思路
---
# 实验一设计思路

---
layout: default
level: 2
---
# 实验一设计思路

// TODO: 这里要完成调度动画展示

---
layout: section
title: 实验一代码实现
---
# 实验一代码实现

---
layoud: default
level: 2
---
# 实验一代码实现——`Core`类定义

<div class="code-blocks" style="width: 850px; height: 400px; overflow-y: scroll;">
````md magic-move
```python{none|2-7|9-22|25-30|all}
# Core类定义
class Core(threading.Thread):
    def __init__(self, core_id, task_queue):
        super().__init__()
        self.core_id = core_id  # core id，which is unique
        self.task_queue = task_queue  # task queue, to get the task
        self.stop_signal = False  # a signal, to notice the core when to stop

    def run(self) -> None:
        """
        In each loop, every core try to get a task from the task queue,
        if get a task, then invoke the process method, else catch the
        queue.Empty exception and keep waiting
        :return: none
        """
        while not self.stop_signal:
            try:
                task = self.task_queue.get(timeout = 1)  # wait for task
                task.process(self.core_id)  # handle the task
                self.task_queue.task_done()
            except queue.Empty:
                continue


    def stop(self) -> None:
        """
        set stop_signal to True to ask the core stop the task elegantly
        :return: none
        """
        self.stop_signal = True
```

```python{all|7-8|11-29|18-22|30-37}
# Core类定义（添加消息队列）
class Core(threading.Thread):
    def __init__(self, core_id, task_queue, lock):
        super().__init__()
        self.core_id = core_id  # core id，which is unique
        self.task_queue = task_queue  # task queue, to get the task
        self.lock = lock  # the lock
        self.message_queue = queue.Queue()  # each core's message queue
        self.stop_signal = False  # a signal, to notice the core when to stop

    def run(self) -> None:
        """
        In each loop, every core try to get a task from the task queue,
        if get a task, then invoke the process method, else catch the
        queue.Empty exception and keep waiting
        :return: none
        """
        while not self.stop_signal:
            if not self.message_queue.empty():
                with self.lock:  # get the lock to read the message
                    message = self.message_queue.get()
                    print(f"Core {self.core_id} received message: {message}")
            try:
                task = self.task_queue.get(timeout=1)  # wait for task
                with self.lock:  # get the lock to process the task
                    task.process(self.core_id)  # handle the task
                self.task_queue.task_done()
            except queue.Empty:
                continue

    def send_messsage(self, message) -> None:
        """
        To allow a core puts a message to another core's message_queue
        :param message: the message will be sent
        :return: None
        """
        self.message_queue.put(message)

    def stop(self) -> None:
        """
        set stop_signal to True to ask the core stop the task elegantly
        :return: none
        """
        self.stop_signal = True
```


````
</div>



---
layout: default
level: 2
---
# 实验一代码实现——`Task`类定义
<br>

```python{none|2-5|7-14|all}
# Task类定义
class Task:
    def __init__(self, task_id, duration):
        self.task_id = task_id  # task id, which is unique
        self.duration = duration   # the task duration time, to simulate different processing requirement

    def process(self, core_id) -> None:
        """
        Simulate the processing for a task
        :param core_id: which core will process this task
        :return: None
        """
        print(f"Core {core_id} is processing Task {self.task_id}")
        time.sleep(self.duration)  # we can use time.sleep to simulate the task's duration time

```

---
layout: default
level: 2
---
# 实验一代码实现——`Scheduler`类定义

<div class="code-blocks" style="width: 850px; height: 400px; overflow-y: scroll;">
````md magic-move
```python{2|6-8|10-16|18-25|27-36|all}
# Scheduler类定义
class Scheduler:
    """
    Class Scheduler
    """
    def __init__(self, num_cores):
        self.task_queue = queue.Queue()
        self.cores = [Core(i, self.task_queue) for i in range(num_cores)]

    def start(self) -> None:
        """
        start each thread of the core, start to wait for task
        :return: None
        """
        for core in self.cores:
            core.start()

    def add_task(self, task) -> None:
        """
        To allow add a new task to the queue, then these tasks will be handled
        by the core thread
        :param task: the task which will be handled
        :return: None
        """
        self.task_queue.put(task)

    def stop(self) -> None:
        """
        Inform all of the cores to stop processing, and wait them until
        all of the cores are stop
        :return: None
        """
        for core in self.cores:
            core.stop()
        for core in self.cores:
            core.join()

```

```python{all|8-9|27-37}
# Scheduler定义（添加锁与消息队列）
class Scheduler:
    """
    Class Scheduler
    """
    def __init__(self, num_cores):
        self.task_queue = queue.Queue()
        self.lock = threading.Lock()  # the lock which is used with all the cores
        self.cores = [Core(i, self.task_queue, self.lock) for i in range(num_cores)]

    def start(self) -> None:
        """
        start each thread of the core, start to wait for task
        :return: None
        """
        for core in self.cores:
            core.start()

    def add_task(self, task) -> None:
        """
        To allow add a new task to the queue, then these tasks will be handled
        by the core thread
        :param task: the task which will be handled
        :return: None
        """
        self.task_queue.put(task)

    def send_message(self, sender_id, receiver_id, message) -> None:
        """
        To allow the message sending among the processors
        :param sender_id: which core send the message
        :param receiver_id: which core receive the message
        :param message: the message
        :return: None
        """
        message_formatted = f"from Core {sender_id}: {message}"
        self.cores[receiver_id].send_messsage(message_formatted)

    def stop(self) -> None:
        """
        Inform all of the cores to stop processing, and wait them until
        all of the cores are stop
        :return: None
        """
        for core in self.cores:
            core.stop()
        for core in self.cores:
            core.join()
```
````
</div>

---
layout: default
level: 2
---
# 实验一代码实现——测试用例
```python
if __name__ == "__main__":
    # Create the scheduler object
    scheduler = Scheduler(num_cores=4)

    # Start all the cores
    scheduler.start()

    # Adding the tasks to the task queue
    for i in range(10):
        task = Task(i, random.uniform(0.1, 0.5))  # create the task, and set the duration time randomly
        scheduler.add_task(task)
        scheduler.send_message(random.randint(0,3), random.randint(0, 3),f"hi")

    # wait all the task finished
    scheduler.task_queue.join()

    # stop all the cores
    scheduler.stop()
```
---
layout: section
title: 选题四设计思路
---
# 选题四设计思路

---
layout: default
level: 2
---
# 选题四设计思路
- 进程树遍历函数编写
- Hook系统调用
  - 找到系统调用表地址
  - 找到空闲系统调用
  - 关闭内存写保护
  - 编写入口函数
- 执行系统调用

---
layout: section
title: 实验四代码实现
---
# 实验四代码实现

---
layout: default
level: 2
---
# 进程树遍历函数编写
#### `task_struct`结构体


<div class="code-blocks" style="width: 850px; height: 400px; overflow-y: scroll;">
````md magic-move

```c
// linux-$(uname -r)\include\linux\sched.h
struct task_struct {
#ifdef CONFIG_THREAD_INFO_IN_TASK
	/*
	 * For reasons of header soup (see current_thread_info()), this
	 * must be the first element of task_struct.
	 */
	struct thread_info thread_info;
#endif
	volatile long state;	/* -1 unrunnable, 0 runnable, >0 stopped */
	void *stack;
	atomic_t usage;
	unsigned int flags;	/* per process flags, defined below */
	unsigned int ptrace;
 
#ifdef CONFIG_SMP
	struct llist_node wake_entry;
	int on_cpu;
#ifdef CONFIG_THREAD_INFO_IN_TASK
	unsigned int cpu;	/* current CPU */
#endif
	unsigned int wakee_flips;
	unsigned long wakee_flip_decay_ts;
	struct task_struct *last_wakee;
 
	int wake_cpu;
#endif
	int on_rq;
 
	int prio, static_prio, normal_prio;
	unsigned int rt_priority;
	const struct sched_class *sched_class;
	struct sched_entity se;
	struct sched_rt_entity rt;
#ifdef CONFIG_SCHED_WALT
	struct ravg ravg;
	/*
	 * 'init_load_pct' represents the initial task load assigned to children
	 * of this task
	 */
	u32 init_load_pct;
#endif
 
#ifdef CONFIG_CGROUP_SCHED
	struct task_group *sched_task_group;
#endif
	struct sched_dl_entity dl;
#ifdef CONFIG_PREEMPT_NOTIFIERS
	/* list of struct preempt_notifier: */
	struct hlist_head preempt_notifiers;
#endif
 
#ifdef CONFIG_BLK_DEV_IO_TRACE
	unsigned int btrace_seq;
#endif
 
	unsigned int policy;
	int nr_cpus_allowed;
	cpumask_t cpus_allowed;
 
#ifdef CONFIG_PREEMPT_RCU
	int rcu_read_lock_nesting;
	union rcu_special rcu_read_unlock_special;
	struct list_head rcu_node_entry;
	struct rcu_node *rcu_blocked_node;
#endif /* #ifdef CONFIG_PREEMPT_RCU */
#ifdef CONFIG_TASKS_RCU
	unsigned long rcu_tasks_nvcsw;
	bool rcu_tasks_holdout;
	struct list_head rcu_tasks_holdout_list;
	int rcu_tasks_idle_cpu;
#endif /* #ifdef CONFIG_TASKS_RCU */
 
#ifdef CONFIG_SCHED_INFO
	struct sched_info sched_info;
#endif
 
	struct list_head tasks;
#ifdef CONFIG_SMP
	struct plist_node pushable_tasks;
	struct rb_node pushable_dl_tasks;
#endif
 
	struct mm_struct *mm, *active_mm;
	/* per-thread vma caching */
	u32 vmacache_seqnum;
	struct vm_area_struct *vmacache[VMACACHE_SIZE];
#if defined(SPLIT_RSS_COUNTING)
	struct task_rss_stat	rss_stat;
#endif
/* task state */
	int exit_state;
	int exit_code, exit_signal;
	int pdeath_signal;  /*  The signal sent when the parent dies  */
	unsigned long jobctl;	/* JOBCTL_*, siglock protected */
 
	/* Used for emulating ABI behavior of previous Linux versions */
	unsigned int personality;
 
	/* scheduler bits, serialized by scheduler locks */
	unsigned sched_reset_on_fork:1;
	unsigned sched_contributes_to_load:1;
	unsigned sched_migrated:1;
	unsigned sched_remote_wakeup:1;
	unsigned :0; /* force alignment to the next boundary */
 
	/* unserialized, strictly 'current' */
	unsigned in_execve:1; /* bit to tell LSMs we're in execve */
	unsigned in_iowait:1;
#if !defined(TIF_RESTORE_SIGMASK)
	unsigned restore_sigmask:1;
#endif
#ifdef CONFIG_MEMCG
	unsigned memcg_may_oom:1;
#ifndef CONFIG_SLOB
	unsigned memcg_kmem_skip_account:1;
#endif
#endif
#ifdef CONFIG_COMPAT_BRK
	unsigned brk_randomized:1;
#endif
#ifdef CONFIG_CGROUPS
	/* disallow userland-initiated cgroup migration */
	unsigned no_cgroup_migration:1;
#endif
 
	unsigned long atomic_flags; /* Flags needing atomic access. */
 
	struct restart_block restart_block;
	pid_t pid;
	pid_t tgid;
 
#ifdef CONFIG_CC_STACKPROTECTOR
	/* Canary value for the -fstack-protector gcc feature */
	unsigned long stack_canary;
#endif
	/*
	 * pointers to (original) parent process, youngest child, younger sibling,
	 * older sibling, respectively.  (p->father can be replaced with
	 * p->real_parent->pid)
	 */
	struct task_struct __rcu *real_parent; /* real parent process */
	struct task_struct __rcu *parent; /* recipient of SIGCHLD, wait4() reports */
	/*
	 * children/sibling forms the list of my natural children
	 */
	struct list_head children;	/* list of my children */
	struct list_head sibling;	/* linkage in my parent's children list */
	struct task_struct *group_leader;	/* threadgroup leader */
 
	/*
	 * ptraced is the list of tasks this task is using ptrace on.
	 * This includes both natural children and PTRACE_ATTACH targets.
	 * p->ptrace_entry is p's link on the p->parent->ptraced list.
	 */
	struct list_head ptraced;
	struct list_head ptrace_entry;
 
	/* PID/PID hash table linkage. */
	struct pid_link pids[PIDTYPE_MAX];
	struct list_head thread_group;
	struct list_head thread_node;
 
	struct completion *vfork_done;		/* for vfork() */
	int __user *set_child_tid;		/* CLONE_CHILD_SETTID */
	int __user *clear_child_tid;		/* CLONE_CHILD_CLEARTID */
	cputime_t utime, stime, utimescaled, stimescaled;
	cputime_t gtime;
	struct prev_cputime prev_cputime;
#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN
	seqcount_t vtime_seqcount;
	unsigned long long vtime_snap;
	enum {
		/* Task is sleeping or running in a CPU with VTIME inactive */
		VTIME_INACTIVE = 0,
		/* Task runs in userspace in a CPU with VTIME active */
		VTIME_USER,
		/* Task runs in kernelspace in a CPU with VTIME active */
		VTIME_SYS,
	} vtime_snap_whence;
#endif
#ifdef CONFIG_NO_HZ_FULL
	atomic_t tick_dep_mask;
#endif
	unsigned long nvcsw, nivcsw; /* context switch counts */
	u64 start_time;		/* monotonic time in nsec */
	u64 real_start_time;	/* boot based time in nsec */
/* mm fault and swap info: this can arguably be seen as either mm-specific or thread-specific */
	unsigned long min_flt, maj_flt;
 
	/* for thrashing accounting */
	unsigned long fm_flt;
#ifdef CONFIG_SWAP
	unsigned long swap_in, swap_out;
#endif
	struct task_cputime cputime_expires;
	struct list_head cpu_timers[3];
 
/* process credentials */
	const struct cred __rcu *ptracer_cred; /* Tracer's credentials at attach */
	const struct cred __rcu *real_cred; /* objective and real subjective task
					 * credentials (COW) */
	const struct cred __rcu *cred;	/* effective (overridable) subjective task
					 * credentials (COW) */
	char comm[TASK_COMM_LEN]; /* executable name excluding path
				     - access with [gs]et_task_comm (which lock
				       it with task_lock())
				     - initialized normally by setup_new_exec */
/* file system info */
	struct nameidata *nameidata;
#ifdef CONFIG_SYSVIPC
/* ipc stuff */
	struct sysv_sem sysvsem;
	struct sysv_shm sysvshm;
#endif
#ifdef CONFIG_DETECT_HUNG_TASK
/* hung task detection */
	unsigned long last_switch_count;
#endif
/* filesystem information */
	struct fs_struct *fs;
/* open file information */
	struct files_struct *files;
/* namespaces */
	struct nsproxy *nsproxy;
/* signal handlers */
	struct signal_struct *signal;
	struct sighand_struct *sighand;
	sigset_t blocked, real_blocked;
	sigset_t saved_sigmask;	/* restored if set_restore_sigmask() was used */
	struct sigpending pending;
 
	unsigned long sas_ss_sp;
	size_t sas_ss_size;
	unsigned sas_ss_flags;
 
	struct callback_head *task_works;
 
	struct audit_context *audit_context;
#ifdef CONFIG_AUDITSYSCALL
	kuid_t loginuid;
	unsigned int sessionid;
#endif
	struct seccomp seccomp;
 
/* Thread group tracking */
   	u32 parent_exec_id;
   	u32 self_exec_id;
/* Protection of (de-)allocation: mm, files, fs, tty, keyrings, mems_allowed,
 * mempolicy */
	spinlock_t alloc_lock;
 
	/* Protection of the PI data structures: */
	raw_spinlock_t pi_lock;
 
	struct wake_q_node wake_q;
 
#ifdef CONFIG_RT_MUTEXES
	/* PI waiters blocked on a rt_mutex held by this task */
	struct rb_root pi_waiters;
	struct rb_node *pi_waiters_leftmost;
	/* Deadlock detection and priority inheritance handling */
	struct rt_mutex_waiter *pi_blocked_on;
#endif
 
#ifdef CONFIG_DEBUG_MUTEXES
	/* mutex deadlock detection */
	struct mutex_waiter *blocked_on;
#endif
#ifdef CONFIG_TRACE_IRQFLAGS
	unsigned int irq_events;
	unsigned long hardirq_enable_ip;
	unsigned long hardirq_disable_ip;
	unsigned int hardirq_enable_event;
	unsigned int hardirq_disable_event;
	int hardirqs_enabled;
	int hardirq_context;
	unsigned long softirq_disable_ip;
	unsigned long softirq_enable_ip;
	unsigned int softirq_disable_event;
	unsigned int softirq_enable_event;
	int softirqs_enabled;
	int softirq_context;
#endif
#ifdef CONFIG_LOCKDEP
# define MAX_LOCK_DEPTH 48UL
	u64 curr_chain_key;
	int lockdep_depth;
	unsigned int lockdep_recursion;
	struct held_lock held_locks[MAX_LOCK_DEPTH];
	gfp_t lockdep_reclaim_gfp;
#endif
#ifdef CONFIG_UBSAN
	unsigned int in_ubsan;
#endif
 
/* journalling filesystem info */
	void *journal_info;
 
/* stacked block device info */
	struct bio_list *bio_list;
 
#ifdef CONFIG_BLOCK
/* stack plugging */
	struct blk_plug *plug;
#endif
 
/* VM state */
	struct reclaim_state *reclaim_state;
 
	struct backing_dev_info *backing_dev_info;
 
	struct io_context *io_context;
	unsigned long ptrace_message;
	siginfo_t *last_siginfo; /* For ptrace use.  */
	struct task_io_accounting ioac;
#if defined(CONFIG_TASK_XACCT)
	u64 acct_rss_mem1;	/* accumulated rss usage */
	u64 acct_vm_mem1;	/* accumulated virtual memory usage */
	cputime_t acct_timexpd;	/* stime + utime since last update */
#endif
#ifdef CONFIG_CPUSETS
	nodemask_t mems_allowed;	/* Protected by alloc_lock */
	seqcount_t mems_allowed_seq;	/* Seqence no to catch updates */
	int cpuset_mem_spread_rotor;
	int cpuset_slab_spread_rotor;
#endif
#ifdef CONFIG_CGROUPS
	/* Control Group info protected by css_set_lock */
	struct css_set __rcu *cgroups;
	/* cg_list protected by css_set_lock and tsk->alloc_lock */
	struct list_head cg_list;
#endif
#ifdef CONFIG_FUTEX
	struct robust_list_head __user *robust_list;
#ifdef CONFIG_COMPAT
	struct compat_robust_list_head __user *compat_robust_list;
#endif
	struct list_head pi_state_list;
	struct futex_pi_state *pi_state_cache;
#endif
#ifdef CONFIG_PERF_EVENTS
	struct perf_event_context *perf_event_ctxp[perf_nr_task_contexts];
	struct mutex perf_event_mutex;
	struct list_head perf_event_list;
#endif
#ifdef CONFIG_DEBUG_PREEMPT
	unsigned long preempt_disable_ip;
#endif
#ifdef CONFIG_NUMA
	struct mempolicy *mempolicy;	/* Protected by alloc_lock */
	short il_next;
	short pref_node_fork;
#endif
#ifdef CONFIG_NUMA_BALANCING
	int numa_scan_seq;
	unsigned int numa_scan_period;
	unsigned int numa_scan_period_max;
	int numa_preferred_nid;
	unsigned long numa_migrate_retry;
	u64 node_stamp;			/* migration stamp  */
	u64 last_task_numa_placement;
	u64 last_sum_exec_runtime;
	struct callback_head numa_work;
	struct list_head numa_entry;
	struct numa_group *numa_group;
 
	/*
	 * numa_faults is an array split into four regions:
	 * faults_memory, faults_cpu, faults_memory_buffer, faults_cpu_buffer
	 * in this precise order.
	 *
	 * faults_memory: Exponential decaying average of faults on a per-node
	 * basis. Scheduling placement decisions are made based on these
	 * counts. The values remain static for the duration of a PTE scan.
	 * faults_cpu: Track the nodes the process was running on when a NUMA
	 * hinting fault was incurred.
	 * faults_memory_buffer and faults_cpu_buffer: Record faults per node
	 * during the current scan window. When the scan completes, the counts
	 * in faults_memory and faults_cpu decay and these values are copied.
	 */
	unsigned long *numa_faults;
	unsigned long total_numa_faults;
 
	/*
	 * numa_faults_locality tracks if faults recorded during the last
	 * scan window were remote/local or failed to migrate. The task scan
	 * period is adapted based on the locality of the faults with different
	 * weights depending on whether they were shared or private faults
	 */
	unsigned long numa_faults_locality[3];
 
	unsigned long numa_pages_migrated;
#endif /* CONFIG_NUMA_BALANCING */
 
#ifdef CONFIG_ARCH_WANT_BATCHED_UNMAP_TLB_FLUSH
	struct tlbflush_unmap_batch tlb_ubc;
#endif
	struct rcu_head rcu;
 
	/*
	 * cache last used pipe for splice
	 */
	struct pipe_inode_info *splice_pipe;
 
	struct page_frag task_frag;
 
#ifdef	CONFIG_TASK_DELAY_ACCT
	struct task_delay_info *delays;
#endif
#ifdef CONFIG_FAULT_INJECTION
	int make_it_fail;
#endif
	/*
	 * when (nr_dirtied >= nr_dirtied_pause), it's time to call
	 * balance_dirty_pages() for some dirty throttling pause
	 */
	int nr_dirtied;
	int nr_dirtied_pause;
	unsigned long dirty_paused_when; /* start of a write-and-pause period */
 
#ifdef CONFIG_LATENCYTOP
	int latency_record_count;
	struct latency_record latency_record[LT_SAVECOUNT];
#endif
	/*
	 * time slack values; these are used to round up poll() and
	 * select() etc timeout values. These are in nanoseconds.
	 */
	u64 timer_slack_ns;
	u64 default_timer_slack_ns;
 
#ifdef CONFIG_KASAN
	unsigned int kasan_depth;
#endif
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	/* Index of current stored address in ret_stack */
	int curr_ret_stack;
	/* Stack of return addresses for return function tracing */
	struct ftrace_ret_stack	*ret_stack;
	/* time stamp for last schedule */
	unsigned long long ftrace_timestamp;
	/*
	 * Number of functions that haven't been traced
	 * because of depth overrun.
	 */
	atomic_t trace_overrun;
	/* Pause for the tracing */
	atomic_t tracing_graph_pause;
#endif
#ifdef CONFIG_TRACING
	/* state flags for use by tracers */
	unsigned long trace;
	/* bitmask and counter of trace recursion */
	unsigned long trace_recursion;
#endif /* CONFIG_TRACING */
#ifdef CONFIG_KCOV
	/* Coverage collection mode enabled for this task (0 if disabled). */
	enum kcov_mode kcov_mode;
	/* Size of the kcov_area. */
	unsigned	kcov_size;
	/* Buffer for coverage collection. */
	void		*kcov_area;
	/* kcov desciptor wired with this task or NULL. */
	struct kcov	*kcov;
#endif
#ifdef CONFIG_MEMCG
	struct mem_cgroup *memcg_in_oom;
	gfp_t memcg_oom_gfp_mask;
	int memcg_oom_order;
 
	/* number of pages to reclaim on returning to userland */
	unsigned int memcg_nr_pages_over_high;
#endif
#ifdef CONFIG_UPROBES
	struct uprobe_task *utask;
#endif
#if defined(CONFIG_BCACHE) || defined(CONFIG_BCACHE_MODULE)
	unsigned int	sequential_io;
	unsigned int	sequential_io_avg;
#endif
#ifdef CONFIG_DEBUG_ATOMIC_SLEEP
	unsigned long	task_state_change;
#endif
	int pagefault_disabled;
#ifdef CONFIG_MMU
	struct task_struct *oom_reaper_list;
#endif
#ifdef CONFIG_VMAP_STACK
	struct vm_struct *stack_vm_area;
#endif
#ifdef CONFIG_THREAD_INFO_IN_TASK
	/* A live task holds one reference. */
	atomic_t stack_refcount;
#endif
 
#ifdef CONFIG_PREEMPT_MONITOR
	unsigned long preempt_dur;
#endif
/* CPU-specific state of this task */
	struct thread_struct thread;
/*
 * WARNING: on x86, 'thread_struct' contains a variable-sized
 * structure.  It *MUST* be at the end of 'task_struct'.
 *
 * Do not put anything below here!
 */
};
```


```c{all|10-11}
// linux-$(uname -r)\include\linux\sched.h
struct task_struct {
    ...
	pid_t pid;
	pid_t tgid;
    ...
	struct task_struct __rcu *real_parent; /* real parent process */
	struct task_struct __rcu *parent; /* recipient of SIGCHLD, wait4() reports */
	...
	struct list_head children;	/* list of my children */
	struct list_head sibling;	/* linkage in my parent's children list */
	...
};
```
````
</div>

---
layout: two-cols
layoutClass: gap-16
level: 2
---

# 进程遍历函数编写

<div class="code-blocks">
```c
// linux-$(uname -r)\include\linux\types.h
struct list_head{
  struct list_head* prev;
  struct list_head* next;
}

```
</div>
<img src="/1.png">
::right::
<h3 style="padding-bottom: 0; text-align:center;">...</h3>
<img src="/struct.png" style="padding-top: 20px;">
<img src="/struct.png" style="padding-top: 60px;">
<img src="/struct.png" style="padding-top: 60px; padding-bottom: 20px;">
<h3 style="padding-top: 0; text-align:center;">...</h3>

---
layout: default
level: 2
---
# 进程遍历函数的编写

````md magic-move
```c {all|14|16}
void preorder_traversal_processtree(struct task_struct *p_task, int b){
    struct list_head *list; // 兄弟链表
    a[counter].pid = p_task->pid;
    a[counter].depth = b; // 记录当前遍历深度
    // 用来确定是否为链表中最后一个兄弟进程
    if (p_task->sibling.next == &(p_task->parent->children)){
        a[counter].have_brother = 0;
    }
    else{
        a[counter].have_brother = 1;
    }
    strcpy(a[counter].name, p_task->comm); // 存储当前进程的进程名
    counter++;
    list_for_each(list, &p_task->children) // 遍历兄弟进程并进行递归{
        printk("for loop\n");
        struct task_struct *t = list_entry(list, struct task_struct, sibling);
        printk("success list_entry()\n");
        preorder_traversal_processtree(t, b + 1);
    }
}
```

```c
// linux-$(uname -r)\include\linux\list.h
/**
 * list_for_each	-	iterate over a list
 * @pos:	the &struct list_head to use as a loop cursor.
 * @head:	the head for your list.
 */
#define list_for_each(pos, head) \
	for (pos = (head)->next; !list_is_head(pos, (head)); pos = pos->next)

```
```c {14|16}
void preorder_traversal_processtree(struct task_struct *p_task, int b){
    struct list_head *list; // 兄弟链表
    a[counter].pid = p_task->pid;
    a[counter].depth = b; // 记录当前遍历深度
    // 用来确定是否为链表中最后一个兄弟进程
    if (p_task->sibling.next == &(p_task->parent->children)){
        a[counter].have_brother = 0;
    }
    else{
        a[counter].have_brother = 1;
    }
    strcpy(a[counter].name, p_task->comm); // 存储当前进程的进程名
    counter++;
    list_for_each(list, &p_task->children) // 遍历兄弟进程并进行递归{
        printk("for loop\n");
        struct task_struct *t = list_entry(list, struct task_struct, sibling);
        printk("success list_entry()\n");
        preorder_traversal_processtree(t, b + 1);
    }
}
```

```c{all|9}
// linux-$(uname -r)\include\linux\list.h
/**
 * list_entry - get the struct for this entry
 * @ptr:	the &struct list_head pointer.
 * @type:	the type of the struct this is embedded in.
 * @member:	the name of the list_head within the struct.
 */
#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)
```

```c{all|10|11|14}
// linux-$(uname -r)\include\linux\kernel.h
/**
 * container_of - cast a member of a structure out to the containing structure
 * @ptr:	the pointer to the member.
 * @type:	the type of the container struct this is embedded in.
 * @member:	the name of the member within the struct.
 *
 */
#define container_of(ptr, type, member) ({				\
	void *__mptr = (void *)(ptr);					\
	BUILD_BUG_ON_MSG(!__same_type(*(ptr), ((type *)0)->member) &&	\
			 !__same_type(*(ptr), void),			\
			 "pointer type mismatch in container_of()");	\
	((type *)(__mptr - offsetof(type, member))); })

```
```c {all}
void preorder_traversal_processtree(struct task_struct *p_task, int b){
    struct list_head *list; // 兄弟链表
    a[counter].pid = p_task->pid;
    a[counter].depth = b; // 记录当前遍历深度
    // 用来确定是否为链表中最后一个兄弟进程
    if (p_task->sibling.next == &(p_task->parent->children)){
        a[counter].have_brother = 0;
    }
    else{
        a[counter].have_brother = 1;
    }
    strcpy(a[counter].name, p_task->comm); // 存储当前进程的进程名
    counter++;
    list_for_each(list, &p_task->children) // 遍历兄弟进程并进行递归{
        printk("for loop\n");
        struct task_struct *t = list_entry(list, struct task_struct, sibling);
        printk("success list_entry()\n");
        preorder_traversal_processtree(t, b + 1);
    }
}
```
````

---
layout: default
level: 2
---
# Hook系统调用——找到系统调用表地址
- `grep sys_call_table /boot/System-$(uname -r)`&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;(编译时的符号表，高版本的Linux内核可能不适用)
- `cat /proc/kallsyms | grep sys_all_table`&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;(安装中生成的符号表，以该指令的结果为准)
## 如果你的Linux内核版本在2.6.33 - 5.7.0
<br>

- `kallsyms_lookup_name("sys_call_table");`

<br>
```c{all|1,5}{maxHeight:'300px'}
// linux-4.19.90/kernel/kallsyms.c
extern const unsigned long kallsyms_num_syms
__attribute__((weak, section(".rodata")));
/* Lookup the address for this symbol. Returns 0 if not found. */
unsigned long kallsyms_lookup_name(const char *name);
EXPORT_SYMBOL_GPL(kallsyms_lookup_name);
```

<br>
```c
/* 获取系统调用服务首地址 */
unsigned long *sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");	
```

---
layout: full
level: 2
---
## Hook系统调用——找到空闲系统调用

<div class="png-box">
<img class="img1" src="/systemcalltable.png" width="400" style="margin-left:0px; margin-top:50px;">
<img class="img2" src="/sys_ni_call.png" width="400">
</div>

<style>
	.png-box{
		display: flex;
		flew-flow: row;
		justify-content: center;
		box-sizing: border-box; 
.img1{
	margin-left:0px;
	width: 450px;
}
.img2{
	margin-left: -200px;
	margin-top: 100px;
	width: 650px;
	height: 100%;
	margin-right:0px;
}
}
</style>

---
layout: default
level: 2
---
# Hook系统调用——关闭内存写保护
### 关于`CR0`寄存器
<br>
<img src="/CR0Register.png">

> `CR0.WP`: **Write Protect (bit 16 of CR0)** — When set, inhibits supervisor-level procedures from writing into readonly pages; when clear, allows supervisor-level procedures to write into read-only pages (regardless of the 
U/S bit setting; see Section 4.1.3 and Section 4.6). This flag facilitates implementation of the copy-onwrite method of creating a new process (forking) used by operating systems such as UNIX. This flag must 
be set before software can set CR4.CET, and it cannot be cleared as long as CR4.CET = 1 (see below).  
&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;&thinsp;——*Intel® 64 and IA-32 Architectures Software Developer Manuals-Volums 3A. 2.5*

---
layout: two-cols-header
layoutClass: gap-14
level: 2
---

# Hook系统调用——关闭内存写保护


::left::

````md magic-move
```c
// 关闭内存写保护
void disable_write_protect(void)
{
    uint64_t cr0 = 0;
    asm volatile("movq %%cr0, %0;"
                 : "=r"(cr0)
                 :
                 :);
    cr0 &= ~(1 << 16);
    asm volatile("movq %0, %%cr0;"
                 :
                 : "r"(cr0));
}
```


```c
// 打开内存写保护
void enable_write_protect(void)
{
    uint64_t cr0 = 0;
    asm volatile(
        "movq %%cr0, %0;"
        : "=r"(cr0)       
        :                 
        :                 
    );
    cr0 |= (1 << 16);
    asm volatile(
        "movq %0, %%cr0;"
        :                    
        : "r"(cr0)
    );
}

```
````
::right::

> Some of the bits in CR0 and CR4 are reserved and must be written with zeros. **Attempting to set any reserved 
bits in CR0\[31:0\] is ignored.** **Attempting to set any reserved bits in CR0\[63:32\] results in a general-protection 
exception,** #GP(0). Attempting to set any reserved bits in CR4 results in a general-protection exception, 
#GP(0).

---
layout: default
level: 2
---
# Hook系统调用——关闭内存写保护

### 那如果是ARM架构的系统呢？<p></p>

#### ARM架构下没有`CR0`寄存器, 前述方法不起作用<p></p>

#### 有三种方法

- 使用`update_mapping_port()`函数，修改`__start_rodata`到`__init_begin`段内存的读写属性&thinsp;&thinsp;&thinsp;&thinsp;❌
- 直接遍历`PTE`，修改读写属性&thinsp;&thinsp;&thinsp;&thinsp;❌
- 使用修改的`set_memory_ro/rw`函数&thinsp;&thinsp;&thinsp;&thinsp;✅

---
layout: default
level: 2
---

## 方法一：使用`update_mapping_port`函数

| 名称       | 区间范围                          | 描述                                                    |
| ---------- | --------------------------------- | ------------------------------------------------------- |
| 代码段     | `__text` ~ `__etext`              | 内核代码段                                              |
| 只读数据段 | `__srart_rodata` ~ `__init_begin` | 内核只读数据，`sys_call_table`**就在其中**              |
| `init`段   | `__init_begin`~`__init_end`       | 所需要的代码和数据                                      |
| 数据段     | `__sdata` ~ `__edata`             | 内核中可读可写的数据                                    |
| `BSS`段    | `__bass_start` ~ `__bass_stop`    | 内核中初始化为0的数据以及没有初始化的全局变量和静态变量 |


---
layout: default
level: 2
---

`update_mapping_port()`函数定义如下：

```c
// \arch\arm64\mm\mmu.c
static void update_mapping_prot(phys_addr_t phys, unsigned long virt,
				phys_addr_t size, pgprot_t prot)
{
	if ((virt >= PAGE_END) && (virt < VMALLOC_START)) {
		pr_warn("BUG: not updating mapping for %pa at 0x%016lx - outside kernel range\n",
			&phys, virt);
		return;
	}
 
	__create_pgd_mapping(init_mm.pgd, phys, virt, size, prot, NULL,
			     NO_CONT_MAPPINGS);
 
	/* flush the TLBs after updating live kernel mappings */
	flush_tlb_kernel_range(virt, virt + size);
}
```

使用`update_mapping_port`函数将整个`__start_rodata`到`__init_begin`内存区域属性改为可读可写`PAGE_KERNEL_RO`

---
layout: default
layoutClass: gap-14
level: 2
---

# 获取代码编写

#### 修改内存属性:

````md magic-move
```c
//修改指定内核地址范围的内存属性为只读
static inline void protect_memory(void)
{
	update_mapping_prot(__pa_symbol(start_rodata), 
			(unsigned long)start_rodata,
			section_size, PAGE_KERNEL_RO);
}

```


```c
//修改指定内核地址范围的内存属性为可读可写等
static inline void unprotect_memory(void)
{
	update_mapping_prot(__pa_symbol(start_rodata), 
	(unsigned long)start_rodata,
	section_size, PAGE_KERNEL);
}

```
````

#### 获取相关变量:

```c
update_mapping_prot = (void *)kallsyms_lookup_name("update_mapping_prot"); // 获取update_mapping_port函数地址
start_rodata = (unsigned long)kallsyms_lookup_name("__start_rodata"); // 获取__start_rodata段地址
init_begin = (unsigned long)kallsyms_lookup_name("__init_begin"); // 获取__init_begin段地址
__sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table"); // 获取系统调用表地址

```
<br>
<p style="text-align: center; font-size: 20pt;">❌ 内核报错:找不到虚拟内存地址，遂放弃</p> 


---
layout: default
level: 2
---
# 方法二：修改页表项属性

```c {all}{maxHeight:'400px'}
// incluldes...
static pte_t *ptep;
static struct mm_struct *mm;

static unsigned long *__sys_call_table;
static unsigned long mkdir_sys_call_addr;

typedef long (*syscall_fn_t)(const struct pt_regs *regs);
//用于保存原始的 mkdir 系统调用
static syscall_fn_t orig_mkdir;
static void set_pte_write(void)
{
	pte_t pte;

	pte = READ_ONCE(*ptep);
	
	//清除pte的可读属性位
	//设置pte的可写属性位
	pte = pte_mkwrite(pte);
	
	//把pte页表项写入硬件页表钟
	set_pte_at(mm, mkdir_sys_call_addr, ptep, pte);

	//页表更新 和 TLB 刷新之间保持正确的映射关系
	//为了保持一致性，必须确保页表的更新和 TLB 的刷新是同步的
	__flush_tlb_kernel_pgtable(mkdir_sys_call_addr);

}

static void set_pte_rdonly(void)
{
	pte_t pte;

	pte = READ_ONCE(*ptep);
	
	//清除pte的可写属性位
	//设置pte的可读属性位
	pte = pte_wrprotect(pte);
	
	set_pte_at(mm, mkdir_sys_call_addr, ptep, pte);

	__flush_tlb_kernel_pgtable(mkdir_sys_call_addr);

}
	
//内核模块初始化函数
static int __init lkm_init(void)
{
	pgd_t *pgdp;
	pud_t *pudp;
	pmd_t *pmdp;

    /* can be directly found in kernel memory */
	mm = (struct mm_struct *)kallsyms_lookup_name("init_mm");
	if(mm == NULL)
	return -1;

    __sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
    if (!__sys_call_table)
		return -1;

	mkdir_sys_call_addr = (unsigned long)(__sys_call_table + __NR_mkdirat);
	
	pgdp = pgd_offset(mm, mkdir_sys_call_addr);
	if (pgd_none(READ_ONCE(*pgdp))) {
		printk(KERN_INFO "failed pgdp");
		return 0;
	}
	
	pudp = pud_offset(pgdp, mkdir_sys_call_addr);
	if (pud_none(READ_ONCE(*pudp))) {
		printk(KERN_INFO "failed pudp");
		return 0;
	}
	
	pmdp = pmd_offset(pudp, mkdir_sys_call_addr);
	if (pmd_none(READ_ONCE(*pmdp))) {
		printk(KERN_INFO "failed pmdp");
		return 0;
	}
	
	ptep = pte_offset_kernel(pmdp, mkdir_sys_call_addr);
	if (!pte_valid(READ_ONCE(*ptep))) {
		printk(KERN_INFO "failed pte");
		return 0;
	}

    //保存原始的系统调用：mkdir
	orig_mkdir = (syscall_fn_t)__sys_call_table[__NR_mkdirat];

    set_pte_write();
    __sys_call_table[__NR_mkdirat] = (unsigned long)mkdir_hook;
    set_pte_rdonly();

    printk("lkm_init\n");

	return 0;
}
```

---
layout: default
level: 2
---
# 方法三：使用修改的`set_mrmory_ro/rw`函数

````md magic-move
```c
// linux-$(uname -r)/arch/arm64/mm/pageattr.c
int set_memory_ro(unsigned long addr, int numpages)
{
	return change_memory_common(addr, numpages,
					__pgprot(PTE_RDONLY),
					__pgprot(PTE_WRITE));
}
```

```c
// linux-$(uname -r)/arch/arm64/mm/pageattr.c
int set_memory_rw(unsigned long addr, int numpages)
{
	return change_memory_common(addr, numpages,
					__pgprot(PTE_WRITE),
					__pgprot(PTE_RDONLY));
}
```
````
经过一系列套娃式的函数调用后...

```c{all|4-8|7}{maxHeight:'250px'}
static int change_memory_common(unsigned long addr, int numpages, pgprot_t set_mask, pgprot_t clear_mask){
	struct vm_struct *area;
	.....
	area = find_vm_area((void *)addr);
	if (!area ||
	    end > (unsigned long)area->addr + area->size ||
	    !(area->flags & VM_ALLOC))
		return -EINVAL;
	......
	vm_unmap_aliases();
	return __change_memory_common(start, size, set_mask, clear_mask);
}
```

---
layout: default
level: 2
---
# 修改代码

```c {all|11-14|11-14,17|11-14,17-18|11-14,17-18,23}{maxHeight:'400px'}
// includes
int (*my_set_memory_ro)(unsigned long addr, int numpages);
int (*my_set_memory_rw)(unsigned long addr, int numpages);
struct vm_struct *(*my_find_vm_area)(const void *addr);
static unsigned long *__sys_call_table;
static syscall_fn_t orig_mkdir; //用于保存原始的系统调用
static unsigned long addr;
static int __init lkm_init(void)
{
    struct vm_struct *area;
    my_set_memory_ro = (void *)kallsyms_lookup_name("set_memory_ro");
    my_set_memory_rw = (void *)kallsyms_lookup_name("set_memory_rw");
    my_find_vm_area = (void *)kallsyms_lookup_name("find_vm_area");
    __sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");
	orig_mkdir = (syscall_fn_t)__sys_call_table[__NR_mkdirat];
    addr = (unsigned long)(__sys_call_table + __NR_mkdirat);
    addr &= PAGE_MASK; // 找当前页的首地址
    area = my_find_vm_area((void *)addr); // find_vm_area用于查找覆盖指定地址范围的虚拟内存区域
    if(!area){
        printk("no find vm area\n");
        return -1;
    }
    area->flags |= VM_ALLOC;
    my_set_memory_rw(addr, 1);
    __sys_call_table[__NR_mkdirat] = (unsigned long)mkdir_hook; //hook 系统调用表表项：sys_call_table[__NR_mkdirat]
    my_set_memory_ro(addr, 1);
	return 0;
}
```

---
layout: default
level: 2
---
## Hook系统调用——编写入口函数

```c
asmlinkage long my_syscall(char __user * buf)
{
	counter = 0;
    preorder_traversal_processtree(&init_task,0); 							//从根进程开始深度遍历多叉树
	if(copy_to_user((struct process *)buf,a,1000*sizeof(struct process))) 	//将数据传回用户空间
		return -EFAULT;
	else
		return sizeof(a);
}
```
<img src="/pt_regs.png" width="50%" style="margin-left:250px;">

---
layout: default
level: 2
---
`struct pt_regs`定义：

<div class="code-blocks" style="width: 850px; height: 400px; overflow-y: scroll;">
````md magic-move

```c
// In x86_64
struct pt_regs {
/*
 * C ABI says these regs are callee-preserved. They aren't saved on kernel entry
 * unless syscall needs a complete, fully filled "struct pt_regs".
 */
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
/* These regs are callee-clobbered. Always saved on kernel entry. */
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
/*
 * On syscall entry, this is syscall#. On CPU exception, this is error code.
 * On hw interrupt, it's IRQ number:
 */
	unsigned long orig_ax;
/* Return frame for iretq */
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	unsigned long ss;
/* top of stack page */
};

```


```c
// In ARM64
struct pt_regs {
	union {
		struct user_pt_regs user_regs;
		struct {
			u64 regs[31];
			u64 sp;
			u64 pc;
			u64 pstate;
		};
	};
	u64 orig_x0;
#ifdef __AARCH64EB__
	u32 unused2;
	s32 syscallno;
#else
	s32 syscallno;
	u32 unused2;
#endif
	u64 sdei_ttbr1;
	/* Only valid when ARM64_HAS_IRQ_PRIO_MASKING is enabled. */
	u64 pmr_save;
	u64 stackframe[2];
	/* Only valid for some EL1 exceptions. */
	u64 lockdep_hardirqs;
	u64 exit_rcu;
};
```
````
</div>

---
layout: default
level: 2
---

# Hook系统调用——编写入口函数
````md magic-move
```c
// 原始函数
asmlinkage long my_syscall(char __user * buf)
{
	counter = 0;
    preorder_traversal_processtree(&init_task,0); 							
	if(copy_to_user((struct process *)buf,a,1000*sizeof(struct process))) 	
		return -EFAULT;
	else
		return sizeof(a);
}
```

```c{all|2,7}
// x86_64下的入口函数
typedef asmlinkage long (*sys_call_ptr_t)(const struct pt_regs *);
asmlinkage long my_syscall(const struct pt_regs *regs)
{
    counter = 0;
    preorder_traversal_processtree(&init_task, 0);                            
    struct process* buf = (struct process*)regs->di;
    if (copy_to_user((struct process *)buf, (struct process*)a, 1000 * sizeof(struct process)))
        return -EFAULT; // 拷贝失败
    else
        return sizeof(a); // 拷贝成功，返回拷贝字节数
}
```

```c{all|2,7}
// aarch64下的入口函数
typedef long(*syscall_fn_t)(const struct pt_regs *regs);
asmlinkage long my_syscall(const struct pt_regs *regs)
{
    counter = 0;
    preorder_traversal_processtree(&init_task, 0);                            
    struct process* buf = (struct process*)regs->regs[0];
    if (copy_to_user((struct process *)buf, (struct process*)a, 1000 * sizeof(struct process)))
        return -EFAULT; // 拷贝失败
    else
        return sizeof(a); // 拷贝成功，返回拷贝字节数
}
```
````

---
layout: section
title: 实机演示
---
# 实机演示
---
layout: default
title: Thanks！
hideInToc: true
---
# 参考文献
1. Intel® 64 and IA-32 Architectures Software Developer Manuals: Intel\[EB/OL\]. \[2024-05-09\].
https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html.
2.  Linux Kernel 源码学习必备知识之：GCC 内联汇编（AT&T 格式）_linux c 内置汇编-CSDN
博客\[EB/OL\]. \[2024-05-09\]. https://blog.csdn.net/m0_50662680/article/details/130875689.
3. Linux-ARM 汇编及 ARM 片内寄存器 _arm 架构的芯片使用汇编语言-CSDN 博客\[EB/OL\]. \[2024-05-09\]. https://blog.csdn.net/xiaoliu_niuniu/article/details/132246641.
4. Linux 系统调用权威指南 - 掘金\[EB/OL\]. \[2024-05-09\]. https://juejin.cn/post/6844903429907677191.
5. Bonan. Linux Rootkit 实验｜ 04 另外几种系统调用挂钩技术\[EB/OL\]. (2017-05-11) \[2024-05-09\]. https://blog.wohin.me/posts/linux-rootkit-04/.
6. Linux - 系统调用（syscall）_linux syscall api 手册 csdn-CSDN 博客\[EB/OL\]. \[2024-05-09\].https://blog.csdn.net/qazw9600/article/details/134618353.
7. Linux 内核设计与实现—系统调用 - 北极狼徒\[EB/OL\]. \[2024-05-09\]. https://jerling.github.io/post/linux_kernel_design_and_impl/.
---
layout: default
hideInToc: true
---
# 参考文献
8. arch/arm64/include/asm/cpucaps.h - pub/scm/linux/kernel/git/maz/arm-platforms - Gitat Google\[EB/OL\]. \[2024-05-09\]. https://kernel.googlesource.com/pub/scm/linux/kernel/git/maz/arm-platforms/+/refs/heads/arm64/a761188873/arch/arm64/include/asm/cpu/caps.h.
9.  Linux ARM64 hook 系统调用-CSDN 博客\[EB/OL\]. \[2024-05-09\]. https://blog.csdn.net/weixin_45030965/article/details/129203081.
10. OS 实验那点事–萌工厂\[EB/OL\]. \[2024-05-09\]. https://moefactory.com/3041.moe.
11. Linux 进程管理之内核栈和 struct pt_regs_linux 内核栈-CSDN 博客\[EB/OL\]. \[2024-05-09\].https://blog.csdn.net/weixin_45030965/article/details/132734258.
12. Linux 进程管理之内核栈和 struct pt_regs_linux 内核栈-CSDN 博客\[EB/OL\]. \[2024-05-09\].https://blog.csdn.net/weixin_45030965/article/details/132734258.
13. linux copy_to_user error-掘金\[EB/OL\]. \[2024-05-09\]. https://juejin.cn/s/linux%20copy_to_user%20error.
14. 【Linux 驱动】copy_to_user 、copy_from_user 函数 _linux 内核 copytouser-CSDN 博客\[EB/OL\]. \[2024-05-09\]. https://blog.csdn.net/challenglistic/article/details/131855665.
---
layout: default
hideInToc: true
---
# 参考文献
15. copy_to_user/copy_from_user 解析与示例 _copy to user-CSDN 博客\[EB/OL\]. \[2024-05-09\]. https://blog.csdn.net/weixin_45930312/article/details/126255496.
16. Unexporting kallsyms_lookup_name() \[LWN.net\]\[EB/OL\]. \[2024-05-09\]. https://lwn.net/Articles/813350/.
17. Linux 内核函数 kallsyms_lookup_name_linux 5.10 内核符号查找函数-CSDN 博客\[EB/OL\]. \[2024-05-09\]. https://blog.csdn.net/weixin_45030965/article/details/132497956.
18. Md.jamal. System call hooking example arguments are incorrect: Stack Overflow\[EB/OL\].(2020-01-24) \[2024-05-09\]. https://stackoverflow.com/q/59851520/24845509.
19. ABBOTT I. Answer to ”System call hooking example arguments are incorrect”: StackOverflow\[EB/OL\]. (2020-01-22) \[2024-05-09\]. https://stackoverflow.com/a/59861681/24845509.
20. Md.jamal. Answer to ”System call hooking example arguments are incorrect”: StackOverflow\[EB/OL\]. (2020-01-24) \[2024-05-09\]. https://stackoverflow.com/a/59904755/24845509.
21. use struct pt_regs based syscall calling for x86-64 \[LWN.net\]\[EB/OL\]. \[2024-05-09\]. https://lwn.net/Articles/750536/.
---
layout: default
hideInToc: true
---
# 参考文献
22. 【操作系统实验第二次】错误：‘init_task‘未声明-CSDN 博客\[EB/OL\]. \[2024-05-09\]. https://blog.csdn.net/m0_50539570/article/details/120773191.
23. Linux 内核模块简单教程 _skipping btf generation-CSDN 博客\[EB/OL\]. \[2024-05-09\]. https://blog.csdn.net/noabcd32/article/details/132741923.
24. 为 linux 添加一个系统调用 _ 利用内核模块法为 linux 添加一个系统调用-CSDN 博客\[EB/OL\]. \[2024-05-09\]. https://blog.csdn.net/weixin_42372407/article/details/129322861?spm=1001.2014.3001.5501.
25. 编译内核函数 copy_from_user() 和 copy_to_user()_ 内核态拷贝到用户态函数头文件-CSDN 博客\[EB/OL\]. \[2024-05-09\]. https://blog.csdn.net/sandalphon4869/article/details/104771876/.
26. 为 linux 添加一个系统调用 _ 利用内核模块法为 linux 添加一个系统调用-CSDN 博客\[EB/OL\]. \[2024-05-09\]. https://blog.csdn.net/weixin_42372407/article/details/129322861.
27. Linux-进程描述符 task_struct 详解 - John_ABC - 博客园\[EB/OL\]. \[2024-05-09\]. https://www.cnblogs.com/JohnABC/p/9084750.html.
28. Linux 内核中 container_of 宏的详细解释-腾讯云开发者社区-腾讯云\[EB/OL\]. \[2024-05-09\].https://cloud.tencent.com/developer/article/1826713.
---
layout: default
hideInToc: true
---
# 参考文献
29. 进程 ID 及进程间的关系-腾讯云开发者社区-腾讯云\[EB/OL\]. (2023-12-04) \[2024-05-09\]. https://cloud.tencent.com/developer/article/2363228.
30. Linux 内核库. 深度剖析 Linux 内核进程描述符 task struct 实现原理（超级详细）: 回答\[EB/OL\]. (2022-02-28) \[2024-05-09\]. https://zhuanlan.zhihu.com/p/473736908.
31. 梁金荣. Linux 使用内核模块添加系统调用的方法（无需编译内核）: Linux 内核之旅\[EB/OL\].(2020-08-01) \[2024-05-09\]. http://kerneltravel.net/blog/2020/syscall_ljr_1/.
32. Allpass200. Linux ARM64 系统调用过程: 嵌入式 Linux 笔记\[EB/OL\]. (2023-05-01) \[2024-05-09\]. https://zhuanlan.zhihu.com/p/626203155.
33. insmod 加载.ko 文件教程 _insmod 加载 ko 文件-CSDN 博客\[EB/OL\]. \[2024-05-09\]. https://blog.csdn.net/qq_14829643/article/details/134410196.
34. 46 | AArch64 体系：ARM 最新编程架构模型剖析\[EB/OL\]. (2021-08-23) \[2024-05-09\]. https://freegeektime.com/100078401/410396/.
---
layout: default
hideInToc: true
---
# 参考文献
35. Sonny. ARM Cortex-A 系列 ARMv8-A 程序员指南：第 4 章 ARMv8 寄存器: ARM 架构编程\[EB/OL\]. (2021-12-20) \[2024-05-09\]. https://zhuanlan.zhihu.com/p/447528678.
36.  ARMv8 寄存器—Armv8/armv9 架构入门指南 v1.0 documentation\[EB/OL\]. \[2024-05-09\]. https://armv8-doc.readthedocs.io/en/latest/04.html#id5.
37. ARM Cortex-A Series Programmer’s Guide for ARMv8-A\[J\]. 2015.
38. G.O.A.T. ARM 架构学习《基础篇》—AArch64 Exception Model: 回答\[EB/OL\]. (2023-11-1)  \[2024-05-09\]. https://zhuanlan.zhihu.com/p/657851124.
39. Linux ARM64 平台上 Hook 系统调用（以 openat 为例）_linux version 4.19.90-52.19.v2207.ky10.aarch64-CSDN 博客\[EB/OL\]. \[2024-05-09\]. https://blog.csdn.net/weixin_42915431/article/details/115289115.
40. Linux ARM64 hook 系统调用-CSDN 博客\[EB/OL\]. \[2024-05-09\]. https://blog.csdn.net/weixin_45030965/article/details/129203081.
41. Linux Arm64 修改页表项属性 _pte special-CSDN 博客\[EB/OL\]. \[2024-05-09\]. https://xiaolizai.blog.csdn.net/article/details/132764364.
---
layout: default
hideInToc: true
---
# 参考文献
42. Linux arm64 set_memory_ro/rw 函数-CSDN 博客\[EB/OL\]. \[2024-05-09\]. https://xiaolizai.blog.csdn.net/article/details/132889566.
43. Linux ARM64 update_mapping_prot 函数 _arm 架构怎么 update-CSDN 博客\[EB/OL\].\[2024-05-09\]. https://blog.csdn.net/weixin_45030965/article/details/129212657.
44. Linux arm64 set_memory_ro/rw 函数 - 小蓝博客\[EB/OL\]. \[2024-05-09\]. https://www.8kiz.cn/archives/6020.html.
---
layout: cover
title: Thanks!
hideInToc: true
---

<h1 class="title">谢谢大家!</h1>


<p class="sub-title">嵌入式系统课程汇报——第一组<br>组员：尹彦江、林秋霞、高万胜<br>2024.5.12</p>

<style>
	.title{
		text-align: center;
	}
	.sub-title{
		text-align: right;
		position: fixed;
    	bottom: 0;
    	right: 0;
    	padding: 10px;
	}
</style>