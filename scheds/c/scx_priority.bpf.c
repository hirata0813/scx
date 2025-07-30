/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A scheduler that prioritizes specific tasks by enqueuing them directly
 * to local DSQ while routing non-priority tasks through a custom DSQ.
 */
#include <scx/common.bpf.h>

enum consts {
    ONE_SEC_IN_NS		= 1000000000,
    SHARED_DSQ		= 0,
    NONPRI_DSQ		= 1,
    PRIORITY_SLICE_MULTIPLIER = 2,
};

char _license[] SEC("license") = "GPL";

const volatile u64 slice_ns = 5 * 1000 * 1000; /* 5ms */
const volatile bool suppress_dump;

/* BPF map to store priority PIDs */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, u8); /* flag: 1 if priority task */
} priority_pids SEC(".maps");

/* BPF map to store priority TIDs */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, u8); /* flag: 1 if priority task */
} priority_tids SEC(".maps");

/* Statistics */
u64 nr_priority_local_sum = 0;
u64 nr_nonpriority_custom = 0;
u64 nr_dispatched_global_sum = 0;

UEI_DEFINE(uei);

/* Check if task is priority task */
static bool is_priority_task(struct task_struct *p)
{
    pid_t pid = p->pid;
    pid_t tgid = p->tgid;
    u8 *val1, *val2;
    
    /* Check if PID is in priority list */
    val1 = bpf_map_lookup_elem(&priority_pids, &tgid);

    /* Check if TID is in priority list */
    val2 = bpf_map_lookup_elem(&priority_tids, &pid);

    if((val1 != NULL && *val1 == 1) && (val2 != NULL && *val2 == 1)){
		bpf_printk("is priority task\n");
		return true;
    }else{
		return false;
    }

}

s32 BPF_STRUCT_OPS(priority_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    s32 cpu;
    u64 dummy;
    
    if (is_priority_task(p)) {
        /* For priority tasks, try to find idle CPU or use prev_cpu */
        cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);

        if (cpu >= 0) {
            /* If we found an idle CPU, enqueue directly to local DSQ */
            __sync_fetch_and_add(&nr_priority_local_sum, 1);
		    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_DFL * PRIORITY_SLICE_MULTIPLIER, SCX_ENQ_HEAD);
            return cpu;

        } else{
            __sync_fetch_and_add(&nr_priority_local_sum, 1);
		    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | prev_cpu, SCX_SLICE_DFL * PRIORITY_SLICE_MULTIPLIER, SCX_ENQ_HEAD);
            return prev_cpu;
        }
    }
    
    /* For non-priority tasks, just return appropriate CPU */
    return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &dummy);
}

static s32 pick_direct_dispatch_cpu(struct task_struct *p, s32 prev_cpu)
{
	s32 cpu;

	if (p->nr_cpus_allowed == 1 ||
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return prev_cpu;

	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (cpu >= 0)
		return cpu;

	return -1;
}


void BPF_STRUCT_OPS(priority_enqueue, struct task_struct *p, u64 enq_flags)
{
    s32 cpu;
    /* Priority tasks should not reach enqueue as they are handled in select_cpu */
    if (is_priority_task(p)) {
        /* Fallback: enqueue to local DSQ if somehow reached here */
        cpu = pick_direct_dispatch_cpu(p, scx_bpf_task_cpu(p));
        if (cpu >= 0) {
		    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, slice_ns , SCX_ENQ_HEAD);
            __sync_fetch_and_add(&nr_priority_local_sum, 1);
            return;
        }
    }
    /* Non-priority tasks go to NONPRI_DSQ */
    scx_bpf_dsq_insert(p, NONPRI_DSQ, slice_ns, 0);
    __sync_fetch_and_add(&nr_nonpriority_custom, 1);
}

void BPF_STRUCT_OPS(priority_dispatch, s32 cpu, struct task_struct *prev)
{
    struct task_struct *p;
    /* scan NONPRI_DSQ and move a task to SHARED_DSQ */
    bpf_for_each(scx_dsq, p, NONPRI_DSQ, 0) {
	__COMPAT_scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p, SHARED_DSQ, 0);
        __sync_fetch_and_sub(&nr_nonpriority_custom, 1);
        __sync_fetch_and_add(&nr_dispatched_global_sum, 1);
        break;
    }

    /* Consume from global DSQ */
    scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(priority_init)
{
    scx_bpf_create_dsq(SHARED_DSQ, -1);
    return scx_bpf_create_dsq(NONPRI_DSQ, -1);
}

void BPF_STRUCT_OPS(priority_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(priority_ops,
            .select_cpu		= (void *)priority_select_cpu,
            .enqueue		= (void *)priority_enqueue,
            .dispatch		= (void *)priority_dispatch,
            .init			= (void *)priority_init,
            .exit			= (void *)priority_exit,
            .name			= "priority");
