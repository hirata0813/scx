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
};

char _license[] SEC("license") = "GPL";

const volatile u32 priortask_cpu;
const volatile bool is_fixed_prior_task;
const volatile bool is_owned_prior_task_cpu;
const volatile u64 priority_slice_multiplier;
const volatile bool suppress_dump;
const volatile u32 max_dispatch;

/* BPF map to store priority PIDs */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, u8); /* flag: 1 if priority task */
} priority_pids SEC(".maps");

/* BPF map to store priority TIDs */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
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

    return ((val1 != NULL && *val1 == 1) && (val2 != NULL && *val2 == 1));
}

s32 BPF_STRUCT_OPS(supersimple_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    s32 cpu;
    bool is_idle = false;


    cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

    if (is_idle) {
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_DFL, 0);
    }

    return cpu;
}

static s32 pick_direct_dispatch_cpu(struct task_struct *p, s32 prev_cpu)
{
	s32 cpu;

	if (is_fixed_prior_task)
		return priortask_cpu;

	if (p->nr_cpus_allowed == 1 ||
	    scx_bpf_test_and_clear_cpu_idle(prev_cpu))
		return prev_cpu;

	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (cpu >= 0)
		return cpu;

	return prev_cpu;
}


void BPF_STRUCT_OPS(supersimple_enqueue, struct task_struct *p, u64 enq_flags)
{
    scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, 0);
}

void BPF_STRUCT_OPS(supersimple_dispatch, s32 cpu, struct task_struct *prev)
{
    /* Consume from global DSQ */
    scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(supersimple_init)
{
    scx_bpf_create_dsq(SHARED_DSQ, -1);
    return scx_bpf_create_dsq(NONPRI_DSQ, -1);
}

void BPF_STRUCT_OPS(supersimple_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(supersimple_ops,
            .select_cpu		= (void *)supersimple_select_cpu,
            .enqueue		= (void *)supersimple_enqueue,
            .dispatch		= (void *)supersimple_dispatch,
            .init			= (void *)supersimple_init,
            .exit			= (void *)supersimple_exit,
            .name			= "supersimple");
