/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A scheduler that prioritizes specific tasks by enqueuing them directly
 * to local DSQ while routing non-priority tasks through a custom DSQ.
 */
#include <scx/common.bpf.h>

#define CPU_NUM 4

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

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, s32);
        __type(value, s32);
        __uint(max_entries, 4);
} cpu_task_map SEC(".maps");

/* BPF map to store priority TIDs */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, s32); /* CPU assigned in enqueue() */
} assigned_list SEC(".maps");

/* Statistics */
u64 nr_priority_local_sum = 0;
u64 nr_nonpriority_custom = 0;
u64 nr_dispatched_global_sum = 0;
u64 nr_select_cpu = 0;

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

static bool is_nonpriority_task(struct task_struct *p)
{
    pid_t pid = p->pid;
    pid_t tgid = p->tgid;
    u8 *val1, *val2;
    
    /* Check if PID is in priority list */
    val1 = bpf_map_lookup_elem(&priority_pids, &tgid);

    /* Check if TID is in priority list */
    val2 = bpf_map_lookup_elem(&priority_tids, &pid);


    return ((val1 != NULL && *val1 == 0) && (val2 != NULL && *val2 == 0));
}

s32 BPF_STRUCT_OPS(priority_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
    s32 cpu = 0;
    u64 dummy;

    pid_t pid = p->pid;
    pid_t tgid = p->tgid;

    /* For non-priority tasks, just return appropriate CPU */
    //if (is_priority_task(p) && is_fixed_prior_task){
    //	return priortask_cpu;
    //}

    //if (is_priority_task(p) == false && is_fixed_prior_task && is_owned_prior_task_cpu){
    //	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &dummy);
    //    if (cpu == 0){
    //    	return 1;
    //    }else{
    //    	return cpu;
    //    }
    //}
    cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &dummy);


    //if (is_priority_task(p)) {
    //	__sync_fetch_and_add(&nr_select_cpu, 1);
    //}else{
    //}


    return cpu;
}

static s32 pick_direct_dispatch_cpu(struct task_struct *p, s32 current_cpu)
{
	s32 cpu;

	if (is_fixed_prior_task)
		return priortask_cpu;

	if (p->nr_cpus_allowed == 1 ||
	    scx_bpf_test_and_clear_cpu_idle(current_cpu))
		return current_cpu;

	cpu = scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
	if (cpu >= 0)
		return cpu;

	return (current_cpu + 1) % 4;
}


static s32 pick_cpu_based_on_cpumap()
{
	// CPU とタスク数の対応を示した MAP を参照し，一番タスク数が少ない CPU を選ぶ
	s32 cpu_candidate = 0;
	s32 cpu_candidate_task_num = 0x7fffffff;
	s32 cpu = 0;
	//s32 key0 = 0;
	//s32 val0 = 0;

	//s32 key1 = 1;
	//s32 val1 = 1;

	//s32 key2 = 2;
	//s32 val2 = 1;
	//
	//s32 key3 = 3;
	//s32 val3 = 1;

	//bpf_map_update_elem(&cpu_task_map, &key0, &val0, BPF_ANY);	
	//bpf_map_update_elem(&cpu_task_map, &key1, &val1, BPF_ANY);	
	//bpf_map_update_elem(&cpu_task_map, &key2, &val2, BPF_ANY);	
	//bpf_map_update_elem(&cpu_task_map, &key3, &val3, BPF_ANY);	

	bpf_repeat(CPU_NUM) {
		s32 *cpu_task_num;

		cpu_task_num = bpf_map_lookup_elem(&cpu_task_map, &cpu);

		// cpu_candidate のタスク数と cpu_task_num の大小関係を比較
		if (cpu_task_num != NULL && *cpu_task_num <= cpu_candidate_task_num) {
			cpu_candidate = cpu;
			cpu_candidate_task_num = *cpu_task_num;
		}

		cpu++;
	}
	//bpf_printk("Selected CPU is %d", cpu_candidate);

	return cpu_candidate;
}

void BPF_STRUCT_OPS(priority_enqueue, struct task_struct *p, u64 enq_flags)
{
    s32 cpu=scx_bpf_task_cpu(p);
    s32 *assigned_cpu;
    u64 dummy;

    pid_t pid = p->pid;
    pid_t tgid = p->tgid;

    //bpf_printk("in enqueue: PID: %d, TGID: %d, CPU=%d\n", tgid, pid, cpu);

    if (is_priority_task(p)) {

	if (is_fixed_prior_task){
    		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | priortask_cpu, SCX_SLICE_DFL, SCX_ENQ_HEAD);
		return;
	}

	// assigned_list を確認し，enqueue()により CPU が割り当てられているか確認
	assigned_cpu = bpf_map_lookup_elem(&assigned_list, &pid);
	if (assigned_cpu == NULL) {
		s32 *val;

		cpu = pick_cpu_based_on_cpumap();
		// 割り当てられていない場合，pick_cpu_based_on_cpumap により，タスクの CPU 選択 & assigned_list を更新
		bpf_map_update_elem(&assigned_list, &pid, &cpu, BPF_ANY);	

		val = bpf_map_lookup_elem(&cpu_task_map, &cpu);	
		if (val != NULL){
			__sync_fetch_and_add(val, 1);
		}

		// DSQ に追加
        	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_DFL * priority_slice_multiplier, SCX_ENQ_HEAD);
    	}else{
		// 割り当てられている場合，その値を参照する
        	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | *assigned_cpu, SCX_SLICE_DFL * priority_slice_multiplier, SCX_ENQ_HEAD);
	}	
	
    } else if(is_nonpriority_task(p)){
	// assigned_list を確認し，enqueue()により CPU が割り当てられているか確認
	assigned_cpu = bpf_map_lookup_elem(&assigned_list, &pid);
	if (assigned_cpu == NULL) {
		s32 *val;

		cpu = pick_cpu_based_on_cpumap();
		// 割り当てられていない場合，pick_cpu_based_on_cpumap により，タスクの CPU 選択 & assigned_list を更新
		bpf_map_update_elem(&assigned_list, &pid, &cpu, BPF_ANY);	

		val = bpf_map_lookup_elem(&cpu_task_map, &cpu);	
		if (val != NULL){
			__sync_fetch_and_add(val, 1);
		}

		// DSQ に追加
        	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_DFL, 0);
    	}else{
		// 割り当てられている場合，その値を参照する
        	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | *assigned_cpu, SCX_SLICE_DFL, 0);
	}	

    } else{
    	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
    }

}

void BPF_STRUCT_OPS(priority_dispatch, s32 cpu, struct task_struct *prev)
{
    struct task_struct *p;
    u32 moved = 0;
    /* scan NONPRI_DSQ and move a task to SHARED_DSQ */
    bpf_for_each(scx_dsq, p, NONPRI_DSQ, 0) {
	__COMPAT_scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p, SHARED_DSQ, 0);
        __sync_fetch_and_sub(&nr_nonpriority_custom, 1);
        __sync_fetch_and_add(&nr_dispatched_global_sum, 1);
        moved++;
        if ((max_dispatch > 0) && (moved >= max_dispatch)) {
            break;
        }
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
