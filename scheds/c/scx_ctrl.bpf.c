#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched; //volatile を適用した変数はコンパイル時の最適化対象から外され，その変数へのアクセスは毎回メモリから直接行われる
// また，const となっており，eBPF側では書き換えず，ユーザ空間側から値を与えるものと考えられる
// ユーザ空間側プログラムで，skel->rodata->fifo_sched = true; という部分があった．ここで与えてると考えられる
// 上記のアクセス方法は，libbpf CO-RE の仕組み(.rodataセクションの値にアクセス)
//
static u64 vtime_now;
UEI_DEFINE(uei);

#define SHARED_DSQ 0
#define STOP 1
#define RUN 0
#define DEFAULT 2

// PID LIST という MAP を定義
// 1エントリに必要な情報：PID，フラグ(キューイングするかしないか)
// 普通に HASH MAP で良さそう
struct {
	__uint(type, BPF_MAP_TYPE_HASH); 
	__uint(key_size, sizeof(u32)); //PID
	__uint(value_size, sizeof(u32)); //フラグ
	__uint(max_entries, 100);
} pidlist SEC(".maps");

// PIDを取得し，出力
static __u32 get_pid()
{
	return (__u32)bpf_get_current_pid_tgid();
}

static int check_process_status(__u32 *pid)
{
	__u32 *flag;
	flag = bpf_map_lookup_elem(&pidlist, pid);
	if (flag){
		if (*flag == 1) 
		    return STOP;//MAPにPIDが存在し，そのflagが1のとき
		else
		    return RUN;//MAPにPIDが存在し，そのflagが0のとき
	} else {
	    return DEFAULT; // MAP に登録されていないプロセスのとき

	} 
}


s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu; //s32 は，signed 32-bit integer
	__u32 pid = get_pid();
	struct cgroup *cgrp = __COMPAT_scx_bpf_task_cgroup(p); // scx_bpf_task_cgroup が使えるか確認した後，その関数を実行


	//bpf_printk("process state: %d", p->__state);
	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle); // 左の関数は，ops.select_cpu()のデフォルト実装
	// 選択されたCPUがアイドル状態なら，id_idleにtrueが書き込まれる
	//bpf_printk("pid: %d, cgroup pointer: %p, cgroup id from scx: %d, cgroup id: %d, cgroup name from scx: %s, cgroup name: %s", pid, cgrp, cgrp->kn->id, p->cgroups->subsys[0]->cgroup->kn->id, cgrp->kn->name, p->cgroups->subsys[0]->cgroup->kn->name);
	
	if (is_idle) {

		if (check_process_status(&pid) == DEFAULT){
			//bpf_printk("RUN! PID: %d", pid);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0); // 選択されたCPUのローカルDSQにタスクを挿入
			//bpf_printk("pid: %d, cgroup pointer: %p, cgroup id from scx: %d, cgroup id: %d, cgroup name from scx: %s, cgroup name: %s", pid, cgrp, cgrp->kn->id, p->cgroups->subsys[0]->cgroup->kn->id, cgrp->kn->name, p->cgroups->subsys[0]->cgroup->kn->name);
		}else{
			bpf_printk("pid: %d, cgroup pointer: %p, cgroup id from scx: %d, cgroup id: %d, cgroup name from scx: %s, cgroup name: %s", pid, cgrp, cgrp->kn->id, p->cgroups->subsys[0]->cgroup->kn->id, cgrp->kn->name, p->cgroups->subsys[0]->cgroup->kn->name);
			//scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, 1000000, 0); // 1ms間のスライスを与える
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0); // IDが4のローカルDSQにタスクを挿入
		}
	}else{
		if (check_process_status(&pid) != DEFAULT){
			bpf_printk("pid: %d, cgroup pointer: %p, cgroup id from scx: %d, cgroup id: %d, cgroup name from scx: %s, cgroup name: %s", pid, cgrp, cgrp->kn->id, p->cgroups->subsys[0]->cgroup->kn->id, cgrp->kn->name, p->cgroups->subsys[0]->cgroup->kn->name);
		}
	}
	bpf_cgroup_release(cgrp);

	return cpu;
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 pid;
	pid = get_pid();

	if (fifo_sched) { //FIFOが有効化(つまり，ユーザ空間で-fオプションがついている)場合
		scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags); // グローバルDSQに挿入する
	} else {
		u64 vtime = p->scx.dsq_vtime;
		if (check_process_status(&pid) == DEFAULT){
			if (time_before(vtime, vtime_now - SCX_SLICE_DFL)) //time_beforeは，第一引数の時刻が第二引数の時刻より前なら，trueを返す common.bpf.h 内で定義されている
				vtime = vtime_now - SCX_SLICE_DFL;
			scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime, enq_flags);

		}else{
			//scx_bpf_dsq_insert(p, 4, 10000000000000, 0); // IDが4のDSQにタスクを挿入
			if (time_before(vtime, vtime_now - SCX_SLICE_DFL)) //time_beforeは，第一引数の時刻が第二引数の時刻より前なら，trueを返す common.bpf.h 内で定義されている
				vtime = vtime_now - SCX_SLICE_DFL;
			scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, 1000000, vtime, enq_flags); // 1ms間のスライスを与える
			//scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime, enq_flags);
		}
	}
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
	s32 pid;
	pid = get_pid();
	if (check_process_status(&pid) != DEFAULT){
		bpf_printk("dispatch");
	}
	if (check_process_status(&pid) != STOP){
		scx_bpf_dsq_move_to_local(SHARED_DSQ);
	}else{
		scx_bpf_dsq_move_to_local(4);
	}
}

void BPF_STRUCT_OPS(simple_running, struct task_struct *p)
{
	s32 pid;
	pid = get_pid();
	if (check_process_status(&pid) != DEFAULT){
		bpf_printk("running");
	}
	if (fifo_sched)
		return;

	/*
	 * Global vtime always progresses forward as tasks start executing. The
	 * test and update can be performed concurrently from multiple CPUs and
	 * thus racy. Any error should be contained and temporary. Let's just
	 * live with it.
	 */
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(simple_stopping, struct task_struct *p, bool runnable)
{
	s32 pid;
	pid = get_pid();
	if (check_process_status(&pid) != DEFAULT){
		bpf_printk("stopping");
	}
	if (fifo_sched)
		return;

	/*
	 * Scale the execution time by the inverse of the weight and charge.
	 *
	 * Note that the default yield implementation yields by setting
	 * @p->scx.slice to zero and the following would treat the yielding task
	 * as if it has consumed all its slice. If this penalizes yielding tasks
	 * too much, determine the execution time by taking explicit timestamps
	 * instead of depending on @p->scx.slice.
	 */
	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(simple_enable, struct task_struct *p)
{
	s32 pid;
	pid = get_pid();
	if (check_process_status(&pid) != DEFAULT){
		bpf_printk("enable");
	}
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
	bpf_printk("init");
	scx_bpf_create_dsq(4, -1);
	scx_bpf_create_dsq(5, 1);
	scx_bpf_create_dsq(6, 2);
	scx_bpf_create_dsq(7, 3);
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
	bpf_printk("exit");
	UEI_RECORD(uei, ei);
}

// sched_ext_ops 構造体を定義するためのマクロ
SCX_OPS_DEFINE(simple_ops,
	       .select_cpu		= (void *)simple_select_cpu, // 起動状態になったタスクを実行するための CPU を選択
	       .enqueue			= (void *)simple_enqueue, // BPFスケジューラ上で，タスクを enque(キューに挿入) する
	       .dispatch		= (void *)simple_dispatch, // BPF スケジューラ and/or ユーザ DSQs からタスクをディスパッチ(待機中タスクにCPU計算時間を割り当て，処理を実行させること)する
	       .running			= (void *)simple_running, // 割り当てられたCPU上で動作を開始したタスク？
	       .stopping		= (void *)simple_stopping, // 実行終了したタスク？
	       .enable			= (void *)simple_enable, // BPFスケジューリングを有効化する？
	       .init			= (void *)simple_init, // BPFスケジューラの初期化
	       .exit			= (void *)simple_exit, // BPF スケジューラの実行終了後に呼ばれる？
	       .name			= "simple");
