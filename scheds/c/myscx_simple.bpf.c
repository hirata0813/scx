/* SPDX-License-Identifier: GPL-2.0 */
/*
 * A simple scheduler.
 *
 * By default, it operates as a simple global weighted vtime scheduler and can
 * be switched to FIFO scheduling. It also demonstrates the following niceties.
 *
 * - Statistics tracking how many tasks are queued to local and global dsq's.
 * - Termination notification for userspace.
 *
 * While very simple, this scheduler should work reasonably well on CPUs with a
 * uniform L3 cache topology. While preemption is not implemented, the fact that
 * the scheduling queue is shared across all CPUs means that whatever is at the
 * front of the queue is likely to be executed fairly quickly given enough
 * number of CPUs. The FIFO scheduling mode may be beneficial to some workloads
 * but comes with the usual problems with FIFO scheduling where saturating
 * threads can easily drown out interactive ones.
 *
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched; //volatile を適用した変数はコンパイル時の最適化対象から外され，その変数へのアクセスは毎回メモリから直接行われる
// また，const となっており，eBPF側では書き換えず，ユーザ空間側から値を与えるものと考えられる
// ユーザ空間側プログラムで，skel->rodata->fifo_sched = true; という部分があった．ここで与えてると考えられる
// 上記のアクセス方法は，libbpf CO-RE の仕組み(.rodataセクションの値にアクセス)
//
static u64 vtime_now;
UEI_DEFINE(uei);

/*
 * Built-in DSQs such as SCX_DSQ_GLOBAL cannot be used as priority queues
 * (meaning, cannot be dispatched to with scx_bpf_dsq_insert_vtime()). We
 * therefore create a separate DSQ with ID 0 that we dispatch to and consume
 * from. If scx_simple only supported global FIFO scheduling, then we could just
 * use SCX_DSQ_GLOBAL.
 */
#define SHARED_DSQ 0

// counter という MAP を定義
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY); //ハマった箇所
	//BPF_MAP_TYPE_PERCPU_ARRAYは，エントリがCPUごとに別れているため，値が入ってないエントリに対応するCPUで動いているプロセスがMAPを読みに行くと，変な値が出力される
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));//ハマった箇所
	__uint(max_entries, 2);
} counter SEC(".maps");

// counter の値を読み，出力
static void print_counter()
{
	int zero=0, one=1;
	u32* num0_p = bpf_map_lookup_elem(&counter, &zero);
	u32* num1_p = bpf_map_lookup_elem(&counter, &one); ///ハマった箇所

	if (num0_p && num1_p)
		bpf_printk("Entry1: %d, Entry2: %d", *num0_p, *num1_p);
}

// 以降は，おそらく BPF_STRUCT_OPS() として，関数定義をしている
// 第一引数が関数名で，第二引数以降はその関数の引数？
//
// simple_select_cpu関数
// この関数は，タスクがwakeしたときに呼ばれる
s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu; //s32 は，signed 32-bit integer

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle); // 左の関数は，ops.select_cpu()のデフォルト実装
	// 選択されたCPUがアイドル状態なら，id_idleにtrueが書き込まれる
	if (is_idle) {
		print_counter();
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0); // 選択されたCPUのローカルDSQにタスクを挿入
	}

	return cpu;
}

//BPF スケジューラにタスクをエンキューする
//ops.select_cpu()の中でinsertする場合(つまり，アイドルなCPUにタスクが割り当てられる場合)，この関数の呼び出しはスキップされる
//タスクpは実行可能状態(CPUに割り当てられている)
//この関数内でpをどのDSQにも入れなかった場合，BPFスケジューラが責任を持つことになる．
//そして，BPFスケジューラもpの割り当てに失敗した場合，pは停止してしまい，もう動かなくなるかもしれない
//上記点に気をつけて実装する必要がある．
void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
	print_counter();

	if (fifo_sched) { //FIFOが有効化(つまり，ユーザ空間で-fオプションがついている)場合
		scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags); // グローバルDSQに挿入する
	} else {
		u64 vtime = p->scx.dsq_vtime;

		/*
		 * Limit the amount of budget that an idling task can accumulate
		 * to one slice.
		 */
		if (time_before(vtime, vtime_now - SCX_SLICE_DFL)) //time_beforeは，第一引数の時刻が第二引数の時刻より前なら，trueを返す
								   //common.bpf.h 内で定義されている
			vtime = vtime_now - SCX_SLICE_DFL;

		scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime,
					 enq_flags);
	}
}

void BPF_STRUCT_OPS(simple_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_dsq_move_to_local(SHARED_DSQ);
}

void BPF_STRUCT_OPS(simple_running, struct task_struct *p)
{
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
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(simple_init)
{
	return scx_bpf_create_dsq(SHARED_DSQ, -1);
}

void BPF_STRUCT_OPS(simple_exit, struct scx_exit_info *ei)
{
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
