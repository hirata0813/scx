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
	if (flag && *flag == 1) //flagが1(つまり，MAPにPIDが存在し，そのflagが1)のとき
	    return STOP;
	else
	    return RUN;
}


s32 BPF_STRUCT_OPS(simple_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu; //s32 は，signed 32-bit integer
	__u32 pid = get_pid();

	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle); // 左の関数は，ops.select_cpu()のデフォルト実装
	// 選択されたCPUがアイドル状態なら，id_idleにtrueが書き込まれる
	
	// TODO: MAPで管理してないやつは普通にスケジューリングする
	// TODO: MAPで管理してるやつは，flagをもとにスケジューリングする
	if (is_idle) {
		if (check_process_status(&pid) == RUN){
			bpf_printk("simple_select_cpu %d", pid);
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0); // 選択されたCPUのローカルDSQにタスクを挿入
		}
	}

	return cpu;
}

void BPF_STRUCT_OPS(simple_enqueue, struct task_struct *p, u64 enq_flags)
{
	s32 pid;
	pid = get_pid();
	bpf_printk("simple_enqueue %d", pid);

	// TODO: MAPで管理してないやつは普通にスケジューリングする
	// TODO: MAPで管理してるやつは，flagをもとにスケジューリングする
	if (fifo_sched) { //FIFOが有効化(つまり，ユーザ空間で-fオプションがついている)場合
		scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags); // グローバルDSQに挿入する
	} else {
		if (check_process_status(&pid) == RUN){

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
