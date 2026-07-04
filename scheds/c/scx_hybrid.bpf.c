// SPDX-License-Identifier: GPL-2.0
/*
 * Hybrid sched_ext Scheduler
 *
 * ロジック:
 *   - タスクが最初にエンキューされたとき、FIFO DSQ (fifo_dsq) に入る。
 *   - FIFO DSQ 上のタスクは preemption_slice_ns ナノ秒間だけ実行される。
 *   - タイムスライス内に終了 (quiescent になる) したタスクは再び FIFO に戻る。
 *   - タイムスライスを使い切った (slice == 0 で stopping) タスクは
 *     CFS ライクな vtime DSQ (cfs_dsq) に格上げされ、以降は vtime ベースで
 *     スケジューリングされる。
 *
 * ghOSt 実装との対応:
 *   ghOSt HybridScheduler    →  この BPF スケジューラ
 *   ShortQueueRq (FIFO)      →  FIFO_DSQ  (カスタム FIFO DSQ)
 *   CfsRq (vtime)            →  CFS_DSQ   (カスタム vtime DSQ)
 *   preemption_time_slice_   →  preemption_slice_ns (ロDATA マップ経由で設定可)
 *   task->new_to_cfs         →  task_ctx->promoted (CFS へ昇格済みフラグ)
 *
 * ビルド方法 (scx リポジトリ構成を想定):
 *   clang -O2 -g -target bpf \
 *     -I /path/to/linux/tools/include \
 *     -I /path/to/scx/scheds/include \
 *     -c hybrid_scx.bpf.c -o hybrid_scx.bpf.o
 *
 * ユーザー空間ローダーは hybrid_scx.c を参照。
 */

#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";
UEI_DEFINE(uei);

/* ------------------------------------------------------------------ */
/* DSQ IDs                                                              */
/* ------------------------------------------------------------------ */
#define MAX_CPUS 64
#define CFS_DSQ(cpu)   ((u64)(cpu) | (1ULL << 32)) /* CFS(vtime)用DSQ: 下位32ビットを CPU 番号に，上位32ビットを DSQ 種別とした DSQ ID */

/* ------------------------------------------------------------------ */
/* 設定 (ユーザー空間から BPF_MAP_TYPE_ARRAY で書き換え可能)           */
/* ------------------------------------------------------------------ */
/* デフォルトのプリエンプション・タイムスライス: 50 µs (ghOSt デフォルトと同じ) */
const volatile u64 preemption_slice_ns = 50000ULL;

/* ------------------------------------------------------------------ */
/* タスクごとのコンテキスト                                             */
/* ------------------------------------------------------------------ */
struct task_ctx {
    /*
     * promoted == false: まだ FIFO フェーズ
     * promoted == true : CFS (vtime) フェーズに昇格済み
     */
    bool promoted;

    /*
     * このタスクが CFS フェーズに入った際の，CPU 累積実行時間(ns)
     * running() コールバックで記録し、stopping() で経過を計算する。
     */
    u64 cfs_start_runtime_ns;

    /* CFS フェーズでの仮想時間 (vtime)
       vtime は，タスクがこれまでに，実際に CPU を掴んで実行された累積時間．小さいほど「CPU をあまり使ってないので優先して実行すべき」という意味
    */
    u64 vtime;
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");


/* ------------------------------------------------------------------ */
/* 特定のタスクに対してのみデバッグしたいとき                                */
/* ------------------------------------------------------------------ */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, u8); /* flag: 1 if priority task */
} debug_filter SEC(".maps");

static bool is_debug_task(struct task_struct *p)
{
    pid_t pid = p->pid;
    u8 *val;

    /* Check if TID is in priority list */
    val = bpf_map_lookup_elem(&debug_filter, &pid);

    return (val != NULL && *val == 1);
}

/* ------------------------------------------------------------------ */
/* 統計 (デバッグ用、per-CPU)                                          */
/* ------------------------------------------------------------------ */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, 4);
} stats SEC(".maps");

enum stat_idx {
    STAT_FIFO_ENQUEUE = 0, /* FIFO DSQ へのエンキュー数 */
    STAT_CFS_PROMOTE,      /* CFS DSQ への昇格数        */
    STAT_CFS_ENQUEUE,      /* CFS DSQ へのエンキュー数  */
    STAT_DIRECT_DISPATCH,  /* select_cpu() での直接ディスパッチ数 */
};

static __always_inline void stat_inc(enum stat_idx idx)
{
    u32 key = (u32)idx;
    u64 *cnt = bpf_map_lookup_elem(&stats, &key);
    if (cnt)
        (*cnt)++;
}

/* ------------------------------------------------------------------ */
/* vtime ユーティリティ                                                 */
/* ------------------------------------------------------------------ */

/*
 * vtime が前にあるか判定 (符号付き比較でラップアラウンドに対応)。
 * Linux カーネルの time_before64() と同じ慣用句。
 */
static __always_inline bool vtime_before(u64 a, u64 b)
{
    return (s64)(a - b) < 0;
}

/*
 * CFS_DSQ のグローバル最小 vtime を追跡する変数。
 * per-CPU でないのは scx_simple と同様のシンプルな単一キュー方式のため。
 */
static u64 vtime_now;

/* ------------------------------------------------------------------ */
/* ops.select_cpu                                                       */
/* ------------------------------------------------------------------ */
/*
 * デフォルト CPU 選択を使い、アイドル CPU が見つかれば即 SCX_DSQ_LOCAL
 * にディスパッチして enqueue() をスキップする。
 * ghOSt における ShortQueueSchedule() の CPU 空き確認に相当。
 */
s32 BPF_STRUCT_OPS(hybrid_select_cpu, struct task_struct *p,
                   s32 prev_cpu, u64 wake_flags)
{
    bool is_idle = false;
    s32 cpu;

    struct task_ctx *tctx = NULL;
    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);

    if (!tctx) {
        /* フォールバック: グローバル FIFO DSQ へ */
        cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
        return cpu;
    }

    if (is_debug_task(p)) {
        if (p->nr_cpus_allowed == 1) {
            cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
        } else if (!tctx->promoted) {
            cpu = 0; // デバッグ対象かつ FIFO
	        bpf_printk("PID: %d, This is debug task. CPU=0", p->pid);
        } else {
            cpu = 1; // デバッグ対象かつ CFS
	        bpf_printk("PID: %d, This is debug task. CPU=1", p->pid);
        }
    } else { // デバッグ対象でない
        if (p->nr_cpus_allowed == 1) {
            cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
        } else {
            cpu = 2;
        }
    }

    return cpu;
}

/* ------------------------------------------------------------------ */
/* ops.enqueue                                                          */
/* ------------------------------------------------------------------ */
/*
 * select_cpu() で直接ディスパッチされなかった場合に呼ばれる。
 *
 * - promoted == false → FIFO_DSQ に積む (タイムスライス = preemption_slice_ns)
 * - promoted == true  → CFS_DSQ  に vtime ベースで積む
 *
 * ghOSt:
 *   TaskNew / TaskRunnable が short_queue_.Enqueue() を呼ぶパスに相当。
 *   TaskPreempted が時間超過を検出して TaskNewToCfs() を呼ぶパスは
 *   stopping() コールバック側で行う。
 */
void BPF_STRUCT_OPS(hybrid_enqueue, struct task_struct *p, u64 enq_flags)
{
    struct task_ctx *tctx = NULL;
    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
    if (!tctx) {
        /* フォールバック: グローバル FIFO DSQ へ */
        scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, preemption_slice_ns, enq_flags);
        return;
    }

    // フォールバック処理: 許可 CPU が1つのような特別なタスクの場合は，例外としてローカルに入れる
    if (p->nr_cpus_allowed == 1) {
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, preemption_slice_ns, enq_flags);
        return;
    }

    s32  cpu;

    if (!tctx->promoted) {
        /* FIFO フェーズ */

        stat_inc(STAT_FIFO_ENQUEUE);

        cpu = 0; // TODO: ここは，FIFO 対応の CPU を pick するようにする．例えば以下のような形
        // s32 fifo_cpu;
        // fifo_cpu = pick_fifo_cpu();
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, preemption_slice_ns, enq_flags);
    } else {
        /* CFS フェーズ: vtime ベース */
        u64 vtime = tctx->vtime; // vtime は，タスクがこれまでに，実際に CPU を掴んで実行された累積時間．小さいほど「CPU をあまり使ってないので優先して実行すべき」という意味

        /*
         * vtime_now は，システム全体における「現在の仮想時間の基準」(runnning と stopping で更新)
         * vtime_now は単調増加のみ
         * vtime_before()により，vtime_now の1スライス以上後ろに取り残されているタスクを判定し，それらの vtime をクランプ
         * vtime_before(a, b)は，a < b であれば true を返す
         * クランプとは，vtime が小さすぎるタスク(例えばずっと I/O 待ちで寝てたやつ)の vtime を引き上げること
         * このようにして，タスクがキューの中で極端に有利な位置に入るのを防ぐ
         */
        if (vtime_before(vtime, vtime_now - preemption_slice_ns))
            vtime = vtime_now - preemption_slice_ns;

        stat_inc(STAT_CFS_ENQUEUE);

        cpu = 1; // TODO: ここは，CFS 対応の CPU を pick するようにする．例えば以下のような形
        // s32 cfs_cpu;
        // cfs_cpu = pick_cfs_cpu();
        // u64 dsq_id = CFS_DSQ(cfs_cpu);
        u64 dsq_id = CFS_DSQ(cpu);
        scx_bpf_dsq_insert_vtime(p, dsq_id, preemption_slice_ns, vtime, enq_flags);
    }
}

/* ------------------------------------------------------------------ */
/* ops.dispatch                                                         */
/* ------------------------------------------------------------------ */
/*
 * CPU が実行するタスクを探す際に呼ばれる。
 * FIFO_DSQ → CFS_DSQ の順で消費する。
 *
 * ghOSt ShortQueueSchedule() における short_queue_ 優先、
 * 次に long_cpulist 上の CFS という順序と対応する。
 */
void BPF_STRUCT_OPS(hybrid_dispatch, s32 cpu, struct task_struct *prev)
{
    u64 dsq_id = CFS_DSQ(cpu);
    bool moved = scx_bpf_dsq_move_to_local(dsq_id);
}

/* ------------------------------------------------------------------ */
/* ops.running                                                          */
/* ------------------------------------------------------------------ */
/*
 * タスクが CPU 上で実際に実行を開始した直後に呼ばれる。
 * FIFO フェーズのタスクについて、このスライスの開始時ランタイムを記録する。
 *
 * ghOSt TaskOnCpu() に相当。
 */
void BPF_STRUCT_OPS(hybrid_running, struct task_struct *p)
{
    struct task_ctx *tctx;

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
    if (!tctx)
        return;

    if (!tctx->promoted) {
        /* FIFO フェーズ: 特にやることはなし*/
    } else {
        /* CFS フェーズ: スライス開始時の CPU 累積実行時間を記録し，vtime_now を最新化 */
        tctx->cfs_start_runtime_ns = p->se.sum_exec_runtime;
        if (vtime_before(vtime_now, tctx->vtime))
            vtime_now = tctx->vtime;
    }
}

/* ------------------------------------------------------------------ */
/* ops.stopping                                                         */
/* ------------------------------------------------------------------ */
/*
 * タスクが CPU を離れる直前 (まだ実行終了していない場合も) に呼ばれる。
 *
 * ここでタイムスライス超過を判定し、超過していれば CFS フェーズへ昇格させる。
 *
 * ghOSt TaskPreempted() 内の
 *   "if (elapsed_runtime >= preemption_time_slice_) → TaskNewToCfs()"
 * に相当する。
 *
 * @runnable: true であればタスクはまだ実行可能 (スライス切れ等でプリエンプト)
 */
void BPF_STRUCT_OPS(hybrid_stopping, struct task_struct *p, bool runnable)
{
    struct task_ctx *tctx;

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
    if (!tctx)
        return;

    if (tctx->promoted) {
        /*
         * CFS フェーズ: 実際に消費した CPU 時間を vtime に反映。
         * nice 値対応が必要なら inverse_weight を掛け算する。
         */
        u64 used = p->se.sum_exec_runtime - tctx->cfs_start_runtime_ns; // このときの CFS での実行で，CPU をどの程度掴んで動いたのかを計算
                                                              // つまり，p->se.sum_exec_runtime から，タスク実行開始時点での CPU 累積実行時間を，引く必要がある
        tctx->vtime += used;
        /* vtime_now を前に進める */
        if (vtime_before(vtime_now, tctx->vtime))
            vtime_now = tctx->vtime;
        return;
    }

    /*
     * FIFO フェーズ:

     * FIFO -> CFS へ昇格するかの判定を行う
     * 判定条件: 実行開始してから，一度も他タスクにプリエンプションされず，与えられたタイムスライス(preemption_slice_ns)分だけ CPU を掴んで実行したかどうか
     * 判定に用いる変数:
     * 1. runnable
     *      true は，このタスクがまだ走行可能(であるが，タイムスライスを使い果たしプリエンプションされた)であることを示す
     *      false は，自発的なブロック (I/O 待ち等)であることを示す
     *      「短時間で終わる処理を何度も繰り返す I/O バウンドなタスク」は FIFO に留まるように設計している
     * 2. p->scx.slice
     *      このタスクが持っている残りタイムスライスを示す
     *      scx_bpf_dsq_insert()などのエンキュー関数において，引数で与えられたタイムスライスの値が scx.slice メンバにもセットされる
     *      p->scx.slice == 0 は，与えられたタイムスライスを使い果たしたことを示す
     *      p->scx.slice > 0 は，他の高優先度タスク(カーネルスレッドなど)に割り込まれたか，自発的にブロックしたかのどちらか
     */
    if (runnable && p->scx.slice == 0) {
        /* CFS フェーズへ昇格 */
        tctx->promoted = true;
        /*
         * 初回 vtime は現在の vtime_now に設定 (新規タスクと同等に扱う)。
         * これにより CFS_DSQ の末尾近くに投入される。
         */
        tctx->vtime = vtime_now;
        stat_inc(STAT_CFS_PROMOTE);
    }
}

/* ------------------------------------------------------------------ */
/* ops.enable                                                           */
/* ------------------------------------------------------------------ */
/*
 * タスクが sched_ext の制御下に入ったときに呼ばれる。
 * task_ctx を初期化する。
 *
 * ghOSt TaskNew() に相当。
 */
void BPF_STRUCT_OPS(hybrid_enable, struct task_struct *p)
{
    struct task_ctx *tctx;

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
                                 BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!tctx)
        return;

    tctx->promoted              = false;
    tctx->cfs_start_runtime_ns = 0;
    tctx->vtime                 = vtime_now;
}

/* ------------------------------------------------------------------ */
/* ops.init                                                             */
/* ------------------------------------------------------------------ */
/*
 * スケジューラ初期化。カスタム DSQ を作成する。
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(hybrid_init)
{
    s32 cpu;
    s32 err;
    u32 nr_cpu_ids = scx_bpf_nr_cpu_ids();

    // CPU 個数分だけ，各 CPU 専用の CFS 用キューを作る
    bpf_for(cpu, 0, nr_cpu_ids) {
        err = scx_bpf_create_dsq(CFS_DSQ(cpu), -1);
        if (err)
            return err;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* ops.exit                                                             */
/* ------------------------------------------------------------------ */
void BPF_STRUCT_OPS(hybrid_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}

/* ------------------------------------------------------------------ */
/* struct sched_ext_ops 定義                                            */
/* ------------------------------------------------------------------ */
SEC(".struct_ops.link")
struct sched_ext_ops hybrid_ops = {
    .select_cpu = (void *)hybrid_select_cpu,
    .enqueue    = (void *)hybrid_enqueue,
    .dispatch   = (void *)hybrid_dispatch,
    .running    = (void *)hybrid_running,
    .stopping   = (void *)hybrid_stopping,
    .enable     = (void *)hybrid_enable,
    .init       = (void *)hybrid_init,
    .exit       = (void *)hybrid_exit,
    .name       = "hybrid",
};
