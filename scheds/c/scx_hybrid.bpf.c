// SPDX-License-Identifier: GPL-2.0
/*
 * Hybrid sched_ext Scheduler
 *
 * ロジック:
 *   - タスクはまず、FIFO DSQ (全 CPU で共通のカスタム DSQ) に入る。
 *   - FIFO DSQ 上のタスクは preemption_slice_ns ナノ秒間だけ実行される。
 *   - FIFO において，タイムスライスを使い切る前に終了(他タスクの割り込みや自発的スリープ)したタスクは再び FIFO に戻る。
 *   - タイムスライスを使い切って終了した(slice == 0 で stopping)タスクは，CFS ポリシ(CPU ごとに持つカスタム CFS DSQ) に格上げされ、以降は vtime ベースで
 *     スケジューリングされる。
 *
 * ghOSt 実装との対応:
 *   ghOSt HybridScheduler    →  この BPF スケジューラ
 *   ShortQueueRq (FIFO)      →  FIFO_DSQ  (全 CPU で共通のカスタム DSQ)
 *   CfsRq (vtime)            →  CFS_DSQ   (CPU ごとに持つカスタム CFS DSQ)
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
/* 
 * CFS(vtime)用DSQ: 下位32ビットを CPU 番号に，上位32ビットを DSQ 種別とした DSQ ID
 * 例えば，CPU 1 に対応する CFS DSQ の ID は「0x100000001」となる
 * 0x1_00000001
 *   ↑ ↑
 *   |  └─ 下位32bit = 0x00000001 = 1  (CPU番号)
 *   └──── 33bit目    = 1              (DSQ種別マーカー、1ULL<<32)
 */
#define CFS_DSQ(cpu)   ((u64)(cpu) | (1ULL << 32))
#define GLOBAL_FIFO_DSQ 0x0ffffffff // 33bit目は0(FIFO のマーカ)，下位32bitは全て立てて，CPU番号と被らないようにしておく
#define GLOBAL_CFS_DSQ 0x1ffffffff // --global-cfs 指定時に使う，CPU に紐付かない単一の CFS DSQ．33bit目は0(FIFO のマーカ)，下位32bitは全て立てて，CPU番号と被らないようにしておく

#define CFS_SCHED_SLICE_NS  10000000ULL
/* ------------------------------------------------------------------ */
/* 設定 (ユーザー空間から BPF_MAP_TYPE_ARRAY で書き換え可能)           */
/* ------------------------------------------------------------------ */
/* デフォルトのプリエンプション・タイムスライス: 50 µs (ghOSt デフォルトと同じ) */
const volatile u64 preemption_slice_ns = 50000ULL;

/*
 * true の場合、CFS フェーズは CPU ごとの CFS_DSQ(cpu) ではなく、
 * 全 CFS CPU で共有する単一の GLOBAL_CFS_DSQ を使う。
 * (--global-cfs オプションでユーザー空間から設定)
 */
const volatile bool global_cfs = false;
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
     * vtime は，タスクがこれまでに，実際に CPU を掴んで実行された累積時間．小さいほど「CPU をあまり使ってないので優先して実行すべき」という意味
     * CFS DSQ にエンキューする際は，都度，vtime の値で DSQ 内のタスクが並べ替えられる
     */
    u64 vtime;

    /* CFS フェーズで，前回実行していた CPU を記録する
     * マイグレーションが発生した際，vtime を適切な値に更新できるようにするため
     */
    s32 last_cpu;

    /* CFS フェーズで，前回実行していた CPU を記録する
     * マイグレーションが発生した際，vtime を適切な値に更新できるようにするため
     */
    

    u64 tasknew;
    u64 firstrun;
    bool is_firstrun_logged;
    bool is_enqueue_passed;
    u64 taskdead;
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/* ------------------------------------------------------------------ */
/* 各タスクのメトリクスを保持する BPF Map                                  */
/* ------------------------------------------------------------------ */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, pid_t);
    __type(value, u64);
} tasknew_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, pid_t);
    __type(value, u64);
} firstrun_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, pid_t);
    __type(value, u64);
} taskdead_map SEC(".maps");

/* ------------------------------------------------------------------ */
/* CPU の割当ポリシを管理する Map・関数                                    */
/* ------------------------------------------------------------------ */
enum cpu_policy {
    CPU_POLICY_UNSET = 0,  /* 未設定 = デフォルト値。明示的にセットされていない場合と区別するため */
    CPU_POLICY_FIFO  = 1,
    CPU_POLICY_CFS   = 2,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64); /* 50 個程度の CPU を管理できるよう余裕を持たせる */
    __type(key, u32);
    __type(value, u32);
} cpu_policy_map SEC(".maps");

// 各ポリシごとに「最後に選んだCPU」を記憶する．これは，あるポリシに対応する CPU を探す際，どれも busy だった場合に，フォールバックとして選ぶ CPU を固定させないため      */
enum rr_idx {
    RR_IDX_FIFO = 0,
    RR_IDX_CFS  = 1,
    RR_IDX_MAX  = 2,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, RR_IDX_MAX);
    __type(key, u32);
    __type(value, u32);
} rr_last_cpu_map SEC(".maps");

static s32 pick_cpu_by_policy(u32 target_policy, u32 rr_idx)
{
    s32 cpu;
    u32 nr_cpus = scx_bpf_nr_cpu_ids();
    s32 fallback_cpu = -1;
    u32 start;
    u32 *last;

    if (nr_cpus == 0)
        return -1;

    /* 前回選んだ CPU の「次」から探索を始める */
    last  = bpf_map_lookup_elem(&rr_last_cpu_map, &rr_idx);
    start = last ? ((*last + 1) % nr_cpus) : 0;

    /* 前回選んだ「次」から該当ポリシの CPU を探しつつ、
     * アイドルなら即採用，busy なら最初の1件を fallback として記憶
     * このようにする理由は，該当ポリシの CPU が全て busy な場合に，フォールバックとして選ばれるものを固定化させないため
     */
    bpf_for(cpu, 0, nr_cpus) {
        u32 candidate = (start + (u32)cpu) % nr_cpus;
        u32 key = candidate;
        u32 *policy = bpf_map_lookup_elem(&cpu_policy_map, &key);

        /* ポリシが一致していない場合は次ループに行く*/
        if (!policy || *policy != target_policy){
            continue;
        }

        /* 最初に見つかったものをフォールバックとして記録しておく*/
        if (fallback_cpu < 0){
            fallback_cpu = (s32)candidate;
        }

        /* アイドルな場合は，それを選ぶ*/
        if (scx_bpf_test_and_clear_cpu_idle(candidate)) {
            u32 val = candidate;
            bpf_map_update_elem(&rr_last_cpu_map, &rr_idx, &val, BPF_ANY);
            return (s32)candidate;
        }
    }

    /* 該当ポリシーのCPUが1つも存在しない */
    if (fallback_cpu < 0)
        return -1;

    /* 全部busyだった場合、最初に見つかったCPUをfallbackとして採用 */
    u32 val = (u32)fallback_cpu;
    bpf_map_update_elem(&rr_last_cpu_map, &rr_idx, &val, BPF_ANY);
   
    return fallback_cpu;
}

static inline s32 pick_fifo_cpu(void)
{
    return pick_cpu_by_policy(CPU_POLICY_FIFO, RR_IDX_FIFO);
}

static inline s32 pick_cfs_cpu(void)
{
    return pick_cpu_by_policy(CPU_POLICY_CFS, RR_IDX_CFS);
}

static inline s32 pick_other_cpu(void)
{
    return pick_cpu_by_policy(CPU_POLICY_UNSET, RR_IDX_CFS);
}

static __always_inline bool is_fifo_cpu(s32 cpu)
{
    u32 key = (u32)cpu;
    u32 *policy = bpf_map_lookup_elem(&cpu_policy_map, &key);

    return policy && *policy == CPU_POLICY_FIFO;
}

static __always_inline bool is_cfs_cpu(s32 cpu)
{
    u32 key = (u32)cpu;
    u32 *policy = bpf_map_lookup_elem(&cpu_policy_map, &key);

    return policy && *policy == CPU_POLICY_CFS;
}

/* ------------------------------------------------------------------ */
/* 特定のタスクに対してのみデバッグしたいとき                                */
/* ------------------------------------------------------------------ */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, u8);
} debug_filter SEC(".maps");

/*
 * debug_filter という BPF Map にエントリがあり，かつ value が1のときに，is_debug_task()は true を返す
 * ログのフィルタリングなどで利用する
 */
static bool is_debug_task(struct task_struct *p)
{
    pid_t pid = p->pid;
    u8 *val;

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
 * CPU ごとの CFS_DSQ の vtime を管理する Map
 */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, u32);
    __type(value, u64);
} vtime_now_map SEC(".maps");

static __always_inline u64 get_vtime_now(s32 cpu)
{
    u32 key = (u32)cpu;
    u64 *val = bpf_map_lookup_elem(&vtime_now_map, &key);
    return val ? *val : 0;
}

static __always_inline void update_vtime_now(s32 cpu, u64 vtime)
{
    u32 key = (u32)cpu;
    u64 *val = bpf_map_lookup_elem(&vtime_now_map, &key);
    if (val)
        *val = vtime;
}

/*
 * --global-cfs モード用の、CPU に紐付かない単一の vtime_now
 * 実在の CPU 番号と衝突しないよう、専用の 1 要素 Map として分離
 * (プレーンな BPF グローバル変数ではなく Map にしているのは、
 *  他の vtime_now と同じアクセス経路に統一するため)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} global_vtime_now_map SEC(".maps");

static __always_inline u64 get_global_vtime_now(void)
{
    u32 key = 0;
    u64 *val = bpf_map_lookup_elem(&global_vtime_now_map, &key);
    return val ? *val : 0;
}

static __always_inline void update_global_vtime_now(u64 vtime)
{
    u32 key = 0;
    u64 *val = bpf_map_lookup_elem(&global_vtime_now_map, &key);
    if (val)
        *val = vtime;
}

static __always_inline void print_vtime_now()
{
    u32 key0 = 0;
    u32 key1 = 1;
    u32 key2 = 2;
    u32 key3 = 3;
    u64 *vtime0;
    u64 *vtime1;
    u64 *vtime2;
    u64 *vtime3;

    vtime0 = bpf_map_lookup_elem(&vtime_now_map, &key0);
    vtime1 = bpf_map_lookup_elem(&vtime_now_map, &key1);
    vtime2 = bpf_map_lookup_elem(&vtime_now_map, &key2);
    vtime3 = bpf_map_lookup_elem(&vtime_now_map, &key3);
    
    if(vtime0 && vtime1 && vtime2 && vtime3){
        bpf_printk("vtime_now: CPU0:%llu, CPU1:%llu, CPU2:%llu, CPU3:%llu", *vtime0, *vtime1, *vtime2, *vtime3);
    }
}

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

    if (!tctx || p->nr_cpus_allowed == 1) {
        /* フォールバック: デフォルトの CPU 選択アルゴリズムに任せる */
        cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
        if (is_idle) {
		    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	    }
        return cpu;
    }

    // ワークロード起動スクリプトは別 CPU で実行
    if (is_debug_task(p)) {
        //cpu = pick_other_cpu();
        cpu = 20;
        //bpf_printk("select_cpu(): pid:%d, comm:%s, cpu:%d", p->pid, p->comm, cpu);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | cpu, SCX_SLICE_DFL, SCX_ENQ_PREEMPT);
        return cpu;
    }

    return prev_cpu;
}

/* ------------------------------------------------------------------ */
/* ops.enqueue                                                          */
/* ------------------------------------------------------------------ */
/*
 * タスクを DSQ にエンキューする際に呼ばれる
 *
 * - promoted == false → グローバル FIFO DSQ にエンキュー (タイムスライス = preemption_slice_ns)
 * - promoted == true  → CFS が割り当てられた CPU を選び，その CPU に紐付いた CFS_DSQ  に vtime ベースでエンキュー
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

    if (!tctx || p->nr_cpus_allowed == 1) {
        /* フォールバック: デフォルトの CPU 選択アルゴリズムに任せる */
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, preemption_slice_ns, enq_flags);
        return;
    }
    tctx->is_enqueue_passed = 1;

    if (!tctx->promoted) {
        /* FIFO フェーズ */
        stat_inc(STAT_FIFO_ENQUEUE);
        bpf_printk("enqueue(): FIFO: pid:%d, comm:%s", p->pid, p->comm);

        /*
         * 関連研究では，FIFO キューはグローバルキューとして実装していたため，本実装もそのようにする
         */
        scx_bpf_dsq_insert(p, GLOBAL_FIFO_DSQ, preemption_slice_ns, enq_flags);
    } else {
        bpf_printk("enqueue(): CFS: pid:%d, comm:%s", p->pid, p->comm);
        /* CFS フェーズ: vtime ベース */

        /* CFS フェーズでは，vtime の小さい順にスケジューリングされる
         * vtime は，タスクがこれまでに，実際に CPU を掴んで実行された累積時間．CFS 小さいほど「CPU をあまり使ってないので優先して実行すべき」という意味
         */
        u64 vtime = tctx->vtime;
        u64 dsq_id;
        u64 vtime_now;

        if (global_cfs) {
            /*
             * --global-cfs: 全 CFS CPU で共有する単一 DSQ を使うため、
             * どの CPU が実際に実行するかを事前に選ぶ必要はない。
             * vtime の基準も単一の global_vtime_now_map を使うので、
             * CPU マイグレーションによる vtime 変換も不要になる。
             */
            dsq_id = GLOBAL_CFS_DSQ;
            vtime_now = get_global_vtime_now();
        } else {
            s32 cfs_cpu;
            cfs_cpu = pick_cfs_cpu();
            dsq_id = CFS_DSQ(cfs_cpu);

            vtime_now = get_vtime_now(cfs_cpu);
            // CPU マイグレーションがあった場合，vtime を新しい CPU の基準に変換する
            if (tctx->last_cpu >= 0 && tctx->last_cpu != cfs_cpu) {
                u64 old_now = get_vtime_now(tctx->last_cpu);
                // 旧 CPU での「相対的な位置」を新 CPU に移植する
                // relative = vtime - old_now  (負なら末尾より前、正なら末尾より後)
                // new_vtime = vtime_now + relative
                if (old_now > 0) {
                    s64 relative = (s64)(vtime - old_now);
                    vtime = (u64)((s64)vtime_now + relative);
                }
            }

            tctx->last_cpu = cfs_cpu;
        }

        /*
         * vtime_now は，各 CFS DSQ における「現在の仮想時間の基準」
         * vtime_now は単調増加のみで，runnning() と stopping() で更新する
         * vtime_before()により，vtime_now の1スライス以上後ろに取り残されているタスクを判定し，それらの vtime をクランプ
         * vtime_before(a, b)は，a < b であれば true を返す
         * クランプとは，vtime が小さすぎるタスク(例えばずっと I/O 待ちで寝てたやつ)の vtime を引き上げること
         * このようにして，タスクがキューの中で極端に有利な位置に入るのを防ぐ
         */
        if (vtime_before(vtime, vtime_now - preemption_slice_ns)){
            vtime = vtime_now - preemption_slice_ns;
            tctx->vtime = vtime;
        }

        stat_inc(STAT_CFS_ENQUEUE);

        scx_bpf_dsq_insert_vtime(p, dsq_id, CFS_SCHED_SLICE_NS, vtime, enq_flags);
    }
}

/* ------------------------------------------------------------------ */
/* ops.dispatch                                                         */
/* ------------------------------------------------------------------ */
/*
 * CPU が実行するタスクを探す際に呼ばれる。
 * このハンドラは，CPU のローカル DSQ，グローバル DSQ 両方が空の際に呼ばれる．
 * このスケジューラでは，基本的には，ローカルとグローバルのどちらにも直接エンキューしないため，このハンドラは定期的に呼び出される想定．
 * ハンドラを呼び出した CPU に割当たっている ポリシを判定し，それに対応するカスタム DSQ から，CPU のローカルキューへタスクを move する．
 *
 * ghOSt ShortQueueSchedule() における short_queue_ 優先、
 * 次に long_cpulist 上の CFS という順序と対応する。
 */
void BPF_STRUCT_OPS(hybrid_dispatch, s32 cpu, struct task_struct *prev)
{
    if(is_fifo_cpu(cpu)){
        /*
         * ハンドラを呼び出した CPU がFIFO 対応の場合，グローバル FIFO DSQ のタスクを移動
         */
        scx_bpf_dsq_move_to_local(GLOBAL_FIFO_DSQ);
    }else if(is_cfs_cpu(cpu)){
        /*
         * ハンドラを呼び出した CPU が CFS 対応の場合、
         * --global-cfs なら全 CFS CPU 共有の GLOBAL_CFS_DSQ から、
         * そうでなければ自分専用の CFS_DSQ(cpu) からタスクを移動する
         */
        u64 dsq_id = global_cfs ? GLOBAL_CFS_DSQ : CFS_DSQ(cpu);
        scx_bpf_dsq_move_to_local(dsq_id);
    }
}

/* ------------------------------------------------------------------ */
/* ops.running                                                          */
/* ------------------------------------------------------------------ */
/*
 * タスクが CPU 上で実際に実行を開始した直後に呼ばれる
 * FIFO フェーズでは，特に何もしない
 * CFS フェーズでは，スライス開始時点での CPU 累積実行時間を記録し，vtime_now を最新化
 *
 * ghOSt TaskOnCpu() に相当。
 */
void BPF_STRUCT_OPS(hybrid_running, struct task_struct *p)
{
    struct task_ctx *tctx;

    s32 cpu2 = bpf_get_smp_processor_id();
    //cpu = pick_other_cpu();

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
    if (!tctx)
        return;

    if (tctx->is_enqueue_passed == 1 && !tctx->is_firstrun_logged){
        tctx->firstrun               = bpf_ktime_get_ns();
        tctx->is_firstrun_logged = 1;
    }

    if (!tctx->promoted) {
        /* FIFO フェーズ: 特にやることはなし*/
        bpf_printk("running(): FIFO: pid:%d, comm:%s, cpu:%d, scx.slice:%llu", p->pid, p->comm, cpu2, p->scx.slice);
    } else {
        bpf_printk("running(): CFS: pid:%d, comm:%s, cpu:%d, scx.slice:%llu", p->pid, p->comm, cpu2, p->scx.slice);
        /* CFS フェーズ: スライス開始時点での CPU 累積実行時間を記録し，vtime_now を最新化
         *              CPU 累積実行時間を記録するのは，stopping() で，そのスライスでの CPU 利用時間を計算し，タスクの vtime を更新するため
         */
        tctx->cfs_start_runtime_ns = p->se.sum_exec_runtime;

        if (global_cfs) {
            u64 vtime_now = get_global_vtime_now();
            if (vtime_before(vtime_now, tctx->vtime))
                update_global_vtime_now(tctx->vtime);
        } else {
            s32 cpu = bpf_get_smp_processor_id();
            u64 vtime_now = get_vtime_now(cpu);

            if (vtime_before(vtime_now, tctx->vtime)){
                update_vtime_now(cpu, tctx->vtime);
            }
        }

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
    s32 cpu2 = bpf_get_smp_processor_id();

    if (tctx->promoted) {
        bpf_printk("stopping(): CFS: pid:%d, comm:%s, cpu:%d, scx.slice:%llu", p->pid, p->comm, cpu2, p->scx.slice);
        /*
         * CFS フェーズ: 実際に消費した CPU 時間を vtime に反映。
         * nice 値対応が必要なら inverse_weight を掛け算する。
         */
        u64 used = p->se.sum_exec_runtime - tctx->cfs_start_runtime_ns; // このスライスでの CFS 実行で，CPU をどの程度掴んで動いたのかを計算
                                                                        // つまり，p->se.sum_exec_runtime から，タスク実行開始時点での CPU 累積実行時間を，引く必要がある
        tctx->vtime += used;
        /* vtime_now を前に進める */
        if (global_cfs) {
            u64 vtime_now = get_global_vtime_now();
            if (vtime_before(vtime_now, tctx->vtime))
                update_global_vtime_now(tctx->vtime);
        } else {
            s32 cpu = bpf_get_smp_processor_id();
            u64 vtime_now = get_vtime_now(cpu);
            if (vtime_before(vtime_now, tctx->vtime)){
                update_vtime_now(cpu, tctx->vtime);
            }
        }
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
    bpf_printk("stopping(): FIFO: pid:%d, comm:%s, cpu:%d, scx.slice:%llu", p->pid, p->comm, cpu2, p->scx.slice);
    if (runnable && p->scx.slice == 0 && tctx->is_enqueue_passed == 1) {
        /* CFS フェーズへ昇格 */
        bpf_printk("stopping(): FIFO -> CFS: pid:%d, comm:%s, cpu:%d, scx.slice:%llu", p->pid, p->comm, cpu2, p->scx.slice);
        tctx->promoted = true;
        /*
         * 初回 vtime は0に設定 (enqueue()で，選択された CFS DSQ の vtime_now を基準にクランプされるため)
         * これにより CFS_DSQ の末尾近くに投入される
         */
        tctx->vtime = 0;
        
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
    tctx->vtime                 = 0;
    tctx->last_cpu              = -1; // 未設定を示す
    tctx->tasknew               = bpf_ktime_get_ns();
    tctx->firstrun              = 0;
    tctx->is_firstrun_logged    = 0;
    tctx->is_enqueue_passed     = 0;
    tctx->taskdead              = 0;
    
    bpf_printk("enable(): pid:%d, comm:%s", p->pid, p->comm);
}

/* ------------------------------------------------------------------ */
/* ops.disable                                                        */
/* ------------------------------------------------------------------ */
/*
 * タスクが終了し，sched_ext の制御下が外れるときに呼ばれる。
 * タスクの終了時刻を記録する。
 */
void BPF_STRUCT_OPS(hybrid_disable, struct task_struct *p)
{
    struct task_ctx *tctx;

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
                                 BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!tctx)
        return;

    tctx->taskdead               = bpf_ktime_get_ns();
    if (bpf_strncmp(p->comm, sizeof(p->comm), "launch_function") == 0) {
        pid_t pid = p->pid;
        bpf_map_update_elem(&tasknew_map, &pid, &tctx->tasknew, BPF_ANY);
        bpf_map_update_elem(&firstrun_map, &pid, &tctx->firstrun, BPF_ANY);
        bpf_map_update_elem(&taskdead_map, &pid, &tctx->taskdead, BPF_ANY);
    }
    bpf_printk("disable(): pid:%d, comm:%s", p->pid, p->comm);
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

    if (global_cfs) {
        // --global-cfs: 全 CFS CPU で共有する DSQ を1つだけ作る
        err = scx_bpf_create_dsq(GLOBAL_CFS_DSQ, -1);
        if (err)
            return err;
    } else {
        // CPU 個数分だけ，各 CPU 専用の CFS 用キューを作る
        bpf_for(cpu, 0, nr_cpu_ids) {
            err = scx_bpf_create_dsq(CFS_DSQ(cpu), -1);
            if (err)
                return err;
        }
    }

    // グローバルな FIFO DSQ を1つ作る
    err = scx_bpf_create_dsq(GLOBAL_FIFO_DSQ, -1);
    if (err)
        return err;

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
    .disable    = (void *)hybrid_disable,
    .init       = (void *)hybrid_init,
    .exit       = (void *)hybrid_exit,
    //.flags      = SCX_OPS_SWITCH_PARTIAL,
    .name       = "hybrid",
};
