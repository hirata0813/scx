// SPDX-License-Identifier: GPL-2.0
/*
 * scx_null: 比較用の「空」sched_ext スケジューラ
 *
 * scx_hybrid と同じロギング基盤 (タスク生成/初回実行/終了時刻の記録、
 * per-CPU 統計カウンタ、デバッグ対象タスクのフィルタ) だけを残し、
 * 実際にスケジューリングを判断するハンドラ
 *   - ops.select_cpu
 *   - ops.enqueue
 *   - ops.dispatch
 * は意図的に一切実装しない。
 *
 * sched_ext のコアは、これらが未実装の場合に次のデフォルト挙動へ
 * フォールバックする:
 *   - select_cpu 未実装 → scx_bpf_select_cpu_dfl() 相当の、
 *     CFS と同様のアイドル CPU 選択ロジックが使われる
 *   - enqueue 未実装    → タスクは自動的にビルトインの
 *     グローバル DSQ (SCX_DSQ_GLOBAL) に積まれる
 *   - dispatch 未実装   → SCX_DSQ_GLOBAL 上のタスクは
 *     カーネル側で自動的に (FIFO 順に) 消費される
 *
 * つまり本スケジューラを attach しても、実際のタスク配置・実行順序は
 * ほぼカーネルのデフォルトの sched_ext フォールバック挙動そのものになる。
 * scx_hybrid のような「実際にスケジューリングする」実装と比較するための
 * ベースライン (何もしないとどうなるか) として使うことを想定している。
 *
 * ビルド方法:
 *   clang -O2 -g -target bpf \
 *     -I /path/to/linux/tools/include \
 *     -I /path/to/scx/scheds/include \
 *     -c scx_null_bpf.c -o scx_null.bpf.o
 *
 * ユーザー空間ローダーは scx_null.c を参照。
 */

#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";
UEI_DEFINE(uei);

/* ------------------------------------------------------------------ */
/* タスクごとのロギング用コンテキスト                                    */
/* ------------------------------------------------------------------ */
/*
 * スケジューリングの判断には一切使わない、観測(ロギング)専用のフィールドのみ。
 */
struct task_ctx {
    /* enable() が呼ばれた時刻 (= タスクが sched_ext の管理下に入った時刻) */
    u64 tasknew;

    /* running() が最初に呼ばれた時刻 (= タスクが実際に初めて CPU を得た時刻) */
    u64 firstrun;
    bool is_firstrun_logged;

    /* disable() が呼ばれた時刻 (= タスクが sched_ext の管理下から外れた時刻) */
    u64 taskdead;
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/* ------------------------------------------------------------------ */
/* 特定のタスクに対してのみ詳細ログを出したいとき                          */
/* ------------------------------------------------------------------ */
/*
 * debug_filter という BPF Map にエントリがあり，かつ value が1のときに，
 * is_debug_task() は true を返す。ログのフィルタリングに使う。
 * (ユーザー空間から --debug-pid で登録する)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, u8);
} debug_filter SEC(".maps");

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
/*
 * スケジューリングの意思決定には一切使わない、単なる呼び出し回数のカウンタ。
 */
enum stat_idx {
    STAT_ENABLE   = 0, /* ops.enable   が呼ばれた回数 (タスク生成) */
    STAT_DISABLE  = 1, /* ops.disable  が呼ばれた回数 (タスク終了) */
    STAT_RUNNING  = 2, /* ops.running  が呼ばれた回数 */
    STAT_STOPPING = 3, /* ops.stopping が呼ばれた回数 */
    STAT_MAX      = 4,
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, STAT_MAX);
} stats SEC(".maps");

static __always_inline void stat_inc(enum stat_idx idx)
{
    u32 key = (u32)idx;
    u64 *cnt = bpf_map_lookup_elem(&stats, &key);
    if (cnt)
        (*cnt)++;
}

/* ------------------------------------------------------------------ */
/* ops.enable                                                           */
/* ------------------------------------------------------------------ */
/*
 * タスクが sched_ext の制御下に入ったときに呼ばれる。
 * ロギング用の task_ctx を初期化するだけで、CPU 割当やキュー投入といった
 * スケジューリングの判断には一切関与しない (それらは呼んですらいない)。
 */
void BPF_STRUCT_OPS(null_enable, struct task_struct *p)
{
    struct task_ctx *tctx;

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
                                 BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!tctx)
        return;

    tctx->tasknew           = bpf_ktime_get_ns();
    tctx->firstrun           = 0;
    tctx->is_firstrun_logged = false;
    tctx->taskdead           = 0;

    stat_inc(STAT_ENABLE);

    if (is_debug_task(p))
        bpf_printk("[scx_null] enable    pid=%d comm=%s", p->pid, p->comm);
}

/* ------------------------------------------------------------------ */
/* ops.running                                                          */
/* ------------------------------------------------------------------ */
/*
 * タスクが CPU 上で実際に実行を開始した直後に呼ばれる。
 * 「enable から初回実行までのレイテンシ」をログするだけで、
 * タイムスライスや優先度の決定には一切関与しない
 * (CPU 選択・実行順序はすべてカーネルのデフォルト実装に委ねている)。
 */
void BPF_STRUCT_OPS(null_running, struct task_struct *p)
{
    struct task_ctx *tctx;

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
    if (!tctx)
        return;

    stat_inc(STAT_RUNNING);

    if (!tctx->is_firstrun_logged) {
        tctx->firstrun           = bpf_ktime_get_ns();
        tctx->is_firstrun_logged = true;

        if (is_debug_task(p)) {
            u64 latency_ns = tctx->firstrun - tctx->tasknew;

            bpf_printk("[scx_null] first_run pid=%d comm=%s latency_ns=%llu",
                       p->pid, p->comm, latency_ns);
        }
    }
}

/* ------------------------------------------------------------------ */
/* ops.stopping                                                         */
/* ------------------------------------------------------------------ */
/*
 * タスクが CPU を離れる直前に呼ばれる。
 * 呼び出し回数の記録とデバッグログのみを行い、
 * (scx_hybrid で行っていたような) 昇格判定やタイムスライスの変更、
 * vtime の更新などは一切行わない。
 */
void BPF_STRUCT_OPS(null_stopping, struct task_struct *p, bool runnable)
{
    struct task_ctx *tctx;

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0, 0);
    if (!tctx)
        return;

    stat_inc(STAT_STOPPING);

    if (is_debug_task(p))
        bpf_printk("[scx_null] stopping  pid=%d comm=%s runnable=%d",
                   p->pid, p->comm, runnable);
}

/* ------------------------------------------------------------------ */
/* ops.disable                                                        */
/* ------------------------------------------------------------------ */
/*
 * タスクが終了し、sched_ext の制御下から外れるときに呼ばれる。
 * タスクの生存時間 (enable から disable まで) をログするだけ。
 */
void BPF_STRUCT_OPS(null_disable, struct task_struct *p)
{
    struct task_ctx *tctx;

    tctx = bpf_task_storage_get(&task_ctx_stor, p, 0,
                                 BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!tctx)
        return;

    tctx->taskdead = bpf_ktime_get_ns();

    stat_inc(STAT_DISABLE);

    if (is_debug_task(p)) {
        u64 lifetime_ns = tctx->taskdead - tctx->tasknew;

        bpf_printk("[scx_null] disable   pid=%d comm=%s lifetime_ns=%llu",
                   p->pid, p->comm, lifetime_ns);
    }
}

/* ------------------------------------------------------------------ */
/* ops.init / ops.exit                                                  */
/* ------------------------------------------------------------------ */
/*
 * スケジューリング用のカスタム DSQ は何一つ作らない
 * (select_cpu/enqueue/dispatch を実装していないため、そもそも不要)。
 */
s32 BPF_STRUCT_OPS_SLEEPABLE(null_init)
{
    return 0;
}

void BPF_STRUCT_OPS(null_exit, struct scx_exit_info *ei)
{
    UEI_RECORD(uei, ei);
}

/* ------------------------------------------------------------------ */
/* struct sched_ext_ops 定義                                            */
/* ------------------------------------------------------------------ */
/*
 * 意図的に select_cpu / enqueue / dispatch を定義しない:
 *   - select_cpu 未実装 → カーネルのデフォルト CPU 選択にフォールバック
 *   - enqueue 未実装    → タスクは自動的にビルトインのグローバル DSQ に積まれる
 *   - dispatch 未実装   → そのグローバル DSQ はカーネル側で自動的に消費される
 * スケジューリングの判断は完全にカーネルのデフォルト実装に委ねられる。
 */
SEC(".struct_ops.link")
struct sched_ext_ops null_ops = {
    .enable     = (void *)null_enable,
    .running    = (void *)null_running,
    .stopping   = (void *)null_stopping,
    .disable    = (void *)null_disable,
    .init       = (void *)null_init,
    .exit       = (void *)null_exit,
    .name       = "null",
};
