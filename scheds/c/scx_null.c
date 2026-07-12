// SPDX-License-Identifier: GPL-2.0
/*
 * scx_null – 比較用の「空」sched_ext スケジューラ ユーザー空間ローダー
 *
 * select_cpu / enqueue / dispatch を一切実装しない、ロギングのみの
 * sched_ext スケジューラ。scx_hybrid のように実際にスケジューリングを
 * 行う実装と比較するための「何もしないベースライン」として使う。
 *
 * attach すると、タスクの CPU 選択・キュー投入・実行順序の決定は
 * すべてカーネルのデフォルトの sched_ext フォールバック挙動に委ねられる。
 * 本ローダーは、タスクの生成/初回実行/終了に関する統計・ログだけを収集する。
 *
 * 使い方:
 *   sudo ./scx_null [--stats-interval <sec>]...
 *
 * オプション:
 *   --stats-interval <sec>   統計を表示する間隔 (秒)。0 で無効。デフォルト: 1
 *   -h, --help               このヘルプを表示
 *
 * ビルド (scx リポジトリの meson/cmake 環境でなく単独の場合):
 *   # BPF オブジェクトを先にビルドしておく
 *   clang -O2 -g -target bpf \
 *     -I /usr/include/x86_64-linux-gnu \
 *     -c scx_null_bpf.c -o scx_null.bpf.o
 *   bpftool gen skeleton scx_null.bpf.o > scx_null.bpf.skel.h
 *
 *   # ユーザー空間ローダーをビルド
 *   gcc -O2 -Wall -o scx_null scx_null.c \
 *     -lbpf -lelf -lz
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <sys/types.h>
#include <bpf/bpf.h>
#include <scx/common.h>

/* BPF スケルトン (bpftool gen skeleton で生成) */
#include "scx_null.bpf.skel.h"

/* ------------------------------------------------------------------ */
/* グローバル変数                                                       */
/* ------------------------------------------------------------------ */
static volatile int g_exit = 0;

static void sig_handler(int sig)
{
    (void)sig;
    g_exit = 1;
}

/* ------------------------------------------------------------------ */
/* 統計インデックス (BPF 側と一致させる)                               */
/* ------------------------------------------------------------------ */
enum stat_idx {
    STAT_ENABLE   = 0,
    STAT_DISABLE  = 1,
    STAT_RUNNING  = 2,
    STAT_STOPPING = 3,
    STAT_MAX      = 4,
};

static const char *stat_names[STAT_MAX] = {
    [STAT_ENABLE]   = "enable  ",
    [STAT_DISABLE]  = "disable ",
    [STAT_RUNNING]  = "running ",
    [STAT_STOPPING] = "stopping",
};

/* ------------------------------------------------------------------ */
/* 統計表示                                                             */
/* ------------------------------------------------------------------ */
static void print_stats(struct scx_null *skel)
{
    int stats_fd = bpf_map__fd(skel->maps.stats);
    int nr_cpus  = libbpf_num_possible_cpus();
    uint64_t totals[STAT_MAX] = {};
    uint64_t vals[nr_cpus];

    for (int i = 0; i < STAT_MAX; i++) {
        uint32_t key = (uint32_t)i;
        if (bpf_map_lookup_elem(stats_fd, &key, vals) == 0) {
            for (int c = 0; c < nr_cpus; c++)
                totals[i] += vals[c];
        }
    }

    printf("\n[scx_null stats]\n");
    for (int i = 0; i < STAT_MAX; i++)
        printf("  %-10s : %lu\n", stat_names[i], totals[i]);
    fflush(stdout);
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  --stats-interval <sec>   Stats print interval in seconds (default: 1, 0=off)\n"
        "  -h, --help               Show this help\n"
        "\n"
        "Note: this scheduler implements NO scheduling-decision hooks\n"
        "(select_cpu / enqueue / dispatch). It exists purely as a logging-only\n"
        "baseline for comparison against scx_hybrid and similar schedulers;\n"
        "CPU selection and dispatch are left entirely to the kernel's default\n"
        "sched_ext fallback behavior.\n",
        prog);
}

int main(int argc, char *argv[])
{
    struct scx_null *skel;
    struct bpf_link *link           = NULL;
    int      stats_interval         = 1;
    int      ret                    = 0;
    int opt;

    /* ---- コマンドラインオプション ---- */
    static const struct option long_opts[] = {
        { "stats-interval", required_argument, NULL, 's' },
        { "help",           no_argument,       NULL, 'h' },
        { 0 },
    };

    while ((opt = getopt_long(argc, argv, "s:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 's':
            stats_interval = atoi(optarg);
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    /* ---- シグナル設定 ---- */
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* ---- libbpf verbosity ---- */
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    unlink("/sys/fs/bpf/debug_filter");
    unlink("/sys/fs/bpf/task_ctx_stor");
    unlink("/sys/fs/bpf/stats");
    unlink("/sys/fs/bpf/_data_uei_dump");
    unlink("/sys/fs/bpf/null_ops");
    unlink("/sys/fs/bpf/scx_null_bss");
    unlink("/sys/fs/bpf/scx_null_data");
    unlink("/sys/fs/bpf/scx_null_rodata");

    /* ---- BPF オブジェクトを開く ---- */
    skel = SCX_OPS_OPEN(null_ops, scx_null);

    /* ---- ロード ---- */
    SCX_OPS_LOAD(skel, null_ops, scx_null, uei);

    bpf_object__pin_maps(skel->obj, "/sys/fs/bpf"); // BPF Map をピン留め

    /* ---- アタッチ ---- */
    link = SCX_OPS_ATTACH(skel, null_ops, scx_null);

    printf("Null (logging-only) sched_ext scheduler loaded.\n");
    printf("  select_cpu / enqueue / dispatch are NOT implemented;\n");
    printf("  all scheduling decisions fall back to the kernel default.\n");
    printf("Press Ctrl-C to unload.\n\n");

    /* ---- メインループ ---- */
    while (!g_exit && !UEI_EXITED(skel, uei)) {
        if (stats_interval > 0) {
            sleep((unsigned)stats_interval);
            if (!g_exit)
                print_stats(skel);
        } else {
            sleep(1);
        }
    }

    /* ---- 最終統計 ---- */
    if (stats_interval > 0)
        print_stats(skel);

    printf("\nEXIT: Null sched_ext scheduler unregistered.\n");

    bpf_link__destroy(link);
    UEI_REPORT(skel, uei);
    scx_null__destroy(skel);
    return ret < 0 ? -ret : ret;
}
