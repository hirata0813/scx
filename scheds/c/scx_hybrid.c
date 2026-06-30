// SPDX-License-Identifier: GPL-2.0
/*
 * Hybrid sched_ext スケジューラ – ユーザー空間ローダー
 *
 * 使い方:
 *   sudo ./scx_hybrid [--preemption-ns <ns>] [--stats-interval <sec>]
 *
 * オプション:
 *   --preemption-ns <ns>      プリエンプション・タイムスライス (ナノ秒)
 *                             デフォルト: 50000 (50 µs, ghOSt デフォルトと同値)
 *   --stats-interval <sec>   統計を表示する間隔 (秒)。0 で無効。デフォルト: 1
 *
 * ビルド (scx リポジトリの meson/cmake 環境でなく単独の場合):
 *   # BPF オブジェクトを先にビルドしておく
 *   clang -O2 -g -target bpf \
 *     -I /usr/include/x86_64-linux-gnu \
 *     -c scx_hybrid.bpf.c -o scx_hybrid.bpf.o
 *   bpftool gen skeleton scx_hybrid.bpf.o > scx_hybrid.skel.h
 *
 *   # ユーザー空間ローダーをビルド
 *   gcc -O2 -Wall -o scx_hybrid scx_hybrid.c \
 *     -lbpf -lelf -lz
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <stdint.h>
#include <errno.h>
#include <getopt.h>
#include <time.h>
#include <inttypes.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>

/* BPF スケルトン (bpftool gen skeleton で生成) */
#include "scx_hybrid.bpf.skel.h"

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
    STAT_FIFO_ENQUEUE   = 0,
    STAT_CFS_PROMOTE    = 1,
    STAT_CFS_ENQUEUE    = 2,
    STAT_DIRECT_DISPATCH = 3,
    STAT_MAX            = 4,
};

static const char *stat_names[STAT_MAX] = {
    [STAT_FIFO_ENQUEUE]    = "fifo_enqueue   ",
    [STAT_CFS_PROMOTE]     = "cfs_promote    ",
    [STAT_CFS_ENQUEUE]     = "cfs_enqueue    ",
    [STAT_DIRECT_DISPATCH] = "direct_dispatch",
};

/* ------------------------------------------------------------------ */
/* 統計表示                                                             */
/* ------------------------------------------------------------------ */
static void print_stats(struct scx_hybrid *skel)
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

    printf("\n[scx_hybrid stats]\n");
    for (int i = 0; i < STAT_MAX; i++)
        printf("  %-20s : %lu\n", stat_names[i], totals[i]);
    fflush(stdout);
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options]\n"
        "  --preemption-ns <ns>     FIFO time slice in nanoseconds (default: 50000)\n"
        "  --stats-interval <sec>   Stats print interval in seconds (default: 1, 0=off)\n"
        "  -h, --help               Show this help\n",
        prog);
}

int main(int argc, char *argv[])
{
    struct scx_hybrid *skel;
    struct bpf_link        *link = NULL;
    uint64_t preemption_ns   = 50000ULL; /* 50 µs */
    int      stats_interval  = 1;
    int      ret             = 0;

    /* ---- コマンドラインオプション ---- */
    static const struct option long_opts[] = {
        { "preemption-ns",   required_argument, NULL, 'p' },
        { "stats-interval",  required_argument, NULL, 's' },
        { "help",            no_argument,       NULL, 'h' },
        { 0 },
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "p:s:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p':
            preemption_ns = strtoull(optarg, NULL, 0);
            break;
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
	unlink("/sys/fs/bpf/hybrid_ops");
	unlink("/sys/fs/bpf/scx_hybr_bss");
	unlink("/sys/fs/bpf/scx_hybr_data");
	unlink("/sys/fs/bpf/scx_hybr_rodata");

    /* ---- BPF オブジェクトを開く ---- */
    skel = SCX_OPS_OPEN(hybrid_ops, scx_hybrid);

    /* ---- preemption_slice_ns を ro-data セクションで設定 ---- */
    skel->rodata->preemption_slice_ns = preemption_ns;

    /* ---- ロード & アタッチ ---- */
    SCX_OPS_LOAD(skel, hybrid_ops, scx_hybrid, uei);
    bpf_object__pin_maps(skel->obj, "/sys/fs/bpf"); // BPF Map をピン留め

    link = SCX_OPS_ATTACH(skel, hybrid_ops, scx_hybrid);

    printf("Hybrid sched_ext scheduler loaded.\n");
    printf("  preemption_slice_ns = %lu ns (%.3f ms)\n",
           preemption_ns, (double)preemption_ns / 1e6);
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

    printf("\nEXIT: Hybrid sched_ext scheduler unregistered.\n");

    bpf_link__destroy(link);
    UEI_REPORT(skel, uei);
	scx_hybrid__destroy(skel);
    return ret < 0 ? -ret : ret;
}
