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
#include <stdbool.h>
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
#include <sys/stat.h>

/* BPF スケルトン (bpftool gen skeleton で生成) */
#include "scx_hybrid.bpf.skel.h"

/* Map をピンするディレクトリ */
#define BPF_FS_HYBRID_DIR "/sys/fs/bpf/scx_hybrid"
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
/* CPU ポリシーの設定                                                   */
/* ------------------------------------------------------------------ */

enum cpu_policy {
    CPU_POLICY_UNSET = 0,  /* 未設定 = デフォルト値。明示的にセットされていない場合と区別するため */
    CPU_POLICY_FIFO  = 1,
    CPU_POLICY_CFS   = 2,
};

/*
 * cpu_policy_map (BPF_MAP_TYPE_ARRAY) に書き込める CPU 数の上限。
 * BPF 側 (scx_hybrid_bpf.c) の cpu_policy_map の max_entries と一致させること。
 * 現状 64 なので、50 個ほどの CPU を fifo/cfs 用途で管理するのに十分な余裕がある。
 */
#define CPU_POLICY_MAP_CAPACITY 64

/*
 * fifo/cfs のどちらにも割り当てられた CPU を記録しておくための表。
 * fifo と cfs 両方の呼び出しをまたいで重複チェックするため、
 * ファイルスコープ (static) で保持する。
 * 値は CPU_POLICY_UNSET / CPU_POLICY_FIFO / CPU_POLICY_CFS のいずれか。
 */
static uint32_t g_cpu_assignment[CPU_POLICY_MAP_CAPACITY];

/*
 * "0,1,3" のようなカンマ区切りに加えて、"1-10" のような範囲指定にも対応した
 * CPU リストをパースし、cpu_policy_map の該当 CPU エントリに policy を書き込む。
 *
 * 対応フォーマット例:
 *   "0,1,3"        単純なカンマ区切り
 *   "1-10"         範囲指定 (1,2,...,10 を意味する)
 *   "0,2,5-10,12"  カンマ区切りと範囲指定の混在
 *
 * fifo/cfs どちらにも指定されなかった CPU は cpu_policy_map に一切書き込まれず、
 * BPF 側で zero 初期化されたまま (CPU_POLICY_UNSET) となる。
 * BPF 側 (hybrid_select_cpu / hybrid_enqueue) は、tctx が無い、または
 * nr_cpus_allowed == 1 のタスクをデフォルトの CPU 選択・SCX_DSQ_LOCAL に
 * フォールバックさせるため、そのような CPU 上で taskset 等により固定実行される
 * ワークロード起動スクリプト等は通常通りのスケジューリングを受けられる。
 *
 * 呼び出しタイミングの注意:
 *   skel_load() の後、attach() の前に呼ぶこと。
 *   (ops.init が attach 時に呼ばれるため、それより前に
 *    map の中身を確定させておく必要がある)
 */
static int parse_cpu_list_and_set_policy(struct bpf_map *map,
                                          const char *cpu_list_str,
                                          uint32_t policy)
{
    char *str = strdup(cpu_list_str);
    char *token;
    char *saveptr;
    int fd;
    int ret = 0;
    int map_capacity;
    long nr_online_cpus;

    if (!str) {
        fprintf(stderr, "strdup failed for cpu list \"%s\"\n", cpu_list_str);
        return -ENOMEM;
    }

    fd = bpf_map__fd(map);
    if (fd < 0) {
        fprintf(stderr, "Failed to get fd for cpu_policy_map\n");
        free(str);
        return fd;
    }

    /* map の実際の max_entries を尋ね、決め打ちのマクロとズレていないか確認する */
    map_capacity = (int)bpf_map__max_entries(map);
    if (map_capacity <= 0 || map_capacity > CPU_POLICY_MAP_CAPACITY)
        map_capacity = CPU_POLICY_MAP_CAPACITY;

    nr_online_cpus = sysconf(_SC_NPROCESSORS_CONF);
    if (nr_online_cpus <= 0)
        nr_online_cpus = map_capacity;

    token = strtok_r(str, ",", &saveptr);
    while (token) {
        long start, end;
        char *dash = strchr(token, '-');

        errno = 0;
        if (dash) {
            /* "start-end" 形式の範囲指定 */
            *dash = '\0';
            start = strtol(token, NULL, 10);
            end   = strtol(dash + 1, NULL, 10);
        } else {
            /* 単一の CPU 番号 */
            start = end = strtol(token, NULL, 10);
        }

        if (start < 0 || end < 0 || start > end) {
            fprintf(stderr,
                    "Invalid cpu range \"%s\"\n", token);
            ret = -EINVAL;
            token = strtok_r(NULL, ",", &saveptr);
            continue;
        }

        for (long cpu = start; cpu <= end; cpu++) {
            uint32_t key = (uint32_t)cpu;
            uint32_t val = policy;

            if (cpu >= map_capacity) {
                fprintf(stderr,
                        "cpu %ld exceeds cpu_policy_map capacity (%d); "
                        "increase max_entries in the BPF program\n",
                        cpu, map_capacity);
                ret = -ERANGE;
                continue;
            }
            if (cpu >= nr_online_cpus) {
                fprintf(stderr,
                        "cpu %ld does not exist on this system "
                        "(nproc=%ld)\n", cpu, nr_online_cpus);
                ret = -ERANGE;
                continue;
            }
            if (g_cpu_assignment[cpu] != CPU_POLICY_UNSET &&
                g_cpu_assignment[cpu] != policy) {
                fprintf(stderr,
                        "cpu %ld is assigned to both --fifo-cpus and "
                        "--cfs-cpus; a cpu can only belong to one\n", cpu);
                ret = -EINVAL;
                continue;
            }
            g_cpu_assignment[cpu] = policy;

            if (bpf_map_update_elem(fd, &key, &val, BPF_ANY)) {
                fprintf(stderr, "Failed to set policy for cpu %ld: %s\n",
                        cpu, strerror(errno));
                ret = -errno;
            }
        }

        token = strtok_r(NULL, ",", &saveptr);
    }

    free(str);
    return ret;
}

/*
 * fifo/cfs いずれにも割り当てられなかった CPU (= 通常通りの挙動をする CPU) の
 * 一覧を表示する。ワークロード起動スクリプト等を taskset -c で固定して
 * 実行したい CPU がここに含まれているか、起動時に目視確認できるようにする。
 */
static void print_cpu_assignment_summary(int map_capacity)
{
    long nr_online_cpus = sysconf(_SC_NPROCESSORS_CONF);
    int cap = map_capacity < nr_online_cpus ? map_capacity : (int)nr_online_cpus;

    printf("CPU assignment:\n");
    for (int cpu = 0; cpu < cap; cpu++) {
        const char *label = "normal (unset)";

        if (g_cpu_assignment[cpu] == CPU_POLICY_FIFO)
            label = "FIFO";
        else if (g_cpu_assignment[cpu] == CPU_POLICY_CFS)
            label = "CFS";

        printf("  cpu %-3d : %s\n", cpu, label);
    }
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
        "  --fifo-cpus <list>       FIFO-only CPUs. Comma separated and/or ranges\n"
        "                           (e.g. \"0,1\", \"1-10\", \"0,2,5-10,12\")\n"
        "  --cfs-cpus  <list>       CFS-only CPUs. Same format as --fifo-cpus\n"
        "                           (e.g. \"2,3\", \"20-29\")\n"
        "  --global-cfs             Use a single global CFS DSQ shared by all\n"
        "                           CFS CPUs, instead of one CFS DSQ per CPU\n"
        "                           (default: off, i.e. one CFS DSQ per CPU)\n"
        "  -h, --help               Show this help\n"
        "\n"
        "Notes:\n"
        "  - Up to %d CPUs total can be assigned via --fifo-cpus/--cfs-cpus\n"
        "    (cpu_policy_map capacity; comfortably covers ~50 CPUs).\n"
        "  - A CPU can only be assigned to one of --fifo-cpus/--cfs-cpus.\n"
        "  - CPUs not listed in either option are left unset and are\n"
        "    scheduled normally, e.g. via a workload launch script pinned\n"
        "    to them with `taskset -c <cpu>`.\n",
        prog, CPU_POLICY_MAP_CAPACITY);
}

int main(int argc, char *argv[])
{
    struct scx_hybrid *skel;
    struct bpf_link        *link = NULL;
    //uint64_t preemption_ns   = 50000ULL; /* 50 µs */
    uint64_t preemption_ns   = 10000000ULL; /* 10 ms */
    int      stats_interval  = 1;
    int      ret             = 0;
    const char *fifo_cpus = NULL;
    const char *cfs_cpus  = NULL;
    int      global_cfs   = 0;
    int opt;


    /* ---- コマンドラインオプション ---- */
    static const struct option long_opts[] = {
        { "preemption-ns",   required_argument, NULL, 'p' },
        { "stats-interval",  required_argument, NULL, 's' },
        { "fifo-cpus",       required_argument, NULL, 'f' },
        { "cfs-cpus",        required_argument, NULL, 'c' },
        { "global-cfs",      no_argument,       NULL, 'g' },
        { "help",            no_argument,       NULL, 'h' },
        { 0 },
    };

    while ((opt = getopt_long(argc, argv, "f:c:p:s:gh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p':
            preemption_ns = strtoull(optarg, NULL, 0);
            break;
        case 's':
            stats_interval = atoi(optarg);
            break;
        case 'f':
            fifo_cpus = optarg;
            break;
        case 'c':
            cfs_cpus = optarg;
            break;
        case 'g':
            global_cfs = 1;
            break;
        case 'h':
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }

    /* ---- CPU ポリシー引数の必須チェック ---- */
    if (!fifo_cpus || !cfs_cpus) {
        fprintf(stderr, "Error: --fifo-cpus and --cfs-cpus are both required.\n\n");
        usage(argv[0]);
        return 1;
    }

    /* ---- シグナル設定 ---- */
    signal(SIGINT,  sig_handler);
    signal(SIGTERM, sig_handler);

    /* ---- libbpf verbosity ---- */
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    /* ---- 以前の Map を unlink ---- */
    mkdir(BPF_FS_HYBRID_DIR, 0700);
	unlink(BPF_FS_HYBRID_DIR "/_rodata_str1_1");
	unlink(BPF_FS_HYBRID_DIR "/tasknew_map");
	unlink(BPF_FS_HYBRID_DIR "/firstrun_map");
	unlink(BPF_FS_HYBRID_DIR "/taskdead_map");
	unlink(BPF_FS_HYBRID_DIR "/cpu_policy_map");
	unlink(BPF_FS_HYBRID_DIR "/global_vtime_now_map");
    unlink(BPF_FS_HYBRID_DIR "/vtime_now_map");
    unlink(BPF_FS_HYBRID_DIR "/rr_last_cpu_map");
    unlink(BPF_FS_HYBRID_DIR "/debug_filter");
    unlink(BPF_FS_HYBRID_DIR "/task_ctx_stor");
    unlink(BPF_FS_HYBRID_DIR "/stats");
	unlink(BPF_FS_HYBRID_DIR "/_data_uei_dump");
	unlink(BPF_FS_HYBRID_DIR "/hybrid_ops");
	unlink(BPF_FS_HYBRID_DIR "/scx_hybr_bss");
	unlink(BPF_FS_HYBRID_DIR "/scx_hybr_data");
	unlink(BPF_FS_HYBRID_DIR "/scx_hybr_rodata");

    /* ---- BPF オブジェクトを開く ---- */
    skel = SCX_OPS_OPEN(hybrid_ops, scx_hybrid);

    /* ---- preemption_slice_ns を ro-data セクションで設定 ---- */
    skel->rodata->preemption_slice_ns = preemption_ns;
    skel->rodata->global_cfs = global_cfs ? true : false;

    /* ---- ロード ---- */
    SCX_OPS_LOAD(skel, hybrid_ops, scx_hybrid, uei);

    /* ---- CPU ポリシー map への書き込み (load後、attach前) ---- */
    if (parse_cpu_list_and_set_policy(skel->maps.cpu_policy_map,
                                       fifo_cpus, CPU_POLICY_FIFO)) {
        fprintf(stderr, "Failed to set FIFO cpu policy\n");
        ret = 1;
        return 1;
    }
    if (parse_cpu_list_and_set_policy(skel->maps.cpu_policy_map,
                                       cfs_cpus, CPU_POLICY_CFS)) {
        fprintf(stderr, "Failed to set CFS cpu policy\n");
        ret = 1;
        return 1;
    }

    print_cpu_assignment_summary((int)bpf_map__max_entries(skel->maps.cpu_policy_map));

    bpf_object__pin_maps(skel->obj, BPF_FS_HYBRID_DIR); // BPF Map をピン留め

    /* ---- アタッチ ---- */
    link = SCX_OPS_ATTACH(skel, hybrid_ops, scx_hybrid);

    printf("Hybrid sched_ext scheduler loaded.\n");
    printf("  preemption_slice_ns = %lu ns (%.3f ms)\n",
           preemption_ns, (double)preemption_ns / 1e6);
    printf("  CFS DSQ mode        = %s\n",
           global_cfs ? "global (shared across all CFS cpus)"
                      : "per-cpu (one CFS DSQ per cpu)");
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
