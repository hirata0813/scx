#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include <signal.h> // シグナルを処理するためのマクロ定義
#include <libgen.h> //ファイルパス解析用
#include <bpf/bpf.h> // libbpf の API 利用のため？
#include <scx/common.h> // scx 関連．パスはおそらく scx/scheds/include/scx/
#include "scx_priority.bpf.skel.h" //eBPF スケジューラのスケルトン(BPF コードとのインタフェース)

#define LINE_MAX_LEN 256

int get_context_switches(pid_t pid, int *voluntary, int *nonvoluntary) {
    char path[64];
    char line[LINE_MAX_LEN];
    snprintf(path, sizeof(path), "/proc/%d/status", pid);

    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "voluntary_ctxt_switches: %d", voluntary) == 1) {
            continue;
        } else if (sscanf(line, "nonvoluntary_ctxt_switches: %d", nonvoluntary) == 1) {
            continue;
        }
    }

    fclose(fp);
    return 0;
}

int main(int argc, char *argv[]) {
    struct timespec start, end, ts, ts_prior;
    double elapsed;
    int slice_mult = atoi(argv[1]); // 第一引数でタイムスライスにかける数
    int dispatch_limit = atoi(argv[2]); // 第ニ引数で非優先タスクのディスパッチ数
    int infinity_count = atoi(argv[3]); // 第三引数で無限ループの数
    int num_nonprio = atoi(argv[4]); // 第四引数で非優先度タスクの数
    int iteration = atoi(argv[5]); // 第五引数でイテレーション数
    FILE *fp = fopen("priority-task-result.csv","a");;
    FILE *fp2 = fopen("priority-task-timestamp.log","a");;

    int pid = getpid();
    int tid = syscall(SYS_gettid);
    int pids_fd = bpf_obj_get("/sys/fs/bpf/priority_pids");
    int tids_fd = bpf_obj_get("/sys/fs/bpf/priority_tids");
    int flag0 = 0;
    int flag1 = 1;
    int voluntary = -1, nonvoluntary = -1;
    long long loop_num = 15000000000LL;
    long long space = loop_num / 100;

    clock_gettime(CLOCK_MONOTONIC, &start);

    // BPF MAP の更新
    if (pids_fd >= 3 && tids_fd >= 3){
         bpf_map_update_elem(pids_fd, &pid, &flag1, BPF_ANY);
         bpf_map_update_elem(tids_fd, &tid, &flag1, BPF_ANY);
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_prior);

    for (volatile long long i=0; i < loop_num; i++){
            //sum++;
	    // ある間隔でタイムスタンプを残す
	    if (i % space == 0){
	        clock_gettime(CLOCK_MONOTONIC, &ts);
    	    	fprintf(fp2, "timestamp: %.6f\n", (ts.tv_sec - ts_prior.tv_sec) + (ts.tv_nsec - ts_prior.tv_nsec) / 1e9);
	        ts_prior = ts;
	    }
    }

    // フラグを戻す
    if (pids_fd >= 3 && tids_fd >= 3){
        bpf_map_update_elem(pids_fd, &pid, &flag0, BPF_ANY);
        bpf_map_update_elem(tids_fd, &tid, &flag0, BPF_ANY);
    }


    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec) / 1e9;

    if (get_context_switches(pid, &voluntary, &nonvoluntary) != 0) {
        fprintf(stderr, "Failed to read context switches for pid %d\n", pid);
    }

    fprintf(fp2, "\n\n");

    fprintf(fp, "%d,%d,%d,%d,%d,%.6f,%d,%d\n", slice_mult, dispatch_limit, infinity_count, num_nonprio, iteration, elapsed, voluntary, nonvoluntary);

    fclose(fp);
    return 0;
}
