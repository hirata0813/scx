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

int main(int argc, char *argv[]) {
    volatile int sum = 0;
    struct timespec start, end, ts25, ts50, ts75;
    double elapsed, elapsed_25, elapsed_50, elapsed_75;
    int slice_mult = atoi(argv[1]); // 第一引数でタイムスライスにかける数
    int dispatch_limit = atoi(argv[2]); // 第ニ引数で非優先タスクのディスパッチ数
    int infinity_count = atoi(argv[3]); // 第三引数で無限ループの数
    int num_nonprio = atoi(argv[4]); // 第四引数で非優先度タスクの数
    int iteration = atoi(argv[5]); // 第五引数でイテレーション数
    FILE *fp = fopen("priority-task-result.csv","a");;

    int pid = getpid();
    int tid = syscall(SYS_gettid);
    int pids_fd = bpf_obj_get("/sys/fs/bpf/priority_pids");
    int tids_fd = bpf_obj_get("/sys/fs/bpf/priority_tids");
    int flag0 = 0;
    int flag1 = 1;
    long long i=0;
    printf("priority task start\n");

    clock_gettime(CLOCK_MONOTONIC, &start);

    // BPF MAP の更新
    if (pids_fd >= 3 && tids_fd >= 3){
         bpf_map_update_elem(pids_fd, &pid, &flag1, BPF_ANY);
         bpf_map_update_elem(tids_fd, &tid, &flag1, BPF_ANY);
    }


    for (; i < 2500000000LL; i++){
            sum++;
    }
    clock_gettime(CLOCK_MONOTONIC, &ts25);
    printf("priority task 25%\n");

    for (; i < 5000000000LL; i++){
            sum++;
    }
    clock_gettime(CLOCK_MONOTONIC, &ts50);
    printf("priority task 50%\n");

    for (; i < 7500000000LL; i++){
            sum++;
    }
    clock_gettime(CLOCK_MONOTONIC, &ts75);
    printf("priority task 75%\n");

    for (; i < 10000000000LL; i++){
            sum++;
    }

    // フラグを戻す
    if (pids_fd >= 3 && tids_fd >= 3){
        bpf_map_update_elem(pids_fd, &pid, &flag0, BPF_ANY);
        bpf_map_update_elem(tids_fd, &tid, &flag0, BPF_ANY);
    }


    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed_25 = (ts25.tv_sec - start.tv_sec) +
                     (ts25.tv_nsec - start.tv_nsec) / 1e9;
    elapsed_50 = (ts50.tv_sec - start.tv_sec) +
                     (ts50.tv_nsec - start.tv_nsec) / 1e9;
    elapsed_75 = (ts75.tv_sec - start.tv_sec) +
                     (ts75.tv_nsec - start.tv_nsec) / 1e9;
    elapsed = (end.tv_sec - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec) / 1e9;

    fprintf(fp, "%d,%d,%d,%d,%d,%.6f,%.6f,%.6f,%.6f\n", slice_mult, dispatch_limit, infinity_count, num_nonprio, iteration, elapsed_25, elapsed_50, elapsed_75, elapsed);

    fclose(fp);
    return 0;
}
