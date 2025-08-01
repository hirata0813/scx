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


int main(int argc, char *argv[]) {
    volatile int sum = 0;
    struct timespec start, end;
    double elapsed;

    int pid = getpid();
    int tid = syscall(SYS_gettid);
    int pids_fd = bpf_obj_get("/sys/fs/bpf/priority_pids");
    int tids_fd = bpf_obj_get("/sys/fs/bpf/priority_tids");
    int flag0 = 0;

    clock_gettime(CLOCK_MONOTONIC, &start);

    // BPF MAP の更新
    if (pids_fd >= 3 && tids_fd >= 3){
         bpf_map_update_elem(pids_fd, &pid, &flag0, BPF_ANY);
         bpf_map_update_elem(tids_fd, &tid, &flag0, BPF_ANY);
    }


    for (long long i=0; i < 100000000000LL; i++){
            sum++;
    }

    // フラグを戻す
    if (pids_fd >= 3 && tids_fd >= 3){
        bpf_map_update_elem(pids_fd, &pid, &flag0, BPF_ANY);
        bpf_map_update_elem(tids_fd, &tid, &flag0, BPF_ANY);
    }


    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("This is non-priority task. Elapsed time: %.6f seconds\n", elapsed);

    return 0;
}
