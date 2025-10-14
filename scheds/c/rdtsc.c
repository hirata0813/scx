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
#include <sched.h>
#include <x86intrin.h>

#include <signal.h> // シグナルを処理するためのマクロ定義
#include <libgen.h> //ファイルパス解析用
#include <bpf/bpf.h> // libbpf の API 利用のため？
#include <scx/common.h> // scx 関連．パスはおそらく scx/scheds/include/scx/
#include "scx_priority.bpf.skel.h" //eBPF スケジューラのスケルトン(BPF コードとのインタフェース)

const unsigned long long CPU_FREQ_HZ = 3500000000UL;
#define LINE_MAX_LEN 256

int main(int argc, char *argv[]) {
    volatile int sum = 0;
    double elapsed, elapsed_25, elapsed_50, elapsed_75;

    int pid = getpid();
    int tid = syscall(SYS_gettid);
    int pids_fd = bpf_obj_get("/sys/fs/bpf/priority_pids");
    int tids_fd = bpf_obj_get("/sys/fs/bpf/priority_tids");
    int flag0 = 0;
    int flag1 = 1;
    long long i=0;
    unsigned long long start, elapse25, elapse50, elapse75, end, v0, v1;


    // BPF MAP の更新
    if (pids_fd >= 3 && tids_fd >= 3){
         bpf_map_update_elem(pids_fd, &pid, &flag1, BPF_ANY);
         bpf_map_update_elem(tids_fd, &tid, &flag1, BPF_ANY);
    }

    start = __rdtsc();

    for (; i < 2500000000LL; i++){
            sum++;
    }

    elapse25 = __rdtsc();

    //ここの間は優先しない
    if (pids_fd >= 3 && tids_fd >= 3){
         bpf_map_update_elem(pids_fd, &pid, &flag0, BPF_ANY);
         bpf_map_update_elem(tids_fd, &tid, &flag0, BPF_ANY);
    }

    for (; i < 5000000000LL; i++){
            sum++;
    }
    elapse50 = __rdtsc();

    //ここの間は優先しない
    if (pids_fd >= 3 && tids_fd >= 3){
         bpf_map_update_elem(pids_fd, &pid, &flag1, BPF_ANY);
         bpf_map_update_elem(tids_fd, &tid, &flag1, BPF_ANY);
    }


    for (; i < 7500000000LL; i++){
            sum++;
    }
    elapse75 = __rdtsc();


    //ここの間は優先しない
    if (pids_fd >= 3 && tids_fd >= 3){
         bpf_map_update_elem(pids_fd, &pid, &flag0, BPF_ANY);
         bpf_map_update_elem(tids_fd, &tid, &flag0, BPF_ANY);
    }

    for (; i < 10000000000LL; i++){
            sum++;
    }
    //ここの間は優先しない

    // フラグを戻す
    if (pids_fd >= 3 && tids_fd >= 3){
        bpf_map_update_elem(pids_fd, &pid, &flag0, BPF_ANY);
        bpf_map_update_elem(tids_fd, &tid, &flag0, BPF_ANY);
    }
    end = __rdtsc();

    v0 = __rdtsc();
    sleep(1);
    v1 = __rdtsc();


    printf("elapse25=%.6f,elapse50=%.6f,elapse75=%.6f,end=%.6f\n", (elapse25 - start) / (double)CPU_FREQ_HZ, (elapse50 - elapse25) / (double)CPU_FREQ_HZ, (elapse75 - elapse50) / (double)CPU_FREQ_HZ, (end - elapse75) / (double)CPU_FREQ_HZ);
    printf("1sのスリープ=%.6f\n", (v1 - v0) / (double)CPU_FREQ_HZ);

    return 0;
}
