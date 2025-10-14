#include <stdio.h>
#include <pthread.h>
#include <unistd.h>
#include <stdatomic.h>
#include <time.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_priority.bpf.skel.h"
#include <sys/types.h>
#include <sys/syscall.h>
#include <sched.h>
#include <x86intrin.h>

const unsigned long long CPU_FREQ_HZ = 3500000000UL;

volatile atomic_int io_done = 0;  // 共有フラグ（0:処理中, 1:完了）
volatile int io_result = 0;       // 結果格納用

// ==== I/O処理スレッド ====
void* io_worker(void* arg) {
    printf("I/O thread: start processing...\n");
    sleep(1);             // 疑似I/O処理（1秒待つ）
    io_result = 42;       // I/Oの結果
    atomic_store(&io_done, 1);  // 完了フラグ
    printf("I/O thread: done.\n");
    return NULL;
}

// ==== I/O依頼関数 ====
int io_request() {
    pthread_t tid;
    io_done = 0;
    pthread_create(&tid, NULL, io_worker, NULL);
    pthread_detach(tid);  // 結果はグローバル変数経由で受け取る
    return 0;             // 疑似的な「リクエストID」
}

// ==== メイン処理 ====
int main() {
    double elapsed, io_req, io_poll;
    int pid = getpid();
    int tid = syscall(SYS_gettid);
    int pids_fd = bpf_obj_get("/sys/fs/bpf/priority_pids");
    int tids_fd = bpf_obj_get("/sys/fs/bpf/priority_tids");
    int flag0 = 0;
    int flag1 = 1;
    FILE *fp = fopen("nonpriority-io-task-result.csv","a");
    long long i=0;
    volatile int sum = 0;

    printf("Main: doing something first...\n");
    sleep(1);

    printf("Main: issuing I/O request.\n");

    io_req = __rdtsc();

    // ==== I/O 依頼フェーズ ====
    //for (; i < 2500000000LL; i++){
    //        sum++;
    //}

    io_request();

    // I/O 依頼時も優先しない(比較用)
    if (pids_fd >= 3 && tids_fd >= 3){
         bpf_map_update_elem(pids_fd, &pid, &flag0, BPF_ANY);
         bpf_map_update_elem(tids_fd, &tid, &flag0, BPF_ANY);
    }

    // ==== I/O ポーリングフェーズ ====
    while (atomic_load(&io_done) == 0) {
        // 擬似的なポーリング処理
    }

    io_poll = __rdtsc();

    if (pids_fd >= 3 && tids_fd >= 3){
        bpf_map_update_elem(pids_fd, &pid, &flag0, BPF_ANY);
        bpf_map_update_elem(tids_fd, &tid, &flag0, BPF_ANY);
    }

    elapsed = (io_poll - io_req) / (double)CPU_FREQ_HZ;

    fprintf(fp, "%.6f\n", elapsed);
    return 0;
}
