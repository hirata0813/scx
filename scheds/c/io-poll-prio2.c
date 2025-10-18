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
#include <stdlib.h>

const unsigned long long CPU_FREQ_HZ = 3500000000UL;

volatile atomic_int io_result = 0;       // I/O結果格納用(メインスレッドでもここをポーリング)
volatile atomic_ullong io_done_clock = 0;       // I/O結果格納用(メインスレッドでもここをポーリング)

// ==== I/O処理スレッド ====
void* io_worker(void *arg) {
    // 周期的に I/O を行う
    printf("I/O thread: start processing...\n");
    char buf[1024 * 1024];
    FILE *f = fopen("/tmp/testfile", "wb");
    struct timespec ts;
			     
    //sleep(1);             // 疑似I/O処理（1秒待つ）
    //printf("I/O処理スレッドでrdtsc(). io_result=%d\n", io_result);
    fwrite(buf, 1, sizeof(buf), f);
    fflush(f);	
	atomic_fetch_add(&io_result, 1);	// io_result の値をインクリメントすることで，I/O完了
	atomic_store(&io_done_clock, __rdtsc()); // I/O完了時のクロックを記録

    //printf("I/O 完了: io_done_clock=%llu, io_result=%d\n", io_done_clock, io_result);

    return NULL;
}


// ==== メイン処理 ====
int main(int argc, char *argv[]) {
    unsigned long long io_done, io_res;
    double elapsed, wait;
    int pid = getpid();
    int tid = syscall(SYS_gettid);
    int pids_fd = bpf_obj_get("/sys/fs/bpf/priority_pids");
    int tids_fd = bpf_obj_get("/sys/fs/bpf/priority_tids");
    int flag0 = 0;
    int flag1 = 1;
    FILE *fp = fopen("priority-io-task-result.csv","a");
    long long i=0;
    volatile int sum = 0;
    int tmp;
    int num_inf = atoi(argv[1]);

    srand(time(NULL));
    printf("Main: doing something first...\n");
    sleep(1);

    printf("Main: issuing I/O request.\n");

    // 周期的な I/O 処理スレッドを立ち上げる


    for(int i = 0; i < 7000; i++) {
	    // 現在のI/O結果を格納
       tmp = atomic_load(&io_result);

       // I/O リクエストを発行
       pthread_t threadid;
       pthread_create(&threadid, NULL, io_worker, NULL);
       pthread_detach(threadid);


	    // 優先フラグの設定
    	if (pids_fd >= 3 && tids_fd >= 3){
    	     bpf_map_update_elem(pids_fd, &pid, &flag1, BPF_ANY);
    	     bpf_map_update_elem(tids_fd, &tid, &flag1, BPF_ANY);
    	}
        //printf("ポーリング開始, tmp=%d\n", tmp);
    	// ==== I/O ポーリングフェーズ ====
    	while (atomic_load(&io_result) == tmp) { // I/O 完了(以前のI/O結果と今回で変化があれば I/O 完了)まで待つ
        	printf("ポーリング中, io_result=%d, tmp=%d\n", io_result, tmp);
    	}

	    // ポーリング完了時にクロック数を取得
    	io_res = __rdtsc();
        //printf("メインスレッドでrdtsc()\n");
    	io_done = atomic_load(&io_done_clock);
        //printf("I/O 検知: io_res=%llu, io_done=%llu, io_result=%llu, tmp=%d\n", io_res, io_done, io_result, tmp);

	// 優先フラグを戻す
    	if (pids_fd >= 3 && tids_fd >= 3){
    	    bpf_map_update_elem(pids_fd, &pid, &flag0, BPF_ANY);
    	    bpf_map_update_elem(tids_fd, &tid, &flag0, BPF_ANY);
    	}

	// I/O 完了〜I/O 応答までの経過時間をファイルに出力
    	elapsed = (io_res - io_done) / (double)CPU_FREQ_HZ;
    	fprintf(fp, "%d,%.9f\n", num_inf, elapsed);
    	//printf("%.9f\n", elapsed);
    }


    return 0;
}
