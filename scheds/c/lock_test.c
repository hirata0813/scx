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


int volatile global_counter = 0;
int retry_wait_usec = 100;
int increments_per_thread = 2;
int num_threads = 100;
bool use_spinlock = false;

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
atomic_flag spinlock = ATOMIC_FLAG_INIT;

void sleep_usec(int usec) {
    struct timespec ts;
    ts.tv_sec = usec / 1000000;
    ts.tv_nsec = (usec % 1000000) * 1000;
    nanosleep(&ts, NULL);
}

void *worker(void *arg) {
    volatile int sum = 0;
    int count = 0;
    int pid = getpid();
    int tid = syscall(SYS_gettid);
    int pids_fd = bpf_obj_get("/sys/fs/bpf/priority_pids");
    int tids_fd = bpf_obj_get("/sys/fs/bpf/priority_tids");
    int flag0 = 0;
    int flag1 = 1;
    FILE *fp = fopen("locktest.log","a");

    while (count < increments_per_thread) {
        if (false) {
            // スピンロック: CPUを手放さずに回り続ける
            while (atomic_flag_test_and_set(&spinlock)) {
                // ロックが取れなかったのでretry_wait_usecだけ忙しく待つ
                sleep_usec(retry_wait_usec);
            }
        } else {
            // 通常のロック: ブロッキング
            pthread_mutex_lock(&mutex);
        }

        // ロック取得成功
	// BPF MAP の更新
	if (pids_fd >= 3 && tids_fd >= 3){
		bpf_map_update_elem(pids_fd, &pid, &flag1, BPF_ANY);
		bpf_map_update_elem(tids_fd, &tid, &flag1, BPF_ANY);
	}

        global_counter++; //共有リソースのインクリメント
        count++;

	// スレッドIDをログファイルに書き込む(ロックを取得したスレッドを，スケジューラが正しく把握できているかの確認に用いる)
	//fprintf(fp, "pid: %d, tid: %d\n", pid, tid);	
	printf("pid: %d, tid: %d\n", pid, tid);	

        // ロック解除
        if (false) {
            atomic_flag_clear(&spinlock);
        } else {
            // ループ処理で，ロック保持時間を少し長くする(スピンロックと似通うことを防ぐため)
            // 1s程度かかるループ処理を挟む
            for (volatile int i=0; i<2000000000; i++){
                    sum++;
            }
	    // フラグを戻す
	    if (pids_fd >= 3 && tids_fd >= 3){
		bpf_map_update_elem(pids_fd, &pid, &flag0, BPF_ANY);
	    	bpf_map_update_elem(tids_fd, &tid, &flag0, BPF_ANY);
	    }
            pthread_mutex_unlock(&mutex);
        }
    }

    return NULL;
}

void print_usage(const char *progname) {
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "  --threads N           Number of threads (default: 4)\n"
        "  --retry-wait usec     Wait time between retries (default: 100 us)\n"
        "  --use-spinlock        Use spinlock instead of mutex\n"
        "  --increments N        Number of increments per thread (default: 100)\n",
        progname);
}

int main(int argc, char *argv[]) {
    static struct option long_options[] = {
        {"threads", required_argument, 0, 't'},
        {"retry-wait", required_argument, 0, 'r'},
        {"use-spinlock", no_argument, 0, 's'},
        {"increments", required_argument, 0, 'i'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "t:r:h:si:", long_options, NULL)) != -1) {
        switch (opt) {
            case 't': num_threads = atoi(optarg); break;
            case 'r': retry_wait_usec = atoi(optarg); break;
            case 's': use_spinlock = true; break;
            case 'i': increments_per_thread = atoi(optarg); break;
            default:
                print_usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    int *thread_ids = malloc(sizeof(int) * num_threads);
    pthread_t *threads = malloc(sizeof(pthread_t) * num_threads);
    struct timespec start, end;
    double elapsed;

    clock_gettime(CLOCK_MONOTONIC, &start);

    for (int i = 0; i < num_threads; ++i) {
        thread_ids[i] = i;
        pthread_create(&threads[i], NULL, worker, &thread_ids[i]);
    }

    for (int i = 0; i < num_threads; ++i) {
        pthread_join(threads[i], NULL);
    }

    if (global_counter == increments_per_thread*num_threads) {
        printf("Final counter value: %d\n", global_counter);
    } else {
        printf("failed");
    }



    free(threads);
    clock_gettime(CLOCK_MONOTONIC, &end);
    elapsed = (end.tv_sec - start.tv_sec) +
                     (end.tv_nsec - start.tv_nsec) / 1e9;

    printf("Elapsed time: %.6f seconds\n", elapsed);
    return 0;
}
