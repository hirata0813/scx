/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <stdio.h>
#include <unistd.h> // POSIX 標準との互換性
#include <signal.h> // シグナルを処理するためのマクロ定義
#include <libgen.h> //ファイルパス解析用
#include <bpf/bpf.h> // libbpf の API 利用のため？
#include <scx/common.h> // scx 関連．パスはおそらく scx/scheds/include/scx/
#include "scx_simple.bpf.skel.h" //eBPF スケジューラのスケルトン(BPF コードとのインタフェース)

// ヘルプメッセージ用配列
const char help_fmt[] =
"A simple sched_ext scheduler.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-f] [-v]\n"
"\n"
"  -f            Use FIFO scheduling instead of weighted vtime scheduling\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

static bool verbose;
static volatile int exit_req; //volatile を適用した変数はコンパイル時の最適化対象から外され，その変数へのアクセスは毎回メモリから直接行われる

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

// SIGINT か SIGTERM を受け取ったら，exit_req を 1にする
static void sigint_handler(int simple)
{
	exit_req = 1;
}

// skelを通じて，BPF MAP(skel->maps.stats) にアクセスし，情報を取得？
static void read_stats(struct scx_simple *skel, __u64 *stats)
{
	int nr_cpus = libbpf_num_possible_cpus(); //利用可能な CPU数を取得
	__u64 cnts[2][nr_cpus]; //2次元配列を定義
	__u32 idx;

	memset(stats, 0, sizeof(stats[0]) * 2); //stats の一番最後の文字を0にする？

	for (idx = 0; idx < 2; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0)
			continue;
		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}

// 定義されている関数は3つ
int main(int argc, char **argv)
{
	struct scx_simple *skel;
	struct bpf_link *link;
	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn); //libbpf の警告やメッセージが出たときのコールバックを設定
	signal(SIGINT, sigint_handler); //SIGINT 受信後の処理を sigint_handler により行う
	signal(SIGTERM, sigint_handler); //SIGTERM 受信後の処理を sigint_handler により行う
restart:
	skel = SCX_OPS_OPEN(simple_ops, scx_simple);

	// 引数解析(引数なしの場合，そもそもこのループでの処理はない)
	while ((opt = getopt(argc, argv, "fvh")) != -1) { //引数のうち，f，v，h が入るものを取り出していく
		switch (opt) {
		case 'f':
			skel->rodata->fifo_sched = true; //-fなら fifo を有効化
			break;
		case 'v':
			verbose = true; //-vなら，libbpf_print_fnによりデバッグ情報など出力
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0])); //-h なら help_fmt を表示
			return opt != 'h'; // -hが指定されたらプログラムの実行が終了(0を返す)
		}
	}

	SCX_OPS_LOAD(skel, simple_ops, scx_simple, uei); //eBPFプログラムのロード？
	link = SCX_OPS_ATTACH(skel, simple_ops, scx_simple); //eBPFプログラムのトレースポイントへのアタッチ？

	while (!exit_req && !UEI_EXITED(skel, uei)) { //プログラムが終了するまで？
		__u64 stats[2];

		read_stats(skel, stats);
		printf("local=%llu global=%llu\n", stats[0], stats[1]);
		fflush(stdout);
		sleep(1);
	}

	//以降の処理は，SIGINT などで上記ループを抜けたあとに実行される
	//多分eBPFプログラムの後始末？
	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_simple__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
