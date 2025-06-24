#include <stdio.h>
#include <unistd.h> // POSIX 標準との互換性
#include <signal.h> // シグナルを処理するためのマクロ定義
#include <libgen.h> //ファイルパス解析用
#include <bpf/bpf.h> // libbpf の API 利用のため？
#include <scx/common.h> // scx 関連．パスはおそらく scx/scheds/include/scx/
#include "scx_ctrl.bpf.skel.h" //eBPF スケジューラのスケルトン(BPF コードとのインタフェース)

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

// pid が key となるエントリの flag(value) を更新する
// あるいは，PID，FLAG のエントリを BPF MAP に登録する
static void update_map(struct scx_ctrl *skel, __u32 *pid, __u32 *flag)
{
	__u32 fd = bpf_map__fd(skel->maps.pidlist);
	bpf_map_update_elem(fd, pid, flag, BPF_ANY);
}

static void print_map(struct scx_ctrl *skel, __u32 *pid)
{
	__u32 ret;
	__u32 value;
	__u32 fd = bpf_map__fd(skel->maps.pidlist);
	ret = bpf_map_lookup_elem(fd, pid, &value);
	if (ret == 0)
	    printf("Key: %d, Value: %d\n", *pid, value);
	else
	    printf("Failed to read value from the map\n");
}


// 定義されている関数は3つ
int main(int argc, char **argv)
{
	__u32 pid = (__u32)fork(); // 親プロセスの場合，fork()により生成された子のPIDが返ってくる
	// 子プロセスの場合，0が返ってくる

	if (pid == 0) {
	        // 子プロセスで実行
		printf("child: pid=%d\n", (int)pid);
	        char *args[] = {"/home/hirata/git/scx/scheds/c/increment", NULL, NULL};
	        execvp(args[0], args);
	        perror("execvp failed");
	} else if (pid > 0) {
		printf("parent: pid=%d\n", (int)pid);
		struct scx_ctrl *skel;
		struct bpf_link *link;
		__u32 opt;
		__u64 ecode;
	
		libbpf_set_print(libbpf_print_fn); //libbpf の警告やメッセージが出たときのコールバックを設定
		signal(SIGINT, sigint_handler); //SIGINT 受信後の処理を sigint_handler により行う
		signal(SIGTERM, sigint_handler); //SIGTERM 受信後の処理を sigint_handler により行う
		
	restart:
		skel = SCX_OPS_OPEN(simple_ops, scx_ctrl);
	
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
	
		SCX_OPS_LOAD(skel, simple_ops, scx_ctrl, uei); //eBPFプログラムのロード？
		link = SCX_OPS_ATTACH(skel, simple_ops, scx_ctrl); //eBPFプログラムのトレースポイントへのアタッチ？
		
	
		__u32 flag = 0;
		__u32 num = 0;
	
		while (!exit_req && !UEI_EXITED(skel, uei)) { //プログラムが終了するまで？
			// 定期的に BPF MAP を更新(PID書き込み，flagアップデートなど)
	
			if (num % 2 == 0){
				flag = 0;
				update_map(skel, &pid, &flag);
			} else {
				flag = 1;
				update_map(skel, &pid, &flag);
			}
			print_map(skel, &pid);
			fflush(stdout);
			sleep(5);
			num++;
		}
	
		//以降の処理は，SIGINT などで上記ループを抜けたあとに実行される
		//多分eBPFプログラムの後始末？
		bpf_link__destroy(link);
		ecode = UEI_REPORT(skel, uei);
		scx_ctrl__destroy(skel);
	
		if (UEI_ECODE_RESTART(ecode))
			goto restart;
	} else {
	        perror("fork failed");
	}
	return 0;
}
