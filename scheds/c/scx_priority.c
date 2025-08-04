/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_priority.bpf.skel.h"

const char help_fmt[] =
"A simple five-level FIFO queue sched_ext scheduler.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-s SLICE_US] [-e COUNT] [-t COUNT] [-T COUNT] [-l COUNT] [-b COUNT]\n"
"       [-P] [-d PID] [-D LEN] [-p] [-v]\n"
"\n"
"  -s SLICE_US   Override slice duration\n"
"  -e COUNT      Trigger scx_bpf_error() after COUNT enqueues\n"
"  -t COUNT      Stall every COUNT'th user thread\n"
"  -T COUNT      Stall every COUNT'th kernel thread\n"
"  -l COUNT      Trigger dispatch infinite looping after COUNT dispatches\n"
"  -b COUNT      Dispatch upto COUNT tasks together\n"
"  -P            Print out DSQ content to trace_pipe every second, use with -b\n"
"  -H            Boost nice -20 tasks in SHARED_DSQ, use with -b\n"
"  -d PID        Disallow a process from switching into SCHED_EXT (-1 for self)\n"
"  -D LEN        Set scx_exit_info.dump buffer length\n"
"  -S            Suppress priority-specific debug dump\n"
"  -p            Switch only tasks on SCHED_EXT policy instead of all\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

static bool verbose;
static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int dummy)
{
	exit_req = 1;
}

int main(int argc, char **argv)
{
	struct scx_priority *skel;
	struct bpf_link *link;
	int opt;
    int ts_multi = atoi(argv[1]); // 第一引数でタイムスライスに掛ける値
    int max_dispatch = atoi(argv[2]); // 第ニ引数でディスパッチする非優先タスクの最大数

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
	unlink("/sys/fs/bpf/priority_pids"); // エラー無視でOK
	unlink("/sys/fs/bpf/priority_tids"); // エラー無視でOK
	unlink("/sys/fs/bpf/_data_uei_dump"); // エラー無視でOK
	unlink("/sys/fs/bpf/priority_ops"); // エラー無視でOK
	unlink("/sys/fs/bpf/scx_prio_bss"); // エラー無視でOK
	unlink("/sys/fs/bpf/scx_prio_data"); // エラー無視でOK
	unlink("/sys/fs/bpf/scx_prio_rodata"); // エラー無視でOK


	skel = SCX_OPS_OPEN(priority_ops, scx_priority);

	skel->rodata->priority_slice_multiplier = ts_multi; // タイムスライスに掛ける値を設定
	skel->rodata->max_dispatch = max_dispatch; // タイムスライスに掛ける値を設定
	skel->rodata->is_fixed_prior_task = false;

	while ((opt = getopt(argc, argv, "c:")) != -1) {
		switch (opt) {
		case 'c':
			skel->rodata->priortask_cpu = strtoull(optarg, NULL, 0);
			skel->rodata->is_fixed_prior_task = true;
			break;
	//	case 's':
	//		skel->rodata->slice_ns = strtoull(optarg, NULL, 0) * 1000;
	//		break;
	//	case 'e':
	//		skel->bss->test_error_cnt = strtoul(optarg, NULL, 0);
	//		break;
	//	case 't':
	//		skel->rodata->stall_user_nth = strtoul(optarg, NULL, 0);
	//		break;
	//	case 'T':
	//		skel->rodata->stall_kernel_nth = strtoul(optarg, NULL, 0);
	//		break;
	//	case 'l':
	//		skel->rodata->dsp_inf_loop_after = strtoul(optarg, NULL, 0);
	//		break;
	//	case 'b':
	//		skel->rodata->dsp_batch = strtoul(optarg, NULL, 0);
	//		break;
	//	case 'P':
	//		skel->rodata->print_shared_dsq = true;
	//		break;
	//	case 'H':
	//		skel->rodata->highpri_boosting = true;
	//		break;
	//	case 'd':
	//		skel->rodata->disallow_tgid = strtol(optarg, NULL, 0);
	//		if (skel->rodata->disallow_tgid < 0)
	//			skel->rodata->disallow_tgid = getpid();
	//		break;
	//	case 'D':
	//		skel->struct_ops.priority_ops->exit_dump_len = strtoul(optarg, NULL, 0);
	//		break;
	//	case 'S':
	//		skel->rodata->suppress_dump = true;
	//		break;
	//	case 'p':
	//		skel->struct_ops.priority_ops->flags |= SCX_OPS_SWITCH_PARTIAL;
	//		break;
	//	case 'v':
	//		verbose = true;
	//		break;
	//	default:
	//		fprintf(stderr, help_fmt, basename(argv[0]));
	//		return opt != 'h';
		}
	}

	SCX_OPS_LOAD(skel, priority_ops, scx_priority, uei);

	//bpf_map__set_pin_path(skel->maps.priority_pids, "/sys/fs/bpf/priority_pids");
	bpf_object__pin_maps(skel->obj, "/sys/fs/bpf"); // 一括ピン止めも可能
	link = SCX_OPS_ATTACH(skel, priority_ops, scx_priority);

	while (!exit_req && !UEI_EXITED(skel, uei)) {

		//printf("stats  : local_sum=%ld nr_custom=%ld nr_dispatch=%ld\n",
		//       skel->bss->nr_priority_local_sum, skel->bss->nr_nonpriority_custom,
		//       skel->bss->nr_dispatched_global_sum);
		//fflush(stdout);
		sleep(1);
	}

	bpf_link__destroy(link);
	UEI_REPORT(skel, uei);
	scx_priority__destroy(skel);
	/*
	 * scx_priority implements ops.cpu_on/offline() and doesn't need to restart
	 * on CPU hotplug events.
	 */
	return 0;
}
