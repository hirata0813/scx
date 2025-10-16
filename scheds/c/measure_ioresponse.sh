#!/bin/bash

# 測定用スクリプト
# priority-task 1つと nonpriority-task 1~10個を同時実行し、実行時間を計測

# 設定
PRIORITY_IOTASK="./io-poll-prio"
NONPRIORITY_IOTASK="./io-poll-nonprio"
ITERATIONS=10
MAX_NONPRIORITY_TASKS=30
INFINITYLOOP="./infinityloop"

PRIORITY_SCHED="scx_priority"
SIMPLE_SCHED="scx_supersimple"
PRIORITY_CPUSELECTION_SCHED="scx_priority_cpuselection"

# 出力ファイル
OUTPUT_FILE1="priority-io-task-result.csv"
OUTPUT_FILE2="nonpriority-io-task-result.csv"

# 前回のログファイルを削除
if [ -e ${OUTPUT_FILE1} ]; then
  sudo rm ${OUTPUT_FILE1}
fi

if [ -e ${OUTPUT_FILE2} ]; then
  sudo rm ${OUTPUT_FILE2}
fi


# scx_priorityが動いているか確認
check_scheduler() {
    local ts_multi=$1
    local num_dispatch=$2
    if ! pgrep -f "scx_priority" > /dev/null; then
      echo "Starting priority scheduler..."
      sudo $PRIORITY_SCHED $ts_multi $num_dispatch &
  
      # スケジューラが起動するまで待つ
      sleep 2
  
    fi

    echo "scx_priority is running. Proceeding with benchmark..."
}

stop_simple_scheduler() {
    if pgrep -f "scx_supersimple" > /dev/null; then
        echo "Stopping supersimple scheduler..."
        sudo pkill -f "scx_supersimple"
        sleep 2
    else
        echo "scx_supersimple is not running."
    fi
}

stop_scheduler() {
    if pgrep -f "scx_priority" > /dev/null; then
        echo "Stopping priority scheduler..."
        sudo pkill -f "scx_priority"
        sleep 2
    else
        echo "scx_priority is not running."
    fi
}

stop_cpuselection_scheduler() {
    if pgrep -f "scx_priority_cpuselection" > /dev/null; then
        echo "Stopping cpuselection scheduler..."
        sudo pkill -f "scx_priority_cpuselection"
        sleep 2
    else
        echo "scx_priority_cpuselection is not running."
    fi
}


# メイン測定ループ
run_benchmark() {
    local slice_mult=$1
    local dispatch_limit=$2
    local infinity_count=$3
    local nonpriority_count=$4
    local iteration=$5
    local benchmark=$6
    
    echo ""
    echo "Running iteration $iteration with $nonpriority_count non-priority tasks"
    
    declare -a pids
    declare -a infinityloop_pids

    # infinity loop tasks開始（CPUバウンドなバックグラウンドタスク）
    for ((i=1; i<=infinity_count; i++)); do
        echo "Starting infinity loop task $i..."
        $INFINITYLOOP &
        infinity_pid=$!
        infinityloop_pids+=($infinity_pid)
	sleep 0.1
    done

    task_num=1
    
    # I/O タスク開始
    echo "Starting priority task..."
    sudo $benchmark $infinity_count &
    priority_pid=$!
    pids+=($priority_pid)
    task_num=$((task_num+1))

    # 配列の要素数を取得
    pids_length=${#pids[@]}

    # 全てのタスクの完了を待つ
    echo "Waiting for all tasks to complete..."
    for pid in "${pids[@]}"; do
        wait $pid 2>/dev/null
    done
    
    echo "All tasks completed for iteration $iteration with $nonpriority_count non-priority tasks"


    # infinity loopタスクを強制終了
    echo "Terminating remaining infinity loop tasks..."
    for infinityloop_pid in "${infinityloop_pids[@]}"; do
        if kill -0 "$infinityloop_pid" 2>/dev/null; then
            echo "Killing remaining task (PID: $infinityloop_pid)"
            kill -TERM "$infinityloop_pid" 2>/dev/null
        fi
    done
    
    # クリーンアップ
    sleep 10
}

# メイン実行
main() {
    echo "Starting benchmark with scx_priority scheduler"

    # パラメータ配列の定義
    slice_multipliers=(1)         # タイムスライスの倍率
    dispatch_limits=(1)         # ディスパッチ制限数（-1は無制限）
    infinity_counts=(0, 1, 10)           # infinity_loopの数

    echo "infinity_loop_num, elapsed" > $OUTPUT_FILE1
    echo "infinity_loop_num, elapsed" > $OUTPUT_FILE2

    # 計測1(I/Oタスク(優先版))
    for dispatch_limit in "${dispatch_limits[@]}"; do
        echo ""
        echo "=============================================="
	echo "Measure 1: I/O タスク(優先版)"
        echo "=============================================="

    	# タイムスライスの差を変えて測定
    	for slice_mult in "${slice_multipliers[@]}"; do
            echo ""
            echo "--- Testing with slice multiplier: ${slice_mult} ---"
    
            # infinity_loop の数を変えながらについて測定
            for infinity_count in "${infinity_counts[@]}"; do
                echo ""
                echo "Testing with ${infinity_count} infinity loops"

                # 各イテレーション(1~10)について測定
        	for ((iteration=1; iteration<=1; iteration++)); do

                    # 各nonpriority task数(1~10)について測定
        	    for ((nonpriority_count=1; nonpriority_count<=1; nonpriority_count++)); do
            		check_scheduler $slice_mult $dispatch_limit
                        run_benchmark $slice_mult $dispatch_limit $infinity_count $nonpriority_count $iteration $PRIORITY_IOTASK
            		# スケジューラの停止
            		stop_scheduler
                    done
                done
            done
        done
    done

    # 計測2(I/Oタスク(優先しない版))
    for dispatch_limit in "${dispatch_limits[@]}"; do
        echo ""
        echo "=============================================="
	echo "Measure 2: I/O タスク(優先しない版)"
        echo "=============================================="

    	# タイムスライスの差を変えて測定
    	for slice_mult in "${slice_multipliers[@]}"; do
            echo ""
            echo "--- Testing with slice multiplier: ${slice_mult} ---"
    
            # infinity_loop の数を変えながらについて測定
            for infinity_count in "${infinity_counts[@]}"; do
                echo ""
                echo "Testing with ${infinity_count} infinity loops"

                # 各イテレーション(1~10)について測定
        	for ((iteration=1; iteration<=1; iteration++)); do

                    # 各nonpriority task数(1~10)について測定
        	    for ((nonpriority_count=1; nonpriority_count<=1; nonpriority_count++)); do
            		check_scheduler $slice_mult $dispatch_limit
                    	echo ""
                    	echo "=== Testing with $nonpriority_count non-priority tasks ==="
                        run_benchmark $slice_mult $dispatch_limit $infinity_count $nonpriority_count $iteration $NONPRIORITY_IOTASK
            		# スケジューラの停止
            		stop_scheduler
                    done
                done
            done
        done
    done

}

# 実行
main "$@"
