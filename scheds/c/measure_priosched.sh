#!/bin/bash

# 測定用スクリプト
# priority-task 1つと nonpriority-task 1~10個を同時実行し、実行時間を計測

# 設定
PRIORITY_TASK="./priority-task"
NONPRIORITY_TASK="./nonpriority-task"
ITERATIONS=10
MAX_NONPRIORITY_TASKS=10
INFINITYLOOP="./infinityloop"

PRIORITY_SCHED="scx_priority"

# 出力ファイル名の動的生成
OUTPUT_FILE1="priority-task-result.csv"
OUTPUT_FILE2="nonpriority-task-result.csv"

# 前回のログファイルを削除
if [ -e ${OUTPUT_FILE1} ]; then
  sudo rm ${OUTPUT_FILE1}
fi

if [ -e ${OUTPUT_FILE2} ]; then
  sudo rm ${OUTPUT_FILE2}
fi

# CSVのヘッダ
# タイムスライスの差，非優先タスクディスパッチ数，無限ループの数，非優先タスクの数，イテレーション，実行時間 の6つ組データを1行とする
echo "ts_multi,num_dispatch,num_inf,num_nonpriotask,iter,prio_elapsed_time" > "$OUTPUT_FILE1"
echo "ts_multi,num_dispatch,num_inf,num_nonpriotask,iter,nonprio_elapsed_time" > "$OUTPUT_FILE2"

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

stop_scheduler() {
    if pgrep -f "scx_priority" > /dev/null; then
        echo "Stopping priority scheduler..."
        sudo pkill -f "scx_priority"
        sleep 2
    else
        echo "scx_priority is not running."
    fi
}

# メイン測定ループ
run_benchmark() {
    local slice_mult=$1
    local dispatch_limit=$2
    local infinity_count=$3
    local nonpriority_count=$4
    local iteration=$5
    
    echo ""
    echo "Running iteration $iteration with $nonpriority_count non-priority tasks"
    echo "Parameters: slice_mult=$slice_mult, dispatch_limit=$dispatch_limit, infinity_count=$infinity_count"
    
    declare -a pids
    declare -a infinityloop_pids

    # infinity loop tasks開始（CPUバウンドなバックグラウンドタスク）
    for ((i=1; i<=infinity_count; i++)); do
        echo "Starting infinity loop task $i..."
        $INFINITYLOOP &
        infinity_pid=$!
        infinityloop_pids+=($infinity_pid)
    done
    
    # non-priority tasks開始
    for ((i=1; i<=nonpriority_count; i++)); do
        echo "Starting non-priority task $i..."
        sudo $NONPRIORITY_TASK $slice_mult $dispatch_limit $infinity_count $nonpriority_count $iteration &
        nonpriority_pid=$!
        pids+=($nonpriority_pid)
    done

    # priority task開始
    echo "Starting priority task..."
    sudo $PRIORITY_TASK $slice_mult $dispatch_limit $infinity_count $nonpriority_count $iteration &
    priority_pid=$!
    pids+=($priority_pid)

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
    slice_multipliers=(50 10)         # タイムスライスの倍率
    dispatch_limits=(1)         # ディスパッチ制限数（-1は無制限）
    infinity_counts=(1 16 0 80)           # infinity_loopの数

    # 非優先タスクのディスパッチ数を変えながら測定
    for dispatch_limit in "${dispatch_limits[@]}"; do
        echo ""
        echo "=============================================="
        echo "Testing with dispatch limit: ${dispatch_limit}"
        echo "=============================================="

    	# タイムスライスの差を変えて測定
    	for slice_mult in "${slice_multipliers[@]}"; do
            echo ""
            echo "--- Testing with slice multiplier: ${slice_mult} ---"
            check_scheduler $slice_mult $dispatch_limit
    
            # infinity_loop の数を変えながらについて測定
            for infinity_count in "${infinity_counts[@]}"; do
                echo ""
                echo "Testing with ${infinity_count} infinity loops"

                # 各nonpriority task数(1~10)について測定
        	for ((nonpriority_count=1; nonpriority_count<=MAX_NONPRIORITY_TASKS; nonpriority_count++)); do
                    echo ""
                    echo "=== Testing with $nonpriority_count non-priority tasks ==="

                    # 各イテレーション(1~10)について測定
        	    for ((iteration=1; iteration<=ITERATIONS; iteration++)); do
                        run_benchmark $slice_mult $dispatch_limit $infinity_count $nonpriority_count $iteration
                    done
                done
            done

            # スケジューラの停止
            stop_scheduler
        done
    done

    # ログファイルのコピーを取る(年月日形式でディレクトリを作成)
    TIMESTAMP=$(date +"%Y-%m%d-%H%M")
    mkdir -p "/home/hirata/logs/$TIMESTAMP"
    cp "$OUTPUT_FILE1" "/home/hirata/logs/$TIMESTAMP/$OUTPUT_FILE1"
    cp "$OUTPUT_FILE2" "/home/hirata/logs/$TIMESTAMP/$OUTPUT_FILE2"

    echo "Benchmark completed. Results saved to $OUTPUT_FILE1 and $OUTPUT_FILE2"
}

# 実行
main "$@"
