#!/bin/bash

# 測定用スクリプト
# priority-task 1つと nonpriority-task 1~10個を同時実行し、実行時間を計測

# 設定
PRIORITY_TASK="./priority-task"
NONPRIORITY_TASK="./nonpriority-task"
ITERATIONS=10
MAX_NONPRIORITY_TASKS=10

# priority schedulerの存在チェック
PRIORITY_SCHED="scx_priority"
if [ ! -x "$PRIORITY_SCHED" ]; then
  echo "Error: $PRIORITY_SCHED not found or not executable"
  exit 1
fi

# 結果保存ディレクトリ
RESULTS_DIR="benchmark_results"
mkdir -p "$RESULTS_DIR"

# CSVヘッダー
echo "nonpriority_count,iteration,priority_time,avg_nonpriority_time" > "$RESULTS_DIR/results.csv"

# scx_priorityが動いているか確認
check_scheduler() {
    if ! pgrep -f "scx_priority" > /dev/null; then
      echo "Starting priority scheduler..."
      sudo "$PRIORITY_SCHED" &
  
      # スケジューラが起動するまで待つ
      sleep 2
  
      # スケジューラが正常に起動したかチェック
      if ! kill -0 "$sched_pid" 2>/dev/null; then
        echo "Error: Failed to start priority scheduler"
        exit 1
      fi  
    fi

    echo "scx_priority is running. Proceeding with benchmark..."
}

# プロセス終了を待つ関数
wait_for_completion() {
    local pids=("$@")
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null
    done
}

# メイン測定ループ
run_benchmark() {
    local nonpriority_count=$1
    local iteration=$2
    
    echo "Running iteration $iteration with $nonpriority_count non-priority tasks..."
    
    # 時間計測用配列
    declare -a nonpriority_times
    declare -a pids
    
    
    # non-priority tasks開始
    for ((i=1; i<=nonpriority_count; i++)); do
        echo "Starting non-priority task $i..."
        nonpriority_start=$(date +%s.%N)
        sudo $NONPRIORITY_TASK $nonpriority_count $iteration &
        nonpriority_pid=$!
        pids+=($nonpriority_pid)
    done

    # priority task開始
    echo "Starting priority task..."
    start_time=$(date +%s.%N)
    sudo $PRIORITY_TASK $nonpriority_count $iteration &
    priority_pid=$!
    pids+=($priority_pid)

    # 全てのタスクの完了を待つ
    echo "Waiting for all tasks to complete..."
    for pid in "${pids[@]}"; do
        wait $pid 2>/dev/null
    done
    
    echo "All tasks completed for iteration $iteration with $nonpriority_count non-priority tasks"
    
    # クリーンアップ
    sleep 1
}

# メイン実行
main() {
    echo "Starting benchmark with scx_priority scheduler"
    echo "Results will be saved in $RESULTS_DIR/"
    
    # スケジューラチェック
    check_scheduler
    
    # 各nonpriority task数(1~10)について測定
    for ((nonpriority_count=1; nonpriority_count<=MAX_NONPRIORITY_TASKS; nonpriority_count++)); do
        echo ""
        echo "=== Testing with $nonpriority_count non-priority tasks ==="
        
        for ((iteration=1; iteration<=ITERATIONS; iteration++)); do
            run_benchmark $nonpriority_count $iteration
            sleep 2  # 測定間隔
        done
    done
}

# 実行
main "$@"
