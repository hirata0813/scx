#!/bin/zsh -eu

# 引数チェック
if [ $# -ne 1 ]; then
  echo "Usage: $0 <target_executable>"
  echo "Example: $0 ./loop"
  exit 1
fi

TARGET_EXECUTABLE=$1

# 実行対象バイナリの存在チェック
if [ ! -x "$TARGET_EXECUTABLE" ]; then
  echo "Error: $TARGET_EXECUTABLE not found or not executable"
  exit 1
fi

# infinity_loopバイナリの存在チェック
INFINITY_LOOP="./infinity_loop"
if [ ! -x "$INFINITY_LOOP" ]; then
  echo "Error: $INFINITY_LOOP not found or not executable"
  exit 1
fi

# priority schedulerの存在チェック
PRIORITY_SCHED="./priority_sched"
if [ ! -x "$PRIORITY_SCHED" ]; then
  echo "Error: $PRIORITY_SCHED not found or not executable"
  exit 1
fi

# 出力ファイル名
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="scheduler_comparison_${TIMESTAMP}.csv"

# 前回のログファイルを削除
if [ -e "$OUTPUT_FILE" ]; then
  rm "$OUTPUT_FILE"
fi

# CSVのヘッダ
echo "scheduler_type,num_infinity_loops,run_number,elapsed_time_sec" > "$OUTPUT_FILE"

# 実行回数
NUM_RUNS=10

# infinity_loopのPIDを管理する配列
typeset -a INFINITY_PIDS

# cleanup関数
cleanup() {
  echo "Cleaning up..."
  
  # infinity_loopプロセスを全て終了
  for pid in "${INFINITY_PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  INFINITY_PIDS=()
  
  # priority schedulerを停止
  sudo pkill -f "$PRIORITY_SCHED" 2>/dev/null || true
  
  echo "Cleanup completed"
}

# シグナルハンドラ設定
trap cleanup EXIT INT TERM

# infinity_loopを指定された数だけ起動する関数
start_infinity_loops() {
  local count=$1
  INFINITY_PIDS=()
  
  for i in $(seq 1 "$count"); do
    "$INFINITY_LOOP" &
    local pid=$!
    INFINITY_PIDS+=($pid)
    echo "Started infinity_loop #$i (PID: $pid)"
  done
  
  # プロセスが確実に起動するまで少し待つ
  sleep 1
}

# infinity_loopを全て停止する関数
stop_infinity_loops() {
  for pid in "${INFINITY_PIDS[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      wait "$pid" 2>/dev/null || true
    fi
  done
  INFINITY_PIDS=()
  echo "Stopped all infinity_loops"
}

# ターゲットプログラムの実行時間を測定する関数
measure_execution_time() {
  local start_time=$(date +%s.%N)
  "$TARGET_EXECUTABLE" > /dev/null 2>&1
  local end_time=$(date +%s.%N)
  echo "$end_time - $start_time" | bc -l
}

# priority schedulerを起動する関数
start_priority_scheduler() {
  echo "Starting priority scheduler..."
  sudo "$PRIORITY_SCHED" &
  local sched_pid=$!
  
  # スケジューラが起動するまで待つ
  sleep 2
  
  # スケジューラが正常に起動したかチェック
  if ! kill -0 "$sched_pid" 2>/dev/null; then
    echo "Error: Failed to start priority scheduler"
    return 1
  fi
  
  echo "Priority scheduler started (PID: $sched_pid)"
  return 0
}

# priority schedulerを停止する関数
stop_priority_scheduler() {
  echo "Stopping priority scheduler..."
  sudo pkill -f "$PRIORITY_SCHED" 2>/dev/null || true
  sleep 1
  echo "Priority scheduler stopped"
}

# ターゲットプログラムを優先タスクに設定する関数
set_target_as_priority() {
  local target_pid=$1
  echo "Setting target program (PID: $target_pid) as priority task"
  sudo "$PRIORITY_SCHED" --add-pid "$target_pid" 2>/dev/null || true
}

echo "=== Scheduler Performance Comparison ==="
echo "Target executable: $TARGET_EXECUTABLE"
echo "Output file: $OUTPUT_FILE"
echo "Number of runs per configuration: $NUM_RUNS"
echo ""

# Phase 1: CFS (Default scheduler)
echo "=== Phase 1: Testing with CFS (Default Scheduler) ==="

for num_loops in $(seq 0 10); do
  echo "Testing with $num_loops infinity_loop(s)..."
  
  # infinity_loopを起動
  if [ "$num_loops" -gt 0 ]; then
    start_infinity_loops "$num_loops"
  fi
  
  # 複数回実行して平均を取る
  total_time=0
  for run in $(seq 1 "$NUM_RUNS"); do
    echo "  Run $run/$NUM_RUNS..."
    elapsed_time=$(measure_execution_time)
    echo "$elapsed_time" >> temp_times.txt
    echo "cfs,$num_loops,$run,$elapsed_time" >> "$OUTPUT_FILE"
    total_time=$(echo "$total_time + $elapsed_time" | bc -l)
    
    # 少し間隔を空ける
    sleep 0.5
  done
  
  # 平均時間を計算
  avg_time=$(echo "scale=6; $total_time / $NUM_RUNS" | bc -l)
  echo "  Average time: $avg_time seconds"
  
  # infinity_loopを停止
  if [ "$num_loops" -gt 0 ]; then
    stop_infinity_loops
  fi
  
  echo ""
done

echo "=== Phase 1 completed ==="
echo ""

# Phase 2: Priority Scheduler
echo "=== Phase 2: Testing with Priority Scheduler ==="

# priority schedulerを起動
if ! start_priority_scheduler; then
  echo "Failed to start priority scheduler. Exiting."
  exit 1
fi

for num_loops in $(seq 0 10); do
  echo "Testing with $num_loops infinity_loop(s) (Priority Scheduler)..."
  
  # infinity_loopを起動
  if [ "$num_loops" -gt 0 ]; then
    start_infinity_loops "$num_loops"
  fi
  
  # 複数回実行して平均を取る
  total_time=0
  for run in $(seq 1 "$NUM_RUNS"); do
    echo "  Run $run/$NUM_RUNS..."
    
    # ターゲットプログラムをバックグラウンドで起動
    sudo "$TARGET_EXECUTABLE" &
    local target_pid=$!
    
    # ターゲットを優先タスクに設定
    set_target_as_priority "$target_pid"
    
    # 実行時間測定
    local start_time=$(date +%s.%N)
    wait "$target_pid" 2>/dev/null || true
    local end_time=$(date +%s.%N)
    
    elapsed_time=$(echo "$end_time - $start_time" | bc -l)
    echo "priority,$num_loops,$run,$elapsed_time" >> "$OUTPUT_FILE"
    total_time=$(echo "$total_time + $elapsed_time" | bc -l)
    
    # 少し間隔を空ける
    sleep 0.5
  done
  
  # 平均時間を計算
  avg_time=$(echo "scale=6; $total_time / $NUM_RUNS" | bc -l)
  echo "  Average time: $avg_time seconds"
  
  # infinity_loopを停止
  if [ "$num_loops" -gt 0 ]; then
    stop_infinity_loops
  fi
  
  echo ""
done

# priority schedulerを停止
stop_priority_scheduler

echo "=== Phase 2 completed ==="
echo ""

# 結果のサマリーを表示
echo "=== Results Summary ==="
echo "Results saved to: $OUTPUT_FILE"
echo ""
echo "Average execution times by configuration:"
echo "Scheduler,Num_Infinity_Loops,Avg_Time(sec)"

# 平均時間を計算して表示
for scheduler in "cfs" "priority"; do
  for num_loops in $(seq 0 10); do
    avg_time=$(awk -F',' -v sched="$scheduler" -v loops="$num_loops" '
      $1 == sched && $2 == loops { sum += $4; count++ }
      END { if (count > 0) printf "%.6f", sum/count; else print "N/A" }
    ' "$OUTPUT_FILE")
    echo "$scheduler,$num_loops,$avg_time"
  done
done

# 一時ファイルの削除
rm -f temp_times.txt

echo ""
echo "=== Measurement completed ==="
