#!/bin/zsh -eu

# 引数チェック
if [ $# -ne 6 ]; then
  echo "Usage: $0 <num_threads_start> <num_threads_step> <num_threads_end> <increments_start> <increments_step> <increments_end>"
  exit 1
fi

# 引数の取得
NUM_THREADS_START=$1
NUM_THREADS_STEP=$2
NUM_THREADS_END=$3
INCREMENTS_START=$4
INCREMENTS_STEP=$5
INCREMENTS_END=$6

# 実行対象バイナリとパラメータ
EXECUTABLE="/home/hirata/tmp/race-condition/lock_test"
RETRY_WAIT_USEC=100
USE_SPINLOCK_FLAG=""  # または "--use-spinlock"

# 出力ファイル名の動的生成
OUTPUT_FILE="mutexlock-${NUM_THREADS_START}-${NUM_THREADS_STEP}-${NUM_THREADS_END}-and-${INCREMENTS_START}-${INCREMENTS_STEP}-${INCREMENTS_END}.csv"

# 前回のログファイルを削除

if [ -e ${OUTPUT_FILE} ]; then
  rm ${OUTPUT_FILE}
fi

# CSVのヘッダ
# スレッド数，インクリメント数，コンテキストスイッチ回数，CPU 使用率，経過時間,CPU 時間(user), CPU 時間(sys) の7つ組データを1行とする
echo "num_threads,increments_per_threads,context_switches,cpu_utilization,elapsed_time,cpu_user,cpu_sys" > "$OUTPUT_FILE"

# パラメータの組み合わせを総当たり
for thread in $(seq "$NUM_THREADS_START" "$NUM_THREADS_STEP" "$NUM_THREADS_END"); do
  for increment in $(seq "$INCREMENTS_START" "$INCREMENTS_STEP" "$INCREMENTS_END"); do
    echo "Running: num_threads=$thread, increments_per_threads=$increment"

    # perf statで実行し、stderrをパース
    PERF_OUTPUT=$(perf stat \
      $EXECUTABLE --threads $thread \
                  --retry-wait "$RETRY_WAIT_USEC" \
                  --increments "$increment" \
                  $USE_SPINLOCK_FLAG 2>&1)

    # 正しくインクリメントされたか確認
    EXPECTED=$(($thread * $increment))
    if echo "$PERF_OUTPUT" | grep -q "Final counter value: $EXPECTED"; then
      # context-switchesとcpu utilization, elapsed time を抽出
      CONTEXT_SWITCHES=$(echo "$PERF_OUTPUT" | grep "context-switches" | awk '{print $1}' | tr -d ",")

      LOGICAL_CPUS=$(nproc)
      CPU_UTILIZED=$(echo "$PERF_OUTPUT" | grep "task-clock" | awk -F'#' '{print $2}' | awk '{print $1}')

      CPU_USAGE_PERCENT=$(awk "BEGIN { printf \"%.2f\", ($CPU_UTILIZED / $LOGICAL_CPUS) * 100 }")

      # 秒オーダ
      ELAPSED_TIME=$(echo "$PERF_OUTPUT" | grep "seconds time elapsed" | awk '{print $1}')

      CPU_TIME_USER=$(echo "$PERF_OUTPUT" | grep "seconds user" | awk '{print $1}')
      CPU_TIME_SYS=$(echo "$PERF_OUTPUT" | grep "seconds sys" | awk '{print $1}')

      # 欠損時対策
      CONTEXT_SWITCHES=${CONTEXT_SWITCHES:-0}
      CPU_USAGE_PERCENT=${CPU_USAGE_PERCENT:-0}
      ELAPSED_TIME=${ELAPSED_TIME:-0}
      CPU_TIME_USER=${CPU_TIME_USER:-0}
      CPU_TIME_SYS=${CPU_TIME_SYS:-0}

      echo "$thread,$increment,$CONTEXT_SWITCHES,$CPU_USAGE_PERCENT,$ELAPSED_TIME,$CPU_TIME_USER,$CPU_TIME_SYS" >> "$OUTPUT_FILE"
    else
      # CSVに追記
      echo "$thread,$increment,0,0,0,0,0" >> "$OUTPUT_FILE"
    fi

  done
done

# キャッシュ汚染
cat /home/hirata/tmp/race-condition/cache_buster.bin > /dev/null

echo "Complete measuring"
