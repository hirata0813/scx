#!/bin/bash

# 測定用スクリプト
# priority-task 1つと nonpriority-task 1~10個を同時実行し、実行時間を計測

# 設定
PRIORITY_TASK="./priority-task"
NONPRIORITY_TASK="./nonpriority-task"
ITERATIONS=10
MAX_NONPRIORITY_TASKS=30
INFINITYLOOP="./infinityloop"

PRIORITY_SCHED="scx_priority"
SIMPLE_SCHED="scx_supersimple"
PRIORITY_CPUSELECTION_SCHED="scx_priority_cpuselection"

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
echo "ts_multi,num_dispatch,num_inf,num_nonpriotask,iter,elapsed_25,elapsed_50,elapsed_75,prio_elapsed_time,task_num,pid" > "$OUTPUT_FILE1"
echo "ts_multi,num_dispatch,num_inf,num_nonpriotask,iter,elapsed_25,elapsed_50,elapsed_75,nonprio_elapsed_time,task_num,pid" > "$OUTPUT_FILE2"

# scx_supersimpleが動いているか確認
check_simple_scheduler() {
    local ts_multi=$1
    local num_dispatch=$2
    if ! pgrep -f "scx_supersimple" > /dev/null; then
      echo "Starting supersimple scheduler..."
      sudo $SIMPLE_SCHED $ts_multi $num_dispatch &
  
      # スケジューラが起動するまで待つ
      sleep 2
  
    fi

    echo "scx_priority is running. Proceeding with benchmark..."
}

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

check_scheduler_priotask_cpu_fixed() {
    local ts_multi=$1
    local num_dispatch=$2
    if ! pgrep -f "scx_priority" > /dev/null; then
      echo "Starting priority scheduler..."
      sudo $PRIORITY_SCHED $ts_multi $num_dispatch -c &
  
      # スケジューラが起動するまで待つ
      sleep 2
  
    fi

    echo "scx_priority is running. Proceeding with benchmark..."
}

check_scheduler_priotask_cpu_owned() {
    local ts_multi=$1
    local num_dispatch=$2
    if ! pgrep -f "scx_priority" > /dev/null; then
      echo "Starting priority scheduler..."
      sudo $PRIORITY_SCHED $ts_multi $num_dispatch -c -C &
  
      # スケジューラが起動するまで待つ
      sleep 2
  
    fi

    echo "scx_priority is running. Proceeding with benchmark..."
}

check_scheduler_different_cpu_selection() {
    local ts_multi=$1
    local num_dispatch=$2
    if ! pgrep -f "scx_priority_cpuselection" > /dev/null; then
      echo "Starting priority scheduler..."
      sudo $PRIORITY_CPUSELECTION_SCHED $ts_multi $num_dispatch &
  
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
run_benchmark_formeasure1() {
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

    task_num=1
    
    # non-priority tasks開始
    for ((i=1; i<=nonpriority_count; i++)); do
        echo "Starting non-priority task $i..."
        sudo $NONPRIORITY_TASK $slice_mult $dispatch_limit $infinity_count $nonpriority_count $iteration $task_num &
        nonpriority_pid=$!
        pids+=($nonpriority_pid)
	task_num=$((task_num+1))
    done


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
    sleep 20
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

    task_num=1
    
    # non-priority tasks開始
    for ((i=1; i<=nonpriority_count; i++)); do
        echo "Starting non-priority task $i..."
        sudo $NONPRIORITY_TASK $slice_mult $dispatch_limit $infinity_count $nonpriority_count $iteration $task_num &
        nonpriority_pid=$!
        pids+=($nonpriority_pid)
	task_num=$((task_num+1))
    done

    # priority task開始
    echo "Starting priority task..."
    sudo $PRIORITY_TASK $slice_mult $dispatch_limit $infinity_count $nonpriority_count $iteration $task_num &
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
    sleep 20
}

# メイン実行
main() {
    echo "Starting benchmark with scx_priority scheduler"

    # パラメータ配列の定義
    slice_multipliers=(1)         # タイムスライスの倍率
    dispatch_limits=(1)         # ディスパッチ制限数（-1は無制限）
    infinity_counts=(0)           # infinity_loopの数

#    # 計測1(CFS と単純なコールバックを実装したSCX との比較)
#    for dispatch_limit in "${dispatch_limits[@]}"; do
#        echo ""
#        echo "=============================================="
#        echo "Measure 1: CFS versus scx_supersimple"
#        echo "=============================================="
#
#    	# タイムスライスの差を変えて測定
#    	for slice_mult in "${slice_multipliers[@]}"; do
#            echo ""
#            echo "--- Testing with slice multiplier: ${slice_mult} ---"
#            check_simple_scheduler $slice_mult $dispatch_limit
#    
#            # infinity_loop の数を変えながらについて測定
#            for infinity_count in "${infinity_counts[@]}"; do
#                echo ""
#                echo "Testing with ${infinity_count} infinity loops"
#
#                # 各nonpriority task数(1~10)について測定
#        	for ((iteration=1; iteration<=ITERATIONS; iteration++)); do
#
#                    # 各イテレーション(1~10)について測定
#        	    for ((nonpriority_count=1; nonpriority_count<=MAX_NONPRIORITY_TASKS; nonpriority_count++)); do
#                    	echo ""
#                    	echo "=== Testing with $nonpriority_count non-priority tasks ==="
#                        run_benchmark_formeasure1 $slice_mult $dispatch_limit $infinity_count $nonpriority_count $iteration
#                    done
#                done
#            done
#
#            # スケジューラの停止
# 	    stop_simple_scheduler
#        done
#    done
#
#    # 計測1: ログファイルのコピーを取る
#
#    mkdir -p "/home/hirata/logs/cfs-versus-scx/simple_scx"
#    cp "$OUTPUT_FILE1" "/home/hirata/logs/cfs-versus-scx/simple_scx/$OUTPUT_FILE1"
#    cp "$OUTPUT_FILE2" "/home/hirata/logs/cfs-versus-scx/simple_scx/$OUTPUT_FILE2"
#    
#echo "ts_multi,num_dispatch,num_inf,num_nonpriotask,iter,elapsed_25,elapsed_50,elapsed_75,prio_elapsed_time,task_num,pid" > "$OUTPUT_FILE1"
#echo "ts_multi,num_dispatch,num_inf,num_nonpriotask,iter,elapsed_25,elapsed_50,elapsed_75,nonprio_elapsed_time,task_num,pid" > "$OUTPUT_FILE2"
#
#
#    # 計測2の前準備(計測2以降のデータとの比較．単純なSCXで実行)
#    for dispatch_limit in "${dispatch_limits[@]}"; do
#        echo ""
#        echo "=============================================="
#        echo "Measure 1: CFS versus scx_supersimple"
#        echo "=============================================="
#
#    	# タイムスライスの差を変えて測定
#    	for slice_mult in "${slice_multipliers[@]}"; do
#            echo ""
#            echo "--- Testing with slice multiplier: ${slice_mult} ---"
#    
#            # infinity_loop の数を変えながらについて測定
#            for infinity_count in "${infinity_counts[@]}"; do
#                echo ""
#                echo "Testing with ${infinity_count} infinity loops"
#
#                # 各nonpriority task数(1~10)について測定
#        	for ((iteration=1; iteration<=ITERATIONS; iteration++)); do
#
#                    # 各イテレーション(1~10)について測定
#        	    for ((nonpriority_count=1; nonpriority_count<=MAX_NONPRIORITY_TASKS; nonpriority_count++)); do
#            		check_simple_scheduler $slice_mult $dispatch_limit
#                    	echo ""
#                    	echo "=== Testing with $nonpriority_count non-priority tasks ==="
#                        run_benchmark $slice_mult $dispatch_limit $infinity_count $nonpriority_count $iteration
#            		# スケジューラの停止
# 	    		stop_simple_scheduler
#                    done
#                done
#            done
#        done
#    done
#
#    # 計測2の前準備: ログファイルのコピーを取る
#
#    mkdir -p "/home/hirata/logs/simple_scx"
#    cp "$OUTPUT_FILE1" "/home/hirata/logs/simple_scx/$OUTPUT_FILE1"
#    cp "$OUTPUT_FILE2" "/home/hirata/logs/simple_scx/$OUTPUT_FILE2"
#
#    echo "ts_multi,num_dispatch,num_inf,num_nonpriotask,iter,elapsed_25,elapsed_50,elapsed_75,prio_elapsed_time,task_num,pid" > "$OUTPUT_FILE1"
#    echo "ts_multi,num_dispatch,num_inf,num_nonpriotask,iter,elapsed_25,elapsed_50,elapsed_75,nonprio_elapsed_time,task_num,pid" > "$OUTPUT_FILE2"
#
#    # 計測2(ローカル DSQ のどこに入れるかのみを変えた場合，A群とB群の実行時間はどれほど違うか)
#    for dispatch_limit in "${dispatch_limits[@]}"; do
#        echo ""
#        echo "=============================================="
#        echo "Measure 2: prior-task: head, nonprior-task: tail"
#        echo "=============================================="
#
#    	# タイムスライスの差を変えて測定
#    	for slice_mult in "${slice_multipliers[@]}"; do
#            echo ""
#            echo "--- Testing with slice multiplier: ${slice_mult} ---"
#    
#            # infinity_loop の数を変えながらについて測定
#            for infinity_count in "${infinity_counts[@]}"; do
#                echo ""
#                echo "Testing with ${infinity_count} infinity loops"
#
#                # 各イテレーション(1~10)について測定
#        	for ((iteration=1; iteration<=ITERATIONS; iteration++)); do
#
#                    # 各nonpriority task数(1~10)について測定
#        	    for ((nonpriority_count=1; nonpriority_count<=MAX_NONPRIORITY_TASKS; nonpriority_count++)); do
#            		check_scheduler $slice_mult $dispatch_limit
#                    	echo ""
#                    	echo "=== Testing with $nonpriority_count non-priority tasks ==="
#                        run_benchmark $slice_mult $dispatch_limit $infinity_count $nonpriority_count $iteration
#            		# スケジューラの停止
#            		stop_scheduler
#                    done
#                done
#            done
#        done
#    done
#
#    # 計測2: ログファイルのコピーを取る
#
#    mkdir -p "/home/hirata/logs/only_queueing"
#    cp "$OUTPUT_FILE1" "/home/hirata/logs/only_queueing/$OUTPUT_FILE1"
#    cp "$OUTPUT_FILE2" "/home/hirata/logs/only_queueing/$OUTPUT_FILE2"
#
#    echo "ts_multi,num_dispatch,num_inf,num_nonpriotask,iter,elapsed_25,elapsed_50,elapsed_75,prio_elapsed_time,task_num,pid" > "$OUTPUT_FILE1"
#    echo "ts_multi,num_dispatch,num_inf,num_nonpriotask,iter,elapsed_25,elapsed_50,elapsed_75,nonprio_elapsed_time,task_num,pid" > "$OUTPUT_FILE2"
#
#    # 計測3(計測2+A群の CPU を固定した場合，A群とB群の実行時間はどれほど違うか)
#    for dispatch_limit in "${dispatch_limits[@]}"; do
#        echo ""
#        echo "=============================================="
#        echo "Measure 3: Measure 2 & cpu_fix"
#        echo "=============================================="
#
#    	# タイムスライスの差を変えて測定
#    	for slice_mult in "${slice_multipliers[@]}"; do
#            echo ""
#            echo "--- Testing with slice multiplier: ${slice_mult} ---"
#    
#            # infinity_loop の数を変えながらについて測定
#            for infinity_count in "${infinity_counts[@]}"; do
#                echo ""
#                echo "Testing with ${infinity_count} infinity loops"
#
#                # 各nonpriority task数(1~10)について測定
#        	for ((iteration=1; iteration<=ITERATIONS; iteration++)); do
#
#                    # 各イテレーション(1~10)について測定
#        	    for ((nonpriority_count=1; nonpriority_count<=MAX_NONPRIORITY_TASKS; nonpriority_count++)); do
#            		check_scheduler_priotask_cpu_fixed $slice_mult $dispatch_limit
#                    	echo ""
#                    	echo "=== Testing with $nonpriority_count non-priority tasks ==="
#                        run_benchmark $slice_mult $dispatch_limit $infinity_count $nonpriority_count $iteration
#            		# スケジューラの停止
#            		stop_scheduler
#                    done
#                done
#            done
#        done
#    done
#
#    # 計測3: ログファイルのコピーを取る
#
#    mkdir -p "/home/hirata/logs/queueing_and_cpufix"
#    cp "$OUTPUT_FILE1" "/home/hirata/logs/queueing_and_cpufix/$OUTPUT_FILE1"
#    cp "$OUTPUT_FILE2" "/home/hirata/logs/queueing_and_cpufix/$OUTPUT_FILE2"
#
#    echo "ts_multi,num_dispatch,num_inf,num_nonpriotask,iter,elapsed_25,elapsed_50,elapsed_75,prio_elapsed_time,task_num,pid" > "$OUTPUT_FILE1"
#    echo "ts_multi,num_dispatch,num_inf,num_nonpriotask,iter,elapsed_25,elapsed_50,elapsed_75,nonprio_elapsed_time,task_num,pid" > "$OUTPUT_FILE2"
#
#    # 計測4(計測2+A群がCPUを占有した場合，A群とB群の実行時間はどれほど違うか)
#    for dispatch_limit in "${dispatch_limits[@]}"; do
#        echo ""
#        echo "=============================================="
#        echo "Measure 4: Measure 2 + cpu own"
#        echo "=============================================="
#
#    	# タイムスライスの差を変えて測定
#    	for slice_mult in "${slice_multipliers[@]}"; do
#            echo ""
#            echo "--- Testing with slice multiplier: ${slice_mult} ---"
#    
#            # infinity_loop の数を変えながらについて測定
#            for infinity_count in "${infinity_counts[@]}"; do
#                echo ""
#                echo "Testing with ${infinity_count} infinity loops"
#
#                # 各nonpriority task数(1~10)について測定
#        	for ((iteration=1; iteration<=30; iteration++)); do
#
#                    # 各イテレーション(1~10)について測定
#        	    for ((nonpriority_count=1; nonpriority_count<=MAX_NONPRIORITY_TASKS; nonpriority_count++)); do
#            		check_scheduler_priotask_cpu_owned $slice_mult $dispatch_limit
#                    	echo ""
#                    	echo "=== Testing with $nonpriority_count non-priority tasks ==="
#                        run_benchmark $slice_mult $dispatch_limit $infinity_count $nonpriority_count $iteration
#            		# スケジューラの停止
#            		stop_scheduler
#                    done
#                done
#            done
#
#        done
#    done
#
#    # 計測4: ログファイルのコピーを取る
#
#    mkdir -p "/home/hirata/logs/queueing_and_cpuown"
#    cp "$OUTPUT_FILE1" "/home/hirata/logs/queueing_and_cpuown/$OUTPUT_FILE1"
#    cp "$OUTPUT_FILE2" "/home/hirata/logs/queueing_and_cpuown/$OUTPUT_FILE2"
#
#    echo "ts_multi,num_dispatch,num_inf,num_nonpriotask,iter,elapsed_25,elapsed_50,elapsed_75,prio_elapsed_time,task_num,pid" > "$OUTPUT_FILE1"
#    echo "ts_multi,num_dispatch,num_inf,num_nonpriotask,iter,elapsed_25,elapsed_50,elapsed_75,nonprio_elapsed_time,task_num,pid" > "$OUTPUT_FILE2"
#
#    # 計測5(計測2+A群，B群それぞれで実行CPUの選び方を変えた場合，A群とB群の実行時間はどれほど違うか)
#    for dispatch_limit in "${dispatch_limits[@]}"; do
#        echo ""
#        echo "=============================================="
#        echo "Measure 5: Measure 2 + different cpu selection"
#        echo "=============================================="
#
#    	# タイムスライスの差を変えて測定
#    	for slice_mult in "${slice_multipliers[@]}"; do
#            echo ""
#            echo "--- Testing with slice multiplier: ${slice_mult} ---"
#    
#            # infinity_loop の数を変えながらについて測定
#            for infinity_count in "${infinity_counts[@]}"; do
#                echo ""
#                echo "Testing with ${infinity_count} infinity loops"
#
#                # 各nonpriority task数(1~10)について測定
#        	for ((iteration=1; iteration<=ITERATIONS; iteration++)); do
#
#                    # 各イテレーション(1~10)について測定
#        	    for ((nonpriority_count=1; nonpriority_count<=MAX_NONPRIORITY_TASKS; nonpriority_count++)); do
# 	    		check_scheduler_different_cpu_selection $slice_mult $dispatch_limit
#                    	echo ""
#                    	echo "=== Testing with $nonpriority_count non-priority tasks ==="
#                        run_benchmark $slice_mult $dispatch_limit $infinity_count $nonpriority_count $iteration
#            		# スケジューラの停止
# 	    		stop_cpuselection_scheduler
#                    done
#                done
#            done
#
#        done
#    done
#
#    # 計測5: ログファイルのコピーを取る
#
#    mkdir -p "/home/hirata/logs/queueing_and_different_cpu_selection"
#    cp "$OUTPUT_FILE1" "/home/hirata/logs/queueing_and_different_cpu_selection/$OUTPUT_FILE1"
#    cp "$OUTPUT_FILE2" "/home/hirata/logs/queueing_and_different_cpu_selection/$OUTPUT_FILE2"
#
    echo "ts_multi,num_dispatch,num_inf,num_nonpriotask,iter,elapsed_25,elapsed_50,elapsed_75,prio_elapsed_time,task_num,pid" > "$OUTPUT_FILE1"
    echo "ts_multi,num_dispatch,num_inf,num_nonpriotask,iter,elapsed_25,elapsed_50,elapsed_75,nonprio_elapsed_time,task_num,pid" > "$OUTPUT_FILE2"

    # 計測6(計測2での実装をアップデート．enqueue()にCPU選択機構を入れる)
    for dispatch_limit in "${dispatch_limits[@]}"; do
        echo ""
        echo "=============================================="
        echo "Measure 6: prior-task: head, nonprior-task: tail, enqueue()にCPU選択機構を入れる"
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
        	for ((iteration=8; iteration<=ITERATIONS; iteration++)); do

                    # 各nonpriority task数(1~10)について測定
        	    for ((nonpriority_count=1; nonpriority_count<=MAX_NONPRIORITY_TASKS; nonpriority_count++)); do
            		check_scheduler $slice_mult $dispatch_limit
                    	echo ""
                    	echo "=== Testing with $nonpriority_count non-priority tasks ==="
                        run_benchmark $slice_mult $dispatch_limit $infinity_count $nonpriority_count $iteration
            		# スケジューラの停止
            		stop_scheduler
                    done
                done
            done
        done
    done

    # 計測6: ログファイルのコピーを取る

    mkdir -p "/home/hirata/logs/queueing_and_cpu_selection_in_enqueue_v3"
    cp "$OUTPUT_FILE1" "/home/hirata/logs/queueing_and_cpu_selection_in_enqueue_v3/$OUTPUT_FILE1"
    cp "$OUTPUT_FILE2" "/home/hirata/logs/queueing_and_cpu_selection_in_enqueue_v3/$OUTPUT_FILE2"


    echo "Benchmark completed. Results saved to $OUTPUT_FILE1 and $OUTPUT_FILE2"
}

# 実行
main "$@"
