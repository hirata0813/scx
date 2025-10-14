#!/bin/bash

# --- 引数チェック ---
if [ $# -ne 2 ]; then
    echo "Usage: $0 <file1> <file2>"
    exit 1
fi

file1="$1"
file2="$2"

# --- ファイル存在確認 ---
if [ ! -f "$file1" ] || [ ! -f "$file2" ]; then
    echo "Error: One or both files do not exist."
    exit 1
fi

# --- 行ごとの差を計算 ---
paste "$file1" "$file2" | awk '{diff = $1 - $2; printf "%.9f\n", diff}'

