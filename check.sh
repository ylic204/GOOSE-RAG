#!/bin/bash

# --- 1. 配置路径 (必须与你的运行脚本保持一致) ---
INPUT_DIR="Datasets/Processed dataset (supervised ML)"
OUTPUT_DIR="./knowledge_base"

# --- 2. 准备列表 ---
echo "--- 文件处理进度检查 ---"

# 2.1 临时文件用于存储列表
ALL_INPUT_LIST=$(mktemp)
PROCESSED_LIST=$(mktemp)
UNPROCESSED_LIST=$(mktemp)

# 2.2 获取所有需要处理的 CSV 文件的文件名（不含路径和扩展名）
# 脚本排除了 921a.csv 和 9111a.csv
find "$INPUT_DIR" -maxdepth 1 -type f -name "*.csv" \
    ! -name "921a.csv" \
    ! -name "9111a.csv" \
    -exec basename {} \; | sed 's/\.csv$//' | sort > "$ALL_INPUT_LIST"

# 2.3 获取所有已生成的 JSON 文件的文件名（不含路径和扩展名，去除 _kb 后缀）
find "$OUTPUT_DIR" -maxdepth 1 -type f -name "*_kb.json" \
    -exec basename {} \; | sed 's/\.json$//' | sed 's/_kb$//' | sort > "$PROCESSED_LIST"

# --- 3. 对比和计算 ---

# 使用 comm 命令找出在 ALL_INPUT_LIST 中，但不在 PROCESSED_LIST 中的行
# -23 表示不打印 PROCESSED_LIST 独有的行（-2）和两个文件共有的行（-3）
comm -23 "$ALL_INPUT_LIST" "$PROCESSED_LIST" > "$UNPROCESSED_LIST"

# --- 4. 打印结果和清理 ---

TOTAL_COUNT=$(wc -l < "$ALL_INPUT_LIST")
PROCESSED_COUNT=$(wc -l < "$PROCESSED_LIST")
UNPROCESSED_COUNT=$(wc -l < "$UNPROCESSED_LIST")

echo "----------------------------------------"
echo "总共需要处理的 CSV 文件 (排除项已移除): $TOTAL_COUNT"
echo "已成功生成 JSON 的文件数量: $PROCESSED_COUNT"
echo "----------------------------------------"
echo "🚨 尚未生成 JSON 的文件数量: $UNPROCESSED_COUNT"
echo "----------------------------------------"

if [ "$UNPROCESSED_COUNT" -gt 0 ]; then
    echo "未处理的文件列表 (.csv 文件名):"
    cat "$UNPROCESSED_LIST"
fi

# 清理临时文件
rm "$ALL_INPUT_LIST" "$PROCESSED_LIST" "$UNPROCESSED_LIST"

echo "--- 检查完成 ---"