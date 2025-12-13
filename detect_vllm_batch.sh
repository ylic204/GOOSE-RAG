#!/bin/bash

# --- 1. 配置常量 ---
# 定义 CSV 文件所在的父目录路径
INPUT_DIR="Datasets/Processed dataset (supervised ML)"
# 模型路径
MODEL_PATH="Qwen/Qwen2.5-7B-Instruct"
# Tensor Parallelism 大小 (使用的 GPU 数量)
TP_SIZE=4

# --- 2. 显卡及环境设置 (保持不变) ---
# 导出要使用的 GPU ID
export CUDA_VISIBLE_DEVICES=4,5,6,7

# 解决 MKL/libgomp 冲突 (如果之前设置过，可以省略，但加上更保险)
export MKL_SERVICE_FORCE_INTEL=1
export MKL_THREADING_LAYER=GNU


# --- 3. 循环处理所有 CSV 文件 ---
echo "--- Starting vLLM Batch Detection Loop ---"
echo "Target Directory: $INPUT_DIR"
echo "Model: $MODEL_PATH (TP Size: $TP_SIZE)"
echo "GPUs: $CUDA_VISIBLE_DEVICES"
echo "----------------------------------------"

# 使用 find 命令查找目录及其子目录中的所有 .csv 文件
# -name "*.csv" 匹配文件名以 .csv 结尾
# -type f 确保只匹配文件
# -print0 配合 while read -d '' -r 可安全处理带有空格的文件名
find "$INPUT_DIR" -maxdepth 1 -type f -name "*.csv" \
  ! -name "921a.csv" \
  ! -name "9111a.csv" \
  -print0 | while IFS= read -r -d $'\0' INPUT_CSV; do
    
    # 提取文件名（不包含路径和扩展名）
    # 例如：从 "Datasets/.../9111a.csv" 提取 "9111a"
    FILENAME=$(basename "$INPUT_CSV" .csv)
    
    # 构建对应的输出 JSON 文件路径
    # 例如：./knowledge_base/9111a_kb.json
    OUTPUT_JSON="./knowledge_base/${FILENAME}_kb.json"
    
    # 确保输出目录存在
    mkdir -p "./knowledge_base"
    
    echo ""
    echo "Processing: $INPUT_CSV"
    echo "Output to: $OUTPUT_JSON"
    
    # 运行 Python 脚本
    python detect_vllm_batch.py \
        --model_path "$MODEL_PATH" \
        --input_file "$INPUT_CSV" \
        --output_file "$OUTPUT_JSON" \
        --tp_size "$TP_SIZE"
        
    # 检查上一个命令的退出状态
    if [ $? -eq 0 ]; then
        echo "SUCCESS: $INPUT_CSV processed successfully."
    else
        echo "ERROR: $INPUT_CSV failed to process. Skipping to next file."
        # 如果你希望脚本在任何失败时停止，可以取消注释下一行
        # # exit 1
    fi

done

echo ""
echo "--- All batch jobs finished. ---"