#!/bin/bash

# --- 1. 配置参数 ---
# 输入文件路径
INPUT_CSV="Datasets/Processed dataset (supervised ML)/9111a.csv"
# 输出文件路径
OUTPUT_JSON="./knowledge_base_vllm.json"
# 模型路径 (可以是 HuggingFace ID 或 本地绝对路径)
# 注意：vLLM 使用的是 HuggingFace ID，不是 Ollama ID
MODEL_PATH="Qwen/Qwen2.5-7B-Instruct"

# 显卡设置
# 使用所有 4 张卡 (0,1,2,3)
export CUDA_VISIBLE_DEVICES=1,2,3,4


# --- 3. 运行 Python 脚本 ---
echo "Starting vLLM Batch Detection..."
echo "Model: $MODEL_PATH"
echo "GPUs: 4 (Tensor Parallelism)"
echo "Input: $INPUT_CSV"

# 运行 Python 脚本
# --tp_size 4 对应你的 4 张 A100
python detect_vllm_batch.py \
    --model_path "$MODEL_PATH" \
    --input_file "$INPUT_CSV" \
    --output_file "$OUTPUT_JSON" \
    --tp_size 4

echo "Job finished."