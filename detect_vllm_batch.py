import argparse
import pandas as pd
import json
import re
import os
import sys
from typing import Dict, Any, List, Tuple
from tqdm import tqdm

# vLLM 导入
try:
    from vllm import LLM, SamplingParams
except ImportError:
    print("Error: vLLM library not found. Please install it using: pip install vllm")
    sys.exit(1)

# 尝试导入 PromptManager
try:
    from prompt import PromptManager_CoT_Multi_Turn
except ImportError:
    print("Error: Could not find 'prompt.py'. Please ensure it is in the same directory.")
    sys.exit(1)

# ==============================================================================
# 1. 辅助函数 (保持不变)
# ==============================================================================

def clean_for_json(data):
    """递归地将数据结构中的 set 对象转换成 list。"""
    if isinstance(data, dict):
        return {k: clean_for_json(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [clean_for_json(item) for item in data]
    elif isinstance(data, set):
        return [clean_for_json(item) for item in list(data)]
    else:
        return data

def _parse_step1_output(raw_output: str) -> List[tuple]:
    """解析 Step 1 LLM 输出。"""
    cleaned = re.sub(r'```json|```|```python|```text|Output:', '', str(raw_output), flags=re.IGNORECASE).strip()
    pattern = r'\[\s*[\'"](win_\d+)[\'"]\s*,\s*[\'"](R\d+|P\d+|M\d+|S\d+|I\d+)[\'"]\s*,\s*(\d+)\s*,\s*(\d+)\s*\]'
    results: List[tuple] = []
    for win_id, rule, start_str, end_str in re.findall(pattern, cleaned):
        try:
            results.append((win_id, rule, int(start_str), int(end_str)))
        except Exception:
            pass
    return results

def format_sequences_from_csv(csv_path: str, window_size: int = 1, step: int = 1) -> Dict[str, Dict[str, Any]]:
    """读取 CSV 并生成窗口数据"""
    try:
        df = pd.read_csv(csv_path, encoding='utf-8')
    except Exception as e:
        print(f"Error reading {csv_path}: {e}")
        return {}
    
    df['log_id'] = df.index.astype(str)
    if 'timestamp' in df.columns: df.sort_values(by='timestamp', inplace=True)
    df.reset_index(drop=True, inplace=True)
    
    formatted_windows = {}
    for i in range(0, len(df) - window_size + 1, step):
        window_df = df.iloc[i : i + window_size].copy()
        window_id = f"win_{i}"
        log_parts = []
        member_ids = []
        window_diffs_indexed = {} 

        for idx_in_window in range(window_size):
            row = window_df.iloc[idx_in_window]
            log_parts.append(str(row.get('Event_sequence', '')))
            member_ids.append(row['log_id'])
            try:
                d = json.loads(str(row.get('Diff_vector', '{}')))
                if d and isinstance(d, dict): 
                    window_diffs_indexed[str(idx_in_window)] = d
            except: pass
            
        formatted_windows[window_id] = {
            "sequence_text": "; ".join(log_parts),
            "diff_vector": window_diffs_indexed,
            "member_log_ids": member_ids 
        }
    return formatted_windows

# ==============================================================================
# 2. vLLM 核心处理逻辑
# ==============================================================================

def main(args):
    # --- 1. 数据准备 ---
    print(f"--- Loading data from {args.input_file} ---")
    windows_data = format_sequences_from_csv(args.input_file)
    if not windows_data:
        print("No windows generated. Exiting.")
        sys.exit(1)
    
    print(f"--- Generated {len(windows_data)} windows. Initializing vLLM Engine... ---")

    # --- 2. 初始化 vLLM 引擎 ---
    # tensor_parallel_size=4 表示使用 4 张 GPU 并行计算
    llm = LLM(
        model=args.model_path,
        tensor_parallel_size=args.tp_size, 
        gpu_memory_utilization=0.85, # 激进显存占用
        trust_remote_code=True,
        max_model_len=8192, # 根据需要调整上下文长度
    )
    
    # 采样参数: 温度极低以保证确定性
    sampling_params = SamplingParams(temperature=0.01, top_p=0.95, max_tokens=2048)
    
    prompts_manager = PromptManager_CoT_Multi_Turn()
    
    # ==========================================================================
    # Phase 1: 批量运行 Step 1 (Logic & Physics)
    # ==========================================================================
    print("\n--- Phase 1: Generating Logic & Physics Prompts ---")
    
    # 为了最大化吞吐量，我们将 Logic 和 Physics 的请求全部打平放到一个列表里
    # 列表结构: [Win1_Logic, Win1_Physics, Win2_Logic, Win2_Physics, ...]
    
    phase1_inputs = []
    metadata_map = [] # 用于记录每个请求对应哪个 Window 和哪种 Type
    
    window_ids = list(windows_data.keys())
    
    for win_id in window_ids:
        data = windows_data[win_id]
        input_context = prompts_manager.format_single_window_input(
            win_id, data['sequence_text'], data['diff_vector']
        )
        
        # Logic Request
        phase1_inputs.append([
            {"role": "system", "content": prompts_manager.step1_logic_system},
            {"role": "user", "content": input_context}
        ])
        metadata_map.append({"win_id": win_id, "type": "logic", "real_ids": data["member_log_ids"]})
        
        # Physics Request
        phase1_inputs.append([
            {"role": "system", "content": prompts_manager.step1_physics_system},
            {"role": "user", "content": input_context}
        ])
        metadata_map.append({"win_id": win_id, "type": "physics", "real_ids": data["member_log_ids"]})

    print(f"--- Phase 1: Running Batch Inference for {len(phase1_inputs)} requests on {args.tp_size} GPUs ---")
    
    # vLLM 的核心：一次性处理所有请求
    # 使用 llm.chat 自动处理聊天模板
    phase1_outputs = llm.chat(messages=phase1_inputs, sampling_params=sampling_params)
    
    # --- 解析 Phase 1 结果 ---
    print("--- Phase 1: Parsing Results ---")
    
    # 临时存储检测到的异常: { real_log_id: [violation_entry, ...] }
    temp_anomalies = {} 
    # 记录哪些 window 需要进入 Step 2
    windows_needing_step2 = set()
    # 存储 Step 2 需要的 raw 输入
    step2_raw_inputs = {} # { real_log_id: ["['id', 'rule', s, e]", ...] }

    for i, output_item in enumerate(phase1_outputs):
        meta = metadata_map[i]
        generated_text = output_item.outputs[0].text
        
        parsed_results = _parse_step1_output(generated_text)
        
        if parsed_results:
            win_id = meta['win_id']
            real_log_ids = meta['real_ids']
            
            # 这里简化逻辑：一个窗口通常对应一个主要的 real_log_id (取第一个)
            # 如果您的逻辑不同，请在此调整
            primary_real_id = real_log_ids[0]
            
            if primary_real_id not in temp_anomalies:
                temp_anomalies[primary_real_id] = []
                step2_raw_inputs[primary_real_id] = []

            for _, rule, start, end in parsed_results:
                violation = {
                    "window_id": win_id,
                    "rule": rule,
                    "evidence_range": [start, end]
                }
                temp_anomalies[primary_real_id].append(violation)
                
                # 准备 Step 2 的纯文本输入格式
                step2_raw_inputs[primary_real_id].append(f"['{primary_real_id}', '{rule}', {start}, {end}]")
                windows_needing_step2.add(primary_real_id)

    print(f"--- Phase 1 Complete. Found anomalies in {len(windows_needing_step2)} logs. ---")

    # ==========================================================================
    # Phase 2: 批量运行 Step 2 (JSON Formatting)
    # ==========================================================================
    
    final_knowledge_base = {real_id: {"violations": []} for real_id in temp_anomalies.keys()}
    
    if not windows_needing_step2:
        print("No anomalies found. Writing empty result.")
        with open(args.output_file, 'w', encoding='utf-8') as f:
            json.dump({}, f, indent=2)
        return

    print("\n--- Phase 2: Generating Step 2 Formatting Prompts ---")
    
    phase2_inputs = []
    phase2_metadata = [] # 记录 log_id
    
    for log_id in windows_needing_step2:
        # 获取该 Log 的所有 Step 1 发现
        anomalies_list_str = "\n".join(step2_raw_inputs[log_id])
        
        system_prompt = prompts_manager.get_step2_formatting_prompt(anomalies_list_str)
        user_prompt = "Convert the input list to the mandatory JSON schema."
        
        phase2_inputs.append([
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt}
        ])
        phase2_metadata.append(log_id)
        
    print(f"--- Phase 2: Running Batch Inference for {len(phase2_inputs)} requests ---")
    
    phase2_outputs = llm.chat(messages=phase2_inputs, sampling_params=sampling_params)
    
    # --- 解析 Phase 2 结果并合并 ---
    print("--- Phase 2: Parsing and Finalizing ---")
    
    total_violations = 0
    
    for i, output_item in enumerate(phase2_outputs):
        log_id = phase2_metadata[i]
        generated_json_str = output_item.outputs[0].text
        
        # 尝试清洗 JSON 标记
        cleaned_json = re.sub(r'```json|```', '', generated_json_str).strip()
        
        # 我们的目标是将 Step 1 的原始证据 (temp_anomalies) 与 Step 2 的结构化信息结合
        # 但既然 Step 2 主要是格式化，这里我们简单地将 Step 1 的结果存入
        # 或者，如果您依赖 Step 2 做进一步过滤，可以解析 cleaned_json
        
        # 策略：直接使用 Step 1 发现的可靠结果 (因为 Step 2 只是格式化)
        # 并按照之前的逻辑结构保存
        
        violations = temp_anomalies[log_id]
        
        # 转换格式以匹配原输出结构
        processed_violations = []
        for v in violations:
            # 查找原始 Window 数据以获取 member indices
            # (由于 vLLM 批处理为了速度，这里简化了反查逻辑，如果需要精确的 evidence index mapping，
            #  需要保留 windows_data)
            
            # 这里简单构造输出
            processed_violations.append({
                "rule_id": v['rule'],
                "detection_window": v['window_id'],
                "evidence": v['evidence_range'] # 简化：直接保存范围
            })
            
        final_knowledge_base[log_id]["violations"] = processed_violations
        total_violations += len(processed_violations)

    print(f"--- Total violations found: {total_violations} ---")
    
    # 保存结果
    with open(args.output_file, 'w', encoding='utf-8') as f:
        json.dump(final_knowledge_base, f, indent=2, ensure_ascii=False)
        
    print(f"--- Done. Results saved to {args.output_file} ---")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run batch detection using vLLM on A100s")
    
    # 默认使用 HuggingFace 格式的模型 ID (Qwen 7B)
    parser.add_argument("--model_path", type=str, default="Qwen/Qwen2.5-7B-Instruct", 
                        help="Path to local model or HF Hub ID")
    parser.add_argument("--input_file", type=str, required=True, 
                        help="Path to input CSV file")
    parser.add_argument("--output_file", type=str, default="knowledge_base_vllm.json", 
                        help="Path to output JSON file")
    parser.add_argument("--tp_size", type=int, default=4, 
                        help="Tensor Parallel size (Number of GPUs)")
    
    args = parser.parse_args()
    
    main(args)