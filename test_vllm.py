import pandas as pd
import json
import re
from typing import Dict, Any, List, Optional
from tqdm import tqdm
import os
import sys
import ast

# 导入 vLLM
try:
    from vllm import LLM, SamplingParams
except ImportError:
    print("Error: vLLM not installed. Please run `pip install vllm`")
    sys.exit(1)

# ==============================================================================
# 1. 配置和模型选择
# ==============================================================================
# 使用 AWQ 量化版本 (6GB 模型权重)，
MODEL_PATH = "meta-llama/Meta-Llama-3-8B-Instruct" 

# --- 配置模式 ---
TEST_MODE = True  # <--- 设为 True 运行自定义 Log，设为 False 运行 CSV
CSV_PATH = "./Processed dataset (supervised ML)/9111a.csv" 
JSON_PATH_CSV = "./knowledge_base_csv_vllm.json"
JSON_PATH_TEST = "./knowledge_base_test_vllm.json"

# ==============================================================================
# 2. Prompt
# ==============================================================================

class PromptManager:
    """
    管理用于 GOOSE/SV 日志分析的 Prompt，适配 vLLM 的单轮批量推理。
    将用户原有的 Logic/Physics System Prompt 作为基础。
    """
    
    @property
    def step1_logic_system(self):
        # 使用用户提供的 Logic System Prompt
        return """
[STRICT_EXTRACTION_MODE]
You are a SCADA Protocol Expert. Analyze 'EVENT LOGS' and 'DIFF CONTEXT' for IEC-61850 violations.

CRITICAL:
- Logs separated by '--- WINDOW ID: ... ---'
- Analyze independently and list all violations.

RULES (Infer trends from delta values, do not rely on semantic labels directly):
- Use delta trends to detect violations:
    * Negative delta → decreasing
    * Zero delta → stable
    * Large positive/negative or alternating delta → jump/oscillation
- Note: The 'emb' field contains a summarized, higher-level semantic derived from delta, which can help reasoning but should NOT be matched directly.

1. R01 (State Error: stNum Decrease): Flag if any 'stNum_' field has decreasing delta trend.
2. P01 (Replay Attack): Flag if both 'stNum_' and 'sqNum_' are stable (delta ~0) for a device.
3. P03 (Sequence Gap/Failure): Flag if any 'sqNum_' or 'smpCnt_' field shows sudden jumps, gaps, or oscillations.

STEP-BY-STEP:
1. Iterate all log entries.
2. For each field, analyze delta trend as described above.
3. Assign violation code.
4. Single-window index range = [0,0]

OUTPUT:
Each violation → ['window_id', 'RULE_CODE', 0, 0]
No violation → NONE
"""

    @property
    def step1_physics_system(self):
        # Physics System Prompt
        return """
[STRICT_EXTRACTION_MODE]
You are a Cyber-Physical Security Expert. Analyze 'EVENT LOGS' + 'DIFF CONTEXT' for physical inconsistencies.

CRITICAL:
- Logs separated by '--- WINDOW ID: ... ---'
- Analyze independently and list violations.

DETECT ATTACK PATTERNS (Infer trends from delta values):
- Use delta trends to detect anomalies as described in Step1 Logic.
- Note: The 'emb' field contains a summarized, higher-level semantic derived from delta, which can help reasoning but should NOT be matched directly.

1. S1 (Spoofing - Trip without Fault):
    - GOOSE shows Trip (True)
    - Corresponding SV delta indicates stable/unchanged measurement → possible spoof

2. M1 (Modification/Injection - Fault without Trip):
    - SV delta shows large spike/jump
    - Corresponding GOOSE shows no Trip (False) → possible modification/injection

3. I1 (Injection - Topology Conflict):
    - Same APPID/SVID appears from multiple 'src' MAC addresses within the same window

STEP-BY-STEP:
1. Iterate all logs.
2. Compare GOOSE status with SV delta trends.
3. Assign violation code.
4. Single-window index range = [0,0]

OUTPUT:
Each violation → ['window_id', 'RULE_CODE', 0, 0]
No violation → NONE
"""

    def format_single_window_input(self, window_id: str, event_sequence: str, diff_vector: Dict[str, Any]) -> str:
        """格式化单个 Log 的输入，明确区分 Log 和 Diff Context。"""
        diff_str = json.dumps(diff_vector, indent=2, ensure_ascii=False) if isinstance(diff_vector, dict) else str(diff_vector)
        
        return f"""
--- WINDOW ID: {window_id} ---

# === Event Logs (Current Packet Status) ===
# {event_sequence}

=== Diff Context (History & Semantics, based on diff_vector) ===
{diff_str}
"""
    
    def build_llama3_prompt(self, system_prompt: str, user_instruction: str) -> str:
        """将系统提示和用户指令封装为 Llama 3 聊天格式。"""
        return (
            f"<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n\n"
            f"{system_prompt}<|eot_id|><|start_header_id|>user<|end_header_id|>\n\n"
            f"{user_instruction}<|eot_id|><|start_header_id|>assistant<|end_header_id|>\n\n"
        )


def build_prompt_batch(windows_data: Dict[str, Dict[str, Any]]) -> tuple[List[str], List[Dict[str, Any]]]:
    """
    根据 Logic 和 Physics 规则，为每个 Log 构建两份独立的 Prompt。
    返回 Prompt 列表和对应的元数据列表。
    """
    manager = PromptManager()
    prompts_list = []
    prompt_metadata = []
    
    for win_id, data in windows_data.items():
        real_log_id = data['member_log_ids'][0]
        
        # 1. 格式化 Log Context (用户指令)
        user_instruction = manager.format_single_window_input(
            win_id, 
            data.get('sequence_text', ""), 
            data.get('diff_vector', {})
        )
        
        # 2. 生成 Logic Prompt
        logic_prompt = manager.build_llama3_prompt(
            manager.step1_logic_system, 
            user_instruction
        )
        prompts_list.append(logic_prompt)
        prompt_metadata.append({
            "win_id": win_id, 
            "real_log_id": real_log_id, 
            "type": "logic"
        })
        
        # 3. 生成 Physics Prompt
        physics_prompt = manager.build_llama3_prompt(
            manager.step1_physics_system, 
            user_instruction
        )
        prompts_list.append(physics_prompt)
        prompt_metadata.append({
            "win_id": win_id, 
            "real_log_id": real_log_id, 
            "type": "physics"
        })
        
    return prompts_list, prompt_metadata

# ==============================================================================
# 3. 辅助函数
# ==============================================================================

def clean_for_json(data):
    """递归地将数据结构中的 set 对象转换成 list，以保证 JSON 可序列化。"""
    if isinstance(data, dict):
        return {k: clean_for_json(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [clean_for_json(item) for item in data]
    elif isinstance(data, set):
        return [clean_for_json(item) for item in list(data)]
    else:
        return data

def _parse_step1_output(raw_output: str) -> List[tuple]:
    """尝试解析 Step 1 LLM 输出的纯文本列表。"""
    results = []
    # 清理常见的LLM注释
    raw_output = re.sub(r'```json|```|```python|```text|Output:', '', raw_output, flags=re.IGNORECASE).strip()
    
    # 按行分割
    for line in raw_output.split('\n'):
        line = line.strip()
        if not line: continue
        
        # 使用正则表达式匹配 ['win_id', 'RULE_CODE', start_index, end_index] 结构
        # 由于是单 Log 模式，start, end 预期为 0, 0 或其他
        match = re.search(r'\[\s*[\'"](win_\d+)[\'"]\s*,\s*[\'"](R\d+|P\d+|M\d+|S\d+|I\d+)[\'"]\s*,\s*(\d+)\s*,\s*(\d+)\s*\]', line)

        if match:
            try:
                win_id, rule, start_str, end_str = match.groups()
                results.append((win_id, rule, int(start_str), int(end_str)))
            except Exception as e:
                # 兼容 tqdm.write，但这里直接用 print
                print(f"Error parsing line: {line[:50]}... Error: {e}", file=sys.stderr)
    
    return results

def try_convert_value(value: str):
    value = value.strip()
    try:
        if '.' in value and value.replace('.', '', 1).isdigit(): return float(value)
        if value.isdigit(): return int(value)
    except: pass
    return value

def parse_log_from_string_dynamic(log_string: str) -> Optional[dict]:
    if not isinstance(log_string, str): return None
    return {"all_parsed_data": {"message": log_string}}

def preprocess_llm_input(data_dict: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(data_dict, dict): return data_dict
    processed_dict = {}
    for key, value in data_dict.items():
        if isinstance(value, str) and len(value) > 100 and value.count('A') / len(value) > 0.95:
            processed_dict[key] = f"BASE64_PADDING_DATA(length:{len(value)})"
        elif isinstance(value, dict):
            processed_dict[key] = preprocess_llm_input(value)
        else:
            processed_dict[key] = value
    return processed_dict
def _parse_step1_output(raw_output: str) -> List[tuple]:
    """尝试解析 Step 1 LLM 输出的纯文本列表。"""
    results = []
    # 清理常见的LLM注释
    raw_output = re.sub(r'```json|```|```python|```text|Output:', '', raw_output, flags=re.IGNORECASE).strip()
    
    # 按行分割
    for line in raw_output.split('\n'):
        line = line.strip()
        if not line: continue
        
        # 使用正则表达式匹配 ['win_id', 'RULE_CODE', start_index, end_index] 结构
        match = re.search(r'\[\s*[\'"](win_\d+)[\'"]\s*,\s*[\'"](R\d+|P\d+|M\d+|S\d+|I\d+)[\'"]\s*,\s*(\d+)\s*,\s*(\d+)\s*\]', line)

        if match:
            try:
                # 提取匹配组
                win_id, rule, start_str, end_str = match.groups()
                # 确保类型正确
                results.append((win_id, rule, int(start_str), int(end_str)))
            except Exception as e:
                tqdm.write(f"Error parsing line: {line[:50]}... Error: {e}")
    
    return results
def format_sequences_from_csv_for_llm(
    csv_path: str, 
    window_size: int = 1, 
    step: int = 1
) -> Dict[str, Dict[str, Any]]:
    try:
        df = pd.read_csv(csv_path, encoding='utf-8')
    except Exception as e:
        print(f"Error reading {csv_path}: {e}")
        return {}
    
    # 关键：强制将索引作为日志ID
    df['log_id'] = df.index.astype(str) 
    
    required_cols = ['Event_sequence', 'Diff_vector']
    for col in required_cols:
        if col not in df.columns:
            if col == 'Diff_vector': df['Diff_vector'] = '{}'
            else: return {}
            
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
            log_parts.append(f"{row['Event_sequence']}")
            member_ids.append(row['log_id']) 

            try:
                d = json.loads(str(row['Diff_vector']))
                if d and isinstance(d, dict): 
                    window_diffs_indexed[str(idx_in_window)] = d
            except: pass
            
        formatted_windows[window_id] = {
            "sequence_text": "; ".join(log_parts),
            "diff_vector": window_diffs_indexed,
            "member_log_ids": member_ids 
        }
    return formatted_windows

def generate_test_windows(test_logs: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """根据自定义 test_logs 生成 'windows' 字典结构。"""
    formatted_windows = {}
    for i, log_data in enumerate(test_logs):
        window_id = f"win_{i}"
        real_log_id = str(i) 
        
        diff_vector = log_data.get("Diff_vector", {})
        if isinstance(diff_vector, str):
            try:
                diff_vector = json.loads(diff_vector)
            except:
                diff_vector = {}
        
        diff_vector = clean_for_json(diff_vector) 
        
        # 格式化 Diff Context
        window_diffs_indexed = {"0": diff_vector}
        
        formatted_windows[window_id] = {
            "sequence_text": log_data["Event_sequence"],
            "diff_vector": window_diffs_indexed, 
            "member_log_ids": [real_log_id] 
        }
    return formatted_windows

# ==============================================================================
# 4. vLLM 推理执行逻辑 (核心)
# ==============================================================================

def run_vllm_inference(windows: Dict[str, Dict[str, Any]], output_path: str):
    
    if not windows: 
        print("Error: Input windows data is empty.")
        return

    print(f"--- Log 1: Successfully created {len(windows)} log windows. ---")
       
    # 1. 构建 Prompts 列表
    prompts_list = build_prompt_batch(windows)
    
    # 映射回原始 ID
    window_id_map = {win_id: data['member_log_ids'][0] for win_id, data in windows.items()}

    # 2. 初始化 vLLM 引擎 (3090 Ti 优化配置)
    print(f"Initializing vLLM Engine ({MODEL_PATH}) ...")
    try:
        llm = LLM(
            model=MODEL_PATH,
            quantization="awq",
            dtype="float16",
            tensor_parallel_size=1,
            gpu_memory_utilization=0.90,  
            max_model_len=4096,
            trust_remote_code=True
        )
    except Exception as e:
        print(f"\nFATAL ERROR: Failed to initialize vLLM. Check model path and quantization setting.")
        print(f"Error details: {e}")
        print(f"If {MODEL_PATH} is inaccessible, try using the native FP16 model 'meta-llama/Meta-Llama-3-8B-Instruct' and removing 'quantization=\"awq\"'.")
        sys.exit(1)
    
    # 采样参数 (Greedy decoding)
    sampling_params = SamplingParams(temperature=0.0, max_tokens=256, stop=["<|eot_id|>"])

    # 3. 执行推理 (vLLM 自动高性能批处理)
    print(f"Generating responses for {len(prompts_list)} inputs (Continuous Batching Active)...")
    
    # vLLM generate 函数会自动使用 tqdm 进度条
    outputs = llm.generate(prompts_list, sampling_params)

    # 4. 处理结果和知识归因
    print("Processing outputs and attributing knowledge...")
    knowledge_base = {}
    total_violations_found = 0
    
    # 确保输出和输入顺序一致
    for output in tqdm(outputs, desc="Parsing Results"):
        # 提取窗口 ID (从 prompt 的 metadata 中获取)
        prompt_text = output.prompt
        # Llama 3 格式中，PromptText 包含用户输入的完整内容
        win_match = re.search(r"--- WINDOW ID: (win_\d+) ---", prompt_text)
        win_id = win_match.group(1) if win_match else None
        
        if not win_id: continue
        
        real_log_id = window_id_map.get(win_id)
        if not real_log_id: continue
        
        generated_text = output.outputs[0].text.strip()
        
        # 解析 Step 1 结果
        anomalies = _parse_step1_output(generated_text)
        
        if real_log_id not in knowledge_base:
            knowledge_base[real_log_id] = {"violations": []}
            
        for _, rule, start, end in anomalies:
            violation_info = {
                "rule_id": rule,
                "detection_window": win_id, 
                "evidence": [0] # 单 Log 模式下，证据默认是 Log 自身
            }
            
            # 避免重复
            is_duplicate = any(
                item["rule_id"] == rule and item.get("detection_window") == win_id
                for item in knowledge_base[real_log_id]["violations"]
            )
            
            if not is_duplicate:
                knowledge_base[real_log_id]["violations"].append(violation_info)
                total_violations_found += 1
                
    print(f"\n--- Log 2: Total violations found across all logs: {total_violations_found}.")
    
    # 5. 保存最终的 Log-Level 知识库
    print(f"\n--- Log 3: Knowledge extraction complete. ---")
    
    non_empty_logs = {k: v for k, v in knowledge_base.items() if v.get("violations")}
    print(f"Total Log IDs with at least one violation record: {len(non_empty_logs)}")
    
    sample_log_ids = list(non_empty_logs.keys())[:5] 
    
    if sample_log_ids:
        for log_id in sample_log_ids:
            kb_entry = json.dumps(knowledge_base[log_id], ensure_ascii=False, indent=2)
            snippet = kb_entry[:100].replace('\n', ' ')
            print(f"Log ID {log_id}: {snippet}...")
    else:
        print("未发现带有违规标签的 Log ID。")

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(knowledge_base, f, indent=2, ensure_ascii=False)
        
if __name__ == '__main__':
    
    # --- 配置模式 ---
    TEST_MODE = True  # <--- 设为 True 运行自定义 Log，设为 False 运行 CSV
    
    # --- CSV 模式配置 ---
    CSV_PATH = "./Processed dataset (supervised ML)/9111a.csv" 
    JSON_PATH_CSV = "./knowledge_base_csv.json"
    
    # --- 测试模式配置 ---
    JSON_PATH_TEST = "./knowledge_base_test.json"
    
    # 测试的 Log 
    test_logs = [
        # Log 0
        {
            "Event_sequence": "GOOSE_PKT (ts=1725084167.383, src=20:17:01:16:f0:11, APPID=0x3103, stNum=1, sqNum=36, GOOSElength_GOOSE3=165, gocbRef_GOOSE3=QUTZS_FDRPIOC/LLN0$GO$gcb_1, goID_GOOSE3=gcb_1, simulation_GOOSE3=False, confRev_GOOSE3=200, ndsCom_GOOSE3=False, num of data_GOOSE3=14, data_GOOSE3=[False, 0, True, 0, False, 0, False, 0, False, 0, False, 0, False, 0]); GOOSE_PKT (ts=1725084166.782, src=20:17:01:16:f0:32, APPID=0x3102, stNum=1, sqNum=36, GOOSElength_GOOSE2=146, gocbRef_GOOSE2=QUTZS_XFMR2PIOC/LLN0$GO$gcb_1, goID_GOOSE2=gcb_1, simulation_GOOSE2=False, confRev_GOOSE2=200, ndsCom_GOOSE2=False, num of data_GOOSE2=8, data_GOOSE2=[True, 0, False, 0, False, 0, True, 0]); GOOSE_PKT (ts=1725084187.028, src=20:17:01:16:f0:23, APPID=0x3101, stNum=2, sqNum=19, GOOSElength_GOOSE1=146, gocbRef_GOOSE1=QUTZS_XFMR1PIOC/LLN0$GO$gcb_1, goID_GOOSE1=gcb_1, simulation_GOOSE1=False, confRev_GOOSE1=200, ndsCom_GOOSE1=False, num of data_GOOSE1=8, data_GOOSE1=[True, 0, True, 0, True, 0, False, 0]); SV_PKT (ts=1725084200.798376, src=20:17:01:16:f2:54, APPID=0x4001, SVlength_sv1=509, noASDU_sv1=13, svID1_sv1=66kV1, smpCnt1_sv1=696, Data1_sv1=0, svID2_sv1=66kV2, smpCnt2_sv1=696, Data2_sv1=0, svID3_sv1=66kV3, smpCnt3_sv1=696, Data3_sv1=35, svID4_sv1=XFMR1W1, smpCnt4_sv1=696, Data4_sv1=0, svID5_sv1=XFMR2W1, smpCnt5_sv1=696, Data5_sv1=35, svID6_sv1=XFMR1W2, smpCnt6_sv1=696, Data6_sv1=0, svID7_sv1=XFMR2W2, smpCnt7_sv1=696, Data7_sv1=60, svID8_sv1=CB_XFMR1, smpCnt8_sv1=696, Data8_sv1=0, svID9_sv1=CB_XFMR2, smpCnt9_sv1=696, Data9_sv1=104, svID10_sv1=F_66kV1, smpCnt10_sv1=696, Data10_sv1=0, svID11_sv1=F_66kV2, smpCnt11_sv1=696, Data11_sv1=0, svID12_sv1=F_XFMR1, smpCnt12_sv1=696, Data12_sv1=0, svID13_sv1=F_XFMR2, smpCnt13_sv1=696, Data13_sv1=0); SV_PKT (ts=1725084200.819751, src=20:17:01:16:f2:54, APPID=0x4002, SVlength_sv2=491, noASDU_sv2=13, svID1_sv2=22kV1, smpCnt1_sv2=689, Data1_sv2=26, svID2_sv2=22kV2, smpCnt2_sv2=689, Data2_sv2=52, svID3_sv2=22kV3, smpCnt3_sv2=689, Data3_sv2=26, svID4_sv2=FDR1, smpCnt4_sv2=689, Data4_sv2=26, svID5_sv2=FDR2, smpCnt5_sv2=689, Data5_sv2=26, svID6_sv2=FDR3, smpCnt6_sv2=689, Data6_sv2=26, svID7_sv2=FDR4, smpCnt7_sv2=689, Data7_sv2=26, svID8_sv2=F_22kV1, smpCnt8_sv2=689, Data8_sv2=0, svID9_sv2=F_22kV2, smpCnt9_sv2=689, Data9_sv2=0, svID10_sv2=F_FDR1, smpCnt10_sv2=689, Data10_sv2=0, svID11_sv2=F_FDR2, smpCnt11_sv2=689, Data11_sv2=0, svID12_sv2=F_FDR3, smpCnt12_sv2=689, Data12_sv2=0, svID13_sv2=F_FDR4, smpCnt13_sv2=689, Data13_sv2=0)",
            "Diff_vector": {
                "{""pkt arrival time_sv1"": ""incrementing"", ""SVlength_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""noASDU_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt1_sv1"": ""incrementing"", ""Data1_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt2_sv1"": ""incrementing"", ""Data2_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt3_sv1"": ""incrementing"", ""Data3_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt4_sv1"": ""incrementing"", ""Data4_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt5_sv1"": ""incrementing"", ""Data5_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt6_sv1"": ""incrementing"", ""Data6_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt7_sv1"": ""incrementing"", ""Data7_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt8_sv1"": ""incrementing"", ""Data8_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt9_sv1"": ""incrementing"", ""Data9_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt10_sv1"": ""incrementing"", ""Data10_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt11_sv1"": ""incrementing"", ""Data11_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt12_sv1"": ""incrementing"", ""Data12_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt13_sv1"": ""incrementing"", ""Data13_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""pkt arrival time_sv2"": ""incrementing"", ""SVlength_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""noASDU_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt1_sv2"": ""incrementing"", ""Data1_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt2_sv2"": ""incrementing"", ""Data2_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt3_sv2"": ""incrementing"", ""Data3_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt4_sv2"": ""incrementing"", ""Data4_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt5_sv2"": ""incrementing"", ""Data5_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt6_sv2"": ""incrementing"", ""Data6_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt7_sv2"": ""incrementing"", ""Data7_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt8_sv2"": ""incrementing"", ""Data8_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt9_sv2"": ""incrementing"", ""Data9_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt10_sv2"": ""incrementing"", ""Data10_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt11_sv2"": ""incrementing"", ""Data11_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt12_sv2"": ""incrementing"", ""Data12_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt13_sv2"": ""incrementing"", ""Data13_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""GOOSElength_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""Timeallowedtolive_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""t_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""stNum_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""sqNum_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""confRev_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""num of data_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""GOOSElength_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""Timeallowedtolive_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""t_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""stNum_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""sqNum_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""confRev_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""num of data_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""GOOSElength_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""Timeallowedtolive_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""t_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""stNum_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""sqNum_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""confRev_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""num of data_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}}"
            }
        },
        # Log 1
        {
            "Event_sequence": "GOOSE_PKT (ts=1725084167.383, src=20:17:01:16:f0:11, APPID=0x3103, stNum=1, sqNum=36, GOOSElength_GOOSE3=165, gocbRef_GOOSE3=QUTZS_FDRPIOC/LLN0$GO$gcb_1, goID_GOOSE3=gcb_1, simulation_GOOSE3=False, confRev_GOOSE3=200, ndsCom_GOOSE3=False, num of data_GOOSE3=14, data_GOOSE3=[False, 0, True, 0, False, 0, False, 0, False, 0, False, 0, False, 0]); GOOSE_PKT (ts=1725084166.782, src=20:17:01:16:f0:32, APPID=0x3102, stNum=1, sqNum=36, GOOSElength_GOOSE2=146, gocbRef_GOOSE2=QUTZS_XFMR2PIOC/LLN0$GO$gcb_1, goID_GOOSE2=gcb_1, simulation_GOOSE2=False, confRev_GOOSE2=200, ndsCom_GOOSE2=False, num of data_GOOSE2=8, data_GOOSE2=[True, 0, False, 0, False, 0, True, 0]); GOOSE_PKT (ts=1725084187.028, src=20:17:01:16:f0:23, APPID=0x3101, stNum=2, sqNum=19, GOOSElength_GOOSE1=146, gocbRef_GOOSE1=QUTZS_XFMR1PIOC/LLN0$GO$gcb_1, goID_GOOSE1=gcb_1, simulation_GOOSE1=False, confRev_GOOSE1=200, ndsCom_GOOSE1=False, num of data_GOOSE1=8, data_GOOSE1=[True, 0, True, 0, True, 0, False, 0]); SV_PKT (ts=1725084200.848808, src=20:17:01:16:f2:54, APPID=0x4001, SVlength_sv1=509, noASDU_sv1=13, svID1_sv1=66kV1, smpCnt1_sv1=697, Data1_sv1=0, svID2_sv1=66kV2, smpCnt2_sv1=697, Data2_sv1=0, svID3_sv1=66kV3, smpCnt3_sv1=697, Data3_sv1=35, svID4_sv1=XFMR1W1, smpCnt4_sv1=697, Data4_sv1=0, svID5_sv1=XFMR2W1, smpCnt5_sv1=697, Data5_sv1=35, svID6_sv1=XFMR1W2, smpCnt6_sv1=697, Data6_sv1=0, svID7_sv1=XFMR2W2, smpCnt7_sv1=697, Data7_sv1=60, svID8_sv1=CB_XFMR1, smpCnt8_sv1=697, Data8_sv1=0, svID9_sv1=CB_XFMR2, smpCnt9_sv1=697, Data9_sv1=104, svID10_sv1=F_66kV1, smpCnt10_sv1=697, Data10_sv1=0, svID11_sv1=F_66kV2, smpCnt11_sv1=697, Data11_sv1=0, svID12_sv1=F_XFMR1, smpCnt12_sv1=697, Data12_sv1=0, svID13_sv1=F_XFMR2, smpCnt13_sv1=697, Data13_sv1=0); SV_PKT (ts=1725084200.869778, src=20:17:01:16:f2:54, APPID=0x4002, SVlength_sv2=491, noASDU_sv2=13, svID1_sv2=22kV1, smpCnt1_sv2=690, Data1_sv2=26, svID2_sv2=22kV2, smpCnt2_sv2=690, Data2_sv2=52, svID3_sv2=22kV3, smpCnt3_sv2=690, Data3_sv2=26, svID4_sv2=FDR1, smpCnt4_sv2=690, Data4_sv2=26, svID5_sv2=FDR2, smpCnt5_sv2=690, Data5_sv2=26, svID6_sv2=FDR3, smpCnt6_sv2=690, Data6_sv2=26, svID7_sv2=FDR4, smpCnt7_sv2=690, Data7_sv2=26, svID8_sv2=F_22kV1, smpCnt8_sv2=690, Data8_sv2=0, svID9_sv2=F_22kV2, smpCnt9_sv2=690, Data9_sv2=0, svID10_sv2=F_FDR1, smpCnt10_sv2=690, Data10_sv2=0, svID11_sv2=F_FDR2, smpCnt11_sv2=690, Data11_sv2=0, svID12_sv2=F_FDR3, smpCnt12_sv2=690, Data12_sv2=0, svID13_sv2=F_FDR4, smpCnt13_sv2=690, Data13_sv2=0)",
            "Diff_vector": {
                "{""pkt arrival time_sv1"": ""incrementing"", ""SVlength_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""noASDU_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt1_sv1"": ""incrementing"", ""Data1_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt2_sv1"": ""incrementing"", ""Data2_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt3_sv1"": ""incrementing"", ""Data3_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt4_sv1"": ""incrementing"", ""Data4_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt5_sv1"": ""incrementing"", ""Data5_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt6_sv1"": ""incrementing"", ""Data6_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt7_sv1"": ""incrementing"", ""Data7_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt8_sv1"": ""incrementing"", ""Data8_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt9_sv1"": ""incrementing"", ""Data9_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt10_sv1"": ""incrementing"", ""Data10_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt11_sv1"": ""incrementing"", ""Data11_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt12_sv1"": ""incrementing"", ""Data12_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt13_sv1"": ""incrementing"", ""Data13_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""pkt arrival time_sv2"": ""incrementing"", ""SVlength_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""noASDU_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt1_sv2"": ""incrementing"", ""Data1_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt2_sv2"": ""incrementing"", ""Data2_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt3_sv2"": ""incrementing"", ""Data3_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt4_sv2"": ""incrementing"", ""Data4_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt5_sv2"": ""incrementing"", ""Data5_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt6_sv2"": ""incrementing"", ""Data6_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt7_sv2"": ""incrementing"", ""Data7_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt8_sv2"": ""incrementing"", ""Data8_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt9_sv2"": ""incrementing"", ""Data9_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt10_sv2"": ""incrementing"", ""Data10_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt11_sv2"": ""incrementing"", ""Data11_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt12_sv2"": ""incrementing"", ""Data12_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt13_sv2"": ""incrementing"", ""Data13_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""GOOSElength_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""Timeallowedtolive_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""t_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""stNum_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""sqNum_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""confRev_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""num of data_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""GOOSElength_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""Timeallowedtolive_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""t_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""stNum_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""sqNum_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""confRev_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""num of data_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""GOOSElength_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""Timeallowedtolive_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""t_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""stNum_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""sqNum_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""confRev_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""num of data_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}}"
            }
        },
        # Log 2
        {
            "Event_sequence": "GOOSE_PKT (ts=1725084167.383, src=20:17:01:16:f0:11, APPID=0x3103, stNum=1, sqNum=36, GOOSElength_GOOSE3=165, gocbRef_GOOSE3=QUTZS_FDRPIOC/LLN0$GO$gcb_1, goID_GOOSE3=gcb_1, simulation_GOOSE3=False, confRev_GOOSE3=200, ndsCom_GOOSE3=False, num of data_GOOSE3=14, data_GOOSE3=[False, 0, True, 0, False, 0, False, 0, False, 0, False, 0, False, 0]); GOOSE_PKT (ts=1725084166.782, src=20:17:01:16:f0:32, APPID=0x3102, stNum=1, sqNum=36, GOOSElength_GOOSE2=146, gocbRef_GOOSE2=QUTZS_XFMR2PIOC/LLN0$GO$gcb_1, goID_GOOSE2=gcb_1, simulation_GOOSE2=False, confRev_GOOSE2=200, ndsCom_GOOSE2=False, num of data_GOOSE2=8, data_GOOSE2=[True, 0, False, 0, False, 0, True, 0]); GOOSE_PKT (ts=1725084187.028, src=20:17:01:16:f0:23, APPID=0x3101, stNum=2, sqNum=19, GOOSElength_GOOSE1=146, gocbRef_GOOSE1=QUTZS_XFMR1PIOC/LLN0$GO$gcb_1, goID_GOOSE1=gcb_1, simulation_GOOSE1=False, confRev_GOOSE1=200, ndsCom_GOOSE1=False, num of data_GOOSE1=8, data_GOOSE1=[True, 0, True, 0, True, 0, False, 0]); SV_PKT (ts=1725084200.89885, src=20:17:01:16:f2:54, APPID=0x4001, SVlength_sv1=509, noASDU_sv1=13, svID1_sv1=66kV1, smpCnt1_sv1=698, Data1_sv1=0, svID2_sv1=66kV2, smpCnt2_sv1=698, Data2_sv1=0, svID3_sv1=66kV3, smpCnt3_sv1=698, Data3_sv1=35, svID4_sv1=XFMR1W1, smpCnt4_sv1=698, Data4_sv1=0, svID5_sv1=XFMR2W1, smpCnt5_sv1=698, Data5_sv1=35, svID6_sv1=XFMR1W2, smpCnt6_sv1=698, Data6_sv1=0, svID7_sv1=XFMR2W2, smpCnt7_sv1=698, Data7_sv1=60, svID8_sv1=CB_XFMR1, smpCnt8_sv1=698, Data8_sv1=0, svID9_sv1=CB_XFMR2, smpCnt9_sv1=698, Data9_sv1=104, svID10_sv1=F_66kV1, smpCnt10_sv1=698, Data10_sv1=0, svID11_sv1=F_66kV2, smpCnt11_sv1=698, Data11_sv1=0, svID12_sv1=F_XFMR1, smpCnt12_sv1=698, Data12_sv1=0, svID13_sv1=F_XFMR2, smpCnt13_sv1=698, Data13_sv1=0); SV_PKT (ts=1725084200.920275, src=20:17:01:16:f2:54, APPID=0x4002, SVlength_sv2=491, noASDU_sv2=13, svID1_sv2=22kV1, smpCnt1_sv2=691, Data1_sv2=26, svID2_sv2=22kV2, smpCnt2_sv2=691, Data2_sv2=52, svID3_sv2=22kV3, smpCnt3_sv2=691, Data3_sv2=26, svID4_sv2=FDR1, smpCnt4_sv2=691, Data4_sv2=26, svID5_sv2=FDR2, smpCnt5_sv2=691, Data5_sv2=26, svID6_sv2=FDR3, smpCnt6_sv2=691, Data6_sv2=26, svID7_sv2=FDR4, smpCnt7_sv2=691, Data7_sv2=26, svID8_sv2=F_22kV1, smpCnt8_sv2=691, Data8_sv2=0, svID9_sv2=F_22kV2, smpCnt9_sv2=691, Data9_sv2=0, svID10_sv2=F_FDR1, smpCnt10_sv2=691, Data10_sv2=0, svID11_sv2=F_FDR2, smpCnt11_sv2=691, Data11_sv2=0, svID12_sv2=F_FDR3, smpCnt12_sv2=691, Data12_sv2=0, svID13_sv2=F_FDR4, smpCnt13_sv2=691, Data13_sv2=0)",
            "Diff_vector": {
                "{""pkt arrival time_sv1"": ""incrementing"", ""SVlength_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""noASDU_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt1_sv1"": ""incrementing"", ""Data1_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt2_sv1"": ""incrementing"", ""Data2_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt3_sv1"": ""incrementing"", ""Data3_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt4_sv1"": ""incrementing"", ""Data4_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt5_sv1"": ""incrementing"", ""Data5_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt6_sv1"": ""incrementing"", ""Data6_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt7_sv1"": ""incrementing"", ""Data7_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt8_sv1"": ""incrementing"", ""Data8_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt9_sv1"": ""incrementing"", ""Data9_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt10_sv1"": ""incrementing"", ""Data10_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt11_sv1"": ""incrementing"", ""Data11_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt12_sv1"": ""incrementing"", ""Data12_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt13_sv1"": ""incrementing"", ""Data13_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""pkt arrival time_sv2"": ""incrementing"", ""SVlength_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""noASDU_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt1_sv2"": ""incrementing"", ""Data1_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt2_sv2"": ""incrementing"", ""Data2_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt3_sv2"": ""incrementing"", ""Data3_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt4_sv2"": ""incrementing"", ""Data4_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt5_sv2"": ""incrementing"", ""Data5_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt6_sv2"": ""incrementing"", ""Data6_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt7_sv2"": ""incrementing"", ""Data7_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt8_sv2"": ""incrementing"", ""Data8_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt9_sv2"": ""incrementing"", ""Data9_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt10_sv2"": ""incrementing"", ""Data10_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt11_sv2"": ""incrementing"", ""Data11_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt12_sv2"": ""incrementing"", ""Data12_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt13_sv2"": ""incrementing"", ""Data13_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""GOOSElength_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""Timeallowedtolive_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""t_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""stNum_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""sqNum_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""confRev_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""num of data_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""GOOSElength_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""Timeallowedtolive_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""t_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""stNum_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""sqNum_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""confRev_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""num of data_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""GOOSElength_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""Timeallowedtolive_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""t_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""stNum_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""sqNum_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""confRev_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""num of data_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}}"
            }
        },
    ]

    if TEST_MODE:
        print("--- Running in TEST_MODE with custom logs using vLLM ---")
        windows_to_process = generate_test_windows(test_logs)
        run_vllm_inference(windows_to_process, JSON_PATH_TEST)
    else:
        # 如果需要跑 CSV 模式，需要补充 format_sequences_from_csv_for_llm 函数
        print(f"--- Running in CSV mode using file: {CSV_PATH} ---")
        print("CSV mode requires the original format_sequences_from_csv_for_llm function, which is not included in this file.")
        sys.exit(1)
