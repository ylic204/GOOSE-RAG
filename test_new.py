import pandas as pd
import json
import re
from typing import Dict, Any, List, Optional
from tqdm import tqdm
import os
import sys
import ast
import concurrent.futures # <-- 关键：引入并行计算模块

# 导入 Ollama (假设已安装)
try:
    import ollama
    # A100 优化配置：Llama 3.1 8B + 并行化
    MODEL_NAME = "llama3.1:8b"     # Llama 3.1 8B 的 Ollama ID
    BATCH_SIZE = 1              
    NUM_WORKERS = 1              
except ImportError:
    ollama = None
    print("Warning: Ollama not installed. LLM functionality will be disabled.")
    MODEL_NAME = "dummy"
    BATCH_SIZE = 1 
    NUM_WORKERS = 1

# ==============================================================================
# 1. 辅助函数和预处理

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
    raw_output = re.sub(r'```json|```|```python|```text|Output:', '', raw_output, flags=re.IGNORECASE).strip()
    
    for line in raw_output.split('\n'):
        line = line.strip()
        if not line: continue
        
        # 匹配 ['win_id', 'RULE_CODE', start_index, end_index] 结构
        match = re.search(r'\[\s*[\'"](win_\d+)[\'"]\s*,\s*[\'"](R\d+|P\d+|M\d+|S\d+|I\d+)[\'"]\s*,\s*(\d+)\s*,\s*(\d+)\s*\]', line)

        if match:
            try:
                win_id, rule, start_str, end_str = match.groups()
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
        
        # 清洗数据
        diff_vector = clean_for_json(diff_vector) 
        
        window_diffs_indexed = {"0": diff_vector}
        
        formatted_windows[window_id] = {
            "sequence_text": log_data["Event_sequence"],
            "diff_vector": window_diffs_indexed, 
            "member_log_ids": [real_log_id] # 在 Test Mode 下，一个 Log 对应一个窗口
        }
    return formatted_windows

# ==============================================================================
# 2. LLM 接口与 Prompt

class LLM_Manager:
    """LLM 调用管理器 (基于 Ollama)"""
    
    def __init__(self, model_name: str, host: str):
        self.model_name = model_name
        self.host = host
        if ollama:
            try:
                # 在多进程环境中，必须在每个进程中实例化客户端
                self.client = ollama.Client(host=self.host)
            except Exception as e:
                self.client = None
        else:
            self.client = None

    def _call_ollama(self, system_prompt: str, user_prompt: str) -> str:
        """调用 Ollama API 进行推理"""
        if not self.client:
            return "Ollama client not available in this process."
        
        format_mode = "json" if "[JSON_SYNTHESIS_MODE]" in system_prompt else ""

        try:
            response = self.client.chat(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                options={"temperature": 0.01, "format": format_mode}
            )
            return response['message']['content'].strip()
        except Exception as e:
            # 在 worker 进程中捕获错误，以便主进程记录
            print(f"Ollama API call error in worker: {e}", file=sys.stderr)
            return f"Error: LLM call failed with {e}"

    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        return self._call_ollama(system_prompt, user_prompt)

# ==============================================================================
# 3. 知识提取主逻辑


class KnowledgeExtractor:
    def __init__(self, model_name=MODEL_NAME, client_host="http://localhost:11434"):
        self.llm = LLM_Manager(model_name, client_host) 
        
        # 导入 PromptManager (假设 prompt.py 在同目录下)
        try:
            from prompt import PromptManager_CoT_Multi_Turn 
            self.prompts = PromptManager_CoT_Multi_Turn()
        except ImportError:
            raise ImportError("Could not find 'prompt.py'. Please ensure it is in the same directory.")

    def _format_single_window_input(self, window_id: str, event_sequence: str, diff_vector: Dict[str, Any]) -> str:
        return self.prompts.format_single_window_input(window_id, event_sequence, diff_vector)
        
    def get_knowledge_label_batch(self, batch_data: List[Dict[str, Any]]) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
        
        combined_input_context = ""
        log_id_map = {} # 映射 window_id 到 real_log_id
        
        for item in batch_data:
            window_id = item['window_id']
            real_log_id = item.get('real_log_id', window_id) 
            log_id_map[window_id] = real_log_id
            
            combined_input_context += self._format_single_window_input(
                window_id, 
                item.get('sequence_text', item.get('event_sequence', "")), 
                item.get('diff_vector', {})
            )

        # --- 2. Step 1: 批量 LLM 调用 (Logic & Physics) ---
        step1_logic_system = self.prompts.step1_logic_system
        logic_raw_output = self.llm._call_llm(step1_logic_system, combined_input_context)
        
        step1_physics_system = self.prompts.step1_physics_system
        physics_raw_output = self.llm._call_llm(step1_physics_system, combined_input_context)

        # --- 3. 解析 Step 1 结果 ---
        logic_results = _parse_step1_output(logic_raw_output)
        physics_results = _parse_step1_output(physics_raw_output)
        
        combined_anomalies = logic_results + physics_results
        
        # 初始化结果，键为原始 Log ID
        final_knowledge_base = {real_id: {"violations": []} for real_id in log_id_map.values()}
        
        if not combined_anomalies:
            return final_knowledge_base
            
        # --- 4. 归属到原始 Log ID，并构造 Step 2 输入 ---
        
        formatted_anomalies_for_step2_input = [] 

        for win_id, rule, start, end in combined_anomalies:
            real_log_id = log_id_map.get(win_id)
            if real_log_id is None: continue
                
            violation_entry = {
                "window_id": win_id, 
                "rule": rule,
                "evidence_range": [start, end]
            }
            # 直接归属到 REAL LOG ID
            final_knowledge_base[real_log_id]['violations'].append(violation_entry)
            
            formatted_anomalies_for_step2_input.append(f"['{real_log_id}', '{rule}', {start}, {end}]")

        # --- 4.2 调用 Step 2 LLM ---
        step2_input_list = "\n".join(formatted_anomalies_for_step2_input)
        step2_system_prompt = self.prompts.get_step2_formatting_prompt(step2_input_list)

        self.llm._call_llm(step2_system_prompt, "Convert the input list to the mandatory JSON schema.")
        
        return final_knowledge_base
        
# 并行
def worker_process_batch(batch_input: List[Dict[str, Any]], model_name: str) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    """
    由 ProcessPoolExecutor 执行的函数。
    它在自己的进程中实例化 KnowledgeExtractor，并处理一个批次 (BATCH_SIZE)。
    """
    # 每个进程必须实例化自己的 KnowledgeExtractor
    extractor = KnowledgeExtractor(model_name=model_name)
    
    # 处理批次
    batch_output = extractor.get_knowledge_label_batch(batch_input)
    
    # 返回原始输出，由主进程聚合
    return batch_output


def run_batch_processing(windows: Dict[str, Dict[str, Any]], output_path: str):
    
    if not windows: 
        print("Error: Input windows data is empty.")
        return

    print(f"--- Successfully created {len(windows)} sliding windows. ---")
       
    knowledge_base = {} 
    win_items = list(windows.items())
    
    # 步骤 1: 将所有窗口数据切分为批次
    batches = []
    for i in range(0, len(win_items), BATCH_SIZE):
        batch = win_items[i : i+BATCH_SIZE]
        batch_input = []
        for win_id, data in batch:
            real_log_id = data["member_log_ids"][0]
            batch_input.append({
                "window_id": win_id,
                "real_log_id": real_log_id,
                "sequence_text": data["sequence_text"],
                "diff_vector": data["diff_vector"]
            })
        batches.append(batch_input)

    print(f"Starting Parallel Batch Extraction (Batch Size={BATCH_SIZE}, Workers={NUM_WORKERS}, Model={MODEL_NAME})...")
    
    # 步骤 2: 使用 ProcessPoolExecutor 进行多进程并行处理
    all_batch_outputs = []
    
    with concurrent.futures.ProcessPoolExecutor(max_workers=NUM_WORKERS) as executor:
        futures = [executor.submit(worker_process_batch, batch, MODEL_NAME) for batch in batches]
        
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Processing Batches"):
            try:
                batch_output = future.result()
                all_batch_outputs.append(batch_output)
            except Exception as exc:
                tqdm.write(f'A worker process generated an exception: {exc}')


    #聚合所有批次结果并进行知识归因
    
    aggregated_output = {}
    for batch_output in all_batch_outputs:
        aggregated_output.update(batch_output)

    total_violations_found = 0
    
    for real_log_id, kb_entry in aggregated_output.items():
        violations_list = kb_entry.get("violations", []) 
        total_violations_found += len(violations_list)

        if not violations_list: continue
            
        for v in violations_list: 
            if not isinstance(v, dict) or "rule" not in v or "evidence_range" not in v: 
                continue
                
            detection_window = v.get("window_id")
            if not detection_window: continue
            
            original_data = windows.get(detection_window) 
            if not original_data: continue
            
            member_log_ids = original_data["member_log_ids"] 
            
            rule_id = v["rule"]
            evidence_range_value = v.get("evidence_range")
            evidence_range_list = [evidence_range_value] if isinstance(evidence_range_value, list) else []

            involved_relative_indices = set()
            for start, end in evidence_range_list:
                try:
                    start_idx = max(0, int(start))
                    end_idx = min(len(member_log_ids) - 1, int(end))
                except ValueError: continue
                
                for idx in range(start_idx, end_idx + 1):
                    involved_relative_indices.add(idx)

            violation_info = {
                "rule_id": rule_id,
                "detection_window": detection_window, 
                "evidence": sorted(list(involved_relative_indices)) 
            }
            
            # 将违规信息分配给每一个受影响的 Log ID
            for idx in involved_relative_indices:
                current_real_log_id = member_log_ids[idx]
                if current_real_log_id not in knowledge_base:
                    knowledge_base[current_real_log_id] = {"violations": []}
                
                # 避免重复添加相同的 (Rule, Window) 记录
                is_duplicate = any(
                    item["rule_id"] == rule_id and item.get("detection_window") == detection_window
                    for item in knowledge_base[current_real_log_id]["violations"]
                )
                            
                if not is_duplicate:
                    knowledge_base[current_real_log_id]["violations"].append(violation_info)

    print(f"\n--- Total violations found across all batches: {total_violations_found}.")
    
    # 4. 保存最终的 Log-Level 知识库
    print(f"\n--- Knowledge extraction complete. ---")
    
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


# ==============================================================================
# 4. 运行示例 (请根据您的文件路径修改)
# ==============================================================================

if __name__ == '__main__':
    
    # --- 配置模式 ---
    TEST_MODE = True  # <--- 设为 True 运行自定义 Log，设为 False 运行 CSV
    
    # --- CSV 模式配置 ---
    CSV_PATH = "./Processed dataset (supervised ML)/9111a.csv" 
    JSON_PATH_CSV = "./knowledge_base_csv.json"
    
    # --- 测试模式配置 ---
    JSON_PATH_TEST = "./knowledge_base_test.json"
    
    # 测试的 Log 数据 都是异常的
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
        # Log 3
        {
            "Event_sequence": "GOOSE_PKT (ts=1725084167.383, src=20:17:01:16:f0:11, APPID=0x3103, stNum=1, sqNum=36, GOOSElength_GOOSE3=165, gocbRef_GOOSE3=QUTZS_FDRPIOC/LLN0$GO$gcb_1, goID_GOOSE3=gcb_1, simulation_GOOSE3=False, confRev_GOOSE3=200, ndsCom_GOOSE3=False, num of data_GOOSE3=14, data_GOOSE3=[False, 0, True, 0, False, 0, False, 0, False, 0, False, 0, False, 0]); GOOSE_PKT (ts=1725084166.782, src=20:17:01:16:f0:32, APPID=0x3102, stNum=1, sqNum=36, GOOSElength_GOOSE2=146, gocbRef_GOOSE2=QUTZS_XFMR2PIOC/LLN0$GO$gcb_1, goID_GOOSE2=gcb_1, simulation_GOOSE2=False, confRev_GOOSE2=200, ndsCom_GOOSE2=False, num of data_GOOSE2=8, data_GOOSE2=[True, 0, False, 0, False, 0, True, 0]); GOOSE_PKT (ts=1725084187.028, src=20:17:01:16:f0:23, APPID=0x3101, stNum=2, sqNum=19, GOOSElength_GOOSE1=146, gocbRef_GOOSE1=QUTZS_XFMR1PIOC/LLN0$GO$gcb_1, goID_GOOSE1=gcb_1, simulation_GOOSE1=False, confRev_GOOSE1=200, ndsCom_GOOSE1=False, num of data_GOOSE1=8, data_GOOSE1=[True, 0, True, 0, True, 0, False, 0]); SV_PKT (ts=1725084200.89885, src=20:17:01:16:f2:54, APPID=0x4001, SVlength_sv1=509, noASDU_sv1=13, svID1_sv1=66kV1, smpCnt1_sv1=698, Data1_sv1=0, svID2_sv1=66kV2, smpCnt2_sv1=698, Data2_sv1=0, svID3_sv1=66kV3, smpCnt3_sv1=698, Data3_sv1=35, svID4_sv1=XFMR1W1, smpCnt4_sv1=698, Data4_sv1=0, svID5_sv1=XFMR2W1, smpCnt5_sv1=698, Data5_sv1=35, svID6_sv1=XFMR1W2, smpCnt6_sv1=698, Data6_sv1=0, svID7_sv1=XFMR2W2, smpCnt7_sv1=698, Data7_sv1=60, svID8_sv1=CB_XFMR1, smpCnt8_sv1=698, Data8_sv1=0, svID9_sv1=CB_XFMR2, smpCnt9_sv1=698, Data9_sv1=104, svID10_sv1=F_66kV1, smpCnt10_sv1=698, Data10_sv1=0, svID11_sv1=F_66kV2, smpCnt11_sv1=698, Data11_sv1=0, svID12_sv1=F_XFMR1, smpCnt12_sv1=698, Data12_sv1=0, svID13_sv1=F_XFMR2, smpCnt13_sv1=698, Data13_sv1=0); SV_PKT (ts=1725084200.920275, src=20:17:01:16:f2:54, APPID=0x4002, SVlength_sv2=491, noASDU_sv2=13, svID1_sv2=22kV1, smpCnt1_sv2=691, Data1_sv2=26, svID2_sv2=22kV2, smpCnt2_sv2=691, Data2_sv2=52, svID3_sv2=22kV3, smpCnt3_sv2=691, Data3_sv2=26, svID4_sv2=FDR1, smpCnt4_sv2=691, Data4_sv2=26, svID5_sv2=FDR2, smpCnt5_sv2=691, Data5_sv2=26, svID6_sv2=FDR3, smpCnt6_sv2=691, Data6_sv2=26, svID7_sv2=FDR4, smpCnt7_sv2=691, Data7_sv2=26, svID8_sv2=F_22kV1, smpCnt8_sv2=691, Data8_sv2=0, svID9_sv2=F_22kV2, smpCnt9_sv2=691, Data9_sv2=0, svID10_sv2=F_FDR1, smpCnt10_sv2=691, Data10_sv2=0, svID11_sv2=F_FDR2, smpCnt11_sv2=691, Data11_sv2=0, svID12_sv2=F_FDR3, smpCnt12_sv2=691, Data12_sv2=0, svID13_sv2=F_FDR4, smpCnt13_sv2=691, Data13_sv2=0)",
            "Diff_vector": {
                "{""pkt arrival time_sv1"": ""incrementing"", ""SVlength_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""noASDU_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt1_sv1"": ""incrementing"", ""Data1_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt2_sv1"": ""incrementing"", ""Data2_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt3_sv1"": ""incrementing"", ""Data3_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt4_sv1"": ""incrementing"", ""Data4_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt5_sv1"": ""incrementing"", ""Data5_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt6_sv1"": ""incrementing"", ""Data6_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt7_sv1"": ""incrementing"", ""Data7_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt8_sv1"": ""incrementing"", ""Data8_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt9_sv1"": ""incrementing"", ""Data9_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt10_sv1"": ""incrementing"", ""Data10_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt11_sv1"": ""incrementing"", ""Data11_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt12_sv1"": ""incrementing"", ""Data12_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt13_sv1"": ""incrementing"", ""Data13_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""pkt arrival time_sv2"": ""incrementing"", ""SVlength_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""noASDU_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt1_sv2"": ""incrementing"", ""Data1_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt2_sv2"": ""incrementing"", ""Data2_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt3_sv2"": ""incrementing"", ""Data3_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt4_sv2"": ""incrementing"", ""Data4_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt5_sv2"": ""incrementing"", ""Data5_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt6_sv2"": ""incrementing"", ""Data6_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt7_sv2"": ""incrementing"", ""Data7_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt8_sv2"": ""incrementing"", ""Data8_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt9_sv2"": ""incrementing"", ""Data9_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt10_sv2"": ""incrementing"", ""Data10_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt11_sv2"": ""incrementing"", ""Data11_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt12_sv2"": ""incrementing"", ""Data12_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt13_sv2"": ""incrementing"", ""Data13_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""GOOSElength_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""Timeallowedtolive_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""t_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""stNum_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""sqNum_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""confRev_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""num of data_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""GOOSElength_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""Timeallowedtolive_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""t_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""stNum_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""sqNum_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""confRev_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""num of data_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""GOOSElength_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""Timeallowedtolive_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""t_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""stNum_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""sqNum_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""confRev_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""num of data_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}}"
            }
        },
    ]

    if TEST_MODE:
        windows_data = generate_test_windows(test_logs)
        print("\n--- Running in Test Mode with hardcoded logs ---")
        run_batch_processing(windows_data, JSON_PATH_TEST)
    else:
        if not os.path.exists(CSV_PATH):
            print(f"Error: CSV file not found at {CSV_PATH}. Please update the path.")
            sys.exit(1)
            
        windows_data = format_sequences_from_csv_for_llm(CSV_PATH)
        print("\n--- Running in CSV Mode ---")
        run_batch_processing(windows_data, JSON_PATH_CSV)