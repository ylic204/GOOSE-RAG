import pandas as pd
import json
import re
from typing import Dict, Any, List, Optional
from tqdm import tqdm
import os
import sys
import ast
import concurrent.futures  # 关键：引入并行计算模块 (现在用于多线程)
# import multiprocessing   # <--- 已移除：不再需要多进程，避免死锁

# 导入 Ollama (假设已安装)
try:
    import ollama
    # A100 优化配置：Llama 3.2
    MODEL_NAME = "qwen2.5:72b"
    # 建议配置：由于切换到了多线程，您可以适当增加并行度
    # 如果显存允许，可以将 NUM_WORKERS 设为 2 或 4
    BATCH_SIZE = 1              
    NUM_WORKERS = 16              
except ImportError:
    ollama = None
    print("Warning: Ollama not installed. LLM functionality will be disabled.")
    MODEL_NAME = "dummy"
    BATCH_SIZE = 1 
    NUM_WORKERS = 1

# Ollama 主机地址（用于连通性检测）
OLLAMA_HOST = "http://localhost:11434"

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

def check_ollama_ready(model_name: str, host: str, timeout: float = 5.0) -> bool:
    """
    主进程健康检查：确认 Ollama 服务可访问且模型已就绪。
    """
    if not ollama:
        print("Warning: ollama package not available.")
        return False
    try:
        import urllib.request
        with urllib.request.urlopen(host, timeout=timeout) as resp:
            if resp.status != 200:
                print(f"Warning: Ollama host responded with status {resp.status}")
    except Exception as e:
        print(f"Error: cannot reach Ollama host {host}: {e}")
        return False
    try:
        client = ollama.Client(host=host)
        client.show(model_name)
        return True
    except Exception as e:
        print(f"Error: Ollama model check failed for '{model_name}': {e}")
        return False

def _parse_step1_output(raw_output: str) -> List[tuple]:
    """
    尝试解析 Step 1 LLM 输出的纯文本列表。
    """
    cleaned = re.sub(r'```json|```|```python|```text|Output:', '', str(raw_output), flags=re.IGNORECASE).strip()
    pattern = r'\[\s*[\'"](win_\d+)[\'"]\s*,\s*[\'"](R\d+|P\d+|M\d+|S\d+|I\d+)[\'"]\s*,\s*(\d+)\s*,\s*(\d+)\s*\]'
    
    results: List[tuple] = []
    for win_id, rule, start_str, end_str in re.findall(pattern, cleaned):
        try:
            results.append((win_id, rule, int(start_str), int(end_str)))
        except Exception as e:
            tqdm.write(f"Error parsing entry: win={win_id}, rule={rule}, raw=({start_str},{end_str}). Error: {e}")
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
                # 在多线程/进程环境中，建议在每个 worker 内部实例化客户端
                self.client = ollama.Client(host=self.host)
            except Exception as e:
                self.client = None
        else:
            self.client = None

    def _call_ollama(self, system_prompt: str, user_prompt: str) -> str:
        """调用 Ollama API 进行推理"""
        if not self.client:
            print("[Debug] Client is None!")
            return "Ollama client not available."
        
        format_mode = "json" if "[JSON_SYNTHESIS_MODE]" in system_prompt else ""
        
        # --- Debug 打印 ---
        print(f"[Debug] Sending request to Ollama ({self.model_name})... Waiting for response.", flush=True)
        # -----------------

        try:
            response = self.client.chat(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                options={"temperature": 0.01, "format": format_mode}
            )
            # --- Debug 打印 ---
            print(f"[Debug] Received response from Ollama (Length: {len(response['message']['content'])}).", flush=True)
            # -----------------
            return response['message']['content'].strip()
        except Exception as e:
            print(f"[Error] Ollama API call error: {e}", file=sys.stderr, flush=True)
            return f"Error: LLM call failed with {e}"

    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        return self._call_ollama(system_prompt, user_prompt)

# ==============================================================================
# 3. 知识提取主逻辑

class KnowledgeExtractor:
    def __init__(self, model_name=MODEL_NAME, client_host=OLLAMA_HOST):
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
        
# 并行处理函数
def worker_process_batch(batch_input: List[Dict[str, Any]], model_name: str) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
    """
    由 ThreadPoolExecutor 执行的函数。
    """
    print(f"[Debug] Worker started processing batch of size {len(batch_input)}", flush=True) # <--- 新增
    
    try:
        extractor = KnowledgeExtractor(model_name=model_name)
        batch_output = extractor.get_knowledge_label_batch(batch_input)
        print(f"[Debug] Worker finished batch.", flush=True) # <--- 新增
        return batch_output
    except Exception as e:
        print(f"[Error] Exception in worker: {e}", flush=True)
        return {}


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
    
    # 步骤 2: 使用 ThreadPoolExecutor 进行多线程并行处理 (解决 ProcessPoolExecutor 死锁问题)
    all_batch_outputs = []
    
    effective_workers = max(1, min(NUM_WORKERS, len(batches)))
    
    # <--- 修改处：切换为 ThreadPoolExecutor
    with concurrent.futures.ThreadPoolExecutor(max_workers=effective_workers) as executor:
        # 提交任务
        futures = [executor.submit(worker_process_batch, batch, MODEL_NAME) for batch in batches]
        
        # 收集结果
        for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Processing Batches"):
            try:
                batch_output = future.result()
                all_batch_outputs.append(batch_output)
            except Exception as exc:
                tqdm.write(f'A worker thread generated an exception: {exc}')


    # 聚合所有批次结果并进行知识归因
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
    TEST_MODE = False  # <--- 设为 True 运行自定义 Log，设为 False 运行 CSV
    
    # --- CSV 模式配置 ---
    CSV_PATH = "Datasets/Processed dataset (supervised ML)/9111a.csv" 
    JSON_PATH_CSV = "./knowledge_base_csv.json"
    
    # --- 测试模式配置 ---
    JSON_PATH_TEST = "./knowledge_base_test.json"
    
    # 测试的 Log 数据
    test_logs = [
        # Log 0
        {
            "Event_sequence": "GOOSE_PKT (ts=1725084167.383, src=20:17:01:16:f0:11, APPID=0x3103, stNum=1, sqNum=36, GOOSElength_GOOSE3=165...)",
            "Diff_vector": "{...}" # (为节省长度，此处省略了原始巨大的测试字符串，但逻辑保持不变)
        },
    ]
    # (注意：为了代码整洁，我没有在这里完整复制您原始庞大的 test_logs 字符串，
    # 但您之前的 test_logs 列表可以直接放回这里，或者就用您的原始数据)

    # 先做 Ollama 连通性与模型可用性检测，避免并行时卡死
    if not check_ollama_ready(MODEL_NAME, OLLAMA_HOST):
        sys.exit(1)

    if TEST_MODE:
        # 注意：这里需要填入您原始代码中完整的 test_logs 数据
        # 如果您运行的是 CSV 模式，这里的 test_logs 为空也无所谓
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