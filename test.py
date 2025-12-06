import pandas as pd
import json
import re
from typing import Dict, Any, List, Optional
from tqdm import tqdm
import os
import sys
import ast
# 导入 Ollama (假设已安装)
try:
    import ollama
    BATCH_SIZE = 1
except ImportError:
    ollama = None
    print("Warning: Ollama not installed. LLM functionality will be disabled.")
    BATCH_SIZE = 1 

# ==============================================================================
# 1. 辅助函数和预处理
# ==============================================================================

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
    """解析 Step 1 LLM 输出的纯文本列表。"""
    results = []
    # 清理常见的LLM注释
    raw_output = re.sub(r'```json|```|```python|```text|Output:', '', raw_output, flags=re.IGNORECASE).strip()

    for line in raw_output.split('\n'):
        line = line.strip()
        if not line: continue
        
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

def clean_for_json(data):
    """递归地将数据结构中的 set 对象转换成 list，以保证 JSON 可序列化。"""
    if isinstance(data, dict):
        return {k: clean_for_json(v) for k, v in data.items()}
    elif isinstance(data, list):
        return [clean_for_json(item) for item in data]
    elif isinstance(data, set):
        # 核心修复：将 set 转换为 list
        return [clean_for_json(item) for item in list(data)]
    else:
        return data
# ==============================================================================
# 2. LLM 接口与 Prompt (OllamaKnowledgeExtractor_Batch)
# ==============================================================================

import ast
import re
from typing import Dict, Any, List, Optional

def _parse_evidence_pairs(text: str) -> List[tuple]:
    """
    尝试从 LLM 的输出中解析出 ['win_id', 'RULE_CODE', start_index, end_index] 格式的列表。
    """
    if not text or text.strip().upper() in ('NONE', '[]', 'NO'):
        return []
    
    # 1. 清理并提取最外层的列表结构
    # 目标是获取 [['win_id', 'R01', 0, 0], ['win_id', 'P03', 0, 0]] 形式
    text = text.strip()
    match = re.search(r'(\[\[[\s\S]*?\]\])', text)
    if not match:
        # 如果不是外层列表，尝试解析为单个列表 ['win_id', 'R01', 0, 0]
        match = re.search(r'(\[\s*\'win_\d+\'[,\s\S]*?\])', text)
        if match:
            text = f"[{match.group(1)}]" # 包装成 List[List] 结构
        else:
            tqdm.write(f"Debug: Failed to find evidence list in: {text[:50]}...")
            return []

    try:
        # 使用 ast.literal_eval 安全地评估 Python 列表字符串
        data = ast.literal_eval(text)
    except Exception as e:
        tqdm.write(f"Error parsing LLM output: {e}, Raw text: {text[:100]}...")
        return []

    results = []
    # 确保 data 是 List[List]
    if isinstance(data, list) and all(isinstance(item, list) for item in data):
        for item in data:
            if len(item) == 4 and isinstance(item[0], str) and isinstance(item[1], str) and all(isinstance(i, int) for i in item[2:]):
                results.append(tuple(item))
            elif len(item) == 4:
                # 尝试修复数据类型（例如：LLM输出了 '0' 而不是 0）
                try:
                    win_id, rule, start, end = item[0], item[1], int(item[2]), int(item[3])
                    results.append((win_id, rule, start, end))
                except:
                    pass
    
    return results

# ==============================================================================
# 2. LLM 调用管理器 (保持原样)
# ==============================================================================


# ==============================================================================
# 3. 知识提取主逻辑 (Check-then-Extract 模式)
# ==============================================================================

class LLM_Manager:
    """LLM 调用管理器（假设基于 Ollama）"""
    
    def __init__(self, model_name: str, host: str):
        self.model_name = model_name
        self.host = host
        if ollama:
            try:
                self.client = ollama.Client(host=self.host)
                # 检查模型是否可用
                self.client.show(self.model_name)
                tqdm.write(f"Ollama client initialized with model: {self.model_name}")
            except Exception as e:
                tqdm.write(f"Error initializing Ollama client: {e}")
                self.client = None
        else:
            self.client = None

    def _call_ollama(self, system_prompt: str, user_prompt: str) -> str:
        """调用 Ollama API 进行推理"""
        if not self.client:
            return "Ollama client not available."
        
        # 强制 Llama 3 使用 JSON 格式 (针对 Step 2) 或纯文本
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
            tqdm.write(f"Ollama API call error: {e}")
            return f"Error: LLM call failed with {e}"

    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """主调用方法，可替换为其他 LLM 接口"""
        return self._call_ollama(system_prompt, user_prompt)


# ==============================================================================
# 3. 知识提取主逻辑 (单步批量模式)
# ==============================================================================

class KnowledgeExtractor:
    def __init__(self, model_name="llama3.1:8b", client_host="http://localhost:11434"):
        self.llm = LLM_Manager(model_name, client_host)
        # 导入更新后的 PromptManager
        from prompt import PromptManager_CoT_Multi_Turn 
        self.prompts = PromptManager_CoT_Multi_Turn()

    def _format_single_window_input(self, window_id: str, event_sequence: str, diff_vector: Dict[str, Any]) -> str:
        """使用 PromptManager 中的方法格式化单个 Log 的输入。"""
        return self.prompts.format_single_window_input(window_id, event_sequence, diff_vector)
        
    def get_knowledge_label_batch(self, batch_data: List[Dict[str, Any]]) -> Dict[str, Dict[str, List[Dict[str, Any]]]]:
        # --- 1. 组合 Log Context ---
        combined_input_context = ""
        log_id_map = {} # 映射 window_id 到最终输出的 log ID (real_log_id)
        
        for item in batch_data:
            window_id = item['window_id']
            real_log_id = item.get('real_log_id', window_id) 
            log_id_map[window_id] = real_log_id
            
            # 拼接 Prompt
            combined_input_context += self._format_single_window_input(
                window_id, 
                item.get('sequence_text', item.get('event_sequence', "")), 
                item.get('diff_vector', {})
            )

        # --- 2. Step 1: 批量 LLM 调用 (Logic & Physics) ---
        tqdm.write(f"\n--- Step 1: Calling LLM for Batch Analysis ({len(batch_data)} logs) ---")
        
        step1_logic_system = self.prompts.step1_logic_system
        logic_raw_output = self.llm._call_llm(step1_logic_system, combined_input_context)
        
        step1_physics_system = self.prompts.step1_physics_system
        physics_raw_output = self.llm._call_llm(step1_physics_system, combined_input_context)

        # --- 3. 解析 Step 1 结果 ---
        logic_results = _parse_step1_output(logic_raw_output)
        physics_results = _parse_step1_output(physics_raw_output)
        
        combined_anomalies = logic_results + physics_results
        
        if not combined_anomalies:
            tqdm.write("--- Step 2 Skipped: No anomalies found in batch. ---")
            return {real_id: {"violations": []} for real_id in log_id_map.values()}
            
        tqdm.write(f"Total anomalies found: {len(combined_anomalies)}")

        # --- 4 & 5. 直接从 Step 1 结果构建最终归属字典 (跳过 Step 2 LLM 的输出进行归属) ---
        
        # 初始化最终归属字典，键为 REAL LOG ID ('0', '1', '2'...)
        final_knowledge_base = {real_id: {"violations": []} for real_id in log_id_map.values()}
        
        # 构造 Step 2 LLM 的输入列表，并同时进行归属
        formatted_anomalies_for_step2_input = []
        for win_id, rule, start, end in combined_anomalies:
            
            # 1. 查找对应的 REAL LOG ID (例如 'win_0' -> '0')
            real_log_id = log_id_map.get(win_id)
            if real_log_id is None:
                tqdm.write(f"Warning: Step 1 LLM returned unknown window_id: {win_id}. Skipping attribution.")
                continue

            # 2. 构造 Step 1 归属的违规条目
            violation_entry = {
                "window_id": win_id,  # 原始 Window ID
                "rule": rule,
                "evidence_range": [start, end]
            }
            
            # 3. 将违规信息添加到对应的 REAL LOG ID 下 (直接归属)
            # 核心修复：在这里完成归属，确保 Step 1 检测到的所有数据都被保留
            final_knowledge_base[real_log_id]['violations'].append(violation_entry)
            
            # 4. 构造 Step 2 的输入（用于调用 Step 2 LLM，如果需要保留其 CoT 或格式化步骤）
            formatted_anomalies_for_step2_input.append(f"['{real_log_id}', '{rule}', {start}, {end}]")


        # --- 4.2 调用 Step 2 LLM (可选，如果仅用于格式化或 CoT) ---
        tqdm.write("\n--- Step 2: Calling Formatting LLM (Output used for logging, not primary attribution) ---")
        
        step2_input_list = "\n".join(formatted_anomalies_for_step2_input)
        step2_system_prompt = self.prompts.get_step2_formatting_prompt(step2_input_list)
        final_json_raw = self.llm._call_llm(step2_system_prompt, "Convert the input list to the mandatory JSON schema.")
        
        return final_knowledge_base
        

# ==============================================================================
# 3. 主执行逻辑 (知识归因和 JSON 结构适配)
# ==============================================================================

def generate_test_windows(test_logs: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Generates the 'windows' dict structure from a list of test logs."""
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
        
        # 💥 关键修复点：在格式化之前清洗数据，确保没有 set 对象
        diff_vector = clean_for_json(diff_vector) 
        
        # 格式化 Diff Context，使其在 window 中包含索引 0 的内容
        window_diffs_indexed = {"0": diff_vector}
        
        formatted_windows[window_id] = {
            "sequence_text": log_data["Event_sequence"],
            "diff_vector": window_diffs_indexed, 
            "member_log_ids": [real_log_id] 
        }
    return formatted_windows


# ==============================================================================
# 3. 主执行逻辑 (知识归因和 JSON 结构适配)
# ==============================================================================

# 💥 修正函数签名：不再接受 csv_path，而是接受 windows 字典
def run_batch_processing(windows: Dict[str, Dict[str, Any]], output_path: str):
    
    if not windows: 
        print("Error: Input windows data is empty.")
        return

    print(f"--- Log 1: Successfully created {len(windows)} sliding windows. ---")
        
    # 步骤 2: 传入 model_name 和 prompts 实例
    extractor = KnowledgeExtractor()
    
    knowledge_base = {} 
    win_items = list(windows.items())
    
    # BATCH_SIZE 应该在文件开头定义，这里假设它是一个全局常量
    print(f"Starting Batch Extraction with BATCH_SIZE={BATCH_SIZE}...")
    
    for i in tqdm(range(0, len(win_items), BATCH_SIZE), desc="Processing Batches"):
        batch = win_items[i : i+BATCH_SIZE]
        batch_input = []
        
        # NOTE: 移除了 real_to_window_map 的创建和填充，因为 Step 1 的结果已包含正确的 window_id
        for win_id, data in batch:
            real_log_id = data["member_log_ids"][0] 
            
            batch_input.append({
                "window_id": win_id,
                "real_log_id": real_log_id, 
                "sequence_text": data["sequence_text"],
                "diff_vector": data["diff_vector"]
            })
        
        # 2. LLM 推理
        batch_output = extractor.get_knowledge_label_batch(batch_input)
        
        # 3. 结果归因 (Attribution)
        current_batch_violations = sum(len(v.get("violations", [])) for v in batch_output.values())
        if current_batch_violations > 0:
            tqdm.write(f"--- Log 2: Batch found {current_batch_violations} total violation records.")

        # real_log_id 来自 batch_output 的键（例如 '0', '1'），它是归属到的 Log ID
        for real_log_id, kb_entry in batch_output.items():
            
            violations_list = kb_entry.get("violations", []) 
            
            if not violations_list:
                continue

            for v in violations_list: 
                
                if not isinstance(v, dict):
                    tqdm.write(f"Warning: Found non-dict element in violations list and skipped: {v}")
                    continue

                # 💥 关键修正：直接从 violation 字典中获取 Window ID
                detection_window = v.get("window_id") 
                if not detection_window: continue
                
                # 使用正确的 Window ID 查找原始窗口数据 (key 应该是 'win_X')
                original_data = windows.get(detection_window) 
                if not original_data: 
                    tqdm.write(f"Warning: Could not find original window data for ID: {detection_window}")
                    continue
                
                member_log_ids = original_data["member_log_ids"] 

                rule_id = v["rule"]
                evidence_range_value = v.get("evidence_range")
                evidence_range_list = [evidence_range_value] if isinstance(evidence_range_value, list) else []

                # --- 扁平化证据索引列表 ---
                involved_relative_indices = set()
                for start, end in evidence_range_list:
                    try:
                        start_idx = max(0, int(start))
                        end_idx = min(len(member_log_ids) - 1, int(end))
                    except ValueError:
                        tqdm.write(f"Warning: Invalid evidence range value found: {start}, {end}. Skipping.")
                        continue
                    
                    for idx in range(start_idx, end_idx + 1):
                        involved_relative_indices.add(idx)

                # 构造完整的违规信息对象
                violation_info = {
                    "rule_id": rule_id,
                    "detection_window": detection_window, 
                    "evidence": sorted(list(involved_relative_indices)) 
                }
                
                # --- 分配给每一个受影响的 Log ID ---
                for idx in involved_relative_indices:
                    # 获取当前要分配的 Log ID (例如 '0', '1', '2'...)
                    current_real_log_id = member_log_ids[idx]
                    
                    if current_real_log_id not in knowledge_base:
                        knowledge_base[current_real_log_id] = {"violations": []}
                    
                    is_duplicate = any(
                        item["rule_id"] == rule_id and item.get("detection_window") == detection_window
                        for item in knowledge_base[current_real_log_id]["violations"]
                    )
                            
                    if not is_duplicate:
                        knowledge_base[current_real_log_id]["violations"].append(violation_info)

    # 4. 保存最终的 Log-Level 知识库
    print(f"\n--- Log 3: Knowledge extraction complete. ---")
    
    # 打印非空 Log 的数量以供验证
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
    
    # !!! 替换为您想要测试的 Log 数据 !!!
    test_logs = [
        # Log 0: Example Log with R01 violation (stNum_ decrease)
        {
            "Event_sequence": "GOOSE_PKT (ts=1725084167.383, src=20:17:01:16:f0:11, APPID=0x3103, stNum=1, sqNum=36, GOOSElength_GOOSE3=165, gocbRef_GOOSE3=QUTZS_FDRPIOC/LLN0$GO$gcb_1, goID_GOOSE3=gcb_1, simulation_GOOSE3=False, confRev_GOOSE3=200, ndsCom_GOOSE3=False, num of data_GOOSE3=14, data_GOOSE3=[False, 0, True, 0, False, 0, False, 0, False, 0, False, 0, False, 0]); GOOSE_PKT (ts=1725084166.782, src=20:17:01:16:f0:32, APPID=0x3102, stNum=1, sqNum=36, GOOSElength_GOOSE2=146, gocbRef_GOOSE2=QUTZS_XFMR2PIOC/LLN0$GO$gcb_1, goID_GOOSE2=gcb_1, simulation_GOOSE2=False, confRev_GOOSE2=200, ndsCom_GOOSE2=False, num of data_GOOSE2=8, data_GOOSE2=[True, 0, False, 0, False, 0, True, 0]); GOOSE_PKT (ts=1725084187.028, src=20:17:01:16:f0:23, APPID=0x3101, stNum=2, sqNum=19, GOOSElength_GOOSE1=146, gocbRef_GOOSE1=QUTZS_XFMR1PIOC/LLN0$GO$gcb_1, goID_GOOSE1=gcb_1, simulation_GOOSE1=False, confRev_GOOSE1=200, ndsCom_GOOSE1=False, num of data_GOOSE1=8, data_GOOSE1=[True, 0, True, 0, True, 0, False, 0]); SV_PKT (ts=1725084200.798376, src=20:17:01:16:f2:54, APPID=0x4001, SVlength_sv1=509, noASDU_sv1=13, svID1_sv1=66kV1, smpCnt1_sv1=696, Data1_sv1=0, svID2_sv1=66kV2, smpCnt2_sv1=696, Data2_sv1=0, svID3_sv1=66kV3, smpCnt3_sv1=696, Data3_sv1=35, svID4_sv1=XFMR1W1, smpCnt4_sv1=696, Data4_sv1=0, svID5_sv1=XFMR2W1, smpCnt5_sv1=696, Data5_sv1=35, svID6_sv1=XFMR1W2, smpCnt6_sv1=696, Data6_sv1=0, svID7_sv1=XFMR2W2, smpCnt7_sv1=696, Data7_sv1=60, svID8_sv1=CB_XFMR1, smpCnt8_sv1=696, Data8_sv1=0, svID9_sv1=CB_XFMR2, smpCnt9_sv1=696, Data9_sv1=104, svID10_sv1=F_66kV1, smpCnt10_sv1=696, Data10_sv1=0, svID11_sv1=F_66kV2, smpCnt11_sv1=696, Data11_sv1=0, svID12_sv1=F_XFMR1, smpCnt12_sv1=696, Data12_sv1=0, svID13_sv1=F_XFMR2, smpCnt13_sv1=696, Data13_sv1=0); SV_PKT (ts=1725084200.819751, src=20:17:01:16:f2:54, APPID=0x4002, SVlength_sv2=491, noASDU_sv2=13, svID1_sv2=22kV1, smpCnt1_sv2=689, Data1_sv2=26, svID2_sv2=22kV2, smpCnt2_sv2=689, Data2_sv2=52, svID3_sv2=22kV3, smpCnt3_sv2=689, Data3_sv2=26, svID4_sv2=FDR1, smpCnt4_sv2=689, Data4_sv2=26, svID5_sv2=FDR2, smpCnt5_sv2=689, Data5_sv2=26, svID6_sv2=FDR3, smpCnt6_sv2=689, Data6_sv2=26, svID7_sv2=FDR4, smpCnt7_sv2=689, Data7_sv2=26, svID8_sv2=F_22kV1, smpCnt8_sv2=689, Data8_sv2=0, svID9_sv2=F_22kV2, smpCnt9_sv2=689, Data9_sv2=0, svID10_sv2=F_FDR1, smpCnt10_sv2=689, Data10_sv2=0, svID11_sv2=F_FDR2, smpCnt11_sv2=689, Data11_sv2=0, svID12_sv2=F_FDR3, smpCnt12_sv2=689, Data12_sv2=0, svID13_sv2=F_FDR4, smpCnt13_sv2=689, Data13_sv2=0)",
            "Diff_vector": {
                "{""pkt arrival time_sv1"": ""incrementing"", ""SVlength_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""noASDU_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt1_sv1"": ""incrementing"", ""Data1_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt2_sv1"": ""incrementing"", ""Data2_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt3_sv1"": ""incrementing"", ""Data3_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt4_sv1"": ""incrementing"", ""Data4_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt5_sv1"": ""incrementing"", ""Data5_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt6_sv1"": ""incrementing"", ""Data6_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt7_sv1"": ""incrementing"", ""Data7_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt8_sv1"": ""incrementing"", ""Data8_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt9_sv1"": ""incrementing"", ""Data9_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt10_sv1"": ""incrementing"", ""Data10_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt11_sv1"": ""incrementing"", ""Data11_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt12_sv1"": ""incrementing"", ""Data12_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt13_sv1"": ""incrementing"", ""Data13_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""pkt arrival time_sv2"": ""incrementing"", ""SVlength_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""noASDU_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt1_sv2"": ""incrementing"", ""Data1_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt2_sv2"": ""incrementing"", ""Data2_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt3_sv2"": ""incrementing"", ""Data3_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt4_sv2"": ""incrementing"", ""Data4_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt5_sv2"": ""incrementing"", ""Data5_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt6_sv2"": ""incrementing"", ""Data6_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt7_sv2"": ""incrementing"", ""Data7_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt8_sv2"": ""incrementing"", ""Data8_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt9_sv2"": ""incrementing"", ""Data9_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt10_sv2"": ""incrementing"", ""Data10_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt11_sv2"": ""incrementing"", ""Data11_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt12_sv2"": ""incrementing"", ""Data12_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt13_sv2"": ""incrementing"", ""Data13_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""GOOSElength_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""Timeallowedtolive_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""t_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""stNum_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""sqNum_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""confRev_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""num of data_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""GOOSElength_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""Timeallowedtolive_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""t_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""stNum_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""sqNum_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""confRev_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""num of data_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""GOOSElength_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""Timeallowedtolive_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""t_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""stNum_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""sqNum_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""confRev_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""num of data_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}}"
            }
        },
        # Log 1: Example Log with P01 violation (Replay Attack - both steady)
        {
            "Event_sequence": "GOOSE_PKT (ts=1725084167.383, src=20:17:01:16:f0:11, APPID=0x3103, stNum=1, sqNum=36, GOOSElength_GOOSE3=165, gocbRef_GOOSE3=QUTZS_FDRPIOC/LLN0$GO$gcb_1, goID_GOOSE3=gcb_1, simulation_GOOSE3=False, confRev_GOOSE3=200, ndsCom_GOOSE3=False, num of data_GOOSE3=14, data_GOOSE3=[False, 0, True, 0, False, 0, False, 0, False, 0, False, 0, False, 0]); GOOSE_PKT (ts=1725084166.782, src=20:17:01:16:f0:32, APPID=0x3102, stNum=1, sqNum=36, GOOSElength_GOOSE2=146, gocbRef_GOOSE2=QUTZS_XFMR2PIOC/LLN0$GO$gcb_1, goID_GOOSE2=gcb_1, simulation_GOOSE2=False, confRev_GOOSE2=200, ndsCom_GOOSE2=False, num of data_GOOSE2=8, data_GOOSE2=[True, 0, False, 0, False, 0, True, 0]); GOOSE_PKT (ts=1725084187.028, src=20:17:01:16:f0:23, APPID=0x3101, stNum=2, sqNum=19, GOOSElength_GOOSE1=146, gocbRef_GOOSE1=QUTZS_XFMR1PIOC/LLN0$GO$gcb_1, goID_GOOSE1=gcb_1, simulation_GOOSE1=False, confRev_GOOSE1=200, ndsCom_GOOSE1=False, num of data_GOOSE1=8, data_GOOSE1=[True, 0, True, 0, True, 0, False, 0]); SV_PKT (ts=1725084200.848808, src=20:17:01:16:f2:54, APPID=0x4001, SVlength_sv1=509, noASDU_sv1=13, svID1_sv1=66kV1, smpCnt1_sv1=697, Data1_sv1=0, svID2_sv1=66kV2, smpCnt2_sv1=697, Data2_sv1=0, svID3_sv1=66kV3, smpCnt3_sv1=697, Data3_sv1=35, svID4_sv1=XFMR1W1, smpCnt4_sv1=697, Data4_sv1=0, svID5_sv1=XFMR2W1, smpCnt5_sv1=697, Data5_sv1=35, svID6_sv1=XFMR1W2, smpCnt6_sv1=697, Data6_sv1=0, svID7_sv1=XFMR2W2, smpCnt7_sv1=697, Data7_sv1=60, svID8_sv1=CB_XFMR1, smpCnt8_sv1=697, Data8_sv1=0, svID9_sv1=CB_XFMR2, smpCnt9_sv1=697, Data9_sv1=104, svID10_sv1=F_66kV1, smpCnt10_sv1=697, Data10_sv1=0, svID11_sv1=F_66kV2, smpCnt11_sv1=697, Data11_sv1=0, svID12_sv1=F_XFMR1, smpCnt12_sv1=697, Data12_sv1=0, svID13_sv1=F_XFMR2, smpCnt13_sv1=697, Data13_sv1=0); SV_PKT (ts=1725084200.869778, src=20:17:01:16:f2:54, APPID=0x4002, SVlength_sv2=491, noASDU_sv2=13, svID1_sv2=22kV1, smpCnt1_sv2=690, Data1_sv2=26, svID2_sv2=22kV2, smpCnt2_sv2=690, Data2_sv2=52, svID3_sv2=22kV3, smpCnt3_sv2=690, Data3_sv2=26, svID4_sv2=FDR1, smpCnt4_sv2=690, Data4_sv2=26, svID5_sv2=FDR2, smpCnt5_sv2=690, Data5_sv2=26, svID6_sv2=FDR3, smpCnt6_sv2=690, Data6_sv2=26, svID7_sv2=FDR4, smpCnt7_sv2=690, Data7_sv2=26, svID8_sv2=F_22kV1, smpCnt8_sv2=690, Data8_sv2=0, svID9_sv2=F_22kV2, smpCnt9_sv2=690, Data9_sv2=0, svID10_sv2=F_FDR1, smpCnt10_sv2=690, Data10_sv2=0, svID11_sv2=F_FDR2, smpCnt11_sv2=690, Data11_sv2=0, svID12_sv2=F_FDR3, smpCnt12_sv2=690, Data12_sv2=0, svID13_sv2=F_FDR4, smpCnt13_sv2=690, Data13_sv2=0)",
            "Diff_vector": {
                "{""pkt arrival time_sv1"": ""incrementing"", ""SVlength_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""noASDU_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt1_sv1"": ""incrementing"", ""Data1_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt2_sv1"": ""incrementing"", ""Data2_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt3_sv1"": ""incrementing"", ""Data3_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt4_sv1"": ""incrementing"", ""Data4_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt5_sv1"": ""incrementing"", ""Data5_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt6_sv1"": ""incrementing"", ""Data6_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt7_sv1"": ""incrementing"", ""Data7_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt8_sv1"": ""incrementing"", ""Data8_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt9_sv1"": ""incrementing"", ""Data9_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt10_sv1"": ""incrementing"", ""Data10_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt11_sv1"": ""incrementing"", ""Data11_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt12_sv1"": ""incrementing"", ""Data12_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt13_sv1"": ""incrementing"", ""Data13_sv1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""pkt arrival time_sv2"": ""incrementing"", ""SVlength_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""noASDU_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt1_sv2"": ""incrementing"", ""Data1_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt2_sv2"": ""incrementing"", ""Data2_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt3_sv2"": ""incrementing"", ""Data3_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt4_sv2"": ""incrementing"", ""Data4_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt5_sv2"": ""incrementing"", ""Data5_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt6_sv2"": ""incrementing"", ""Data6_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt7_sv2"": ""incrementing"", ""Data7_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt8_sv2"": ""incrementing"", ""Data8_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt9_sv2"": ""incrementing"", ""Data9_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt10_sv2"": ""incrementing"", ""Data10_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt11_sv2"": ""incrementing"", ""Data11_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt12_sv2"": ""incrementing"", ""Data12_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""smpCnt13_sv2"": ""incrementing"", ""Data13_sv2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""GOOSElength_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""Timeallowedtolive_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""t_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""stNum_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""sqNum_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""confRev_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""num of data_GOOSE1"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""GOOSElength_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""Timeallowedtolive_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""t_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""stNum_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""sqNum_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""confRev_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""num of data_GOOSE2"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""GOOSElength_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""Timeallowedtolive_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""t_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""stNum_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""sqNum_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""confRev_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}, ""num of data_GOOSE3"": {""delta"": [0.0, 0.0, 0.0], ""sem"": ""steady""}}"
            }
        },
        # Log 2: Example Log with S1 violation (Trip=True, but SV stable)
        # S1: GOOSE shows Trip (True) AND SV delta indicates stable/unchanged measurement
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