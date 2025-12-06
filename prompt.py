import ast
import re
from typing import Dict, Any, List, Optional
import json

class PromptManager_CoT_Multi_Turn:
    """
    管理用于 GOOSE/SV 日志分析的Prompt。
    
    设计理念：
    - 基于 delta 趋势推理规则，而非硬编码 semantic labels。
    - emb 字段为 delta 的高级语义总结，可辅助推理，但不可直接匹配。
    - 支持多窗口批量推理，每个 window 独立分析。
    """

    # ----------------------------------------------------------------------
    # STEP 1: LOGIC ANALYSIS (协议规则，基于 delta 推理)
    # ----------------------------------------------------------------------
    @property
    def step1_logic_system(self):
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

    # ----------------------------------------------------------------------
    # STEP 1: PHYSICS ANALYSIS (物理一致性规则，基于 delta 推理)
    # ----------------------------------------------------------------------
    @property
    def step1_physics_system(self):
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

    # ----------------------------------------------------------------------
    # STEP 2: FORMATTING (JSON 输出)
    # ----------------------------------------------------------------------
    def get_step2_formatting_prompt(self, input_list):
        """
        生成用于 JSON 格式化的 System Prompt。
        """
        return f"""
[JSON_SYNTHESIS_MODE]
You are a dedicated JSON Formatting Engine. Your ONLY task is to convert the following raw anomaly list into the final required JSON structure.

### INPUT
A plain text list of detected anomalies:
{input_list}

### OUTPUT FORMAT (CRITICAL)

**ABSOLUTE_RULE: ONLY PRINT THE FINAL JSON OBJECT.**

**DO NOT** generate any preamble, explanation, or commentary.
**KEYS_ARE_FINAL: The keys MUST be "window_id", "rule", and "evidence_range". DO NOT substitute them.**

### MANDATORY_SCHEMA_EXAMPLE (STRICTLY FOLLOW THIS STRUCTURE):
Input List: 
['win_1', 'R01', 0, 0]
['win_2', 'R03', 0, 0]

Output JSON (Keys and order MUST be exact, matching the example below): 
{{
  "violations": [
    {{"window_id": "win_1", "rule": "R01", "evidence_range": [0, 0]}}, 
    {{"window_id": "win_2", "rule": "R03", "evidence_range": [0, 0]}}
  ]
}}

If the input list is empty or contains 'NONE', return: {{"violations": []}}
"""

    # ----------------------------------------------------------------------
    # 辅助函数：格式化单窗口输入
    # ----------------------------------------------------------------------
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

    # ----------------------------------------------------------------------
    # 根据规则生成 Extract 阶段 Prompt
    # ----------------------------------------------------------------------
    def get_extract_prompt(self, rule_code: str, input_context: str) -> str:
        """根据规则和输入内容，生成 Extract 阶段的完整 Prompt。"""
        rule = self.RULES[rule_code]
        return f"""
[EXTRACT_MODE]
{rule['extract_sys']}

User Instruction: 
For window ID '{self._get_window_id(input_context)}', output the evidence list for Rule {rule_code}. Remember the index range MUST be [0, 0].
{rule['extract_user'].replace('[LOG DATA HERE]', input_context)}
"""

    # ----------------------------------------------------------------------
    # 从格式化输入中提取 window ID
    # ----------------------------------------------------------------------
    def _get_window_id(self, input_context: str) -> str:
        match = re.search(r'--- WINDOW ID: (\w+) ---', input_context)
        return match.group(1) if match else "UNKNOWN_WIN"
