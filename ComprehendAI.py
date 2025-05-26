import traceback
import idaapi
import idc
import idautils
import ida_xref
import json
import os

from idaapi import action_handler_t, UI_Hooks
from threading import Lock, Thread, Event
from openai import OpenAI # Ensure openai version is compatible, e.g., pip install --upgrade openai
from enum import Enum

# 尝试导入 Hex-Rays 相关模块
try:
    import ida_hexrays
    HEXRAYS_AVAILABLE = True
except ImportError:
    print("ComprehendAI: Hex-Rays SDK not found. Function call analysis will be limited to assembly and basic XRefs.")
    HEXRAYS_AVAILABLE = False

# --- Enums ---
class TaskType(Enum):
    ANALYSIS = 1
    CUSTOM_QUERY = 2
    CUSTOM_QUERY_WITH_CODE = 3

class QueryStatus(Enum):
    SUCCESS = 1
    FAILED = 2
    STOPPED = 3

# --- 配置管理 ---
class ConfigManager:
    _instance = None
    _lock = Lock()

    def __new__(cls):
        with cls._lock:
            if not cls._instance:
                cls._instance = super().__new__(cls)
                cls._instance._initialize()
            return cls._instance

    def _initialize(self):
        self.script_dir = os.path.dirname(os.path.abspath(__file__))
        self.config_path = os.path.join(self.script_dir, 'config.json')
        self.config = self._load_config()
        self.openai_client = self._create_openai_client()

    def _load_config(self):
        default_config = {
            "openai": {
                "api_key": "YOUR_API_KEY_HERE",
                "base_url": "YOUR_BASE_URL_HERE",
                "model": "gpt-3.5-turbo",
                "max_code_length": 30000,
                "stop_recursion_on_truncate": True
            }
        }
        try:
            with open(self.config_path, "r", encoding='utf-8') as f:
                loaded_config = json.load(f)
                if "openai" not in loaded_config:
                    loaded_config["openai"] = default_config["openai"]
                else:
                    for key, value in default_config["openai"].items():
                        loaded_config["openai"].setdefault(key, value)
                return loaded_config
        except FileNotFoundError:
            idaapi.warning(f"ComprehendAI: Config file not found at {self.config_path}. Using default. AI features may not work.")
            return default_config
        except json.JSONDecodeError:
            idaapi.warning(f"ComprehendAI: Error decoding config file {self.config_path}. Using default. Check its format.")
            return default_config
        except Exception as e:
            idaapi.warning(f"ComprehendAI: Failed to load config: {str(e)}. Using default.")
            return default_config

    def _create_openai_client(self):
        try:
            cfg_openai = self.config.get("openai", {})
            api_key = cfg_openai.get("api_key")
            base_url = cfg_openai.get("base_url")

            if not api_key or api_key == "YOUR_API_KEY_HERE":
                print("ComprehendAI: OpenAI API key is missing or placeholder. Please configure it in config.json.")
                return None

            if base_url == "YOUR_BASE_URL_HERE" or not base_url:
                base_url = None

            return OpenAI(
                api_key=api_key,
                base_url=base_url
            )
        except KeyError as e:
            print(f"ComprehendAI: Missing OpenAI configuration key in config.json: {e}. AI features will be impacted.")
            return None
        except Exception as e:
            print(f"ComprehendAI: Error creating OpenAI client: {e}")
            traceback.print_exc()
            return None

    @property
    def model_name(self):
        return self.config.get("openai", {}).get("model", "gpt-3.5-turbo")

    @property
    def max_code_length(self):
        return self.config.get("openai", {}).get("max_code_length", 30000)

    @property
    def stop_recursion_on_truncate(self):
        return self.config.get("openai", {}).get("stop_recursion_on_truncate", True)

    @property
    def client(self):
        return self.openai_client

# --- 反汇编/反编译代码提取 ---
class DisassemblyProcessor:
    def __init__(self, max_depth=15):
        self.max_depth = max_depth
        self._lock = Lock()
        self._reset_state()
        self.config_manager = ConfigManager()

    def _reset_state(self):
        with self._lock:
            self.processed_funcs = set()
            self.func_disasm_list = []
            self.code_limit_reached = False
            self.actual_code_sent_length = 0

    def get_current_function_disasm(self):
        self._reset_state()
        current_ea = idc.get_screen_ea()
        func_start = idc.get_func_attr(current_ea, idc.FUNCATTR_START)

        if func_start == idaapi.BADADDR:
            raise ValueError("光标必须位于函数内部才能分析。")

        print(f"ComprehendAI: Starting analysis from {idc.get_func_name(func_start)} ({hex(func_start)}), max depth: {self.max_depth}")
        self._process_function(func_start, self.max_depth, [])

        result_code = "\n".join(self.func_disasm_list)
        return result_code

    def _get_global_data_references_for_function(self, func_ea, cfunc=None):
        globals_info = []
        processed_addrs = set()
        func_name_for_debug = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"

        if HEXRAYS_AVAILABLE and cfunc:
            class GlobalDataVisitor(ida_hexrays.ctree_visitor_t):
                def __init__(self, found_globals_list, processed_addrs_set):
                    super().__init__(ida_hexrays.CV_FAST)
                    self.found_globals_list = found_globals_list
                    self.processed_addrs_set = processed_addrs_set

                def visit_expr(self, e):
                    if e.op == ida_hexrays.cot_obj:
                        if e.x is None:
                            # print(f"ComprehendAI_DEBUG: GlobalDataVisitor: cot_obj at {hex(e.ea)} has e.x as None. Skipping.")
                            return 0 
                        addr = e.x.obj_ea
                        if addr != idaapi.BADADDR and addr not in self.processed_addrs_set:
                            seg = idaapi.getseg(addr)
                            if seg and (idaapi.segtype(addr) == idaapi.SEG_DATA or idaapi.segtype(addr) == idaapi.SEG_BSS or seg.perm & idaapi.SEGPERM_READ):
                                self.processed_addrs_set.add(addr)
                                name = idc.get_name(addr, idaapi.GN_VISIBLE) or f"data_{addr:08X}"
                                str_content_bytes = idc.get_strlit_contents(addr, -1, idc.STRTYPE_C)
                                if str_content_bytes is not None:
                                    try: str_value = str_content_bytes.decode('utf-8')
                                    except UnicodeDecodeError:
                                        try: str_value = str_content_bytes.decode('latin-1') + " (decoded as latin-1)"
                                        except UnicodeDecodeError: str_value = f"(binary string, hex: {str_content_bytes[:min(len(str_content_bytes), 16)].hex()}...)"
                                    display_str_value = str_value[:100] + "..." if len(str_value) > 100 else str_value
                                    self.found_globals_list.append(f"  {name} (0x{addr:08X}): \"{display_str_value}\"")
                                else:
                                    item_size = idc.get_item_size(addr)
                                    bytes_val = idc.get_bytes(addr, min(item_size, 8))
                                    if bytes_val: self.found_globals_list.append(f"  {name} (0x{addr:08X}): (data, size {item_size}, hex: {bytes_val.hex()})")
                    return 0

            visitor = GlobalDataVisitor(globals_info, processed_addrs)
            try:
                visitor.apply_to(cfunc.body, None)
            except Exception as e_visitor:
                print(f"ComprehendAI_DEBUG: Error during GlobalDataVisitor apply_to for {func_name_for_debug} ({hex(func_ea)}): {e_visitor}")
            
            print(f"ComprehendAI_DEBUG: For function {func_name_for_debug} ({hex(func_ea)}), found {len(globals_info)} global data references via ctree.")
        else:
            if not HEXRAYS_AVAILABLE: print(f"ComprehendAI_DEBUG: Hex-Rays not available, skipping ctree-based global data for {func_name_for_debug} ({hex(func_ea)}).")
            if not cfunc: print(f"ComprehendAI_DEBUG: cfunc is None for {func_name_for_debug} ({hex(func_ea)}), skipping ctree-based global data.")
        return globals_info

    def _process_function(self, func_ea, depth, call_stack_names):
        func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
        current_func_name_for_stack = func_name
        new_call_stack_names = call_stack_names + [current_func_name_for_stack]

        if func_ea in self.processed_funcs or depth < 0: return
        with self._lock:
            if func_ea in self.processed_funcs: return
            self.processed_funcs.add(func_ea)

        code_to_append = ""
        cfunc_for_code = None
        globals_data_str = ""

        try:
            if HEXRAYS_AVAILABLE:
                try:
                    cfunc_for_code = idaapi.decompile(func_ea)
                    if cfunc_for_code:
                        print(f"ComprehendAI_DEBUG: Decompilation successful for {func_name} ({hex(func_ea)}). Attempting to get globals.")
                        code_to_append = str(cfunc_for_code)
                        globals_list = self._get_global_data_references_for_function(func_ea, cfunc_for_code)
                        if globals_list:
                            globals_data_str = "// Relevant Global Data:\n" + "\n".join(globals_list) + "\n"
                    else:
                        print(f"ComprehendAI_DEBUG: Decompilation returned None for {func_name} ({hex(func_ea)}). Global data via ctree will be skipped. Falling back to disassembly.")
                        code_to_append = self._get_disassembly_text(func_ea)
                except ida_hexrays.DecompilationFailure as hx_fail:
                    print(f"ComprehendAI_DEBUG: DecompilationFailure for {func_name} ({hex(func_ea)}): {hx_fail}. Global data via ctree skipped. Falling back to disassembly.")
                    code_to_append = self._get_disassembly_text(func_ea)
            else:
                code_to_append = self._get_disassembly_text(func_ea)

            if code_to_append.strip() or globals_data_str.strip():
                with self._lock:
                    call_path_str = " -> ".join(new_call_stack_names)
                    current_block_header = f"// Function: {func_name} ({hex(func_ea)})\n// Call Path: {call_path_str}\n"
                    block_content = globals_data_str + code_to_append
                    full_block_to_add = current_block_header
                    if self.code_limit_reached:
                        full_block_to_add += "// --- SKIPPED (already past code length limit) ---\n"
                    else:
                        prospective_len_contribution = len(current_block_header) + len(block_content)
                        if self.actual_code_sent_length + prospective_len_contribution > self.config_manager.max_code_length:
                            self.code_limit_reached = True
                            full_block_to_add += "// --- CODE (and associated data) TRUNCATED HERE DUE TO TOTAL LENGTH LIMIT ---\n"
                        else:
                            full_block_to_add += block_content
                    
                    if full_block_to_add.strip() != f"// Function: {func_name} ({hex(func_ea)})" or "---" in full_block_to_add:
                         self.func_disasm_list.append(full_block_to_add + "\n")
                         if not ("SKIPPED" in full_block_to_add or ("TRUNCATED HERE" in full_block_to_add and not block_content.strip())):
                            self.actual_code_sent_length += len(full_block_to_add) +1
        except Exception as e:
            print(f"ComprehendAI: Error during main processing of function {func_name} ({hex(func_ea)}): {str(e)}")
            traceback.print_exc()
            try:
                assembly_fallback = self._get_disassembly_text(func_ea)
                if assembly_fallback:
                    call_path_str = " -> ".join(new_call_stack_names)
                    fallback_block_header = f"// Function (Disassembly fallback): {func_name} ({hex(func_ea)})\n// Call Path: {call_path_str}\n"
                    full_fallback_block = fallback_block_header
                    with self._lock:
                        if self.code_limit_reached: full_fallback_block += "// --- SKIPPED (already past code length limit) ---\n"
                        else:
                            prospective_len_contribution = len(fallback_block_header) + len(assembly_fallback) +1
                            if self.actual_code_sent_length + prospective_len_contribution > self.config_manager.max_code_length:
                                self.code_limit_reached = True
                                full_fallback_block += "// --- CODE TRUNCATED HERE DUE TO TOTAL LENGTH LIMIT ---\n"
                            else: full_fallback_block += assembly_fallback
                        self.func_disasm_list.append(full_fallback_block + "\n")
                        if not ("SKIPPED" in full_fallback_block or "TRUNCATED HERE" in full_fallback_block):
                           self.actual_code_sent_length += len(full_fallback_block) +1
            except Exception as inner_e:
                print(f"ComprehendAI: Failed to get disassembly for {func_name} ({hex(func_ea)}) during fallback: {str(inner_e)}")

        callees = set()
        if not (self.code_limit_reached and self.config_manager.stop_recursion_on_truncate):
            if HEXRAYS_AVAILABLE:
                cfunc_for_callees = cfunc_for_code if cfunc_for_code else idaapi.decompile(func_ea)
                if cfunc_for_callees: callees = self._get_callees_from_pseudocode(func_ea, cfunc_for_callees)
                else: callees = self._get_callees_from_xrefs(func_ea)
            else: callees = self._get_callees_from_xrefs(func_ea)
        for callee_ea in callees: self._process_function(callee_ea, depth - 1, new_call_stack_names)

    def _get_disassembly_text(self, func_ea):
        disasm_lines = []
        func_end_ea = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
        if func_end_ea == idaapi.BADADDR: return ""
        head_ea = func_ea
        while head_ea != idaapi.BADADDR and head_ea < func_end_ea:
            disasm_lines.append(idc.generate_disasm_line(head_ea, 0))
            next_ea = idc.next_head(head_ea, func_end_ea)
            if next_ea <= head_ea : break
            head_ea = next_ea
        return "\n".join(disasm_lines)

    def _get_callees_from_xrefs(self, func_ea):
        callees = set()
        func_end = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
        if func_end == idaapi.BADADDR: return callees
        for head in idautils.Heads(func_ea, func_end):
            for xref in idautils.XrefsFrom(head, ida_xref.XREF_CODE):
                if xref.type in [ida_xref.fl_CN, ida_xref.fl_CF]:
                    callee_ea_candidate = xref.to
                    if idc.get_func_attr(callee_ea_candidate, idc.FUNCATTR_START) == callee_ea_candidate:
                        callees.add(callee_ea_candidate)
        return callees

    def _get_callees_from_pseudocode(self, func_ea, cfunc):
        callees = set()
        if not cfunc: return self._get_callees_from_xrefs(func_ea)
        class CallVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self, found_callees_set):
                super().__init__(ida_hexrays.CV_FAST)
                self.found_callees_set = found_callees_set
            def visit_expr(self, e):
                if e.op == ida_hexrays.cot_call:
                    if e.x is not None and e.x.op == ida_hexrays.cot_obj:
                        callee_ea_candidate = e.x.obj_ea
                        if idc.get_func_attr(callee_ea_candidate, idc.FUNCATTR_START) == callee_ea_candidate:
                            self.found_callees_set.add(callee_ea_candidate)
                return 0
        visitor = CallVisitor(callees)
        try: visitor.apply_to(cfunc.body, None)
        except Exception as e_call_visitor:
            print(f"ComprehendAI_DEBUG: Error during CallVisitor apply_to for {hex(func_ea)}: {e_call_visitor}")
        for xref_callee in self._get_callees_from_xrefs(func_ea): callees.add(xref_callee)
        return callees

# --- OpenAI 服务 ---
class AIService:
    def __init__(self):
        self.config_manager = ConfigManager()
        self.stop_event = Event()

    def ask_ai(self, prompt_content, ai_isRunning_lock: Lock):
        if not self.config_manager.client:
            print("ComprehendAI: ❌ OpenAI client not initialized. Please check your config.json.")
            if ai_isRunning_lock.locked(): ai_isRunning_lock.release()
            return
        messages = [{"role": "user", "content": prompt_content}]
        print("ComprehendAI: 正在向AI发送请求并等待回复...")
        self.stop_event.clear(); final_status = QueryStatus.FAILED
        try: final_status = self._request_openai(messages)
        except Exception as e: print(f"ComprehendAI: ❌ An unexpected error in _request_openai: {e}"); traceback.print_exc(); final_status = QueryStatus.FAILED
        finally:
            if ai_isRunning_lock.locked(): ai_isRunning_lock.release()
            if final_status == QueryStatus.SUCCESS: print("\nComprehendAI: ✅ 分析完成！")
            elif final_status == QueryStatus.FAILED: print("\nComprehendAI: ❌ 分析失败，请检查IDA输出或错误日志。")
            elif final_status == QueryStatus.STOPPED: print("\nComprehendAI: ✅ 分析已由用户停止。")

    def _request_openai(self, messages):
        full_response_content = ""
        try:
            if not self.config_manager.client or not self.config_manager.model_name: return QueryStatus.FAILED
            print("\n" + "=" * 20 + " AI 回复 " + "=" * 20 + "\n")
            completion = self.config_manager.client.chat.completions.create(model=self.config_manager.model_name, messages=messages, stream=True)
            for chunk in completion:
                if self.stop_event.is_set(): print("\nComprehendAI: detected stop event."); return QueryStatus.STOPPED
                if chunk.choices and chunk.choices[0].delta and chunk.choices[0].delta.content:
                    content_piece = chunk.choices[0].delta.content
                    print(content_piece, end='', flush=True); full_response_content += content_piece
            if not full_response_content.strip() and not self.stop_event.is_set(): print("ComprehendAI: AI返回了空内容。")
            return QueryStatus.SUCCESS
        except OpenAI.APIConnectionError as e: print(f"\nComprehendAI: OpenAI API 连接错误: {e}"); return QueryStatus.FAILED # type: ignore
        except OpenAI.RateLimitError as e: print(f"\nComprehendAI: OpenAI API 速率限制错误: {e}"); return QueryStatus.FAILED # type: ignore
        except OpenAI.APIStatusError as e: print(f"\nComprehendAI: OpenAI API 状态错误 (HTTP {e.status_code}): {e.response}"); return QueryStatus.FAILED # type: ignore
        except Exception as e: print(f"\nComprehendAI: 请求OpenAI时发生错误: {e}"); traceback.print_exc(); return QueryStatus.FAILED

# --- 用户接口处理 ---
class AnalysisHandler:
    def __init__(self):
        self.disassembler = DisassemblyProcessor()
        self.ai_service = AIService()
        self.ai_isRunning_lock = Lock()
        self.prompt_template = """
你是一名顶尖的人工智能逆向工程专家，具备对复杂代码结构进行深度分析和精准概括的能力。
我会提供你一个或多个C伪代码函数片段。第一个函数是【主分析目标】，其余是其调用链上的【自定义子函数】。
每个函数代码块上方可能会有 `// Call Path: ...` 和 `// Relevant Global Data: ...` 注释。你【必须】严格利用这些元信息进行分析。
{MAX_DEPTH_INFO}
{TRUNCATION_INFO}

请严格按照以下结构和要求，生成一份【高度浓缩】、【避免重复】、【逻辑清晰】的Markdown格式分析报告：

**1. 主分析目标函数核心概述 (针对第一个函数代码块):**
   * **核心目的与策略**：一句话总结该主函数最核心的功能以及它为达到此目的所采用的主要策略。
   * **关键执行路径摘要**：
      * 简述其关键的初始化步骤。
      * 描述其主要的API调用序列或对【关键自定义子函数】的调用序列。
      * **【格式要求】**：当描述中涉及的参数来源于 `// Relevant Global Data:` 中列出的全局变量时，**必须使用 `变量符号名 (其实际值)` 的格式进行表述。例如：如果数据显示 `ServiceName` 的值是 `"mssecsvc2.0"`，则描述应为 `CreateServiceA` 调用中服务名为 `ServiceName ("mssecsvc2.0")`。对于其他全局变量如 `FileName`、`DisplayName` 等同理。**
      * 若存在对程序流程有重大影响的逻辑分支，请简要说明其判断条件和主要走向。

**2. 整体程序行为推测 (综合所有提供的代码和元信息):**
   * **主要功能/恶意行为**：综合所有代码和元信息，总结此模块实现的主要功能。**【格式要求】**：对所有涉及的文件、服务、进程、注册表等操作中使用的全局变量，**必须采用 `变量符号名 (实际值)` 的格式进行描述。**
   * **防御规避（若有）**：简述1-2个最明显的手段。
   * **潜在网络交互（若有）**：根据代码迹象推测。

**3. 关键自定义子函数剖析 (按调用链顺序或重要性组织):**
   * 对于【每一个】由脚本提供的、且在主流程中被调用的【自定义子函数】（例如 `sub_XXXXX`，非Windows API），请按以下格式进行分析：
      * **函数名与调用路径**：`sub_XXXXX` (根据代码块中提供的 `// Call Path:` 注释填写，**力求展示从主分析目标到当前子函数的完整调用链，例如：`主分析目标函数名()->sub_ intermediary()->sub_XXXXX()`**)。
      * **核心贡献**：一句话描述该子函数为【其直接调用者】或【主分析目标】贡献了什么核心功能。
      * **关键实现**：简述其内部1-2个最核心的API调用或操作。**【格式要求】**：若引用了全局数据，**必须采用 `变量符号名 (实际值)` 的格式。**
   * **注意**：不重要的或信息不足的子函数可简述或注明无法分析，但不能遗漏。
   
**4. 关键全局变量列表及核心API价值总结 (此部分用于总结，前面分析中已按格式要求使用具体值):**
   * **关键全局变量列表**：以列表形式，总结对理解程序核心行为【最重要】的全局变量。格式：`- 变量符号名 (0x地址): "实际值" - 简述其在此代码片段中的核心作用。`
   * **核心Windows API**：列出在整个代码片段中扮演【决定性角色】的1-3个Windows API，并一句话点明它们在此处的战略价值。

**5. 综合风险评估与最终目的推测:**
   * **主要风险点**：列出1-2个主要安全风险。
   * **最终目的**：一句话总结模块最可能的设计目的。

**输出要求（再次强调）：**
* **精确性**：对API参数（如`dwStartType`）、常量值的解读必须准确。
* **【全局变量格式强制】**：报告中任何地方在叙述性文字中提及通过 `// Relevant Global Data:` 提取到的全局变量时，**必须使用 `变量符号名 (其实际值)` 的格式**。例如，不能只写 `ServiceName`，也不能只写 `"mssecsvc2.0"`，而必须是 `ServiceName ("mssecsvc2.0")`。在“关键全局变量列表”部分，使用指定的列表项格式。
* **高度浓缩，避免冗余**。
* **强调调用链和上下文关联**。
* **结构化输出**：严格按照提供的Markdown标题和结构。

下面是你要分析的代码：
"""
    def set_analysis_depth(self, depth_val):
        if isinstance(depth_val, int) and depth_val >= 0:
            self.disassembler.max_depth = depth_val
            print(f"ComprehendAI: 分析深度已设置为: {depth_val}")
        else: idaapi.warning("ComprehendAI: 错误: 深度必须是非负整数。")

    def _create_analysis_prompt(self, disassembly_code):
        depth_info = f"注意：以下代码包含了主函数以及它递归调用的子函数，最大调用深度为 {self.disassembler.max_depth} 层。"
        trunc_info = ""
        if self.disassembler.code_limit_reached:
            trunc_info = f"重要提示：由于总代码长度超过预设 {self.disassembler.config_manager.max_code_length} 字符限制，部分函数代码可能被截断或仅显示名称。分析可能不完整。"
        return self.prompt_template.replace("{MAX_DEPTH_INFO}", depth_info).replace("{TRUNCATION_INFO}", trunc_info) + disassembly_code

    def _create_custom_query_with_code_prompt(self, disassembly_code, question_text):
        depth_info = f"代码上下文（主函数及其子函数，最大深度 {self.disassembler.max_depth} 层）："
        trunc_info = ""
        if self.disassembler.code_limit_reached:
            trunc_info = f"（代码可能因超长被截断，最大长度约 {self.disassembler.config_manager.max_code_length} 字符）"
        return f"我的问题是：{question_text}\n\n请基于知识及以下代码回答。\n{depth_info} {trunc_info}\n{disassembly_code}"

    def create_ai_task(self, task_type: TaskType, question_text=""):
        prompt_to_send = ""
        if task_type in [TaskType.ANALYSIS, TaskType.CUSTOM_QUERY_WITH_CODE]:
            try:
                if idc.get_func_attr(idc.get_screen_ea(), idc.FUNCATTR_START) == idaapi.BADADDR:
                     idaapi.warning("ComprehendAI: 请将光标置于函数内部。"); return
                disassembly_code = self.disassembler.get_current_function_disasm()
                if not disassembly_code.strip(): idaapi.warning("ComprehendAI: ❌ 未能获取代码。"); return
                if task_type == TaskType.ANALYSIS: prompt_to_send = self._create_analysis_prompt(disassembly_code)
                else: prompt_to_send = self._create_custom_query_with_code_prompt(disassembly_code, question_text)
            except ValueError as e: idaapi.warning(f"ComprehendAI: ❌ 错误: {e}"); return
            except Exception as e: idaapi.warning(f"ComprehendAI: ❌ 准备分析时未知错误: {e}"); traceback.print_exc(); return
        elif task_type == TaskType.CUSTOM_QUERY:
            if not question_text.strip(): idaapi.warning("ComprehendAI: 问题不能为空。"); return
            prompt_to_send = question_text
        else: idaapi.warning(f"ComprehendAI: 未知任务类型: {task_type}"); return

        if len(prompt_to_send) > 3000: print(f"ComprehendAI: Prompt较长(约{len(prompt_to_send)}字符)，仅显示开头。")
        elif not prompt_to_send.strip(): print("ComprehendAI: Prompt为空，未发送。"); return

        if self.ai_isRunning_lock.acquire(blocking=False):
            try:
                task = Thread(target=self.ai_service.ask_ai, args=(prompt_to_send, self.ai_isRunning_lock,)); task.daemon = True; task.start()
            except Exception as e_thread: print(f"ComprehendAI: ❌ 启动线程失败: {e_thread}"); traceback.print_exc();
            finally: # Ensure lock is released if thread start fails immediately
                if task is None or not task.is_alive(): # Check if thread actually started
                    if self.ai_isRunning_lock.locked(): self.ai_isRunning_lock.release()
        else: idaapi.warning("ComprehendAI: ❌ AI正在处理任务,请稍后。")

    def stop_ai_task(self):
        if self.ai_isRunning_lock.locked(): print("ComprehendAI: 尝试停止AI任务..."); self.ai_service.stop_event.set()
        else: print("ComprehendAI: 无正在运行的AI任务。")

# --- IDA 插件框架 ---
class ComprehendAIPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "ComprehendAI: AI-based Reverse Analysis"
    help = "Uses OpenAI to assist in reverse engineering tasks."
    wanted_name = "ComprehendAI"
    ACTION_PREFIX = "ComprehendAI:"
    ACTION_DEFS = [
        ("Analysis", "分析函数及调用树", "Ctrl+Shift+A", "AI分析当前函数及其调用"),
        ("CustomQueryWithCode", "结合代码提问AI", "Ctrl+Shift+X", "结合当前代码向AI提问"),
        ("CustomQuery", "直接提问AI", "Ctrl+Shift+Q", "自定义问题发送给AI"),
        ("SetDepth", "设置分析深度", "", "设置函数调用树递归深度"),
        ("SetPrompt", "设置分析模板", "", "自定义主分析Prompt模板"),
        ("Stop", "停止AI分析", "Ctrl+Shift+S", "停止当前AI分析任务"),
    ]

    def init(self):
        self.handler = AnalysisHandler()
        self._register_actions()
        self.menu_hook = self.MenuHooker(self.ACTION_PREFIX, [ad[0] for ad in self.ACTION_DEFS])
        self.menu_hook.hook()
        print("ComprehendAI: 插件已初始化。分析热键: Ctrl+Shift+A。停止热键: Ctrl+Shift+S。")
        print("ComprehendAI: 请在 config.json 中配置 OpenAI API Key, Base URL (可选) 和 Model。")
        return idaapi.PLUGIN_KEEP

    def run(self, arg): idaapi.warning("ComprehendAI: 请使用右键菜单或热键。")
    def term(self):
        if hasattr(self, 'menu_hook') and self.menu_hook: self.menu_hook.unhook()
        self._unregister_actions()
        if hasattr(self, 'handler'): self.handler.stop_ai_task()
        print("ComprehendAI: 插件已卸载。")

    def _register_actions(self):
        for name_suffix, label, hotkey, tooltip in self.ACTION_DEFS:
            action_id = self.ACTION_PREFIX + name_suffix
            action_desc = idaapi.action_desc_t(action_id, label, self.MenuActionHandler(name_suffix, self.handler, TaskType), hotkey or None, tooltip, 0)
            if not idaapi.register_action(action_desc): print(f"ComprehendAI: 注册操作失败: {action_id}")

    def _unregister_actions(self):
        for name_suffix, *rest in self.ACTION_DEFS: idaapi.unregister_action(self.ACTION_PREFIX + name_suffix)

    class MenuHooker(UI_Hooks):
        def __init__(self, prefix, suffixes): super().__init__(); self.prefix = prefix; self.suffixes = suffixes
        def finish_populating_widget_popup(self, widget, popup):
            if idaapi.get_widget_type(widget) in (idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE):
                for suffix in self.suffixes: idaapi.attach_action_to_popup(widget, popup, self.prefix + suffix, "ComprehendAI/")

    class MenuActionHandler(action_handler_t):
        def __init__(self, suffix, handler, task_type_class): super().__init__(); self.suffix = suffix; self.handler = handler; self.TaskType = task_type_class
        def activate(self, ctx):
            action = self.suffix
            if action == "Analysis": self.handler.create_ai_task(self.TaskType.ANALYSIS)
            elif action in ["CustomQuery", "CustomQueryWithCode"]:
                prompt_title = "ComprehendAI: 输入您的问题 ("
                prompt_title += "将结合当前函数代码, " if action == "CustomQueryWithCode" else "不附带代码, "
                prompt_title += "支持多行)"
                result_val = idaapi.ask_text(1024 * 8, "", prompt_title)
                question = None
                if result_val is not None:
                    if isinstance(result_val, bytes):
                        try: question = result_val.decode('utf-8')
                        except UnicodeDecodeError: idaapi.warning("ComprehendAI: 问题含无效UTF-8字符。")
                    elif isinstance(result_val, str): question = result_val
                    else: idaapi.warning(f"ComprehendAI: ask_text 返回未知类型: {type(result_val)}")
                if question and question.strip():
                    task = self.TaskType.CUSTOM_QUERY_WITH_CODE if action == "CustomQueryWithCode" else self.TaskType.CUSTOM_QUERY
                    self.handler.create_ai_task(task, question)
                elif result_val is not None: idaapi.warning("ComprehendAI: 问题不能为空。")
            elif action == "SetDepth":
                depth = self.handler.disassembler.max_depth
                new_depth = idaapi.ask_long(depth, "ComprehendAI: 设置分析深度 (0仅当前函数):")
                if new_depth is not None: self.handler.set_analysis_depth(new_depth)
            elif action == "SetPrompt":
                default_val = self.handler.prompt_template
                res_val = idaapi.ask_text(1024*32, default_val, "ComprehendAI: 编辑主分析Prompt模板 (多行)")
                new_prompt = None
                if res_val is not None:
                    if isinstance(res_val, bytes):
                        try: new_prompt = res_val.decode('utf-8')
                        except UnicodeDecodeError: idaapi.warning("ComprehendAI: Prompt模板含无效UTF-8。")
                    elif isinstance(res_val, str): new_prompt = res_val
                    else: idaapi.warning(f"ComprehendAI: ask_text 返回未知类型: {type(res_val)}")
                    if new_prompt is not None: self.handler.prompt_template = new_prompt; print("ComprehendAI: Prompt模板已更新。")
            elif action == "Stop": self.handler.stop_ai_task()
            return 1
        def update(self, ctx):
            return idaapi.AST_ENABLE if self.suffix != "Stop" or self.handler.ai_isRunning_lock.locked() else idaapi.AST_DISABLE

def PLUGIN_ENTRY(): return ComprehendAIPlugin()
