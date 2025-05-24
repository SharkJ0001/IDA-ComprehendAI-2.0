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
                # print("ComprehendAI: base_url is placeholder or empty, will use official OpenAI endpoint.")

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
        self._process_function(func_start, self.max_depth, []) # Initial call_stack_names is empty list

        result_code = "\n".join(self.func_disasm_list)
        # print(f"ComprehendAI_DEBUG: Final collected code for AI (length {len(result_code)}), actual sent length tracker: {self.actual_code_sent_length}:\n{result_code[:1000]}...")
        return result_code

    def _get_global_data_references_for_function(self, func_ea, cfunc=None):
        globals_info = []
        processed_addrs = set()

        if HEXRAYS_AVAILABLE and cfunc:
            class GlobalDataVisitor(ida_hexrays.ctree_visitor_t):
                def __init__(self, found_globals_list, processed_addrs_set):
                    super().__init__(ida_hexrays.CV_FAST)
                    self.found_globals_list = found_globals_list
                    self.processed_addrs_set = processed_addrs_set

                def visit_expr(self, e):
                    if e.op == ida_hexrays.cot_obj:
                        # --- FIX: Check if e.x is None before accessing e.x.obj_ea ---
                        if e.x is None:
                            # print(f"ComprehendAI_DEBUG: cot_obj at {hex(e.ea)} has e.x as None. Skipping this specific object.")
                            return 0 # Continue traversal, but skip this problematic e.x

                        addr = e.x.obj_ea
                        # --- END FIX ---
                        if addr != idaapi.BADADDR and addr not in self.processed_addrs_set:
                            seg = idaapi.getseg(addr)
                            if seg and (idaapi.segtype(addr) == idaapi.SEG_DATA or idaapi.segtype(addr) == idaapi.SEG_BSS or seg.perm & idaapi.SEGPERM_READ):
                                self.processed_addrs_set.add(addr)
                                name = idc.get_name(addr, idaapi.GN_VISIBLE) or f"data_{addr:08X}"

                                str_content_bytes = idc.get_strlit_contents(addr, -1, idc.STRTYPE_C)
                                if str_content_bytes is not None:
                                    try:
                                        str_value = str_content_bytes.decode('utf-8')
                                    except UnicodeDecodeError:
                                        try:
                                            str_value = str_content_bytes.decode('latin-1') + " (decoded as latin-1)"
                                        except UnicodeDecodeError:
                                            str_value = f"(binary string, hex: {str_content_bytes[:min(len(str_content_bytes), 16)].hex()}...)"

                                    display_str_value = str_value[:100] + "..." if len(str_value) > 100 else str_value
                                    self.found_globals_list.append(f"  {name} (0x{addr:08X}): \"{display_str_value}\"")
                                else:
                                    item_size = idc.get_item_size(addr)
                                    bytes_val = idc.get_bytes(addr, min(item_size, 8))
                                    if bytes_val:
                                         self.found_globals_list.append(f"  {name} (0x{addr:08X}): (data, size {item_size}, hex: {bytes_val.hex()})")
                    return 0

            visitor = GlobalDataVisitor(globals_info, processed_addrs)
            try: # Add try-except around apply_to as it might raise due to ctree issues
                visitor.apply_to(cfunc.body, None)
            except Exception as e_visitor:
                print(f"ComprehendAI_DEBUG: Error during GlobalDataVisitor apply_to for {hex(func_ea)}: {e_visitor}")


        return globals_info

    def _process_function(self, func_ea, depth, call_stack_names): # call_stack_names is now required
        func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"

        current_func_name_for_stack = func_name
        new_call_stack_names = call_stack_names + [current_func_name_for_stack]

        # print(f"ComprehendAI_DEBUG: _process_function ENTER: {func_name}({hex(func_ea)}), depth: {depth}, call_stack: {' -> '.join(new_call_stack_names)}, processed: {func_ea in self.processed_funcs}, limit_reached: {self.code_limit_reached}")


        if func_ea in self.processed_funcs or depth < 0:
            return

        with self._lock:
            if func_ea in self.processed_funcs:
                return
            self.processed_funcs.add(func_ea)

        code_to_append = ""
        cfunc_for_code = None
        globals_data_str = ""

        try:
            if HEXRAYS_AVAILABLE:
                try:
                    cfunc_for_code = idaapi.decompile(func_ea)
                    if cfunc_for_code:
                        code_to_append = str(cfunc_for_code)
                        globals_list = self._get_global_data_references_for_function(func_ea, cfunc_for_code)
                        if globals_list:
                            globals_data_str = "// Relevant Global Data:\n" + "\n".join(globals_list) + "\n"
                    else:
                        code_to_append = self._get_disassembly_text(func_ea)
                except ida_hexrays.DecompilationFailure:
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

                    if full_block_to_add.strip() != f"// Function: {func_name} ({hex(func_ea)})" or \
                       "---" in full_block_to_add:
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
                        if self.code_limit_reached:
                            full_fallback_block += "// --- SKIPPED (already past code length limit) ---\n"
                        else:
                            prospective_len_contribution = len(fallback_block_header) + len(assembly_fallback) +1
                            if self.actual_code_sent_length + prospective_len_contribution > self.config_manager.max_code_length:
                                self.code_limit_reached = True
                                full_fallback_block += "// --- CODE TRUNCATED HERE DUE TO TOTAL LENGTH LIMIT ---\n"
                            else:
                                full_fallback_block += assembly_fallback

                        self.func_disasm_list.append(full_fallback_block + "\n")
                        if not ("SKIPPED" in full_fallback_block or "TRUNCATED HERE" in full_fallback_block):
                           self.actual_code_sent_length += len(full_fallback_block) +1
            except Exception as inner_e:
                print(f"ComprehendAI: Failed to get disassembly for {func_name} ({hex(func_ea)}) during fallback: {str(inner_e)}")

        callees = set()
        if self.code_limit_reached and self.config_manager.stop_recursion_on_truncate:
            pass
        else:
            if HEXRAYS_AVAILABLE:
                cfunc_for_callees = cfunc_for_code if cfunc_for_code else idaapi.decompile(func_ea)
                if cfunc_for_callees:
                    callees = self._get_callees_from_pseudocode(func_ea, cfunc_for_callees)
                else:
                    callees = self._get_callees_from_xrefs(func_ea)
            else:
                callees = self._get_callees_from_xrefs(func_ea)

        for callee_ea in callees:
            self._process_function(callee_ea, depth - 1, new_call_stack_names)

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
        if not cfunc:
            return self._get_callees_from_xrefs(func_ea)

        class CallVisitor(ida_hexrays.ctree_visitor_t):
            def __init__(self, found_callees_set):
                super().__init__(ida_hexrays.CV_FAST)
                self.found_callees_set = found_callees_set

            def visit_expr(self, e):
                if e.op == ida_hexrays.cot_call:
                    # --- FIX: Check if e.x is None before accessing e.x.obj_ea ---
                    if e.x is not None and e.x.op == ida_hexrays.cot_obj: # Also check e.x.op
                        callee_ea_candidate = e.x.obj_ea
                        if idc.get_func_attr(callee_ea_candidate, idc.FUNCATTR_START) == callee_ea_candidate:
                            self.found_callees_set.add(callee_ea_candidate)
                return 0

        visitor = CallVisitor(callees)
        try: # Add try-except around apply_to for CallVisitor as well
            visitor.apply_to(cfunc.body, None)
        except Exception as e_call_visitor:
            print(f"ComprehendAI_DEBUG: Error during CallVisitor apply_to for {hex(func_ea)}: {e_call_visitor}")


        for xref_callee in self._get_callees_from_xrefs(func_ea): # Supplement
            callees.add(xref_callee)

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
        self.stop_event.clear()
        final_status = QueryStatus.FAILED

        try:
            final_status = self._request_openai(messages)
        except Exception as e:
            print(f"ComprehendAI: ❌ An unexpected error occurred in _request_openai: {e}")
            traceback.print_exc()
            final_status = QueryStatus.FAILED
        finally:
            if ai_isRunning_lock.locked():
                ai_isRunning_lock.release()

            if final_status == QueryStatus.SUCCESS:
                print("\nComprehendAI: ✅ 分析完成！")
            elif final_status == QueryStatus.FAILED:
                print("\nComprehendAI: ❌ 分析失败，请检查IDA输出或错误日志。")
            elif final_status == QueryStatus.STOPPED:
                print("\nComprehendAI: ✅ 分析已由用户停止。")

    def _request_openai(self, messages):
        full_response_content = ""
        try:
            if not self.config_manager.client or not self.config_manager.model_name:
                print("ComprehendAI: OpenAI client or model not configured.")
                return QueryStatus.FAILED

            print("\n" + "=" * 20 + " AI 回复 " + "=" * 20 + "\n")
            completion = self.config_manager.client.chat.completions.create(
                model=self.config_manager.model_name,
                messages=messages,
                stream=True,
            )
            for chunk in completion:
                if self.stop_event.is_set():
                    print("\nComprehendAI: detected stop event, terminating stream.")
                    return QueryStatus.STOPPED

                if chunk.choices and chunk.choices[0].delta and chunk.choices[0].delta.content:
                    content_piece = chunk.choices[0].delta.content
                    print(content_piece, end='', flush=True)
                    full_response_content += content_piece

            if not full_response_content.strip() and not self.stop_event.is_set():
                print("ComprehendAI: AI返回了空内容。")

            return QueryStatus.SUCCESS

        except OpenAI.APIConnectionError as e: # type: ignore
            print(f"\nComprehendAI: OpenAI API 连接错误: {e}")
            return QueryStatus.FAILED
        except OpenAI.RateLimitError as e: # type: ignore
            print(f"\nComprehendAI: OpenAI API 速率限制错误: {e}")
            return QueryStatus.FAILED
        except OpenAI.APIStatusError as e: # type: ignore
            print(f"\nComprehendAI: OpenAI API 状态错误 (HTTP {e.status_code}): {e.response}")
            return QueryStatus.FAILED
        except Exception as e:
            print(f"\nComprehendAI: 请求OpenAI时发生错误: {e}")
            traceback.print_exc()
            return QueryStatus.FAILED

# --- 用户接口处理 ---
class AnalysisHandler:
    def __init__(self):
        self.disassembler = DisassemblyProcessor()
        self.ai_service = AIService()
        self.ai_isRunning_lock = Lock()
        self.prompt_template = """
你是一名顶尖的人工智能逆向工程专家，精通恶意软件分析、系统底层机制和Windows API。
我会提供你一段或多段反汇编代码（可能是C伪代码或汇编代码）。
1. 如果提供了多段代码，【第一个函数代码块】是本次分析的【主分析目标函数】，其余函数是其直接或间接调用的【自定义子函数】。
2. 每个函数代码块上方可能会列出该函数直接引用的 "Relevant Global Data" 或 "Call Path" 信息，请在分析时务必结合这些信息。
{MAX_DEPTH_INFO}
{TRUNCATION_INFO}

请严格按照以下结构和要求，生成一份【高度浓缩】、【避免重复】、【逻辑清晰】的Markdown格式分析报告：

**1. 主分析目标函数核心概述 (针对第一个函数代码块):**
   * **核心目的与策略**：一句话总结该主函数最核心的功能以及它为达到此目的所采用的主要策略（例如，通过服务安装实现持久化，通过资源加载执行payload等）。
   * **关键执行路径摘要**：
      * 简述其关键的初始化步骤。
      * 描述其主要的API调用序列或对【关键自定义子函数】的调用序列。**请直接结合提取到的全局变量值进行描述（例如，服务名为"XXX"，文件名为"YYY"）。**
      * 若存在对程序流程有重大影响的逻辑分支，请简要说明其判断条件和主要走向。

**2. 整体程序行为推测 (综合所有提供的函数代码和全局数据):**
   * **持久化机制**：明确指出。如果通过创建服务/文件等实现，**必须使用提取到的全局变量名和路径进行描述。**
   * **核心恶意载荷行为**：如果代码涉及加载、解密、写入或执行其他可执行文件/代码（例如从资源、特定路径读取），请详细描述此过程，包括涉及的文件名、路径、创建的进程名等。**这是分析的重点。**
   * **防御规避技术**：简述观察到的具体技术，如服务名/文件名伪装、API动态解析、反调试技巧等。
   * **潜在网络行为**：若当前代码片段中存在，或其启动的进程/调用的子函数明显暗示了网络通信，请指出。

**3. 关键自定义子函数分析 (按调用链顺序或重要性组织):**
   * 对于【每一个】由脚本提供的、且在主流程中被调用的【自定义子函数】（例如 `sub_XXXXX`，非Windows API），请按以下格式进行分析：
      * **函数名与调用链**：`sub_XXXXX` (请根据代码块中提供的 `// Call Path:` 注释来填充调用路径)。
      * **核心功能**：清晰、简洁地描述该子函数的主要功能。
      * **关键操作**：列出其内部1-3个最关键的操作、API调用，或对【更深层子函数】的调用。
      * **在调用链中的作用**：说明它如何为其直接调用者服务，以及它对实现【主分析目标函数】的整体目标有何贡献。**结合其引用的全局数据（如有）进行分析。**
   * **注意**：如果某个子函数非常简单（如直接返回常量、简单赋值），一句话描述其功能和作用即可。如果由于代码截断或信息不足无法分析，请明确指出“信息不足，无法详细分析此子函数”。**但不能完全遗漏脚本提供的任何自定义子函数。**

**4. 关键全局变量及核心API价值总结 (仅总结对理解整体行为【最关键且未在前面充分展开】的信息):**
   * **关键全局变量**：以列表形式，总结对理解程序核心行为【最重要】的全局变量，简述其值和决定性作用。避免重复已在前面分析中详细使用的变量。
   * **核心Windows API**：列出在整个代码片段中扮演【决定性角色】的1-3个Windows API，并一句话点明它们在此处的战略价值。

**5. 综合风险评估与最终目的推测:**
   * 基于以上所有分析，总结该代码片段（或其代表的程序模块）的主要风险。
   * 推测其最可能的最终目的。

**输出要求：**
* **精确性**：对API参数（如`dwStartType`）、常量、全局变量值的解读必须准确。
* **高度浓缩，避免冗余**：在不同部分描述同一事物时，应各有侧重，或在后续部分仅做引用式提及。例如，如果在子函数分析中已详细说明某API作用，则在API总结中可不再赘述。
* **强调调用链和上下文关联**：子函数的分析必须体现其在调用链中的位置和作用。
* **结构化输出**：严格按照提供的Markdown标题和结构输出。

下面是你要分析的代码：
"""
    def set_analysis_depth(self, depth_val):
        if isinstance(depth_val, int) and depth_val >= 0:
            self.disassembler.max_depth = depth_val
            print(f"ComprehendAI: 分析深度已设置为: {depth_val}")
        else:
            idaapi.warning("ComprehendAI: 错误: 深度必须是非负整数。")

    def _create_analysis_prompt(self, disassembly_code):
        depth_info_str = f"注意：以下代码包含了主函数以及它递归调用的子函数，最大调用深度为 {self.disassembler.max_depth} 层。"
        truncation_info_str = ""
        if self.disassembler.code_limit_reached:
            truncation_info_str = f"重要提示：由于总代码长度超过了预设的 {self.disassembler.config_manager.max_code_length} 字符限制，上面提供的部分函数代码可能被截断或仅显示函数名（标记为 TRUNCATED 或 SKIPPED）。因此，对深层函数的分析可能不完整或缺失。"

        current_prompt = self.prompt_template.replace("{MAX_DEPTH_INFO}", depth_info_str)
        current_prompt = current_prompt.replace("{TRUNCATION_INFO}", truncation_info_str)

        return current_prompt + disassembly_code

    def _create_custom_query_with_code_prompt(self, disassembly_code, question_text):
        depth_info_str = f"代码上下文（主函数及其调用的子函数，最大深度 {self.disassembler.max_depth} 层）："
        truncation_info_str = ""
        if self.disassembler.code_limit_reached:
            truncation_info_str = f"（注意：代码可能因超长被截断，只显示部分函数或函数名，最大代码长度约 {self.disassembler.config_manager.max_code_length} 字符）"

        return f"我的问题是：{question_text}\n\n请基于你的知识以及以下相关的反汇编/伪代码来回答。\n{depth_info_str} {truncation_info_str}\n{disassembly_code}"


    def create_ai_task(self, task_type: TaskType, question_text=""):
        prompt_to_send = ""
        if task_type in [TaskType.ANALYSIS, TaskType.CUSTOM_QUERY_WITH_CODE]:
            try:
                if idc.get_func_attr(idc.get_screen_ea(), idc.FUNCATTR_START) == idaapi.BADADDR:
                     idaapi.warning("ComprehendAI: 请将光标置于函数内部再执行此操作。")
                     return
                disassembly_code = self.disassembler.get_current_function_disasm()
                if not disassembly_code.strip():
                    idaapi.warning("ComprehendAI: ❌ 未能获取到反汇编/伪代码。请确保光标在有效函数内部。")
                    return

                if task_type == TaskType.ANALYSIS:
                    prompt_to_send = self._create_analysis_prompt(disassembly_code)
                else: # CUSTOM_QUERY_WITH_CODE
                    prompt_to_send = self._create_custom_query_with_code_prompt(disassembly_code, question_text)
            except ValueError as e:
                idaapi.warning(f"ComprehendAI: ❌ 错误: {e}")
                return
            except Exception as e:
                idaapi.warning(f"ComprehendAI: ❌ 准备分析时发生未知错误: {e}")
                traceback.print_exc()
                return
        elif task_type == TaskType.CUSTOM_QUERY:
            if not question_text.strip():
                idaapi.warning("ComprehendAI: 问题不能为空。")
                return
            prompt_to_send = question_text
        else:
            idaapi.warning(f"ComprehendAI: 未知的任务类型: {task_type}")
            return

        if len(prompt_to_send) > 3000 :
             print(f"ComprehendAI: 发送给AI的Prompt内容较长 (约 {len(prompt_to_send)} 字符)，此处仅显示开头部分。")
             # print("Prompt starts with:\n" + prompt_to_send[:300] + "...")
        elif not prompt_to_send.strip():
            print("ComprehendAI: Prompt为空或仅包含空白，任务未发送。")
            return


        if self.ai_isRunning_lock.acquire(blocking=False):
            try:
                task = Thread(target=self.ai_service.ask_ai, args=(prompt_to_send, self.ai_isRunning_lock,))
                task.daemon = True
                task.start()
            except Exception as e_thread_start:
                print(f"ComprehendAI: ❌ 启动AI任务线程失败: {e_thread_start}")
                traceback.print_exc()
                if self.ai_isRunning_lock.locked():
                    self.ai_isRunning_lock.release()
        else:
            idaapi.warning("ComprehendAI: ❌ 当前AI正在处理任务,请稍后尝试。")

    def stop_ai_task(self):
        if self.ai_isRunning_lock.locked():
            print("ComprehendAI: 正在尝试停止AI任务...")
            self.ai_service.stop_event.set()
        else:
            print("ComprehendAI: 当前没有正在运行的AI任务可以停止。")

# --- IDA 插件框架 ---
class ComprehendAIPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "ComprehendAI: AI-based Reverse Analysis"
    help = "Uses OpenAI to assist in reverse engineering tasks."
    wanted_name = "ComprehendAI"

    ACTION_PREFIX = "ComprehendAI:"
    ACTION_DEFS = [
        ("Analysis", "分析函数及调用树", "Ctrl+Shift+A", "对当前函数及其调用的函数进行AI分析"),
        ("CustomQueryWithCode", "结合代码提问AI", "Ctrl+Shift+X", "结合当前函数代码向AI提问"),
        ("CustomQuery", "直接提问AI", "Ctrl+Shift+Q", "自定义问题并发送给AI（不附带代码）"),
        ("SetDepth", "设置分析深度", "", "设置函数调用树的递归分析深度"),
        ("SetPrompt", "设置分析模板", "", "自定义主分析功能的Prompt模板"),
        ("Stop", "停止AI分析", "Ctrl+Shift+S", "停止当前正在进行的AI分析任务"),
    ]

    def init(self):
        self.handler = AnalysisHandler()
        self._register_actions()
        self.menu_hook = self.MenuHooker(self.ACTION_PREFIX, [ad[0] for ad in self.ACTION_DEFS])
        self.menu_hook.hook()
        print("ComprehendAI: 插件已初始化。默认分析热键: Ctrl+Shift+A。停止热键: Ctrl+Shift+S。")
        print("ComprehendAI: 请在插件目录下的 config.json 文件中配置您的 OpenAI API Key, Base URL (可选) 和 Model。")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.warning("ComprehendAI: 请使用右键菜单或热键来调用功能。")

    def term(self):
        if hasattr(self, 'menu_hook') and self.menu_hook:
            self.menu_hook.unhook()
        self._unregister_actions()
        if hasattr(self, 'handler'):
            self.handler.stop_ai_task()
        print("ComprehendAI: 插件已卸载。")

    def _register_actions(self):
        for name_suffix, label, hotkey, tooltip in self.ACTION_DEFS:
            action_id = self.ACTION_PREFIX + name_suffix
            action_desc = idaapi.action_desc_t(
                action_id, label,
                self.MenuActionHandler(name_suffix, self.handler, TaskType),
                hotkey if hotkey else None,
                tooltip, 0)
            if not idaapi.register_action(action_desc):
                print(f"ComprehendAI: 注册操作失败: {action_id}")

    def _unregister_actions(self):
        for name_suffix, _, _, _ in self.ACTION_DEFS:
            idaapi.unregister_action(self.ACTION_PREFIX + name_suffix)

    class MenuHooker(UI_Hooks):
        def __init__(self, action_prefix, action_name_suffixes):
            super().__init__()
            self.action_prefix = action_prefix
            self.action_name_suffixes = action_name_suffixes

        def finish_populating_widget_popup(self, widget, popup_handle):
            widget_type = idaapi.get_widget_type(widget)
            if widget_type in (idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE):
                for name_suffix in self.action_name_suffixes:
                    idaapi.attach_action_to_popup(widget, popup_handle,
                                                  self.action_prefix + name_suffix,
                                                  "ComprehendAI/")

    class MenuActionHandler(action_handler_t):
        def __init__(self, action_name_suffix, handler: AnalysisHandler, task_type_enum_class: type(Enum)):
            super().__init__()
            self.action_name_suffix = action_name_suffix
            self.handler = handler
            self.TaskType = task_type_enum_class

        def activate(self, ctx):
            action = self.action_name_suffix

            if action == "Analysis":
                self.handler.create_ai_task(self.TaskType.ANALYSIS) # type: ignore
            elif action == "CustomQuery":
                result_val = idaapi.ask_text(1024 * 8, "", "ComprehendAI: 输入您的问题 (不附带代码, 支持多行)")
                question = None
                if result_val is not None:
                    if isinstance(result_val, bytes):
                        try:
                            question = result_val.decode('utf-8')
                        except UnicodeDecodeError:
                            idaapi.warning("ComprehendAI: 输入的问题包含无效的UTF-8字符。")
                    elif isinstance(result_val, str):
                        question = result_val
                    else:
                        idaapi.warning(f"ComprehendAI: ask_text 返回了未知类型: {type(result_val)}")

                if question is not None and question.strip():
                    self.handler.create_ai_task(self.TaskType.CUSTOM_QUERY, question) # type: ignore
                elif result_val is not None and (question is None or not question.strip()):
                    idaapi.warning("ComprehendAI: 问题不能为空或格式不正确。")

            elif action == "CustomQueryWithCode":
                result_val = idaapi.ask_text(1024 * 8, "", "ComprehendAI: 输入您的问题 (将结合当前函数代码, 支持多行)")
                question = None
                if result_val is not None:
                    if isinstance(result_val, bytes):
                        try:
                            question = result_val.decode('utf-8')
                        except UnicodeDecodeError:
                            idaapi.warning("ComprehendAI: 输入的问题包含无效的UTF-8字符。")
                    elif isinstance(result_val, str):
                        question = result_val
                    else:
                        idaapi.warning(f"ComprehendAI: ask_text 返回了未知类型: {type(result_val)}")

                if question is not None and question.strip():
                    self.handler.create_ai_task(self.TaskType.CUSTOM_QUERY_WITH_CODE, question) # type: ignore
                elif result_val is not None and (question is None or not question.strip()):
                    idaapi.warning("ComprehendAI: 问题不能为空或格式不正确。")

            elif action == "SetDepth":
                current_depth = self.handler.disassembler.max_depth
                new_depth_val = idaapi.ask_long(current_depth, "ComprehendAI: 设置分析深度 (默认15, 0表示仅当前函数):")
                if new_depth_val is not None:
                    self.handler.set_analysis_depth(new_depth_val)
            elif action == "SetPrompt":
                default_prompt_val = self.handler.prompt_template
                result_val = idaapi.ask_text(1024 * 32,
                                             default_prompt_val,
                                             "ComprehendAI: 编辑主分析Prompt模板 (支持多行)")
                new_prompt_str = None
                if result_val is not None:
                    if isinstance(result_val, bytes):
                        try:
                            new_prompt_str = result_val.decode('utf-8')
                        except UnicodeDecodeError:
                            idaapi.warning("ComprehendAI: Prompt模板包含无效UTF-8字符，未更新。")
                    elif isinstance(result_val, str):
                        new_prompt_str = result_val
                    else:
                         idaapi.warning(f"ComprehendAI: ask_text 返回了未知类型: {type(result_val)}")

                    if new_prompt_str is not None:
                        self.handler.prompt_template = new_prompt_str
                        print("ComprehendAI: 主分析Prompt模板已更新。")
            elif action == "Stop":
                self.handler.stop_ai_task()
            return 1

        def update(self, ctx):
            if self.action_name_suffix == "Stop":
                return idaapi.AST_ENABLE if self.handler.ai_isRunning_lock.locked() else idaapi.AST_DISABLE
            return idaapi.AST_ENABLE_ALWAYS

def PLUGIN_ENTRY():
    return ComprehendAIPlugin()