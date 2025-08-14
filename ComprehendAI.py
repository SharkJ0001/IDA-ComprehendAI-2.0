import traceback
import idaapi
import idc
import idautils
import ida_xref
import json
import os

from idaapi import action_handler_t, UI_Hooks
from threading import Lock, Thread, Event
# 确保 openai 版本兼容，例如：pip install --upgrade openai
# 导入依然使用 openai 库，因为百炼兼容模式是基于此结构的
from openai import OpenAI, APIConnectionError, RateLimitError, APIStatusError, BadRequestError
from enum import Enum

# 尝试导入 Hex-Rays 相关模块
try:
    import ida_hexrays
    HEXRAYS_AVAILABLE = True
except ImportError:
    print("ComprehendAI: 未找到 Hex-Rays SDK。函数调用分析将仅限于汇编和基本交叉引用。")
    HEXRAYS_AVAILABLE = False

# --- 枚举 ---
class TaskType(Enum):
    ANALYSIS = 1 # 分析任务
    CUSTOM_QUERY = 2 # 自定义查询（不带代码）
    CUSTOM_QUERY_WITH_CODE = 3 # 自定义查询（带代码）

class QueryStatus(Enum):
    SUCCESS = 1 # 成功
    FAILED = 2  # 失败
    STOPPED = 3 # 已停止

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
        self.api_client = self._create_api_client()

    def _load_config(self):
        default_config = {
            "api_settings": {
                "api_key": "YOUR_API_KEY_HERE",
                "base_url": "YOUR_BASE_URL_HERE",
                "model": "YOUR_MODEL_NAME_HERE",
                "max_code_length": 30000,
                "stop_recursion_on_truncate": True
            }
        }
        try:
            with open(self.config_path, "r", encoding='utf-8') as f:
                loaded_config = json.load(f)
                if "api_settings" not in loaded_config:
                    if "openai" in loaded_config:
                        loaded_config["api_settings"] = loaded_config.pop("openai")
                        print("ComprehendAI_INFO: 在 config.json 中找到 'openai' 键, 已解释为 'api_settings'。请考虑更新 config.json。")
                    else:
                        loaded_config["api_settings"] = default_config["api_settings"]
                
                for key, value in default_config["api_settings"].items():
                    loaded_config["api_settings"].setdefault(key, value)
                return loaded_config
        except FileNotFoundError:
            idaapi.warning(f"ComprehendAI: 在 {self.config_path} 未找到配置文件。将使用默认配置，AI 功能可能无法工作。")
            return {"api_settings": default_config["api_settings"]}
        except json.JSONDecodeError:
            idaapi.warning(f"ComprehendAI: 解码配置文件 {self.config_path} 出错。将使用默认配置，请检查文件格式。")
            return {"api_settings": default_config["api_settings"]}
        except Exception as e:
            idaapi.warning(f"ComprehendAI: 加载配置失败: {str(e)}。将使用默认配置。")
            return {"api_settings": default_config["api_settings"]}

    def _create_api_client(self):
        try:
            cfg_api = self.config.get("api_settings", {})
            api_key = cfg_api.get("api_key")
            base_url = cfg_api.get("base_url")

            if not api_key or api_key == "YOUR_API_KEY_HERE":
                print("ComprehendAI: API 密钥缺失或为占位符。请在 config.json 中配置。")
                return None
            if not base_url or base_url == "YOUR_BASE_URL_HERE":
                print("ComprehendAI: Base URL 缺失或为占位符。对于阿里云百炼等服务，此项为必需。")
                pass

            return OpenAI(api_key=api_key, base_url=base_url)
        except KeyError as e:
            print(f"ComprehendAI: config.json 中缺少 API 配置项: {e}。AI 功能将受影响。")
            return None
        except Exception as e:
            print(f"ComprehendAI: 创建 API 客户端时出错: {e}")
            traceback.print_exc()
            return None

    @property
    def model_name(self):
        return self.config.get("api_settings", {}).get("model", "qwen-turbo")

    @property
    def max_code_length(self):
        return self.config.get("api_settings", {}).get("max_code_length", 80000)

    @property
    def stop_recursion_on_truncate(self):
        return self.config.get("api_settings", {}).get("stop_recursion_on_truncate", True)

    @property
    def client(self):
        return self.api_client

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
            raise ValueError("❌ 光标必须位于函数内部才能分析。")

        print(f"ComprehendAI: 开始分析函数 {idc.get_func_name(func_start)} ({hex(func_start)}), 最大深度: {self.max_depth}")
        self._process_function(func_start, self.max_depth, [])

        return "\n".join(self.func_disasm_list)

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
                        if e.x is None: return 0
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
                                        try: str_value = str_content_bytes.decode('latin-1') + " (以latin-1解码)"
                                        except UnicodeDecodeError: str_value = f"(二进制字符串, 十六进制: {str_content_bytes[:min(len(str_content_bytes), 16)].hex()}...)"
                                    display_str_value = str_value[:100] + "..." if len(str_value) > 100 else str_value
                                    self.found_globals_list.append(f"  {name} (0x{addr:08X}): \"{display_str_value}\"")
                                else:
                                    item_size = idc.get_item_size(addr)
                                    bytes_val = idc.get_bytes(addr, min(item_size, 8))
                                    if bytes_val: self.found_globals_list.append(f"  {name} (0x{addr:08X}): (数据, 大小 {item_size}, 十六进制: {bytes_val.hex()})")
                    return 0

            visitor = GlobalDataVisitor(globals_info, processed_addrs)
            try:
                visitor.apply_to(cfunc.body, None)
            except Exception as e_visitor:
                print(f"ComprehendAI DEBUG: GlobalDataVisitor 在处理 {func_name_for_debug} ({hex(func_ea)}) 时出错: {e_visitor}")
            
        elif not HEXRAYS_AVAILABLE:
            print(f"ComprehendAI DEBUG: Hex-Rays 不可用，跳过对 {func_name_for_debug} ({hex(func_ea)}) 基于伪代码树的全局数据提取。")
        return globals_info

    def _process_function(self, func_ea, depth, call_stack_names):
        func_name = idc.get_func_name(func_ea) or f"sub_{func_ea:X}"
        new_call_stack_names = call_stack_names + [func_name]

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
                        code_to_append = str(cfunc_for_code)
                        globals_list = self._get_global_data_references_for_function(func_ea, cfunc_for_code)
                        if globals_list:
                            globals_data_str = "// 相关全局数据:\n" + "\n".join(globals_list) + "\n"
                    else:
                        code_to_append = self._get_disassembly_text(func_ea)
                except ida_hexrays.DecompilationFailure:
                    code_to_append = self._get_disassembly_text(func_ea)
            else:
                code_to_append = self._get_disassembly_text(func_ea)

            if code_to_append.strip() or globals_data_str.strip():
                with self._lock:
                    call_path_str = " -> ".join(new_call_stack_names)
                    current_block_header = f"// 函数: {func_name} ({hex(func_ea)})\n// 调用路径: {call_path_str}\n"
                    block_content = globals_data_str + code_to_append
                    full_block_to_add = current_block_header

                    if self.code_limit_reached:
                        full_block_to_add += "// --- 已跳过 (已超出代码长度限制) ---\n"
                    else:
                        prospective_len = len(current_block_header) + len(block_content)
                        if self.actual_code_sent_length + prospective_len > self.config_manager.max_code_length:
                            self.code_limit_reached = True
                            full_block_to_add += "// --- 代码 (及相关数据) 在此处因总长度限制被截断 ---\n"
                        else:
                            full_block_to_add += block_content
                    
                    if full_block_to_add.strip() != f"// 函数: {func_name} ({hex(func_ea)})" or "---" in full_block_to_add:
                         self.func_disasm_list.append(full_block_to_add + "\n")
                         if not ("已跳过" in full_block_to_add or ("在此处因总长度限制被截断" in full_block_to_add and not block_content.strip())):
                            self.actual_code_sent_length += len(full_block_to_add) + 1
        except Exception as e:
            print(f"ComprehendAI: 处理函数 {func_name} ({hex(func_ea)}) 时发生错误: {str(e)}")
            traceback.print_exc()

        callees = set()
        if not (self.code_limit_reached and self.config_manager.stop_recursion_on_truncate):
            cfunc_for_callees = cfunc_for_code
            if HEXRAYS_AVAILABLE:
                if not cfunc_for_callees:
                    try: cfunc_for_callees = idaapi.decompile(func_ea)
                    except ida_hexrays.DecompilationFailure: cfunc_for_callees = None
                
                if cfunc_for_callees:
                    callees = self._get_callees_from_pseudocode(func_ea, cfunc_for_callees)
                else:
                    callees = self._get_callees_from_xrefs(func_ea)
            else:
                callees = self._get_callees_from_xrefs(func_ea)
        for callee_ea in callees: self._process_function(callee_ea, depth - 1, new_call_stack_names)

    def _get_disassembly_text(self, func_ea):
        disasm_lines = []
        func_end_ea = idc.get_func_attr(func_ea, idc.FUNCATTR_END)
        if func_end_ea == idaapi.BADADDR: return ""
        head_ea = func_ea
        while head_ea != idaapi.BADADDR and head_ea < func_end_ea:
            disasm_lines.append(idc.generate_disasm_line(head_ea, 0))
            next_ea = idc.next_head(head_ea, func_end_ea)
            if next_ea <= head_ea: break
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
            print(f"ComprehendAI DEBUG: CallVisitor 在处理 {hex(func_ea)} 时出错: {e_call_visitor}")
        return callees

# --- API 服务 ---
class APIService: 
    def __init__(self):
        self.config_manager = ConfigManager()
        self.stop_event = Event()

    def ask_ai(self, prompt_content, ai_isRunning_lock: Lock):
        if not self.config_manager.client:
            cfg_settings = self.config_manager.config.get('api_settings', {})
            api_key_preview = (cfg_settings.get('api_key', 'N/A')[:5] + "...") if cfg_settings.get('api_key') and len(cfg_settings.get('api_key', '')) > 5 else cfg_settings.get('api_key', 'N/A')
            base_url_val = cfg_settings.get('base_url', 'N/A')
            print(f"ComprehendAI: ❌ API 客户端未初始化。请检查 config.json (API Key: {api_key_preview}, Base URL: {base_url_val})。")
            if ai_isRunning_lock.locked(): ai_isRunning_lock.release()
            return
        
        if not prompt_content or not prompt_content.strip(): 
            print("ComprehendAI: ❌ Prompt 内容为空或仅包含空白字符。")
            if ai_isRunning_lock.locked(): ai_isRunning_lock.release()
            return

        messages = [{"role": "user", "content": prompt_content}]
        model_to_use = self.config_manager.model_name
        print(f"ComprehendAI: 正在向模型 {model_to_use} (at {self.config_manager.client.base_url}) 发送请求...")
        self.stop_event.clear()
        final_status = QueryStatus.FAILED

        try:
            final_status = self._request_api(messages, model_to_use)
        except Exception as e: 
            print(f"ComprehendAI: ❌ API请求期间发生意外错误: {e}")
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

    def _request_api(self, messages, model_name_to_use):
        full_response_content = ""
        try:
            print("\n" + "---" * 10 + " AI 回复 " + "---" * 10 + "\n")
            completion = self.config_manager.client.chat.completions.create(
                model=model_name_to_use,
                messages=messages,
                stream=True
            )
            for chunk in completion:
                if self.stop_event.is_set():
                    print("\nComprehendAI: 检测到停止事件。")
                    return QueryStatus.STOPPED
                if chunk.choices and chunk.choices[0].delta and chunk.choices[0].delta.content:
                    content_piece = chunk.choices[0].delta.content
                    print(content_piece, end='', flush=True)
                    full_response_content += content_piece
            
            print()
            
            if not full_response_content.strip() and not self.stop_event.is_set():
                print("ComprehendAI: AI返回了空内容。")
            return QueryStatus.SUCCESS

        except APIConnectionError as e: 
            print(f"\nComprehendAI: API 连接错误: {e}") 
            return QueryStatus.FAILED
        except RateLimitError as e: 
            print(f"\nComprehendAI: API 速率限制错误: {e}")
            return QueryStatus.FAILED
        except APIStatusError as e:
            print(f"\nComprehendAI: API 状态错误 (HTTP {e.status_code}): {e.response}")
            return QueryStatus.FAILED
        except BadRequestError as e:
            print(f"\nComprehendAI: API 请求错误 (HTTP {e.status_code}): {e.response}")
            return QueryStatus.FAILED
        except Exception as e:
            print(f"\nComprehendAI: 请求API时发生未知错误: {e}")
            traceback.print_exc()
            return QueryStatus.FAILED

# --- 用户接口处理 ---
class AnalysisHandler:
    def __init__(self):
        self.disassembler = DisassemblyProcessor()
        self.api_service = APIService()
        self.ai_isRunning_lock = Lock()
        
        self.prompt_template = """
你是一名世界顶级的网络安全逆向工程专家。你的任务不是简单描述代码做了什么，而是要深入分析其行为模式，并推断出其真实战略意图。在分析时，请始终以 MITRE ATT&CK 框架作为你的思维模型，将代码行为映射到具体的攻击战术上。
请严格遵循以下格式和要求，生成一份洞察深刻、逻辑严谨、对人类分析师极具价值的专业报告。

[任务背景]
我将提供一个主函数（第一个代码块）以及它调用链上的相关子函数。
代码块上方的 `// 调用路径:` 和 `// 相关全局数据:` 注释至关重要，你【必须】在分析中充分利用这些上下文信息。
{MAX_DEPTH_INFO}
{TRUNCATION_INFO}

[报告生成规则]

ComprehendAI 深度分析报告 📃
🎯 一、定性分析与核心意图
▸ 样本定性: (基于整体行为，首先给出一个明确的定性结论。例如：这是一个安装器(Installer)、下载器(Downloader)、键盘记录器(Keylogger)、勒索软件加密模块，或是一个正常的系统功能组件。)
▸ 核心意图: (一句话精准概括该代码模块的最终战略目标。例如：通过伪装成系统服务的方式，在目标系统上实现持久化访问。)
▸ 主要实现策略: (简要描述为达成该意图，代码所采用的关键技术组合。例如：通过API unhooking防御规避，注入svchost.exe执行网络通信，并利用AES算法加密配置文件。)

🔍 二、战术行为剖析 (TTPs)
(本章节是报告的核心，重点分析代码行为与攻击战术的关联，而不是罗列API调用)

▸ 持久化 (Persistence):
▸ (描述代码是如何实现开机自启或长期驻留的。明确指出具体技术，例如：“通过向注册表键 HKCU\Software\Microsoft\Windows\CurrentVersion\Run 写入 恶意程序路径 来创建自启动项 (T1547.001)”。)

▸ 权限提升 (Privilege Escalation):
▸ (描述代码是否尝试获取更高权限。例如：“通过 AdjustTokenPrivileges 获取 SeDebugPrivilege 权限，为其后续进行进程注入铺平道路 (T1134.001)”。)

▸ 防御规避 (Defense Evasion):
▸ (描述代码用于躲避检测的手段。例如：“通过调用 IsDebuggerPresent 进行反调试检测 (T1497.001)”；“服务名 mssecsvc2.0 模仿系统服务，是一种伪装技术 (T1036.005)”；“通过 CreateToolhelp32Snapshot 遍历进程，寻找杀毒软件进程并试图结束它 (T1562.001)”。)

▸ 信息搜集 (Collection) / 命令与控制 (Command and Control):
▸ (描述数据窃取和网络通信行为。例如：“通过HTTP POST请求，将从 C:\Users 目录下收集的 .doc 文件发送到硬编码的C2地址 http[:]//evil-server[.]com/upload (T1041)”。)

▸ 影响 (Impact):
▸ (描述代码对系统造成的最终破坏性后果。例如：“遍历磁盘，使用硬编码的RSA密钥加密非系统文件，并在目录下留下勒索信 readme.txt (T1486)”。)

(注：如果代码不涉及某个战术，则省略该标题。)

🔗 三、关键函数与数据流分析
▸ 函数: sub_XXXXX
▸ 调用路径: (根据提供的 // 调用路径: 注释填写)
▸ 战术贡献: (清晰说明该函数为哪个核心战术服务。避免简单的功能描述。例如：错误示范：“调整文件指针”。正确示范：“此函数为**‘防御规避’**战术服务，它通过计算PE文件的校验和来验证自身是否被修改，以对抗静态补丁分析。”)
▸ 核心实现: (描述其关键逻辑如何服务于战术贡献。例如：“它读取文件头部，定位到 OptionalHeader.CheckSum 字段，并与重新计算的值进行比较。”)

🔑 四、重要指标与上下文 (IOCs & Context)
▸ 硬编码数据/全局变量:
▸ 变量符号名 (0x地址): "实际值"
▸ 战略作用: (解释该数据在整个攻击链中的作用。例如：c2_domain_str (0x409510): "http[:]//evil-server[.]com/upload" - 这是恶意软件的命令与控制(C2)服务器地址，用于上传窃取的数据。)
▸ 关键API调用:
▸ API名称:
▸ 战术价值: (点明该API在此处实现的具体战术目的。例如：CreateRemoteThread - 执行代码注入的核心API，用于在远程进程中启动恶意线程，是典型的**“进程注入” (T1055)** 行为。)

💡 五、结论与分析建议
▸ 综合结论: (对样本的性质、意图和威胁等级进行最终总结。例如：“此样本是一个功能完善的窃密木马，具备通过注册表Run键持久化、反调试、窃取文档并通过HTTP上传的能力，威胁等级高。”)
▸ 后续分析建议:
▸ (为人类分析师提供明确的、可操作的下一步建议。)
▸ ▸ 静态分析: “使用PE工具分析其导入表，重点关注网络和加密相关的API。”
▸ ▸ 动态调试: “在 send 函数下断点，观察其发送到C2服务器的具体数据包内容。”
▸ ▸ 沙箱/网络: “在隔离环境中运行样本，监控其文件和注册表行为，并记录所有网络流量。”

[分析要求与思维模型]

意图导向: 你的所有分析都必须围绕“这段代码想干什么坏事？”展开，而不是“这段代码在干什么？”。

关联战术: 将具体的代码实现与公认的安全术语（持久化、权限提升、防御规避等）强力关联。

突出重点: 忽略无实际意义的初始化和通用代码，聚焦于实现核心恶意功能的代码路径。

格式遵从: 严格遵循上述以 🎯, 🔍, 🔗, 🔑, 💡 和 ▸ 为核心的结构。全局变量格式 变量名 (实际值) 必须遵守。

现在，请开始分析以下代码：
"""
    def set_analysis_depth(self, depth_val):
        if isinstance(depth_val, int) and depth_val >= 0:
            self.disassembler.max_depth = depth_val
            print(f"ComprehendAI: ✅ 分析深度已设置为: {depth_val}")
        else: idaapi.warning("ComprehendAI: ❌ 错误: 深度必须是非负整数。")

    def _create_analysis_prompt(self, disassembly_code):
        depth_info = f"注意：以下代码包含了主函数以及它递归调用的子函数，最大调用深度为 {self.disassembler.max_depth} 层。"
        trunc_info = ""
        if self.disassembler.code_limit_reached:
            trunc_info = f"重要提示：由于总代码长度超过预设 {self.disassembler.config_manager.max_code_length} 字符限制，部分函数代码可能被截断或仅显示名称。分析可能不完整。"
        
        if not disassembly_code or not disassembly_code.strip():
            return None 

        return self.prompt_template.replace("{MAX_DEPTH_INFO}", depth_info).replace("{TRUNCATION_INFO}", trunc_info) + disassembly_code

    def _create_custom_query_with_code_prompt(self, disassembly_code, question_text):
        depth_info = f"代码上下文（主函数及其子函数，最大深度 {self.disassembler.max_depth} 层）："
        trunc_info = ""
        if self.disassembler.code_limit_reached:
            trunc_info = f"（代码可能因超长被截断，最大长度约 {self.disassembler.config_manager.max_code_length} 字符）"
        
        if not disassembly_code or not disassembly_code.strip():
            return None 

        return f"我的问题是：{question_text}\n\n请基于知识及以下代码回答。\n{depth_info} {trunc_info}\n{disassembly_code}"

    def create_ai_task(self, task_type: TaskType, question_text=""):
        prompt_to_send = ""
        disassembly_code_to_use = ""

        if task_type in [TaskType.ANALYSIS, TaskType.CUSTOM_QUERY_WITH_CODE]:
            try:
                if idc.get_func_attr(idc.get_screen_ea(), idc.FUNCATTR_START) == idaapi.BADADDR:
                     idaapi.warning("ComprehendAI: ❌ 请将光标置于函数内部。"); return
                
                disassembly_code_to_use = self.disassembler.get_current_function_disasm()
                if not disassembly_code_to_use or not disassembly_code_to_use.strip():
                    idaapi.warning("ComprehendAI: ❌ 未能获取代码或代码为空。")
                    return

                if task_type == TaskType.ANALYSIS:
                    prompt_to_send = self._create_analysis_prompt(disassembly_code_to_use)
                else: # TaskType.CUSTOM_QUERY_WITH_CODE
                    prompt_to_send = self._create_custom_query_with_code_prompt(disassembly_code_to_use, question_text)
                
                if prompt_to_send is None:
                    idaapi.warning("ComprehendAI: ❌ 创建Prompt失败。")
                    return

            except ValueError as e:
                idaapi.warning(f"ComprehendAI: ❌ 错误: {e}"); return
            except Exception as e:
                idaapi.warning(f"ComprehendAI: ❌ 准备分析时发生未知错误: {e}"); traceback.print_exc(); return
        
        elif task_type == TaskType.CUSTOM_QUERY:
            if not question_text or not question_text.strip():
                idaapi.warning("ComprehendAI: ❌ 问题不能为空。"); return
            prompt_to_send = question_text
        else:
            idaapi.warning(f"ComprehendAI: ❌ 未知任务类型: {task_type}"); return

        if not prompt_to_send or not prompt_to_send.strip():
            print("ComprehendAI: 最终 Prompt 为空，未发送。")
            return

        if self.ai_isRunning_lock.acquire(blocking=False):
            try:
                task = Thread(target=self.api_service.ask_ai, args=(prompt_to_send, self.ai_isRunning_lock,))
                task.daemon = True
                task.start()
            except Exception as e:
                print(f"ComprehendAI: ❌ 启动AI任务线程失败: {e}")
                traceback.print_exc()
                if self.ai_isRunning_lock.locked():
                    self.ai_isRunning_lock.release()
        else:
            idaapi.warning("ComprehendAI: ❌ AI 正在处理之前的任务，请稍候。")

    def stop_ai_task(self):
        if self.ai_isRunning_lock.locked():
            print("ComprehendAI: 正在尝试停止AI任务...")
            self.api_service.stop_event.set()
        else:
            print("ComprehendAI: ✅ 当前无正在运行的AI任务。")

# --- IDA 插件框架 ---
class ComprehendAIPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "ComprehendAI: 基于AI的逆向分析助手"
    help = "使用配置的API服务 (如阿里云百炼) 辅助逆向工程任务。"
    wanted_name = "ComprehendAI"
    ACTION_PREFIX = "ComprehendAI:"

    ACTION_DEFS = [
        ("Analysis", "分析函数及调用树", "Ctrl+Shift+A", "AI分析当前函数及其调用链"),
        ("CustomQueryWithCode", "结合当前代码提问AI", "Ctrl+Shift+X", "结合当前函数上下文向AI提问"),
        ("CustomQuery", "直接提问AI (无代码)", "Ctrl+Shift+Q", "向AI发送自定义问题"),
        ("SetDepth", "设置分析深度...", "", "设置函数调用链的递归分析深度"),
        ("SetPrompt", "编辑分析模板...", "", "自定义主分析任务的Prompt模板"),
        ("Stop", "停止AI分析", "Ctrl+Shift+S", "停止当前正在进行的AI分析任务"),
    ]

    def init(self):
        self.handler = AnalysisHandler()
        self._register_actions()
        self.menu_hook = self.MenuHooker(self.ACTION_PREFIX, [ad[0] for ad in self.ACTION_DEFS])
        self.menu_hook.hook()
        print("ComprehendAI: ✅ 插件已初始化。")
        print("ComprehendAI: 分析热键: Ctrl+Shift+A。停止热键: Ctrl+Shift+S。")
        print("ComprehendAI: 请在 config.json 中正确配置 API Key, Base URL 和 Model。")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        idaapi.warning("ComprehendAI: 请使用右键菜单或已注册的热键来调用功能。")
    
    def term(self):
        if hasattr(self, 'menu_hook') and self.menu_hook:
            self.menu_hook.unhook()
        self._unregister_actions()
        if hasattr(self, 'handler'):
            self.handler.stop_ai_task() 
        print("ComprehendAI: ✅ 插件已卸载。")

    def _register_actions(self):
        for name_suffix, label, hotkey, tooltip in self.ACTION_DEFS:
            action_id = self.ACTION_PREFIX + name_suffix
            action_desc = idaapi.action_desc_t(action_id, label, self.MenuActionHandler(name_suffix, self.handler), hotkey or None, tooltip, 0)
            if not idaapi.register_action(action_desc):
                print(f"ComprehendAI: ❌ 注册操作失败: {action_id}")

    def _unregister_actions(self):
        for name_suffix, *rest in self.ACTION_DEFS:
            idaapi.unregister_action(self.ACTION_PREFIX + name_suffix)

    class MenuHooker(UI_Hooks):
        def __init__(self, prefix, suffixes):
            super().__init__()
            self.prefix = prefix
            self.suffixes = suffixes
        
        def finish_populating_widget_popup(self, widget, popup):
            widget_type = idaapi.get_widget_type(widget)
            if widget_type in [idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE]:
                for suffix in self.suffixes:
                    idaapi.attach_action_to_popup(widget, popup, self.prefix + suffix, "ComprehendAI/") 

    class MenuActionHandler(action_handler_t):
        def __init__(self, suffix, handler_instance): 
            super().__init__()
            self.suffix = suffix
            self.handler = handler_instance
        
        def activate(self, ctx):
            action = self.suffix
            if action == "Analysis":
                self.handler.create_ai_task(TaskType.ANALYSIS)
            elif action == "CustomQueryWithCode":
                prompt_title = "ComprehendAI: 输入您的问题 (将结合当前函数代码)"
                result_val = idaapi.ask_text(1024 * 8, "", prompt_title)
                question = self._get_text_from_ask_dialog(result_val)
                if question:
                    self.handler.create_ai_task(TaskType.CUSTOM_QUERY_WITH_CODE, question)
                elif result_val is not None:
                    idaapi.warning("ComprehendAI: ❌ 问题不能为空。")
            elif action == "CustomQuery":
                prompt_title = "ComprehendAI: 输入您的问题 (不附带代码)"
                result_val = idaapi.ask_text(1024 * 8, "", prompt_title)
                question = self._get_text_from_ask_dialog(result_val)
                if question:
                    self.handler.create_ai_task(TaskType.CUSTOM_QUERY, question)
                elif result_val is not None:
                     idaapi.warning("ComprehendAI: ❌ 问题不能为空。")
            elif action == "SetDepth":
                current_depth = self.handler.disassembler.max_depth
                new_depth = idaapi.ask_long(current_depth, "ComprehendAI: 设置分析深度 (0仅当前函数):")
                if new_depth is not None:
                    if new_depth >= 0:
                        self.handler.set_analysis_depth(new_depth)
                    else:
                        idaapi.warning("ComprehendAI: ❌ 深度必须是非负数。")
            elif action == "SetPrompt":
                current_prompt = self.handler.prompt_template
                new_prompt_val = idaapi.ask_text(0x10000, current_prompt, "ComprehendAI: 编辑主分析Prompt模板")
                new_prompt = self._get_text_from_ask_dialog(new_prompt_val)
                if new_prompt is not None:
                    self.handler.prompt_template = new_prompt
                    print("ComprehendAI: ✅ Prompt模板已更新。")
            elif action == "Stop":
                self.handler.stop_ai_task()
            return 1

        def _get_text_from_ask_dialog(self, result_val):
            question = None
            if result_val is not None:
                try: question = result_val.decode('utf-8') if isinstance(result_val, bytes) else str(result_val)
                except UnicodeDecodeError: idaapi.warning("ComprehendAI: ❌ 输入包含无效UTF-8字符。")
                
                if question is not None and not question.strip():
                    return None
            return question

        def update(self, ctx):
            if self.suffix == "Stop":
                return idaapi.AST_ENABLE if self.handler.ai_isRunning_lock.locked() else idaapi.AST_DISABLE
            return idaapi.AST_ENABLE_FOR_WIDGET

def PLUGIN_ENTRY():
    return ComprehendAIPlugin()
