#!/usr/bin/env python3
"""
ShellSentry-AI 多维静态正则引擎 v1.0
====================================
攻击面覆盖：WebShell 高危函数 · 恶意混淆 · 内存马 · C2 网络 · 持久化

设计原则：
  - 全量扫描：所有规则对所有文件一视同仁（对抗后缀名伪装）
  - 五维覆盖：code_execution / obfuscation / memory_horse / c2_network / persistence
  - 丰富上下文：每个命中含行号 + 匹配文本 + 分类 + 严重度 + CWE 映射
  - 为 AI 语义引擎提供结构化底层数据
"""
import bisect
import re
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass, field

# 单条规则单行扫描超时（秒）。
# 重要事实：CPython 标准库 re 的 re.compile/re.match 签名均为 (pattern, flags)，
# **不接受 timeout 参数**（该能力属于第三方 regex 库）。因此历史上此处传入的
# timeout 恒定触发 TypeError 并静默降级，ReDoS 超时防护实际从未生效。
# 本模块改为以「超长行分窗」作为主要的输入规模限制手段，timeout 仅在检测到
# 运行环境支持时（如以 regex 替代 re）才作为附加保护启用。
REGEX_SCAN_TIMEOUT = 2.0

# 超长行分窗参数：当运行环境不支持 re 超时（Python < 3.11）或某条规则已触发
# 超时时，把该行切成带重叠的窗口再匹配，用以限制单次匹配的输入规模。
# 窗口远大于典型规则的模式跨度，配合重叠可覆盖绝大多数单行模式。
LONG_LINE_THRESHOLD = 4000
LONG_LINE_WINDOW = 2000
LONG_LINE_OVERLAP = 200


def _supports_regex_timeout() -> bool:
    """探测当前 re 实现是否支持 timeout 参数（标准库 re 不支持，regex 库支持）。"""
    try:
        re.compile("a", timeout=0.001)
    except TypeError:
        return False
    except re.error:
        return False
    return True


SUPPORTS_REGEX_TIMEOUT = _supports_regex_timeout()


def _line_segments(line: str) -> List[Tuple[int, str]]:
    """返回 [(行内起始偏移, 片段文本)]。

    短行返回整行；超长行切成带重叠的窗口，用于限制单次正则匹配的输入规模。
    保留偏移是为了在重叠区去重——同一处命中可能被相邻窗口各匹配一次。
    """
    if len(line) <= LONG_LINE_WINDOW:
        return [(0, line)]
    segments: List[Tuple[int, str]] = []
    step = max(1, LONG_LINE_WINDOW - LONG_LINE_OVERLAP)
    start = 0
    while start < len(line):
        segments.append((start, line[start:start + LONG_LINE_WINDOW]))
        if start + LONG_LINE_WINDOW >= len(line):
            break
        start += step
    return segments


_SPAN_QUANT_RE = re.compile(r"\{(\d+)(?:,(\d*))?\}")


def _pattern_exceeds_overlap(pattern: str, overlap: int = LONG_LINE_OVERLAP) -> bool:
    """判断某规则模式的最大匹配跨度是否可能超过分窗重叠宽度。

    命中则说明该规则在超长行上必须整行匹配：分窗会把"跨越窗口边界且长于重叠区"
    的匹配截成两段，两个窗口各缺一半而漏检（典型：{500,}/{1000,} 超长引号载荷）。
    """
    for m in _SPAN_QUANT_RE.finditer(pattern):
        lo = int(m.group(1))
        upper = m.group(2)  # None=无逗号；""={m,} 无上界；否则为数字串
        if lo >= overlap:
            return True
        if upper == "":
            return True
        if upper is not None and int(upper) >= overlap:
            return True
    return False

# ============================================================
# P1-2 污点可达性分析（3-C）—— 纯静态、零执行
# ============================================================
# 目标：把"静态命中规则"升级为"是否由外部输入驱动"的判定，
#   解决 defineClass / 反射 / Runtime.exec 在无害库中也常见导致的误报。
# 设计原则：
#   - 仅做"同作用域变量赋值传播 + 直接 source 参数"两层，不做跨函数/跨文件全程序分析
#     （收益低、误判风险高）；无法判定一律维持原严重度，不擅自升降。
#   - 反射/类加载家族（在无害框架中极常见）若确认内部/常量驱动 → 降权为 low；
#     直接执行类 sink（exec/system/eval 等）即便内部驱动也保持原严重度
#     （硬编码命令仍可能是植入后门，安全优先，不降权）。

# 外部输入源（污点 Source）正则——命中即视为"外部可控"
TAINT_SOURCE_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r"\$_GET\b", r"\$_POST\b", r"\$_REQUEST\b", r"\$_COOKIE\b",
        r"\$_FILES\b", r"\$_SERVER\b",                 # PHP 超全局
        r"request\.get(?:Parameter|Header|QueryString|InputStream|Reader|Cookies?|Part)\b",
        r"\$\w+\.getParameter\b",                       # JSP EL ${param.x}
        r"\bargv\b", r"sys\.argv", r"os\.environ\b",    # CLI / 环境变量
        r"\bunserialize\s*\(",                          # PHP 反序列化入口
        r"ObjectInputStream", r"readObject\s*\(", r"__wakeup\s*\(",  # Java/PHP 反序列化
        r"getInputStream\s*\(\s*\)", r"getQueryString\s*\(\s*\)",
        r"\bcookie\b", r"getCookies\b",
        r"base64_decode\s*\(\s*[\$\(]",                 # 运行时（非字面量）解码输入
        r"file_get_contents\s*\(\s*['\"]php://input",   # PHP 原始请求体
    ]
]

# 反射 / 类加载家族规则：内部驱动时降权（无害库常见）
TAINT_REFLECTION_RULES = {
    "JAVA-EXEC-003",   # URLClassLoader 远程加载类
    "JAVA-EXEC-004",   # ClassLoader.defineClass(Base64)
    "JAVA-EXEC-005",   # Class.forName().newInstance
    "PHP-EXEC-011",    # ReflectionFunction/Method（字面量函数名多为良性元编程）
    # P1-1 跨行/跨语句反射链：在无害框架中同样常见，交污点分析判定是否降权
    "XLINE-JAVA-002",
    "XLINE-JAVA-004",
    "XLINE-CHAIN-001",
    "XLINE-CHAIN-002",
}
TAINT_DOWNGRADE_TO = "low"

# 变量赋值提取：LHS 简单变量，RHS 表达式（到 ; 或行尾）
_TAINT_ASSIGN_RE = re.compile(r"(?<![\w$.])([$]?[A-Za-z_]\w*)\s*=\s*(.+?)(?=;|$)")
# 类/资源名字面量（带点分段标识符，如 "com.foo.Bar"）——判定"内部常量驱动"的唯一依据，
# 避免把方法名("do")/命令("ls")等字面量误判为内部常量而错误降权。
_TAINT_CLASS_LITERAL_RE = re.compile(r"""['"]([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+)['"]""")
# 行内变量 token（含可选 $ 前缀）
_TAINT_VAR_TOKEN_RE = re.compile(r"[$]?[A-Za-z_]\w*")


def _taint_is_scope_boundary(line: str) -> bool:
    """识别函数/方法/类/块边界，用于限定污点传播作用域，避免跨作用域误传播。"""
    s = line.strip()
    if s == "}" or s.startswith("}"):
        return True
    # 语句行不是作用域边界：`[\w<>\[\]]+\s+[\w]+` 分支会把 "return foo(" / "new Foo("
    # 这类"关键字 空格 标识符("误判成方法定义，从而清空变量污点、漏标 external。
    # 定义行以 `{`/`:` 结尾（不在 `;` 结尾），且不以控制流/返回类关键字开头。
    if s.endswith(";"):
        return False
    if re.match(r"(?:return|throw|yield|await|if|for|while|switch|case|else|do|break|continue|new|delete)\b",
                s, re.IGNORECASE):
        return False
    if re.match(r"(?:public|private|protected|static|final|async\s+)?\s*"
                r"(?:function|def|sub|class|void|[\w<>\[\]]+\s+[\w]+)\s*[\(\{]",
                s, re.IGNORECASE):
        return True
    return False


def _taint_var_marked(line: str, var_taint: Dict[str, str], mark: str) -> bool:
    """行内是否出现被标记为 mark 的变量（作为 sink 参数使用）。"""
    for tok in _TAINT_VAR_TOKEN_RE.findall(line):
        key = tok.lstrip("$")
        if var_taint.get(key) == mark:
            return True
    return False


# ============================================================
# 数据结构
# ============================================================

@dataclass
class RegexMatch:
    """单条正则命中"""
    rule_id: str
    line_number: int
    matched_text: str
    category: str           # code_execution | obfuscation | memory_horse | c2_network | persistence
    severity: str           # critical | high | medium | low
    description: str
    language: str           # php | java | asp | python | shell | generic
    tags: List[str] = field(default_factory=list)
    cwe: str = ""
    # P1-2 污点可达性：external=由外部输入驱动 / internal=内部常量或字面量驱动 /
    # unknown=无法静态判定（动态/跨作用域） / n/a=非 code_execution sink
    taint: str = "unknown"
    # P2-1 跨语言归因：规则声明语言与文件实际语言不符时置 True。
    # 仅作可观测标记与去重依据，不单独改变严重度判定。
    cross_language: bool = False


@dataclass
class ScanResult:
    """正则扫描完整结果"""
    total_matches: int = 0
    matches: List[RegexMatch] = field(default_factory=list)
    matches_by_category: Dict[str, int] = field(default_factory=dict)
    matches_by_severity: Dict[str, int] = field(default_factory=dict)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    # 语言检测提示（供 AI 引擎参考）
    language_hints: List[str] = field(default_factory=list)
    # 去重后的规则 ID 列表（供概览）
    triggered_rules: List[str] = field(default_factory=list)
    # 摘要文本（供 AI Prompt 注入）
    summary: str = ""
    # 扫描过程告警（如正则超时降级），供调用方展示，不参与判定
    warnings: List[str] = field(default_factory=list)
    # P2-1 因跨语言重复归因而被抑制的命中数（仅统计，不参与判定）
    cross_language_suppressed: int = 0


# ============================================================
# P2-1 语言识别特征库
# ============================================================

# 内容采样长度：语言特征通常集中在文件头部（shebang / import / package），
# 取前 N 字符即可覆盖，同时避免对超大输入做全量正则。
LANG_SAMPLE_CHARS = 4000

# 认定某语言所需的最少独立特征命中数。
# 设为 2 是为了让 "public class"（Java 与 C# 同形）、"function"（PHP 与 JS 同形）
# 这类单一同形结构不足以单独定性，必须配合该语言的其它独有特征。
LANG_MARKER_THRESHOLD = 2

# 各语言独有语法标记。注意刻意避开跨语言同形结构作为唯一依据。
LANG_MARKERS: Dict[str, List[Any]] = {
    "php": [
        re.compile(r"<\?php", re.I),
        re.compile(r"\$\w+\s*=\s*\$_(?:GET|POST|REQUEST|COOKIE|SERVER|FILES)", re.I),
        re.compile(r"\b(?:echo|print)\s+[\"'$]", re.I),
        re.compile(r"->\s*\w+\s*\("),
        re.compile(r"\bnamespace\s+[\w\\\\]+;"),
    ],
    "java": [
        re.compile(r"\bimport\s+java[x]?\."),
        re.compile(r"\bpublic\s+(?:final\s+)?class\s+\w+"),
        re.compile(r"\bjavax?\.servlet\."),
        re.compile(r"\bSystem\.(?:out|err)\.print"),
        re.compile(r"@(?:Override|RequestMapping|Controller|Autowired)\b"),
    ],
    "csharp": [
        re.compile(r"\busing\s+System(?:\.|\s|;)"),
        re.compile(r"\bnamespace\s+[\w.]+(?:\s*\{)"),
        re.compile(r"\bConsole\.(?:Write|WriteLine|Read)"),
        re.compile(r"\b(?:public|private|internal)\s+partial\s+class\b"),
        re.compile(r"\bstring\[\]\s+args\b"),
    ],
    "javascript": [
        re.compile(r"\brequire\s*\(\s*[\"']|\bfrom\s+[\"'][\w./-]+[\"']"),
        re.compile(r"\bmodule\.exports\b|\bexport\s+(?:default|const|function|class)\b"),
        re.compile(r"\bdocument\.|window\.|location\.|navigator\."),
        re.compile(r"^\s*(?:var|let|const)\s+\w+\s*=", re.M),
        re.compile(r"=>|\bfunction\s*\(|\bfunction\s+\w+\s*\("),
        re.compile(r"\bconsole\.log\s*\(|\bgetElementById\b|\baddEventListener\b|\binnerHTML\b"),
    ],
    "go": [
        re.compile(r"\bpackage\s+main\b"),
        re.compile(r"\bimport\s+\("),
        re.compile(r"\bfunc\s+\w+\s*\([^)]*\)\s*(?:\(|\{|[\w\[\]*])"),
        re.compile(r"\bfmt\.(?:Print|Printf|Println|Sprintf)"),
        re.compile(r":="),
    ],
    "ruby": [
        re.compile(r"\brequire\s+[\"'][\w/]+[\"']"),
        re.compile(r"\bputs\s+[\"':\w]"),
        re.compile(r"\battr_(?:reader|writer|accessor)\b"),
        re.compile(r"^\s*end\s*$", re.M),
        re.compile(r"\bdef\s+\w+\s*(?:\(|\s*$)", re.M),
    ],
    "powershell": [
        re.compile(r"\$\w+\s*=\s*Get-\w+"),
        re.compile(r"\b(?:Get|Set|New|Invoke|Write)-\w+"),
        re.compile(r"\bparam\s*\(\s*\["),
        re.compile(r"-(?:EncodedCommand|ExecutionPolicy|NoProfile)\b"),
        re.compile(r"\$\(\s*\$\w+\s*\)|\$_\."),
    ],
    "python": [
        re.compile(r"\bdef\s+\w+\s*\([^)]*\)\s*:"),
        re.compile(r"^\s*(?:from\s+[\w.]+\s+)?import\s+\w+", re.M),
        re.compile(r"\bif\s+__name__\s*==\s*[\"']__main__[\"']"),
        re.compile(r"\bself\.\w+\s*="),
        re.compile(r":\s*$", re.M),
    ],
    "shell": [
        re.compile(r"#!/(?:bin|usr/bin)/\w*(?:sh|bash|zsh)"),
        re.compile(r"^\s*(?:export\s+)?[A-Z_]+=\S", re.M),
        re.compile(r"\$\(\s*[a-z_]+\s|\$\{?[A-Z_]+\}?"),
        re.compile(r"\b(?:if|elif)\s+\[\s|;\s*then\b"),
        re.compile(r"\b(?:echo|printf)\s+[\"']"),
    ],
    "asp": [
        re.compile(r"<%@\s*(?:Page|Language|Import)", re.I),
        re.compile(r"\bResponse\.Write\b", re.I),
        re.compile(r"\bRequest\.(?:QueryString|Form|Cookies)\b", re.I),
        re.compile(r"\bServer\.CreateObject\b", re.I),
        re.compile(r"\bDim\s+\w+\s*(?:As\s+\w+)?", re.I),
    ],
}


# ============================================================
# 五维正则规则库
# ============================================================
# 每条规则格式:
#   (rule_id, pattern, category, severity, description, language, [tags], cwe)

PATTERN_RULES: List[Dict[str, Any]] = [
    # ════════════════════════════════════════════════════════
    # 维度一：WebShell 高危函数执行 (code_execution)
    # ════════════════════════════════════════════════════════

    # ── PHP ──
    ("PHP-EXEC-001", r"\beval\s*\(\s*\$", "code_execution", "critical",
     "PHP eval() 动态变量执行 — WebShell 最常见入口", "php",
     ["eval", "webshell", "code_execution"], "CWE-94"),
    ("PHP-EXEC-002", r"\bassert\s*\(\s*\$", "code_execution", "critical",
     "PHP assert() 接收动态变量 — 常被用作 eval 替代绕过", "php",
     ["assert", "webshell", "code_execution"], "CWE-94"),
    ("PHP-EXEC-003", r"\b(?:system|passthru|shell_exec|exec)\s*\(.*\$", "code_execution", "critical",
     "PHP 命令执行函数接收动态输入", "php",
     ["system", "command_execution", "webshell"], "CWE-78"),
    ("PHP-EXEC-004", r"\b(?:popen|proc_open)\s*\(.*\$", "code_execution", "high",
     "PHP 进程管道函数接收动态输入", "php",
     ["popen", "proc_open", "command_execution"], "CWE-78"),
    ("PHP-EXEC-005", r"\bpreg_replace\s*\(.*['\"]/.*[^\\\\]/e", "code_execution", "critical",
     "PHP preg_replace /e 修饰符 — PHP5 经典代码执行后门", "php",
     ["preg_replace", "deprecated", "code_execution"], "CWE-94"),
    ("PHP-EXEC-006", r"\bcreate_function\s*\(\s*\$", "code_execution", "critical",
     "PHP create_function() 动态函数创建 — 底层 eval 等价", "php",
     ["create_function", "code_execution"], "CWE-94"),
    ("PHP-EXEC-007", r"\b(?:call_user_func|call_user_func_array)\s*\(.*\$", "code_execution", "high",
     "PHP 回调函数动态调用 — 常见免杀绕过手法", "php",
     ["callback", "dynamic_call"], "CWE-94"),
    ("PHP-EXEC-008", r"\b(?:array_map|array_filter|array_walk|array_reduce)\s*\(\s*['\"](?:system|eval|assert|passthru|exec|shell_exec)", "code_execution", "high",
     "PHP 数组回调伪装命令执行", "php",
     ["array_callback", "obfuscation"], "CWE-94"),
    ("PHP-EXEC-009", r"\$\{?\{.*\$", "code_execution", "medium",
     "PHP 变量变量/动态变量名 ($$) — 常见免杀手法", "php",
     ["variable_variable", "obfuscation"], "CWE-94"),
    ("PHP-EXEC-010", r"\b(?:include|require|include_once|require_once)\s*\(\s*\$", "code_execution", "high",
     "PHP 动态文件包含 — 潜在远程文件包含 (RFI)", "php",
     ["file_inclusion", "rfi"], "CWE-98"),
    ("PHP-EXEC-011", r"\b(?:ReflectionFunction|ReflectionMethod)\s*\(.*\$", "code_execution", "medium",
     "PHP 反射 API 动态调用 — 绕过函数名检测", "php",
     ["reflection", "obfuscation"], "CWE-94"),
    ("PHP-EXEC-012", r"\b(?:register_shutdown_function|register_tick_function)\s*\(.*\$", "code_execution", "medium",
     "PHP 注册回调为后门触发器", "php",
     ["shutdown", "persistence"], "CWE-94"),
    ("PHP-EXEC-013", r"\$\w+\s*=\s*(?:\$_+(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|(?:['\"][^'\"]*['\"]\s*\.\s*)+['\"][^'\"]*['\"])\s*[^;]*;\s*[^;]*?\$\w+\s*\(", "code_execution", "high",
     "PHP 变量函数一句话木马 — 函数名来自外部输入或字符串拼接（如 $f=$_GET['f']; $f(...) / $a='sys'.'tem'; $a(...)）", "php",
     ["variable_function", "dynamic_call", "webshell"], "CWE-94"),

    # ── Java/JSP ──
    ("JAVA-EXEC-001", r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(", "code_execution", "critical",
     "Java Runtime.exec() 命令执行 — JSP WebShell 核心特征", "java",
     ["runtime", "exec", "jsp_webshell"], "CWE-78"),
    ("JAVA-EXEC-002", r"new\s+ProcessBuilder\s*\(.*\)\s*\.\s*start\s*\(\s*\)", "code_execution", "critical",
     "Java ProcessBuilder 进程创建", "java",
     ["processbuilder", "command_execution"], "CWE-78"),
    ("JAVA-EXEC-003", r"new\s+URLClassLoader\s*\(.*\)\s*\.\s*loadClass", "code_execution", "high",
     "Java URLClassLoader 远程加载类 — Ice Scorpion 特征", "java",
     ["urlclassloader", "remote_loading"], "CWE-470"),
    ("JAVA-EXEC-004", r"\bdefineClass\s*\(.*Base64", "code_execution", "critical",
     "Java ClassLoader.defineClass 动态加载 Base64 编码字节码 — 经典内存马注入", "java",
     ["defineclass", "memory_horse", "base64"], "CWE-470"),
    ("JAVA-EXEC-005", r"Class\s*\.\s*forName\s*\(.*\)\s*\.\s*newInstance", "code_execution", "high",
     "Java 反射动态加载类 — 常见免杀绕过", "java",
     ["reflection", "forname"], "CWE-470"),
    ("JAVA-EXEC-006", r"new\s+javax\.script\.ScriptEngineManager", "code_execution", "high",
     "Java ScriptEngine 脚本引擎 — 可执行 JS/Python 代码", "java",
     ["scriptengine", "nashorn"], "CWE-94"),
    ("JAVA-EXEC-007", r"\.getMethod\s*\(.*\)\s*\.\s*invoke\s*\(.*\)", "code_execution", "medium",
     "Java 反射方法调用 — 免杀绕过常用", "java",
     ["reflection", "invoke"], "CWE-470"),

    # ── ASP/ASPX ──
    ("ASP-EXEC-001", r"\bEval\s*\(\s*Request", "code_execution", "critical",
     "ASP Eval(Request) — ASP 一句话木马经典特征", "asp",
     ["eval", "asp_webshell"], "CWE-94"),
    ("ASP-EXEC-002", r"\bExecute\s*\(\s*Request", "code_execution", "critical",
     "ASP Execute(Request) — 动态执行请求内容", "asp",
     ["execute", "asp_webshell"], "CWE-94"),
    ("ASP-EXEC-003", r"\bExecuteGlobal\s*\(\s*Request", "code_execution", "critical",
     "ASP ExecuteGlobal(Request) — 全局作用域代码执行", "asp",
     ["executeglobal", "asp_webshell"], "CWE-94"),
    ("ASP-EXEC-004", r"Server\s*\.\s*CreateObject\s*\(.*Scripting", "code_execution", "high",
     "ASP Server.CreateObject 创建脚本对象", "asp",
     ["createobject", "scripting"], "CWE-94"),
    ("ASP-EXEC-005", r"WScript\s*\.\s*Shell", "code_execution", "critical",
     "ASP 调用 WScript.Shell — Windows 命令执行", "asp",
     ["wscript", "shell", "command_execution"], "CWE-78"),
    ("ASP-EXEC-006", r"Scripting\s*\.\s*FileSystemObject", "code_execution", "high",
     "ASP Scripting.FileSystemObject — 文件操作后门", "asp",
     ["filesystemobject", "file_operation"], "CWE-73"),

    # ── Python ──
    ("PY-EXEC-001", r"\bos\.(?:system|popen)\s*\(.*(?:\$|input|request|get|post|cookie)", "code_execution", "critical",
     "Python os.system/popen 执行动态输入 — Web 后门", "python",
     ["os_system", "popen", "command_execution"], "CWE-78"),
    ("PY-EXEC-002", r"\bsubprocess\.(?:Popen|call|run|check_output|check_call)\s*\(.*(?:input|request|get|post|cookie|\$)", "code_execution", "critical",
     "Python subprocess 执行动态输入", "python",
     ["subprocess", "command_execution"], "CWE-78"),
    ("PY-EXEC-003", r"\bexec\s*\(\s*(?:compile|__import__|base64|request|input)", "code_execution", "critical",
     "Python exec() 动态执行 — Web 后门特征", "python",
     ["exec", "code_execution"], "CWE-94"),
    ("PY-EXEC-004", r"\beval\s*\(\s*(?:request|input|get|post|cookie)", "code_execution", "critical",
     "Python eval() 执行动态输入", "python",
     ["eval", "code_execution"], "CWE-94"),
    ("PY-EXEC-005", r"\bpickle\.(?:loads|load)\s*\(", "code_execution", "high",
     "Python pickle 反序列化 — 潜在 RCE", "python",
     ["pickle", "deserialization", "rce"], "CWE-502"),
    ("PY-EXEC-006", r"\b__import__\s*\(.*(?:os|subprocess|sys|ctypes)", "code_execution", "high",
     "Python __import__ 动态导入敏感模块", "python",
     ["import", "dynamic_import"], "CWE-94"),
    ("PY-EXEC-007", r"\b(?:ctypes|CFFI)\s*\.\s*(?:CDLL|WinDLL|dlopen)\s*\(", "code_execution", "high",
     "Python ctypes/cffi 动态加载系统库 — 绕过检测执行", "python",
     ["ctypes", "native_code"], "CWE-94"),

    # ── Shell ──
    ("SH-EXEC-001", r"\bnc\s+.*-e\s+/bin/(?:sh|bash|zsh)", "code_execution", "critical",
     "Netcat 反弹 Shell — 经典后门", "shell",
     ["netcat", "reverse_shell", "nc"], "CWE-78"),
    ("SH-EXEC-002", r"\bbash\s+-i\s*>&\s*/dev/tcp/", "code_execution", "critical",
     "Bash 反弹 Shell (TCP)", "shell",
     ["bash", "reverse_shell", "dev_tcp"], "CWE-78"),
    ("SH-EXEC-003", r"/dev/tcp/\d+\.\d+\.\d+\.\d+/", "code_execution", "critical",
     "Linux /dev/tcp 反弹 Shell 设备", "shell",
     ["dev_tcp", "reverse_shell"], "CWE-78"),

    # ════════════════════════════════════════════════════════
    # 维度二：恶意混淆特征 (obfuscation)
    # ════════════════════════════════════════════════════════

    ("OBF-001", r"\(\s*~[\x21-\x7E]{2,}(?:\s*\.\s*~[\x21-\x7E]{2,}){3,}", "obfuscation", "critical",
     "PHP 无字母数字异或注入 (XOR Shell) — 特徵：(~XXX)(~YYY) 大段位运算拼接", "php",
     ["xor_shell", "non_alphanumeric", "bitwise"], "CWE-506"),
    ("OBF-002", r"""['"](?:[\x21-\x7E]{1000,})['"]""", "obfuscation", "high",
     "超长无空格连续字符串字面量 (≥1000, 含引号) — 疑似硬编码嵌入的 Base64/Hex 恶意荷载", "generic",
     ["long_string", "embedded_payload", "base64"], "CWE-506"),
    ("OBF-003", r"\b(?:base64_decode|base64_encode)\s*\(.*(?:base64_decode|gzinflate|gzuncompress|str_rot13)\s*\(", "obfuscation", "critical",
     "多层解码嵌套 — base64 -> gzinflate -> str_rot13 链式混淆 (冰蝎/哥斯拉特征)", "php",
     ["multilayer_decode", "behinder", "godzilla"], "CWE-506"),
    ("OBF-004", r"\b(?:str_rot13|gzuncompress|gzinflate|gzdecode|convert_uudecode)\s*\(.*(?:base64|\$)", "obfuscation", "high",
     "PHP 动态解密/解压变形函数 — 免杀荷载还原", "php",
     ["decrypt", "decompress", "dynamic"], "CWE-506"),
    ("OBF-005", r"\bhex2bin\s*\(|['\"][0-9A-Fa-f]{64,}['\"]", "obfuscation", "medium",
     "大段 Hex 编码字符串 — 疑似编码混淆荷载", "generic",
     ["hex", "encoding"], "CWE-506"),
    ("OBF-006", r"\b(?:chr|ord)\s*\(\s*(?:0x[0-9A-Fa-f]+|\d{2,3})", "obfuscation", "medium",
     "chr/ord 字符码点绕过 — 规避关键字检测", "php",
     ["chr", "ord", "character_code"], "CWE-506"),
    ("OBF-007", r"\bstrrev\s*\(.*base64", "obfuscation", "medium",
     "PHP strrev 字符串反转 + base64 — 免杀双重绕过", "php",
     ["strrev", "reverse", "base64"], "CWE-506"),
    ("OBF-008", r"['\"]\s*\.\s*['\"]\s*\.\s*['\"]\s*\.\s*['\"]\s*\.", "obfuscation", "medium",
     "多段字符串拼接 (>4段) — 疑似关键字拆分绕过", "generic",
     ["string_concat", "keyword_split"], "CWE-506"),
    ("OBF-009", r"['\"][\x21-\x7E]{500,}['\"]\s*\.\s*['\"]", "obfuscation", "medium",
     "大段字符串拼接 — 分散存储恶意代码", "generic",
     ["string_concat", "payload_split"], "CWE-506"),
    ("OBF-010", r"\b(?:urldecode|rawurldecode)\s*\(.*(?:eval|assert|system|\$)", "obfuscation", "high",
     "URL 解码后动态执行 — 免杀 URL 编码绕过", "php",
     ["urldecode", "encoding_bypass"], "CWE-506"),

    # ════════════════════════════════════════════════════════
    # 维度三：Java/多平台内存马 (memory_horse)
    # ════════════════════════════════════════════════════════

    # ── 传统 Filter/Servlet/Listener ──
    ("MEM-001", r"new\s+javax\.servlet\.(?:Filter|Servlet|ServletRequestListener|ServletRequestAttributeListener)", "memory_horse", "critical",
     "Java Servlet/Filter 动态实例化 — 内存马注册前兆", "java",
     ["filter", "servlet", "dynamic_registration"], "CWE-706"),
    ("MEM-002", r"\.\s*addFilter\s*\(|\.\s*addServlet\s*\(|\.\s*addListener\s*\(|addMappingForUrlPatterns\s*\(", "memory_horse", "critical",
     "动态注册 Filter/Servlet/Listener — 经典内存马核心行为", "java",
     ["filter_registration", "servlet_registration", "listener"], "CWE-706"),
    ("MEM-003", r"FilterRegistration\s*\.\s*Dynamic|ServletRegistration\s*\.\s*Dynamic", "memory_horse", "critical",
     "Servlet 3.0+ 动态 Registration API — 内存马标准接口", "java",
     ["servlet3", "dynamic_registration"], "CWE-706"),

    # ── Spring 内存马 ──
    ("MEM-004", r"RequestMappingHandlerMapping|RequestMappingInfo", "memory_horse", "critical",
     "Spring RequestMapping 动态注册 — Spring 内存马核心", "java",
     ["spring", "requestmapping", "controller"], "CWE-706"),
    ("MEM-005", r"WebApplicationContext|ApplicationContext\s*\.\s*getBean|ConfigurableWebApplicationContext", "memory_horse", "critical",
     "Spring ApplicationContext 动态获取 — Controller/Interceptor 注入前兆", "java",
     ["spring", "applicationcontext", "bean_injection"], "CWE-706"),
    ("MEM-006", r"InterceptorRegistration|HandlerInterceptor|HandlerInterceptorAdapter", "memory_horse", "high",
     "Spring Interceptor 动态注册 — 内存马拦截器变种", "java",
     ["spring", "interceptor"], "CWE-706"),

    # ── Agent 内存马 ──
    ("MEM-007", r"(?:com\.sun\.tools\.attach\.)?VirtualMachine\s*\.\s*(?:attach|loadAgent)", "memory_horse", "critical",
     "Java Agent 内存马 — VirtualMachine.attach/loadAgent 注入", "java",
     ["agent", "virtualmachine", "attach"], "CWE-706"),
    ("MEM-008", r"java\.lang\.instrument\.Instrumentation|Instrumentation\s*\.\s*(?:addTransformer|redefineClasses|retransformClasses)", "memory_horse", "critical",
     "Java Instrumentation API — Agent 内存马字节码转换", "java",
     ["instrumentation", "bytecode_transform", "agent"], "CWE-706"),
    ("MEM-009", r"(?:premain|agentmain)\s*\(\s*String\s+\w+\s*,\s*Instrumentation", "memory_horse", "critical",
     "Java Agent premain/agentmain 入口 — Agent 内存马标准签名", "java",
     ["agent", "premain", "agentmain"], "CWE-706"),

    # ── WebSocket 内存马 ──
    ("MEM-010", r"ServerEndpoint|ServerApplicationConfig\s*\.\s*getEndpoint", "memory_horse", "high",
     "Java WebSocket Endpoint 动态注册 — WebSocket 内存马", "java",
     ["websocket", "endpoint"], "CWE-706"),
    ("MEM-011", r"javax\.websocket\.server\.ServerContainer\s*\.\s*addEndpoint", "memory_horse", "high",
     "WebSocket ServerContainer.addEndpoint — 动态 WebSocket 注册", "java",
     ["websocket", "dynamic_endpoint"], "CWE-706"),

    # ── 通用内存马工具特征 ──
    ("MEM-012", r"javassist|Javassist|ClassPool\s*\.\s*getDefault", "memory_horse", "high",
     "Javassist 字节码操控库 — 内存马常用工具", "java",
     ["javassist", "bytecode"], "CWE-706"),
    ("MEM-013", r"ASM\s*\.\s*(?:ClassVisitor|ClassWriter|ClassReader)", "memory_horse", "medium",
     "ASM 字节码框架 — 内存马底层操作", "java",
     ["asm", "bytecode"], "CWE-706"),

    # ════════════════════════════════════════════════════════
    # 维度四：C2 网络特征与反弹 Shell (c2_network)
    # ════════════════════════════════════════════════════════

    # ── 硬编码 IP ──
    ("NET-001", r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b", "c2_network", "medium",
     "硬编码 IPv4 地址 (八位组 0-255 校验) — 疑似 C2 外联", "generic",
     ["ipv4", "hardcoded"], "CWE-798"),
    ("NET-002", r"0x[0-9A-Fa-f]{8}\b", "c2_network", "high",
     "十六进制 IP 编码 (如 0x7F000001) — IP 混淆绕过", "generic",
     ["hex_ip", "obfuscation", "ip_bypass"], "CWE-506"),
    ("NET-003", r"\b(?:4294967295|[12]\d{9}|3[0-7]\d{8})\b", "c2_network", "high",
     "长整数 IP 编码 — 十进制 IP 混淆", "generic",
     ["decimal_ip", "obfuscation", "ip_bypass"], "CWE-506"),
    ("NET-004", r"\binet_aton\s*\(|\binet_ntoa\s*\(|\binet_pton\s*\(|\binet_ntop\s*\(", "c2_network", "high",
     "IP 转换函数 — 常用于 IP 混淆绕过", "generic",
     ["inet", "ip_conversion", "obfuscation"], "CWE-506"),

    # ── 高危端口 ──
    ("NET-005", r"\b(?:4444|5555|6666|7777|8888|9999|50050|1337|31337|8080|8443|9090|10086)\b", "c2_network", "high",
     "高危/非标端口 — Metasploit/CobaltStrike/冰蝎 常用", "generic",
     ["port", "c2_port", "backdoor_port"], "CWE-798"),

    # ── Socket / 网络连接 ──
    ("NET-006", r"\b(?:fsockopen|pfsockopen|stream_socket_client)\s*\(.*\$", "c2_network", "high",
     "PHP Socket 连接函数接收动态参数 — C2 信道建立", "php",
     ["socket", "fsockopen", "c2_channel"], "CWE-300"),
    ("NET-007", r"\bsocket\s*\.\s*(?:connect|create_connection|socket)\s*\(", "c2_network", "high",
     "Socket 连接函数 — 建立外发 C2 通道", "generic",
     ["socket", "connect", "c2_channel"], "CWE-300"),
    ("NET-008", r"\bcurl_exec\s*\(|curl_setopt\s*\(.*CURLOPT_URL", "c2_network", "medium",
     "cURL 执行 — 数据外发/远程加载", "generic",
     ["curl", "data_exfiltration"], "CWE-300"),
    ("NET-009", r"\.\s*DownloadString\s*\(|\.\s*DownloadFile\s*\(|\.\s*DownloadData\s*\(", "c2_network", "high",
     "PowerShell/.NET DownloadString/DownloadFile — 远程荷载下载", "generic",
     ["downloadstring", "powershell", "remote_load"], "CWE-300"),
    ("NET-010", r"new\s+WebClient\s*\(\s*\)\s*\.\s*(?:DownloadString|DownloadFile|UploadString)", "c2_network", "high",
     "Java .NET WebClient 远程下载 — C2 荷载拉取", "java",
     ["webclient", "download", "remote_load"], "CWE-300"),

    # ── 反弹 Shell ──
    ("NET-011", r"\bmkfifo\s+|/tmp/\w+\.pipe|/tmp/\w+\.fifo", "c2_network", "critical",
     "命名管道 mkfifo — Linux 经典反弹 Shell 管道", "shell",
     ["mkfifo", "named_pipe", "reverse_shell"], "CWE-78"),
    ("NET-012", r"\bpty\.spawn\s*\(\s*['\"](/bin/|/usr/bin/)", "c2_network", "critical",
     "Python pty.spawn 派生交互式终端 — 反弹 Shell 升级 TTY", "python",
     ["pty", "spawn", "tty_upgrade"], "CWE-78"),
    ("NET-013", r"""python\s+.*['\"]import\s+pty['\"]|python3?\s+-c\s+['\"].*pty""", "c2_network", "critical",
     "Python 命令行导入 pty — 反弹 Shell TTY 升级", "shell",
     ["pty", "reverse_shell", "tty_upgrade"], "CWE-78"),

    # ── 隐蔽隧道 ──
    ("NET-014", r"\b(?:iodine|dns2tcp|dnscat2|heyoka)\b", "c2_network", "critical",
     "DNS 隧道工具 — 隐蔽 C2 信道", "generic",
     ["dns_tunnel", "covert_channel"], "CWE-300"),
    ("NET-015", r"\b(?:icmpsh|icmpshell|ptunnel|hans)\b|\bICMP\s*\.\s*(?:send|create)\b", "c2_network", "critical",
     "ICMP 隧道工具 — 隐蔽 C2 信道", "generic",
     ["icmp_tunnel", "covert_channel"], "CWE-300"),
    ("NET-016", r"\bssh\s+-[LDR]\s+\d+|ssh\s+.*-f\s+-N\b", "c2_network", "high",
     "SSH 端口转发/隧道 — 隐蔽数据通道", "shell",
     ["ssh_tunnel", "port_forwarding"], "CWE-300"),
    ("NET-017", r"\b(?:ngrok|frp|chisel|socat)\b", "c2_network", "high",
     "内网穿透/隧道工具 — FRP/Ngrok/Chisel 代理", "generic",
     ["tunnel", "proxy", "frp", "ngrok"], "CWE-300"),

    # ── 冰蝎/哥斯拉加密通信特征 ──
    ("NET-018", r"\bAES\s*\.\s*(?:encrypt|decrypt)|Cipher\s*\.\s*getInstance\s*\(\s*['\"]AES", "c2_network", "high",
     "AES 加密通信 — 冰蝎/哥斯拉标准 C2 加解密", "generic",
     ["aes", "encryption", "behinder", "godzilla"], "CWE-327"),
    ("NET-019", r"\bopenssl_(?:encrypt|decrypt|public_encrypt|private_decrypt)\s*\(", "c2_network", "high",
     "OpenSSL 加解密 — 加密 C2 通信", "php",
     ["openssl", "encryption", "c2"], "CWE-327"),

    # ════════════════════════════════════════════════════════
    # 维度五：系统持久化常驻指纹 (persistence)
    # ════════════════════════════════════════════════════════

    # ── Linux 持久化 ──
    ("PER-001", r"\bcrontab\s+-[elr]|/etc/cron\.(?:d|daily|hourly|monthly|weekly)\b", "persistence", "critical",
     "Linux crontab 计划任务操作 — 持久化驻留", "shell",
     ["crontab", "cron", "persistence"], "CWE-506"),
    ("PER-002", r"@(?:reboot|daily|hourly|weekly|monthly|yearly|midnight|annually)", "persistence", "critical",
     "Cron 特殊时间宏 — 计划任务持久化预定义时间", "shell",
     ["cron", "schedule", "persistence"], "CWE-506"),
    ("PER-003", r"~/.bashrc|~/.profile|~/.bash_profile|/etc/profile\b", "persistence", "high",
     "Shell 配置文件写入 — 登录时自动执行后门", "shell",
     ["bashrc", "profile", "login_execution"], "CWE-506"),
    ("PER-004", r"\bssh.*authorized_keys\b|\.ssh/authorized_keys", "persistence", "critical",
     "SSH authorized_keys 操作 — 添加后门公钥", "shell",
     ["ssh", "authorized_keys", "backdoor_key"], "CWE-506"),
    ("PER-005", r"\b(?:systemctl\s+enable|update-rc\.d|chkconfig\s+--add)\b", "persistence", "critical",
     "Linux 服务注册 — 持久化自启服务", "shell",
     ["systemctl", "service", "autostart"], "CWE-506"),
    ("PER-006", r"/etc/init\.d/|/etc/systemd/system/", "persistence", "high",
     "Linux 启动脚本目录 — 服务持久化位置", "shell",
     ["initd", "systemd", "startup"], "CWE-506"),

    # ── Windows 持久化 ──
    ("PER-007", r"\bschtasks\s+/create\b|\bschtasks\s+\/query\b", "persistence", "critical",
     "Windows schtasks 计划任务 — 持久化驻留", "generic",
     ["schtasks", "scheduled_task", "persistence"], "CWE-506"),
    ("PER-008", r"\bsc\s+create\b.*start=\s*auto\b|\bsc\s+config\b", "persistence", "critical",
     "Windows sc create 服务注册自动启动 — 持久化", "generic",
     ["sc_create", "service", "persistence"], "CWE-506"),
    ("PER-009", r"HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\b|HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\b", "persistence", "critical",
     "Windows 注册表 Run 键 — 开机自启持久化", "generic",
     ["registry", "run_key", "startup", "persistence"], "CWE-506"),
    ("PER-010", r"\breg\s+add\s+.*CurrentVersion\\Run\b|reg\s+add\s+.*RunOnce\b", "persistence", "critical",
     "注册表添加自启项 — Windows 持久化标准手法", "generic",
     ["reg_add", "registry", "persistence"], "CWE-506"),
    ("PER-011", r"Startup\\|\\Start Menu\\Programs\\Startup\\|AppData\\Roaming\\Microsoft\\Windows\\Start Menu", "persistence", "high",
     "Windows 启动文件夹 — 快捷方式持久化", "generic",
     ["startup_folder", "persistence"], "CWE-506"),
    ("PER-012", r"\bWMI\s*\.\s*ExecQuery|__EventFilter|CommandLineEventConsumer", "persistence", "high",
     "WMI 事件订阅 — Windows 高级持久化 (WMI Persistence)", "generic",
     ["wmi", "event_subscription", "persistence"], "CWE-506"),

    # ── 跨平台持久化特征 ──
    ("PER-013", r"\bboot\.ini\b|\bautoexec\.bat\b|\bwin\.ini\b", "persistence", "high",
     "Windows 经典启动配置文件篡改", "generic",
     ["boot_config", "persistence", "legacy"], "CWE-506"),
    ("PER-014", r"\buseradd\s+|adduser\s+|net\s+user\s+\S+\s+/add\b|net\s+localgroup\s+administrators", "persistence", "critical",
     "系统账户创建 — 添加后门/影子账户持久化", "generic",
     ["useradd", "backdoor_account", "persistence"], "CWE-506"),

    # ── 低危：信息收集/侦查特征 ──
    ("INFO-001", r"\b(?:whoami|hostname|ipconfig|ifconfig|netstat)\b", "code_execution", "low",
     "系统信息探测命令 — 攻击前置侦查行为", "generic",
     ["recon", "information_gathering"], "CWE-200"),
    ("INFO-002", r"\b(?:ping\s+-[tn]\s+\d|nslookup|dig\s+|traceroute|tracert)\b", "c2_network", "low",
     "网络探测命令 — 可能用于 C2 连通性测试", "generic",
     ["recon", "network_probe"], "CWE-200"),

    # ════════════════════════════════════════════════════════
    # 维度一扩展：JS / Node 高危执行 (code_execution)
    # ════════════════════════════════════════════════════════
    ("JS-EXEC-001", r"(?:require|import)\s*\(?\s*['\"]child_process['\"]", "code_execution", "high",
     "Node.js 引入 child_process 模块 — 命令执行前置", "javascript",
     ["child_process", "node", "import"], "CWE-78"),
    ("JS-EXEC-002", r"child_process\.(?:exec|execSync|spawn|spawnSync|execFile)\s*\(", "code_execution", "critical",
     "Node.js child_process 命令执行 — WebShell/后门核心", "javascript",
     ["child_process", "command_execution", "node"], "CWE-78"),
    ("JS-EXEC-003", r"new\s+Function\s*\(", "code_execution", "critical",
     "JS new Function() 从字符串创建函数 — 动态代码执行", "javascript",
     ["new_function", "code_execution"], "CWE-94"),
    ("JS-EXEC-004", r"vm\.(?:runInThisContext|runInNewContext|runInContext|compileFunction)\s*\(", "code_execution", "critical",
     "Node.js vm 模块任意代码执行 — 沙箱逃逸/后门", "javascript",
     ["vm", "code_execution"], "CWE-94"),
    ("JS-EXEC-005", r"\beval\s*\(\s*(?![\$])", "code_execution", "critical",
     "JS eval() 动态执行 — 免杀常见入口（已排除 PHP 变量形式 eval($)）", "javascript",
     ["eval", "code_execution"], "CWE-94"),
    ("JS-EXEC-006", r"\b(?:setTimeout|setInterval)\s*\(\s*['\"]", "code_execution", "low",
     "JS 以字符串形式传入 setTimeout/setInterval — 字符串即代码执行（良性也常见，低危提示）", "javascript",
     ["settimeout", "string_code"], "CWE-94"),

    # ════════════════════════════════════════════════════════
    # 维度一扩展：Go 高危执行 / 外连 (code_execution / c2_network)
    # ════════════════════════════════════════════════════════
    ("GO-EXEC-001", r"exec\s*\.\s*Command\s*\(", "code_execution", "critical",
     "Go os/exec.Command 命令执行 — 后门核心", "go",
     ["go", "command_execution"], "CWE-78"),
    ("GO-EXEC-002", r"os\.(?:Exec|StartProcess|Execvp)\s*\(", "code_execution", "critical",
     "Go os 包进程执行函数", "go",
     ["go", "command_execution"], "CWE-78"),
    ("GO-EXEC-003", r"import\s+[\"']os/exec[\"']", "code_execution", "low",
     "Go 引入 os/exec 包 — 命令执行前置（良性也常见，低危提示）", "go",
     ["go", "import", "os_exec"], "CWE-78"),
    ("GO-C2-001", r"net\.(?:Dial|DialTimeout|DialTCP|DialUDP)\s*\(", "c2_network", "high",
     "Go 主动外连 Socket — 疑似 C2 信道", "go",
     ["go", "socket", "c2_channel"], "CWE-300"),

    # ════════════════════════════════════════════════════════
    # 维度一扩展：Ruby 高危执行 (code_execution)
    # ════════════════════════════════════════════════════════
    ("RUBY-EXEC-001", r"\bsystem\s*\(", "code_execution", "critical",
     "Ruby system() 命令执行", "ruby",
     ["ruby", "command_execution"], "CWE-78"),
    ("RUBY-EXEC-002", r"`[^`\n]{1,200}`", "code_execution", "medium",
     "Ruby 反引号执行 shell 命令 — 一句话木马特征（良性脚本也常用，中危提示）", "ruby",
     ["ruby", "backtick", "command_execution"], "CWE-78"),
    ("RUBY-EXEC-003", r"\bexec\s*\(", "code_execution", "critical",
     "Ruby exec() 替换进程执行命令", "ruby",
     ["ruby", "command_execution"], "CWE-78"),
    ("RUBY-EXEC-004", r"\beval\s*\(", "code_execution", "critical",
     "Ruby eval() 动态执行", "ruby",
     ["ruby", "eval", "code_execution"], "CWE-94"),
    ("RUBY-EXEC-005", r"Open3\.(?:capture|popen|spawn)", "code_execution", "high",
     "Ruby Open3 子进程执行", "ruby",
     ["ruby", "open3", "command_execution"], "CWE-78"),
    ("RUBY-EXEC-006", r"%x\s*\(", "code_execution", "critical",
     "Ruby %x() 命令执行", "ruby",
     ["ruby", "percent_x", "command_execution"], "CWE-78"),

    # ════════════════════════════════════════════════════════
    # 维度一扩展：C# / .NET 高危执行 (code_execution)
    # ════════════════════════════════════════════════════════
    ("NET-EXEC-001", r"Process\s*\.\s*Start\s*\(", "code_execution", "critical",
     ".NET Process.Start 命令执行 — 后门核心", "csharp",
     ["dotnet", "process_start", "command_execution"], "CWE-78"),
    ("NET-EXEC-002", r"Assembly\s*\.\s*(?:Load|LoadFrom|LoadFile|LoadFromStream|UnsafeLoadFrom)\s*\(", "code_execution", "critical",
     ".NET Assembly.Load 动态加载程序集 — 内存马/后门", "csharp",
     ["dotnet", "assembly_load", "dynamic_load"], "CWE-470"),
    ("NET-EXEC-003", r"CSharpCodeProvider\s*\(\s*\)\s*\.\s*CompileAssemblyFromSource", "code_execution", "critical",
     ".NET CSharpCodeProvider 运行时编译源码 — 动态代码执行", "csharp",
     ["dotnet", "code_provider", "dynamic_compile"], "CWE-94"),
    ("NET-EXEC-004", r"PowerShell\s*\.\s*Create\s*\(|System\.Management\.Automation\.PowerShell", "code_execution", "high",
     ".NET PowerShell 运行时创建 — 命令执行前置", "csharp",
     ["dotnet", "powershell"], "CWE-78"),
    ("NET-EXEC-005", r"AppDomain\s*\.\s*CurrentDomain\s*\.\s*Load\s*\(", "code_execution", "high",
     ".NET AppDomain.Load 动态加载 — 程序集注入", "csharp",
     ["dotnet", "appdomain", "dynamic_load"], "CWE-470"),

    # ════════════════════════════════════════════════════════
    # 维度二扩展：现代 PHP 免杀 (obfuscation / code_execution)
    # ════════════════════════════════════════════════════════
    ("PHP-EVADE-002", r"[\"'][^\"']{1,12}[\"']\s*\^", "obfuscation", "medium",
     "PHP 字符串异或构造 ($_=\"X\"^\"Y\") — 免杀关键字绕过", "php",
     ["string_xor", "non_alphanumeric", "bitwise"], "CWE-506"),
    ("PHP-EVADE-003", r"\$_POST\s*\[\s*\d+\s*\]\s*\(\s*\$_POST\s*\[\s*\d+\s*\]", "code_execution", "critical",
     "PHP 变量函数调用 $_POST[0]($_POST[1]) — 一句话木马变形", "php",
     ["variable_function", "post_array", "webshell"], "CWE-94"),

    # ════════════════════════════════════════════════════════
    # 维度三扩展：内存马变体（WebFlux / Actuator / 进程注入）
    # ════════════════════════════════════════════════════════
    ("MEM-014", r"RouterFunction|HandlerFunction|RouterFunctions\s*\.\s*route|DispatcherHandler", "memory_horse", "high",
     "Spring WebFlux 路由函数动态注册 — WebFlux 内存马", "java",
     ["spring", "webflux", "router"], "CWE-706"),
    ("MEM-015", r"@Endpoint\s*\(|ActuatorEndpoint|['\"]/actuator['\"]", "memory_horse", "low",
     "Spring Boot Actuator 自定义端点/暴露 — 内存马暴露面（低危提示）", "java",
     ["spring", "actuator", "endpoint"], "CWE-706"),
    ("MEM-016", r"CreateRemoteThread|VirtualAllocEx|WriteProcessMemory|NtMapViewOfSection|QueueUserAPC", "memory_horse", "critical",
     "Windows 进程注入 API — 无文件内存注入", "generic",
     ["process_injection", "windows", "in_memory"], "CWE-506"),
    ("MEM-017", r"ptrace\s*\(|PTRACE_ATTACH|PTRACE_TRACEME", "memory_horse", "high",
     "Linux ptrace 进程注入/调试 — 无文件攻击", "generic",
     ["ptrace", "process_injection", "linux"], "CWE-506"),
    ("MEM-018", r"SetWindowsHookEx|SetWinEventHook", "memory_horse", "high",
     "Windows 钩子注入 — 持久化/无文件攻击", "generic",
     ["hook", "process_injection", "windows"], "CWE-506"),
]


# 需整行匹配（不参与分窗）的规则集：其模式跨度可能超过重叠区，见 _pattern_exceeds_overlap。
# 这类规则均为线性扫描（无嵌套量词回溯），整行匹配既安全又避免跨窗漏检。
_FULL_LINE_RULE_IDS = {
    rule[0] for rule in PATTERN_RULES
    if isinstance(rule[1], str) and _pattern_exceeds_overlap(rule[1])
}


# ============================================================
# P1-1 跨行规则层（Cross-line Rules）
# ============================================================
# 背景（实测确认）：scan() 采用逐行扫描，任何跨越多行的模式都不可能命中。
#   例：Runtime.getRuntime()\n    .exec(cmd) 虽然 JAVA-EXEC-001 的 \s* 允许换行，
#   但两部分位于不同行，逐行匹配下永不命中；多行内存马（Class.forName(...)\n.newInstance()、
#   defineClass(...)\n.newInstance()、getMethod(...)\n.invoke()）实测命中数为 0。
#
# 设计要点：
#   1) 与主规则库零重叠：跨行规则仅在「命中文本确实包含换行」时才计入。
#      单行写法虽也能被跨行正则匹配，但会被该判据丢弃，交由既有单行规则负责。
#      由于逐行扫描不可能命中含换行的文本，二者严格互补，不会虚增命中数。
#   2) 锚点驱动开窗：先用锚点正则定位候选区域，只在锚点附近的多行窗口上匹配，
#      使开销与文件总长无关，避免大文件上 O(行数 × 规则数) 的劣化。
#   3) 零执行：纯正则，不引入任何新的运行时能力。
#
# 格式（比 PATTERN_RULES 多一个 anchors 字段）：
#   (rule_id, pattern, category, severity, description, language, tags, cwe, anchors)

CROSS_LINE_RULES: List[Dict[str, Any]] = [
    # ── Java 方法链被换行打断 ──
    ("XLINE-JAVA-001",
     r"Runtime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(",
     "code_execution", "critical",
     "Java Runtime.getRuntime().exec() — 跨行写法（逐行扫描漏检，需跨行层补抓）",
     "java", ["runtime", "exec", "cross_line"], "CWE-78",
     ["getRuntime", "exec"]),

    ("XLINE-JAVA-002",
     r"Class\s*\.\s*forName\s*\([\s\S]{0,200}?\)\s*\.\s*newInstance\s*\(",
     "code_execution", "high",
     "Java Class.forName().newInstance() — 跨行反射实例化（内存马常见）",
     "java", ["reflection", "newInstance", "cross_line"], "CWE-470",
     ["forName", "newInstance"]),

    ("XLINE-JAVA-003",
     r"\bdefineClass\s*\([\s\S]{0,300}?\)\s*\.?\s*newInstance\s*\(",
     "memory_horse", "critical",
     "ClassLoader.defineClass() 后跨行实例化 — 字节马/内存马加载链",
     "java", ["defineclass", "memory_horse", "cross_line"], "CWE-470",
     ["defineClass", "newInstance"]),

    ("XLINE-JAVA-004",
     r"\.get(?:Declared)?Method\s*\([\s\S]{0,200}?\)\s*[\s\S]{0,80}?\.invoke\s*\(",
     "code_execution", "medium",
     "Java 反射 getMethod().invoke() — 跨行反射调用链",
     "java", ["reflection", "invoke", "cross_line"], "CWE-470",
     ["getMethod", "invoke"]),

    # ── Servlet 组件注册型内存马（跨行）──
    ("XLINE-MEM-001",
     r"\.(?:addServlet|addFilter|addListener)\s*\([\s\S]{0,300}?newInstance\s*\(",
     "memory_horse", "critical",
     "Servlet/Filter/Listener 注册时跨行反射实例化 — 典型内存马注入手法",
     "java", ["memory_horse", "servlet", "cross_line"], "CWE-506",
     ["addServlet", "addFilter", "addListener", "newInstance"]),

    # ── 执行函数跨行包裹解码函数（PHP / Python / JS / .NET 通用）──
    ("XLINE-EXEC-001",
     r"\b(?:eval|assert|system|exec|passthru|shell_exec|popen|proc_open)\s*\(\s*[\s\S]{0,160}?"
     r"(?:base64_decode|b64decode|base64\s*\.\s*b64decode|gzinflate|gzuncompress|"
     r"gzdecode|str_rot13|hex2bin|convert_uudecode|urldecode|rawurldecode|"
     r"atob|FromBase64String)\s*\(",
     "code_execution", "critical",
     "执行函数跨行包裹解码函数（eval(\\n  base64_decode(...)）— 混淆 WebShell 常见",
     "generic", ["eval", "decode", "obfuscation", "cross_line"], "CWE-94",
     ["base64_decode", "b64decode", "gzinflate", "gzuncompress", "gzdecode",
      "str_rot13", "hex2bin", "uudecode", "urldecode", "atob", "FromBase64String"]),
]

# 跨行窗口：以锚点所在行为中心，向前/向后各取的行数
CROSS_LINE_WINDOW_BEFORE = 3
CROSS_LINE_WINDOW_AFTER = 4
# 单个窗口的字符上限（超出则截断，防止异常长行拖慢匹配）
CROSS_LINE_WINDOW_MAX_CHARS = 4000
# 候选窗口数量上限（防御锚点极多的巨型输入导致扫描劣化）。
# 实测：7.5MB / 4000 锚点的极端输入下，上限 400→1200 仅增约 1.1s，
# 而覆盖度提升约 3 倍；真实恶意样本锚点集中，通常不会触及该上限。
CROSS_LINE_MAX_WINDOWS = 1200

# ── 跨语句反射链（P1-1b）──
# 真实内存马几乎都写成"先获取 Class/Method 存入变量，再用该变量实例化/调用"，
# 两步位于不同语句，跨行正则也无法命中，需按变量传播配对。
CROSS_STMT_MAX_DISTANCE = 25  # 工厂与使用之间的最大行距
_CLASS_FACTORY_RE = re.compile(
    r"(?:Class\s*\.\s*forName|\bdefineClass|\bloadClass|"
    r"new\s+Reflection(?:Class|Function|Method))\s*\(",
    re.IGNORECASE,
)
_METHOD_FACTORY_RE = re.compile(r"\.get(?:Declared)?Method\s*\(", re.IGNORECASE)

# ── 形参驱动识别（P3 误报治理）──
# `Class.forName(className)` 中的 className 若为所在方法的形参，静态上既非外部输入、
# 也非内部常量（真实来源取决于调用方），判 high 会大量误伤工厂/框架代码。
# 仅匹配"以 { 或 : 结尾、无语句终止符"的方法定义行，避免把普通调用 foo(x) 当签名。
# 标识符长度加界（{1,120}/{1,64}）：无界 \w+ 在超长"字母数字长串"单行上会灾难性
# 回溯（40KB 单行实测 ~10s）；真实类型名/方法名远短于上限，加界不改变匹配语义。
_TAINT_METHOD_DEF_RE = re.compile(
    r"[\w<>\[\]?]{1,120}\s+[\w$]{1,64}\s*\(([^()]*)\)\s*(?:throws\s+[\w\s,.]*)?[{:]\s*$"
)
# 工厂调用实参提取（不含嵌套括号，够用且无回溯风险）
_CLASS_FACTORY_ARG_RE = re.compile(
    r"(?:forName|defineClass|loadClass)\s*\(([^()]*)\)", re.IGNORECASE)
_METHOD_FACTORY_ARG_RE = re.compile(
    r"\.get(?:Declared)?Method\s*\(([^()]*)\)", re.IGNORECASE)


def _parse_formals(params_src: str) -> set:
    """从方法签名参数串提取形参名（去泛型，取每段末位标识符）。"""
    out = set()
    for seg in params_src.split(","):
        seg = re.sub(r"<[^<>]*>", " ", seg).strip()
        tokens = re.findall(r"[$]?[A-Za-z_]\w*", seg)
        if tokens:
            out.add(tokens[-1].lstrip("$"))
    return out


def _is_param_driven(def_text: str, kind: str, formals: set) -> bool:
    """工厂实参是否由所在方法的形参驱动（静态不可判定其真实来源）。"""
    if not formals:
        return False
    arg_re = _CLASS_FACTORY_ARG_RE if kind == "class" else _METHOD_FACTORY_ARG_RE
    m = arg_re.search(def_text)
    if not m:
        return False
    for tok in _TAINT_VAR_TOKEN_RE.findall(m.group(1)):
        if tok.lstrip("$") in formals:
            return True
    return False

# 所有锚点合并成一条正则，用于一次性 O(n) 定位候选区域
_CROSS_LINE_ANCHOR_RE = re.compile(
    "|".join(sorted({re.escape(a) for rule in CROSS_LINE_RULES for a in rule[8]})),
    re.IGNORECASE,
)


# ============================================================
# 扫描引擎
# ============================================================

_HIGHLIGHT_CATEGORIES = {
    "code_execution", "obfuscation", "memory_horse", "c2_network", "persistence",
}
_CRYPTO_CONTEXT_RE = re.compile(
    r"Cipher\s*\.\s*getInstance|SecretKeySpec|IvParameterSpec|"
    r"openssl_(?:encrypt|decrypt)|AES|DES|RC4|doFinal|MessageDigest|md5\s*\(",
    re.IGNORECASE,
)

# ── 加密通信类规则的通道上下文降权（P3 误报治理）──
# `Cipher.getInstance("AES")` / `openssl_encrypt(...)` 是任何加密工具库的标配，
# 单独出现不构成"加密 C2 通信"的证据。真正的冰蝎/哥斯拉必然同时具备
# 外发通道或外部请求输入；两者皆无时按本地加解密处理，避免良性库被判 high。
CRYPTO_COMM_RULES = {"NET-018", "NET-019"}
# 通道能力一：网络/下载/命令执行类 API
_EGRESS_CAPABILITY_RE = re.compile(
    r"\b(?:Socket|ServerSocket|URLConnection|HttpURLConnection|HttpClient|openConnection)\b|"
    r"java\.net\.|fsockopen|pfsockopen|stream_socket_client|socket_create|socket_connect|"
    r"curl_exec|curl_setopt|DownloadString|DownloadFile|WebClient|Invoke-WebRequest|"
    r"requests\.(?:get|post)\b|urllib|fetch\s*\(|XMLHttpRequest|/dev/tcp|"
    r"Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec|ProcessBuilder|Invoke-Expression|os\.system|"
    r"subprocess\.|Runtime\.getRuntime\(\)",
    re.IGNORECASE,
)
# 通道能力二：外部请求/标准输入读取（WebShell 与请求体加解密的必备环节）
_INGRESS_CAPABILITY_RE = re.compile(
    r"request\s*\.\s*get|request\s*\[|\bRequest\s*\.\s*(?:Form|QueryString|Body|Params)|"
    r"Server\.Variables|\$_GET|\$_POST|\$_REQUEST|\$_COOKIE|php://input|"
    r"getInputStream|getReader|readLine\s*\(|readObject\s*\(|ObjectInputStream|"
    r"\bstdin\b|System\.in\b|Read-Host|Get-Content\s+.*-Raw",
    re.IGNORECASE,
)
_STRING_ASSIGN_RE = re.compile(
    # 变量名长度加界（{0,63}）避免无界 \w* 在超长字母数字单行上灾难性回溯
    # （40KB 单行实测 ~12s）；真实变量名远短于 64，匹配语义不变。
    r"(?P<var>[$]?[A-Za-z_]\w{0,63})\s*=\s*['\"](?P<value>[A-Za-z0-9+/=_-]{8,128})['\"]"
)
_DIRECT_CRYPTO_LITERAL_RE = re.compile(
    r"(?:SecretKeySpec|IvParameterSpec|Cipher\s*\.\s*getInstance)\s*\([^\n]{0,100}?"
    r"['\"](?P<value>[A-Za-z0-9+/=_-]{8,128})['\"]",
    re.IGNORECASE,
)
_CRYPTO_VAR_USAGE_TEMPLATE = (
    r"(?:SecretKeySpec|IvParameterSpec)\s*\([^)]*?"
    r"(?<!\w)[$]?{variable}(?!\w)(?:\s*\.\s*getBytes\s*\([^)]*\))?"
    r"|(?:init|update|doFinal)\s*\([^)]*?(?<!\w)[$]?{variable}(?!\w)"
)


def build_highlight_hints(code: str, matches: List[RegexMatch]) -> List[Dict[str, Any]]:
    """Build stable, evidence-backed token highlights without executing the sample."""
    lines = code.splitlines()
    hints: List[Dict[str, Any]] = []
    seen = set()

    def add(line: int, text: str, category: str, reason: str, source: str = "regex"):
        token = (text or "").strip()
        if not token or len(token) > 160 or line < 1 or line > len(lines):
            return
        if token not in lines[line - 1]:
            return
        key = (line, token, category)
        if key in seen:
            return
        seen.add(key)
        hints.append({
            "line": line, "text": token, "category": category,
            "reason": reason, "source": source,
        })

    for match in matches:
        if (match.category in _HIGHLIGHT_CATEGORIES
                and match.severity in {"critical", "high", "medium"}):
            add(match.line_number, match.matched_text, match.category, match.description)

    crypto_lines = {index for index, line in enumerate(lines, 1) if _CRYPTO_CONTEXT_RE.search(line)}
    if crypto_lines:
        assignments = []
        for index, line in enumerate(lines, 1):
            for match in _STRING_ASSIGN_RE.finditer(line):
                assignments.append((index, match.group("var").lstrip("$"), match.group("value")))
            for match in _DIRECT_CRYPTO_LITERAL_RE.finditer(line):
                add(index, match.group("value"), "crypto_key", "硬编码值直接参与加解密调用", "context")

        crypto_window = "\n".join(lines[max(0, min(crypto_lines) - 9):min(len(lines), max(crypto_lines) + 8)])
        for line_number, variable, value in assignments:
            explicit_name = re.search(r"key|secret|pass|pwd|aes|des|iv", variable, re.IGNORECASE)
            used_near_crypto = re.search(
                _CRYPTO_VAR_USAGE_TEMPLATE.format(variable=re.escape(variable)),
                crypto_window,
                re.IGNORECASE,
            )
            near_crypto = any(abs(line_number - crypto_line) <= 8 for crypto_line in crypto_lines)
            if used_near_crypto and (explicit_name or near_crypto):
                add(line_number, value, "crypto_key", "硬编码值参与加解密或通信认证", "context")

    return sorted(hints, key=lambda item: (item["line"], item["text"], item["category"]))


def suppress_cross_language_matches(matches: List[dict], language_hints) -> Tuple[List[dict], int]:
    """跨语言归因去重——须在**合并了复合行为命中之后**再跑一次。

    为什么需要第二次：复合命中（FLOW-* 等）的 language 取文件语言，是"原生锚点"，
    但它们由 enrich_regex_scan 在 RegexScanner.scan() 的跨语言策略**之后**才并入，
    策略当时看不到锚点，于是"整组只有跨语言命中"被整体保留——报告里就会出现
    「Perl 文件命中 PHP-EXEC-003」「JS 文件命中 RUBY-EXEC-003」这种别扭归因。

    判据与 scan() 内保持一致（保守、不丢检）：仅当同一 (行号, 类别) 组内既有跨语言
    命中、又有原生/通用命中时，才移除跨语言那一条；整组都是跨语言命中则保留。
    返回 (保留的 matches, 被移除条数)。
    """
    hints = set(language_hints or [])
    if not hints or hints == {"generic"}:
        return list(matches), 0
    for m in matches:
        lang = m.get("language")
        if lang and lang != "generic" and lang not in hints:
            m["cross_language"] = True
    groups: Dict[Tuple[Any, Any], List[int]] = {}
    for idx, m in enumerate(matches):
        groups.setdefault((m.get("line_number"), m.get("category")), []).append(idx)
    drop: set = set()
    for idxs in groups.values():
        if len(idxs) < 2:
            continue
        flags = [bool(matches[i].get("cross_language")) for i in idxs]
        if any(flags) and not all(flags):
            drop.update(i for i in idxs if matches[i].get("cross_language"))
    kept = [m for i, m in enumerate(matches) if i not in drop]
    return kept, len(drop)


class RegexScanner:
    """
    多维静态正则扫描引擎。

    使用示例：
        scanner = RegexScanner()
        result = scanner.scan(code_content, filename="shell.php")
        print(f"命中 {result.total_matches} 条规则")
        print(f"严重: {result.critical_count}, 高: {result.high_count}")
    """

    # 编译后缓存（类级别，避免重复编译）
    _compiled_patterns: Optional[List[tuple]] = None

    @classmethod
    def _get_compiled(cls) -> List[tuple]:
        """懒加载编译正则规则库（线程安全在单进程下不成问题）"""
        if cls._compiled_patterns is not None:
            return cls._compiled_patterns

        compiled = []
        for rule in PATTERN_RULES:
            rule_id, pattern, category, severity, description, language, tags, cwe = rule
            try:
                if SUPPORTS_REGEX_TIMEOUT:
                    # 仅当 re 实现支持 timeout 时才传入（标准库 re 不支持，见文件头说明）
                    compiled_re = re.compile(
                        pattern, re.IGNORECASE | re.MULTILINE, timeout=REGEX_SCAN_TIMEOUT
                    )
                else:
                    # 标准库 re 无超时能力，ReDoS 防护由 scan() 的超长行分窗承担
                    compiled_re = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                compiled.append((rule_id, compiled_re, category, severity, description, language, tags, cwe))
            except re.error as e:
                # 规则语法错误不应阻断整个引擎
                print(f"[RegexScanner] WARNING: 规则 {rule_id} 编译失败: {e}", flush=True)
        cls._compiled_patterns = compiled
        return compiled

    @staticmethod
    def detect_language_hints(filename: str = "", code: str = "") -> List[str]:
        """
        从文件名和代码内容推测语言类型。

        P2-1 修复：
        - 补齐 javascript / go / ruby / csharp / perl 的扩展名与内容特征
          （此前这些语言的脚本一律落到 generic，语言元数据失真）；
        - 修正 .cs 因 "public class" 被误判为 java 的问题；
        - 内容判定改为「多特征计分」，支持混合语言（如 PHP 页面内嵌 JS）
          同时输出多种语言，避免单特征误判。

        返回语言提示列表（供 AI 引擎参考，并作为跨语言归因依据）。
        """
        hints: List[str] = []
        ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""

        ext_map = {
            "php": "php", "phtml": "php", "phar": "php",
            "php3": "php", "php4": "php", "php5": "php", "php7": "php", "inc": "php",
            "jsp": "java", "jspx": "java", "java": "java", "war": "java",
            "asp": "asp", "aspx": "asp", "asmx": "asp", "ashx": "asp", "asa": "asp",
            "py": "python", "pyw": "python", "pyi": "python",
            "ps1": "powershell", "psm1": "powershell", "psd1": "powershell",
            "sh": "shell", "bash": "shell", "zsh": "shell", "ksh": "shell",
            "js": "javascript", "jsx": "javascript", "mjs": "javascript",
            "cjs": "javascript", "ts": "javascript", "tsx": "javascript",
            "go": "go",
            "rb": "ruby", "rake": "ruby", "erb": "ruby", "gemspec": "ruby",
            "cs": "csharp", "csx": "csharp",
            "pl": "perl", "pm": "perl", "cgi": "perl",
            "vbs": "asp", "vba": "asp",
        }
        if ext in ext_map:
            hints.append(ext_map[ext])

        # ── 内容特征计分 ──
        # 每种语言取若干独有语法标记；命中 ≥ LANG_MARKER_THRESHOLD 个不同标记
        # 才认定该语言存在。阈值 >1 可抑制 "public class" 这类跨语言同形结构
        # 造成的误判（Java 与 C# 共用该写法）。
        sample = code[:LANG_SAMPLE_CHARS]
        scores: Dict[str, int] = {}
        for lang, patterns in LANG_MARKERS.items():
            score = 0
            for pat in patterns:
                if pat.search(sample):
                    score += 1
                    if score >= LANG_MARKER_THRESHOLD:
                        break
            if score >= LANG_MARKER_THRESHOLD:
                scores[lang] = score

        # 按得分降序并入，保证强特征语言排在前面
        for lang, _score in sorted(scores.items(), key=lambda kv: -kv[1]):
            if lang not in hints:
                hints.append(lang)

        if not hints:
            hints.append("generic")
        return hints

    @classmethod
    def _apply_cross_language_policy(cls, result: "ScanResult") -> None:
        """P2-1 跨语言归因治理。

        背景：规则库带 language 字段，但扫描时全量匹配、从不按语言过滤，
        因此 PHP 的 eval( 会同时命中 PHP-EXEC-001 与 RUBY-EXEC-004，Java 的
        .exec( 会同时命中 XLINE-JAVA-001 与 RUBY-EXEC-003。这类重复归因会
        虚增 critical/high 计数，并在报告中出现"Ruby 规则命中 PHP 文件"这种
        损害结论可信度的描述。

        策略（保守，优先保证不丢检）：
        1. 标记：规则语言与文件实际语言不符时置 cross_language=True；
        2. 去重：仅当「同一行 + 同一类别」既有原生语言命中、又有跨语言命中时，
           才移除跨语言那一条（原生规则已覆盖该处风险，不产生信息损失）；
        3. 不降级、不抑制孤立的跨语言命中——混合语言文件（如 PHP 内嵌 JS）
           中非原生语言的部分往往是真实载荷所在。

        仅在语言可确信判定（非 generic）时生效；generic 输入完全不做处理。
        """
        hints = set(result.language_hints)
        if not hints or hints == {"generic"}:
            return

        for m in result.matches:
            if m.language != "generic" and m.language not in hints:
                m.cross_language = True

        # 按 (行号, 类别) 分组：组内存在原生命中时，移除该组的跨语言命中
        groups: Dict[Tuple[int, str], List[RegexMatch]] = {}
        for m in result.matches:
            groups.setdefault((m.line_number, m.category), []).append(m)

        suppressed_ids: set = set()
        for (_line, _cat), group in groups.items():
            if len(group) < 2:
                continue
            if not any(m.cross_language for m in group):
                continue
            if not any(not m.cross_language for m in group):
                # 整组都是跨语言命中：说明该语言在文件中确实存在但未被识别，
                # 或语言识别有误——保留全部，避免丢检。
                continue
            for m in group:
                if m.cross_language:
                    suppressed_ids.add(id(m))

        if suppressed_ids:
            result.matches = [m for m in result.matches if id(m) not in suppressed_ids]
            result.cross_language_suppressed = len(suppressed_ids)

    @classmethod
    def _apply_taint_analysis(cls, result: "ScanResult", lines: List[str]) -> None:
        """P1-2 污点可达性分析：对 code_execution 类 sink 标注 taint 并调整严重度。

        纯静态、零执行：仅基于正则匹配行内 source / 变量赋值传播判定。
        直接改 result.matches 中每条 RegexMatch 的 .taint 与 .severity（原地修改）。
        """
        if not result.matches:
            return

        # 1) 行→是否含外部源 索引 + 变量污点映射（按作用域边界限定）
        line_has_source: Dict[int, bool] = {}
        var_taint: Dict[str, str] = {}
        # 最近一条方法签名的形参（跨语句链层同一判据，保持判定一致）
        formals: set = set()
        for i, line in enumerate(lines, start=1):
            sig = _TAINT_METHOD_DEF_RE.search(line)
            if sig:
                formals = _parse_formals(sig.group(1))
            if _taint_is_scope_boundary(line):
                var_taint = {}  # 进入新作用域，清空变量污点，防止跨作用域误传播
            line_has_source[i] = any(p.search(line) for p in TAINT_SOURCE_PATTERNS)
            for am in _TAINT_ASSIGN_RE.finditer(line):
                var = am.group(1).lstrip("$")
                rhs = am.group(2)
                if any(p.search(rhs) for p in TAINT_SOURCE_PATTERNS):
                    var_taint[var] = "external"
                elif _TAINT_CLASS_LITERAL_RE.search(rhs):
                    var_taint.setdefault(var, "internal_class")

        # 2) 逐 sink 判定
        for m in result.matches:
            if m.category != "code_execution":
                m.taint = "n/a"
                continue
            # 跨语句链在生成阶段已按"工厂行"完成污点判定，此处不得用 sink 行覆盖
            if getattr(m, "taint", "unknown") in {"external", "internal", "param"}:
                continue
            ln = m.line_number
            line = lines[ln - 1] if 1 <= ln <= len(lines) else ""
            if line_has_source.get(ln) or _taint_var_marked(line, var_taint, "external"):
                taint = "external"
            elif _TAINT_CLASS_LITERAL_RE.search(line) or _taint_var_marked(line, var_taint, "internal_class"):
                taint = "internal"
            elif (_is_param_driven(line, "class", formals)
                  or _is_param_driven(line, "method", formals)):
                taint = "param"
            else:
                taint = "unknown"
            m.taint = taint

            # 3) 严重度调整（安全优先：仅在明确证据下升降）
            if taint == "external":
                if m.severity != "critical":
                    m.severity = "critical"   # 外部可达 → 升/保 critical
            elif taint == "internal":
                if m.rule_id in TAINT_REFLECTION_RULES:
                    # 反射/类加载家族：内部/常量驱动，几乎必为无害框架代码 → 降权
                    m.severity = TAINT_DOWNGRADE_TO
                # 其余 sink（exec/system/eval）内部驱动保持原严重度（硬编码命令仍可疑）
            elif taint == "param" and m.rule_id in TAINT_REFLECTION_RULES:
                # 形参驱动反射：无外部可达证据，与跨语句链层保持同一判据。
                # 保留 medium 而非 low——真实来源取决于调用方，需语义层复核。
                m.severity = "medium" if m.severity in ("high", "critical") else m.severity
            # unknown → 维持原规则严重度，不擅自升降

    @classmethod
    def _apply_crypto_channel_policy(cls, result: "ScanResult", lines: List[str]) -> None:
        """P3 误报治理：无通道证据的加解密调用降权为 low。

        判据是"能否与外界交换数据"而非"用了什么加密 API"：
        只有当样本同时具备外发通道（网络/下载/命令执行）或外部输入读取时，
        加密才可能被用于 C2 通信；否则按本地加解密处理。
        """
        if not result.matches:
            return

        has_channel = False
        for line in lines:
            if _EGRESS_CAPABILITY_RE.search(line) or _INGRESS_CAPABILITY_RE.search(line):
                has_channel = True
                break
        if has_channel:
            return

        for m in result.matches:
            if m.rule_id not in CRYPTO_COMM_RULES:
                continue
            if m.severity not in ("high", "critical"):
                continue
            m.severity = "low"
            m.tags = list(m.tags) + ["local_crypto_only"]
            m.description = f"{m.description}（无外发通道证据：按本地加解密降权）"

    # 跨行规则编译缓存
    _cross_compiled: Optional[List[tuple]] = None

    @classmethod
    def _get_cross_compiled(cls) -> List[tuple]:
        """懒加载编译跨行规则库。"""
        if cls._cross_compiled is not None:
            return cls._cross_compiled
        compiled = []
        for rule in CROSS_LINE_RULES:
            rule_id, pattern, category, severity, description, language, tags, cwe, anchors = rule
            try:
                compiled_re = re.compile(pattern, re.IGNORECASE)
                compiled.append(
                    (rule_id, compiled_re, category, severity, description, language, tags, cwe, anchors)
                )
            except re.error as e:
                print(f"[RegexScanner] WARNING: 跨行规则 {rule_id} 编译失败: {e}", flush=True)
        cls._cross_compiled = compiled
        return compiled

    @classmethod
    def _scan_cross_line(cls, code: str, lines: List[str]) -> Tuple[List[RegexMatch], List[str]]:
        """P1-1 跨行规则扫描：锚点驱动开窗，仅在多行窗口上匹配。

        逐行扫描无法命中任何跨越多行的模式，本层用于补抓多行内存马、
        跨行方法链、执行函数跨行包裹解码等形态。

        Returns:
            (命中列表, 过程告警)
        """
        warnings: List[str] = []
        if len(lines) < 2:
            return [], warnings

        # 行起始全局偏移 → 供命中偏移反查行号（bisect 二分，O(log n)）
        line_starts: List[int] = []
        off = 0
        for ln in lines:
            line_starts.append(off)
            off += len(ln) + 1  # +1 抵消 split("\n") 去掉的换行符

        # 1) 锚点定位 → 候选窗口（按窗口区间去重，与文件总长无关）
        windows: Dict[Tuple[int, int], int] = {}
        truncated = False
        for am in _CROSS_LINE_ANCHOR_RE.finditer(code):
            idx = bisect.bisect_right(line_starts, am.start()) - 1
            start = max(0, idx - CROSS_LINE_WINDOW_BEFORE)
            end = min(len(lines), idx + CROSS_LINE_WINDOW_AFTER + 1)
            key = (start, end)
            if key in windows:
                continue
            if len(windows) >= CROSS_LINE_MAX_WINDOWS:
                truncated = True
                break
            windows[key] = line_starts[start]

        if truncated:
            warnings.append(
                f"跨行扫描窗口数达上限 {CROSS_LINE_MAX_WINDOWS}，"
                f"仅覆盖前 {CROSS_LINE_MAX_WINDOWS} 个候选区域"
            )

        # 2) 在窗口上跑跨行规则
        hits: List[RegexMatch] = []
        seen: set = set()
        for (start, end), win_off in windows.items():
            win_text = "\n".join(lines[start:end])
            if len(win_text) > CROSS_LINE_WINDOW_MAX_CHARS:
                win_text = win_text[:CROSS_LINE_WINDOW_MAX_CHARS]

            for (rule_id, compiled_re, category, severity, description,
                 language, tags, cwe, anchors) in cls._get_cross_compiled():
                try:
                    for match in compiled_re.finditer(win_text):
                        raw = match.group(0)
                        # 零重叠判据：仅当命中确实跨行时才计入。
                        # 单行写法由主规则库（逐行扫描）负责，此处丢弃以避免重复计数。
                        if "\n" not in raw and "\r" not in raw:
                            continue
                        abs_off = win_off + match.start()
                        key = (rule_id, abs_off)
                        if key in seen:
                            continue
                        seen.add(key)
                        idx = bisect.bisect_right(line_starts, abs_off) - 1
                        # 命中文本可能跨多行，压缩为单行便于报告展示
                        text = re.sub(r"\s+", " ", raw).strip()
                        if len(text) > 120:
                            text = text[:117] + "..."
                        hits.append(RegexMatch(
                            rule_id=rule_id,
                            line_number=idx + 1,
                            matched_text=text,
                            category=category,
                            severity=severity,
                            description=description,
                            language=language,
                            tags=list(tags),
                            cwe=cwe,
                        ))
                except Exception:
                    # 单条规则异常不中断整体扫描
                    continue

        return hits, warnings

    @classmethod
    def _scan_cross_statement(cls, lines: List[str]) -> List[RegexMatch]:
        """P1-1b 跨语句反射链：Class/Method 工厂 → 同变量实例化或调用。

        真实内存马常写成两条语句（Class.forName(c) 存入变量 → var.newInstance()），
        跨行正则同样无法命中，需按"变量赋值 → 变量使用"配对，并限制行距以免误连。

        纯静态、零执行：仅正则提取赋值左值与调用接收者。
        """
        if len(lines) < 2:
            return []

        # 变量 → (定义行号, 工厂类型 class|method, 定义行文本)
        factories: Dict[str, Tuple[int, str, str]] = {}
        hits: List[RegexMatch] = []
        seen: set = set()

        # 外部污染变量（一阶传播）：request.getParameter("c") → c → Class.forName(c) → k。
        # 工厂行本身常不含 source 词，须经变量传递才能判定驱动来源。
        external_vars: set = set()

        # 当前方法签名形参（最近一条方法定义行），用于识别"形参驱动"反射
        formals: set = set()

        for i, line in enumerate(lines, start=1):
            sig = _TAINT_METHOD_DEF_RE.search(line)
            if sig:
                formals = _parse_formals(sig.group(1))

            for am in _TAINT_ASSIGN_RE.finditer(line):
                var = am.group(1).lstrip("$")
                rhs = am.group(2)
                if any(p.search(rhs) for p in TAINT_SOURCE_PATTERNS):
                    external_vars.add(var)
                elif any(tok.lstrip("$") in external_vars
                         for tok in _TAINT_VAR_TOKEN_RE.findall(rhs)):
                    external_vars.add(var)
                if _CLASS_FACTORY_RE.search(rhs):
                    factories[var] = (i, "class", line)
                elif _METHOD_FACTORY_RE.search(rhs):
                    factories[var] = (i, "method", line)

            if "newInstance" not in line and "invoke" not in line:
                continue

            for var, (def_line, kind, def_text) in factories.items():
                if i <= def_line or i - def_line > CROSS_STMT_MAX_DISTANCE:
                    continue
                if kind == "class":
                    rule_id, category, severity = "XLINE-CHAIN-001", "code_execution", "high"
                    desc = ("跨语句反射链：Class/defineClass 结果经变量中转后实例化 "
                            "— 内存马常见写法")
                    tags = ["reflection", "newInstance", "cross_statement"]
                    sink_re = r"(?<![\w$])[$]?" + re.escape(var) + r"\s*(?:->|\.)\s*newInstance\s*\("
                else:
                    rule_id, category, severity = "XLINE-CHAIN-002", "code_execution", "medium"
                    desc = "跨语句反射链：getMethod 结果经变量中转后 invoke 调用"
                    tags = ["reflection", "invoke", "cross_statement"]
                    sink_re = r"(?<![\w$])[$]?" + re.escape(var) + r"\s*(?:->|\.)\s*invoke\s*\("

                if not re.search(sink_re, line):
                    continue
                key = (rule_id, var, i)
                if key in seen:
                    continue
                seen.add(key)

                # 污点判定必须看"工厂行"而非 sink 行：类名是否为外部输入、
                # 是否为内部字面量常量，都体现在 Class.forName(...) 那一行。
                # 否则无害反射（Class.forName("com.example.Greeter")）会绕开
                # 单行规则本已享受的降权，造成与单行形态不一致的误报。
                taint = "unknown"
                if (any(p.search(def_text) for p in TAINT_SOURCE_PATTERNS)
                        or var in external_vars):
                    taint = "external"
                    severity = "critical"
                elif _TAINT_CLASS_LITERAL_RE.search(def_text):
                    taint = "internal"
                    severity = TAINT_DOWNGRADE_TO
                elif _is_param_driven(def_text, kind, formals):
                    # 形参驱动：类名来自调用方，静态不可判定。既不能算 external（无证据），
                    # 也不该按 high 报警（工厂/框架代码普遍如此）→ 降一档保留可见度。
                    taint = "param"
                    severity = "medium" if kind == "class" else TAINT_DOWNGRADE_TO

                text = line.strip()
                if len(text) > 120:
                    text = text[:117] + "..."
                hits.append(RegexMatch(
                    rule_id=rule_id,
                    line_number=i,
                    matched_text=text,
                    category=category,
                    severity=severity,
                    description=desc,
                    language="generic",
                    tags=tags,
                    cwe="CWE-470",
                    taint=taint,
                ))

        return hits

    @classmethod
    def scan(cls, code: str, filename: str = "") -> ScanResult:
        """
        对代码文本执行全量五维正则扫描。

        Args:
            code:     待扫描的代码文本
            filename: 原始文件名（用于语言推测，不影响规则匹配）

        Returns:
            ScanResult（含所有命中、分类统计、摘要）
        """
        result = ScanResult()
        if not code or not code.strip():
            result.summary = "⚠️ 输入为空，正则引擎跳过"
            return result

        lines = code.split("\n")
        compiled = cls._get_compiled()

        # 语言推测（仅用于元数据，不隔离规则）
        result.language_hints = cls.detect_language_hints(filename, code)

        # 记录已命中规则 ID（去重，用于概览）
        triggered_set: set = set()

        # 2.5 修复：逐行扫描。每行行号天然可得(1-based)，消除原
        #   code[:pos].count("\n") 的 O(n) 行号计算（最坏接近 O(规则数×代码长²)）。
        #   单条规则编译时加 re 超时（见 _get_compiled），防御超长行上的灾难性回溯。
        # 2.6 修复：INFO-* 侦查类规则（whoami/ping 等）噪音大，直接跳过——
        #   不再计入命中/统计；其语义仍由 AI 引擎直接读码判定，避免误报稀释结论。
        cat_counter: Dict[str, int] = {}
        sev_counter = {"critical": 0, "high": 0, "medium": 0, "low": 0}

        timed_out_rules: set = set()
        windowed_lines = 0

        for line_num, line in enumerate(lines, start=1):
            if not line:
                continue
            # re 无超时能力时，对超长行主动分窗以限制单次匹配的输入规模；
            # 若 re 支持超时则保持整行匹配，仅在真正触发超时后才降级分窗。
            if not SUPPORTS_REGEX_TIMEOUT and len(line) > LONG_LINE_THRESHOLD:
                base_segments = _line_segments(line)
                windowed_lines += 1
            else:
                base_segments = [(0, line)]

            for (rule_id, compiled_re, category, severity, description,
                 language, tags, cwe) in compiled:
                # 2.6：侦查类规则跳过，不计入命中
                if rule_id.startswith("INFO-"):
                    continue

                # 跨度可能超过重叠区的规则改用整行匹配，避免跨窗被截断而漏检
                # （见 _FULL_LINE_RULE_IDS）；其余规则沿用分窗以限制单次匹配规模。
                rule_segments = [(0, line)] if rule_id in _FULL_LINE_RULE_IDS else base_segments

                found: List[Tuple[int, Any]] = []
                try:
                    for seg_offset, seg_text in rule_segments:
                        for match in compiled_re.finditer(seg_text):
                            found.append((seg_offset, match))
                except TimeoutError:
                    # 该规则在本行触发 ReDoS 超时：丢弃本轮已得的部分结果，
                    # 降级为带重叠的分窗重扫，并记入告警便于使用方排查。
                    # 注意：必须排在 except Exception 之前，否则会被静默吞掉。
                    timed_out_rules.add(rule_id)
                    retry_segments = rule_segments if rule_id in _FULL_LINE_RULE_IDS else _line_segments(line)
                    for win_offset, win_text in retry_segments:
                        try:
                            for match in compiled_re.finditer(win_text):
                                found.append((win_offset, match))
                        except Exception:
                            continue
                except Exception:
                    # 单条规则错误不中断整体扫描
                    continue

                # 分窗重叠区会对同一处命重复匹配，按行内绝对位置去重
                seen_positions: set = set()
                for seg_offset, match in found:
                    position = seg_offset + match.start()
                    if position in seen_positions:
                        continue
                    seen_positions.add(position)
                    matched_text = match.group(0)
                    # 截断过长的匹配文本
                    if len(matched_text) > 120:
                        matched_text = matched_text[:117] + "..."

                    rm = RegexMatch(
                        rule_id=rule_id,
                        line_number=line_num,
                        matched_text=matched_text,
                        category=category,
                        severity=severity,
                        description=description,
                        language=language,
                        tags=list(tags),
                        cwe=cwe,
                    )
                    result.matches.append(rm)
                    triggered_set.add(rule_id)
                    cat_counter[category] = cat_counter.get(category, 0) + 1
                    if severity in sev_counter:
                        sev_counter[severity] += 1

        # ── P1-1 跨行规则层（须在污点分析前并入，以享受可达性标注）──
        xline_hits, xline_warnings = cls._scan_cross_line(code, lines)
        xline_hits.extend(cls._scan_cross_statement(lines))
        for rm in xline_hits:
            result.matches.append(rm)
            triggered_set.add(rm.rule_id)
            cat_counter[rm.category] = cat_counter.get(rm.category, 0) + 1
        if xline_warnings:
            result.warnings.extend(xline_warnings)

        # ── P2-1 跨语言归因治理（须在污点分析前，减少待分析命中）──
        cls._apply_cross_language_policy(result)

        # ── P1-2 污点可达性分析（必须在严重度统计前执行）──
        cls._apply_taint_analysis(result, lines)

        # ── P3 加密通信降权（须在严重度统计前执行）──
        cls._apply_crypto_channel_policy(result, lines)

        # ── 统计 ──
        # 严重度已含污点调整，且跨语言去重后命中集合可能变化，
        # 因此全部从最终 result.matches 重算，避免与累计计数器不一致。
        result.total_matches = len(result.matches)
        result.triggered_rules = sorted({m.rule_id for m in result.matches})
        cat_counter = {}
        for _m in result.matches:
            cat_counter[_m.category] = cat_counter.get(_m.category, 0) + 1
        result.matches_by_category = cat_counter
        sev_counter = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for _m in result.matches:
            if _m.severity in sev_counter:
                sev_counter[_m.severity] += 1
        result.matches_by_severity = {k: v for k, v in sev_counter.items() if v}
        result.critical_count = sev_counter["critical"]
        result.high_count = sev_counter["high"]
        result.medium_count = sev_counter["medium"]
        result.low_count = sev_counter["low"]

        if windowed_lines:
            result.warnings.append(
                f"超长行分窗：{windowed_lines} 行超过 {LONG_LINE_THRESHOLD} 字符，"
                f"已按 {LONG_LINE_WINDOW} 字符窗口（重叠 {LONG_LINE_OVERLAP} 字符）分片匹配，"
                f"窗口边界处极长模式可能被截断"
            )
        if timed_out_rules:
            shown = ", ".join(sorted(timed_out_rules)[:10])
            suffix = "" if len(timed_out_rules) <= 10 else f" 等 {len(timed_out_rules)} 条"
            result.warnings.append(
                f"正则超时降级：{len(timed_out_rules)} 条规则在超长行上触发回溯超时，"
                f"已改用分窗重扫（{shown}{suffix}）"
            )

        # ── 生成摘要 ──
        parts = []
        parts.append(f"正则引擎扫描完成: {result.total_matches} 条命中, "
                      f"触发 {len(result.triggered_rules)} 条独立规则")
        parts.append(f"语言推测: {', '.join(result.language_hints)}")
        parts.append(f"严重度分布: [严重:{result.critical_count}] "
                      f"[高:{result.high_count}] [中:{result.medium_count}] [低:{result.low_count}]")

        cat_summary = ", ".join(
            f"{cat}:{cnt}" for cat, cnt in
            sorted(result.matches_by_category.items(), key=lambda x: -x[1])
        )
        parts.append(f"分类分布: {cat_summary}")

        # Top 规则
        if result.triggered_rules:
            parts.append(f"命中规则: {', '.join(result.triggered_rules[:15])}")
            if len(result.triggered_rules) > 15:
                parts.append(f"  ... 共 {len(result.triggered_rules)} 条")

        # 污点可达性统计
        _ext = sum(1 for _m in result.matches if getattr(_m, "taint", None) == "external")
        _int = sum(1 for _m in result.matches if getattr(_m, "taint", None) == "internal")
        if _ext or _int:
            parts.append(f"污点可达性: [外部输入驱动:{_ext}] [内部/常量驱动:{_int}]")

        result.summary = "\n".join(parts)
        return result

    @classmethod
    def scan_to_dict(cls, code: str, filename: str = "") -> Dict[str, Any]:
        """
        扫描并返回字典（供 API JSON 序列化）。
        """
        result = cls.scan(code, filename)
        return {
            "total_matches": result.total_matches,
            "critical_count": result.critical_count,
            "high_count": result.high_count,
            "medium_count": result.medium_count,
            "low_count": result.low_count,
            "matches_by_category": result.matches_by_category,
            "matches_by_severity": result.matches_by_severity,
            "language_hints": result.language_hints,
            "triggered_rules": result.triggered_rules,
            "summary": result.summary,
            "warnings": list(result.warnings),
            # P2-1：因跨语言重复归因而被抑制的命中数（可观测，不参与判定）
            "cross_language_suppressed": result.cross_language_suppressed,
            "matches": [
                {
                    "rule_id": m.rule_id,
                    "line_number": m.line_number,
                    "matched_text": m.matched_text,
                    "category": m.category,
                    "severity": m.severity,
                    "description": m.description,
                    "language": m.language,
                    "tags": m.tags,
                    "cwe": m.cwe,
                    "taint": m.taint,
                    # P2-1：规则语言与文件语言不符时为 True
                    "cross_language": m.cross_language,
                }
                for m in result.matches
            ],
            "highlight_hints": build_highlight_hints(code, result.matches),
        }


# ============================================================
# P3-2 确定性置信度计算（替代 LLM 自填，零执行、零 LLM 依赖）
# ============================================================

def _conf_sev_counts(regex_scan: Optional[Dict[str, Any]]) -> Dict[str, int]:
    """从扫描字典安全提取各严重度计数。"""
    if not regex_scan:
        return {"critical": 0, "high": 0, "medium": 0, "low": 0}
    sev = regex_scan.get("matches_by_severity", {}) or {}
    return {
        "critical": int(regex_scan.get("critical_count", 0) or sev.get("critical", 0) or 0),
        "high": int(regex_scan.get("high_count", 0) or sev.get("high", 0) or 0),
        "medium": int(regex_scan.get("medium_count", 0) or sev.get("medium", 0) or 0),
        "low": int(regex_scan.get("low_count", 0) or sev.get("low", 0) or 0),
    }


def _conf_taint_critical(regex_scan: Optional[Dict[str, Any]]) -> tuple:
    """统计 code_execution 类 critical sink 中，外部输入驱动 / 内部常量驱动的数量。"""
    ext = 0
    intl = 0
    if regex_scan:
        for m in regex_scan.get("matches", []) or []:
            if m.get("severity") == "critical":
                t = m.get("taint")
                if t == "external":
                    ext += 1
                elif t == "internal":
                    intl += 1
    return ext, intl


def compute_audit_confidence(
    regex_scan: Optional[Dict[str, Any]],
    decode_confidence: str = "low",
) -> float:
    """
    P3-2 确定性置信度（0-1 浮点）。

    仅依赖静态分析结果（正则严重度、污点可达性、程序化解码置信度），
    完全不依赖 LLM 输出，避免模型自填带来的不可复现 / 幻觉风险。

    语义：本值表示"引擎判定该样本为恶意的置信度"。
      - 外部输入可达的 RCE 落点（external + critical）：确定性最高。
      - 内部 / 常量驱动的 critical（理论可达，未证实外部触发）：仍高，但略降。
      - 仅 high / medium / low 命中：随证据强度递减。
      - 完全无命中：高置信为良性 → 对"恶意"判定置信度极低（约 0.10）。

    Returns:
        float，区间 [0.10, 0.96]。
    """
    sev = _conf_sev_counts(regex_scan)
    ext_crit, int_crit = _conf_taint_critical(regex_scan)
    dc = (decode_confidence or "low").lower()

    # 完全无静态命中 → 良性（对"恶意"判定置信度极低）
    if sev["critical"] == 0 and sev["high"] == 0 and sev["medium"] == 0 and sev["low"] == 0:
        return 0.10

    # 外部输入可达的 RCE 落点 → 最高置信（确定可达攻击面）
    if ext_crit > 0:
        return 0.96

    # 存在 critical（含内部驱动）
    if sev["critical"] > 0:
        return 0.92 if int_crit == 0 else 0.88

    # 高危代码执行（非 critical）
    if sev["high"] > 0:
        return 0.85 if dc == "high" else 0.80

    # 中危（混淆 / 可疑动态调用等）
    if sev["medium"] > 0:
        if dc == "high":
            return 0.65
        if dc == "medium":
            return 0.60
        return 0.55

    # 仅 low 命中（轻微混淆噪声等）
    return 0.30


def derive_risk_level(regex_scan: Optional[Dict[str, Any]]) -> str:
    """
    P3-2 由静态证据派生风险等级文本，供 done 事件 risk_assessment.overall_risk 使用。
    仅依赖 regex_scan，零 LLM 依赖。
    """
    sev = _conf_sev_counts(regex_scan)
    if sev["critical"] > 0:
        return "高危"
    if sev["high"] > 0:
        return "高"
    if sev["medium"] > 0:
        return "中"
    if sev["low"] > 0:
        return "低"
    return "安全"
