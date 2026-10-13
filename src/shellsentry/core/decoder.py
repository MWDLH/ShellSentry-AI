#!/usr/bin/env python3
"""
ShellSentry-AI 程序化纯解码层 v1.0 (decoder.py)
================================================

设计目标：
    为 [DE_OBFUSCATE] 反混淆面板提供"确定性还原"的 ground truth，
    让反混淆从"LLM 概率性推断"升级为"标准算法解码 + LLM 解读"。

安全铁律（最高优先级，任何改动不得违反）：
    - **零代码执行**。本模块绝不调用 eval / exec / compile / subprocess /
      popen，也绝不 import 任何由外部输入决定的模块。所有解码均为
      标准确定性算法（base64 / hex / rot13 / urldecode / zlib / gzip /
      deflate / PowerShell EncodedCommand / 单字节 XOR / 字符码还原）。
    - 对 eval(base64_decode($x)) 这类混淆，**仅提取"字面量参数"**做静态解码；
      若参数为运行时变量，则标记 dynamic_arg 交 LLM 处理，**绝不执行**。
    - 输入永远被视为不可信恶意样本；本模块不向外发起任何网络/文件操作。

解码策略（纯静态、链式探测）：
    base64 / hex / rot13 / urldecode 单步解码 → 若结果为文本且可打印则记为候选；
    若为压缩字节流则尝试 zlib/gzip/deflate 解压 → 再判可打印；
    若字节流既非文本也非压缩数据，则尝试单字节 XOR 暴力还原（结果须命中
    危险关键词才采纳，避免 255 种密钥带来噪声）；
    对"解码函数字面量参数"（base64_decode("...") 等）优先提取并解码；
    对 PowerShell -EncodedCommand 走 base64→UTF-16LE 专用通道；
    对 chr()/fromCharCode()/Chr() 数字码拼接做序列还原；
    对成功解码文本递归（深度 ≤ 4）以覆盖 base64(gzip(base64(...))) 等多层嵌套。
    递归全程共享 visited 集合，阻断 rot13 这类自逆运算回到原文的回路。

相关性门控（避免向 LLM 注入良性噪声）：
    仅当解码文本命中危险关键词，或本身来自"解码函数字面量参数"时才视为
    relevant（注入提示词）；纯良性长 base64（如配置 blob）虽能被解码，
    但不计入 relevant，避免干扰 DE_OBFUSCATE 输出。
"""

import base64
import codecs
import re
import zlib
from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from urllib.parse import unquote

# ============================================================
# 安全常量
# ============================================================

# 候选提取：引号字符串若"像编码"（base64/hex 形态）即纳入，下限 16 字符
# （见 _looks_encoded）；不再使用固定长阈值，避免漏掉短恶意 base64。

# 递归解码最大深度（防指数爆炸）
MAX_DECODE_DEPTH = 4

# 单次解码最多保留的候选数
MAX_RESULTS = 24

# 单次解压输出上限：防止"解压炸弹"（数十 KB 压缩数据膨胀到 GB 级）在单线程
# 审计进程中耗尽内存/长时间阻塞。合法反混淆载荷远小于此值，超限即放弃该候选。
MAX_INFLATE_OUTPUT = 2 * 1024 * 1024

# 可打印字符比例阈值（≥ 此值视为"像文本"）
PRINTABLE_RATIO = 0.90

# 相关性关键词（命中即判定解码文本为高相关，注入 LLM 参考）
# 刻意剔除 key/cmd/shell/token/password/AES/RC4 等"在良性配置文本中也常见"的泛化词，
# 仅保留确定性强的执行/外联/家族标记，避免向 LLM 注入良性噪声。
RELEVANT_KEYWORDS = re.compile(
    r"(eval|assert|system|exec|passthru|shell_exec|popen|proc_open|"
    r"Runtime\.getRuntime|ProcessBuilder|defineClass|ClassLoader|"
    r"\$_POST|\$_GET|\$_REQUEST|request\.|response\.|"
    r"os\.system|subprocess|pickle|__import__|"
    r"fromCharCode|ActiveXObject|WScript|CreateObject|"
    r"/dev/tcp|reverse\s+shell|nc\s+-e|"
    r"DownloadString|WebClient|curl\s|wget\s|"
    # PowerShell 执行族：-EncodedCommand 载荷解码后常以 IEX/Invoke-Expression 出现
    r"\bIEX\s*\(|Invoke-Expression|Invoke-WebRequest|Invoke-Command|Start-Process|"
    r"behinder|godzilla|蚁剑|冰蝎|webshell|c2\b|"
    r"动态|反射|加解密|内存马|后门|"
    r"base64_decode|gzinflate|gzuncompress|str_rot13)",
    re.IGNORECASE,
)

# 强执行类关键词（命中即 confidence=high）
STRONG_EXEC = re.compile(
    r"(eval|assert|system|exec|passthru|shell_exec|popen|proc_open|"
    r"Runtime\.getRuntime|ProcessBuilder|defineClass|"
    r"subprocess|os\.system|__import__|fromCharCode|WScript|CreateObject|"
    r"/dev/tcp|reverse\s*shell|nc\s+-e|"
    r"\bIEX\s*\(|Invoke-Expression|Invoke-Command|Start-Process)",
    re.IGNORECASE,
)

# 解码函数名（用于字面量参数提取 + 运行时依赖检测）
# 注意：必须用非捕获组 (?:...) 包裹，否则与其他正则拼接时分组会错位，
# 导致整条规则退化为"匹配裸函数名"，所有捕获组落空（group(2)=None）。
DECODE_FNS = (
    r"(?:base64_decode|b64decode|base64_encode|gzinflate|gzuncompress|"
    r"gzdecode|gzdeflate|gzencode|str_rot13|hex2bin|"
    r"convert_uudecode|urldecode|rawurldecode)"
)
DECODE_FN_RE = re.compile(DECODE_FNS, re.IGNORECASE)


# ============================================================
# 基础解码原语（全部返回 bytes / str / None，绝不执行）
# ============================================================

def _strip_non_b64(s: str) -> str:
    """去除 base64 非法字符（保留标准 + URL-safe 字符与填充符）。"""
    return re.sub(r"[^A-Za-z0-9+/=_-]", "", s)


def _fn_base64(s: str) -> Optional[bytes]:
    """尝试标准 / URL-safe base64 解码（容错：去空白、补填充）。"""
    t = re.sub(r"\s+", "", s)
    t = _strip_non_b64(t)
    if len(t) < 8:
        return None
    t += "=" * (-len(t) % 4)
    try:
        return base64.b64decode(t, validate=False)
    except Exception:
        # 刻意不抛：这里返回 None 表示"不是有效的 base64"，
        # 是解码探测的正常结果而非错误（下游会继续尝试 URL-safe 与其它算法）。
        # 若改为抛出，会中断整个 decode_recursive 的多算法探测流程。
        pass
    try:
        return base64.urlsafe_b64decode(t)
    except Exception:
        return None


def _fn_hex(s: str) -> Optional[bytes]:
    """尝试十六进制解码（容错 0x 前缀、空白）。"""
    t = re.sub(r"\s+", "", s)
    if t.lower().startswith("0x"):
        t = t[2:]
    t = re.sub(r"[^0-9A-Fa-f]", "", t)
    if len(t) < 16 or len(t) % 2 != 0:
        return None
    try:
        return bytes.fromhex(t)
    except Exception:
        return None


def _fn_rot13(s: str) -> Optional[str]:
    """ROT13（仅当含字母时尝试）。

    P1-2 修正：必须跳过 URL 百分号转义序列内部的字母。
    否则 %5B 会被整体 rot13 成 %5O（B→O），破坏转义结构，
    使后续 urldecode 无法解析，再经 rot13 自逆回路还原出半成品结果
    （如 eval($_POST%5B'cmd'%5D)%3B），污染注入 LLM 的解码参考。
    """
    if not re.search(r"[A-Za-z]", s):
        return None
    try:
        if "%" in s:
            parts = re.split(r"(%[0-9A-Fa-f]{2})", s)
            return "".join(
                p if p.startswith("%") else codecs.decode(p, "rot_13")
                for p in parts
            )
        return codecs.decode(s, "rot_13")
    except Exception:
        return None


def _fn_urldecode(s: str) -> Optional[str]:
    """URL 百分号解码（纯字符串算法，无网络/无执行）。

    仅当确实含 %XX 序列时才有意义，避免把普通文本原样返回造成噪声。
    """
    if "%" not in s:
        return None
    try:
        out = unquote(s)
    except Exception:
        return None
    return out if out != s else None


def _fn_ps_encoded(s: str) -> Optional[str]:
    """PowerShell -EncodedCommand：base64 承载的 UTF-16LE 文本。

    纯算法：base64 解码 → UTF-16LE 解码，绝不执行任何命令。
    """
    raw = _fn_base64(s)
    if raw is None or len(raw) < 4:
        return None
    for enc in ("utf-16-le", "utf-16"):
        try:
            txt = raw.decode(enc)
        except Exception:
            continue
        # 剔除 UTF-16 解码常见的空字符填充后再判可打印
        if _printable_ratio(txt.replace("\x00", "")) >= PRINTABLE_RATIO:
            return txt.replace("\x00", "")
    return None


def _try_inflate(b: bytes) -> Optional[bytes]:
    """尝试 zlib / raw-deflate / gzip 自动识别解压。

    用 decompressobj 限制单次输出上限：若达到 MAX_INFLATE_OUTPUT 后仍有未消费
    输入（unconsumed_tail 非空），说明是解压炸弹，直接放弃该候选而不返回部分结果。
    """
    for wbits in (15, -15, 47):  # 47 = 15+32 自动识别 gzip
        try:
            obj = zlib.decompressobj(wbits)
            out = obj.decompress(b, MAX_INFLATE_OUTPUT)
            if obj.unconsumed_tail:
                continue  # 超出上限 → 视为炸弹，放弃
            out += obj.flush()
            if not obj.eof:
                continue  # 流未完整结束（截断/损坏）→ 与旧版 zlib.decompress 行为一致，放弃
            return out
        except Exception:
            continue
    return None


# ── P1-2 新增解码通道 ──
# 单字节 XOR 暴力：用于还原"解码后仍非文本"的字节流（常见于简单免杀）。
# 为避免 256 次尝试带来噪声与开销，仅采纳命中 RELEVANT_KEYWORDS 的结果。
XOR_MAX_LEN = 512
XOR_PRINTABLE_RATIO = 0.95

# PowerShell -EncodedCommand 载荷（base64 承载 UTF-16LE）
_PS_ENC_RE = re.compile(
    r"-(?:encodedcommand|enc|e)\b\s+([A-Za-z0-9+/=_-]{16,})",
    re.IGNORECASE,
)

# 字符码拼接：chr(101)+chr(118)... / String.fromCharCode(101,118,...)
_CHARCODE_CALL_RE = re.compile(
    r"(?:chr|chrw|fromCharCode)\s*\(\s*(\d{1,4}(?:\s*,\s*\d{1,4})*)\s*\)",
    re.IGNORECASE,
)
# 相邻调用之间允许的连接符与最大间隔，超出则视为互不相关的两段
_CHARCODE_JOIN_MAX_GAP = 12
_CHARCODE_JOIN_ALLOWED = re.compile(r"^[+.&\s\\]*$")


def _try_xor_bruteforce(b: bytes) -> Optional[Tuple[str, int]]:
    """单字节 XOR 暴力还原（纯算法、零执行）。

    用 bytes.translate 做整表异或（C 实现），避免 Python 层逐字节循环。
    仅当还原文本命中危险关键词时才采纳，否则视为噪声丢弃。

    Returns:
        (还原文本, 密钥字节) 或 None
    """
    if not b or len(b) > XOR_MAX_LEN:
        return None
    for key in range(1, 256):
        try:
            out = b.translate(bytes(i ^ key for i in range(256)))
        except Exception:
            continue
        txt = _to_text(out)
        if not txt or _printable_ratio(txt) < XOR_PRINTABLE_RATIO:
            continue
        if RELEVANT_KEYWORDS.search(txt):
            return txt, key
    return None


def extract_ps_encoded(code: str) -> List[Tuple[str, int]]:
    """提取 PowerShell -EncodedCommand / -enc 载荷。

    Returns:
        [(base64 载荷, 字符偏移), ...]
    """
    return [(m.group(1), m.start(1)) for m in _PS_ENC_RE.finditer(code)]


def extract_charcode_sequences(code: str) -> List[Tuple[int, str]]:
    """还原 chr()/ChrW()/fromCharCode() 数字码拼接出的明文（纯算法、零执行）。

    覆盖三种常见形态：
      - JS:  String.fromCharCode(101,118,97,108)
      - PHP/Python: chr(101).chr(118) / chr(101)+chr(118)
      - ASP/VB: Chr(101) & Chr(118)

    Returns:
        [(起始偏移, 还原文本), ...]
    """
    calls = list(_CHARCODE_CALL_RE.finditer(code))
    if not calls:
        return []

    results: List[Tuple[int, str]] = []

    def flush(group: List[re.Match]) -> None:
        codes: List[int] = []
        for m in group:
            codes.extend(int(x) for x in re.findall(r"\d+", m.group(1)))
        if len(codes) < 3:  # 过短不足以构成有意义的字符串，多为噪声
            return
        chars: List[str] = []
        for c in codes:
            if 0 <= c <= 0x10FFFF and (32 <= c <= 126 or 9 <= c <= 13 or c > 127):
                chars.append(chr(c))
        if len(chars) < 3:
            return
        text = "".join(chars)
        if len(text) >= 4 and _printable_ratio(text) >= PRINTABLE_RATIO:
            results.append((group[0].start(), text))

    group: List[re.Match] = [calls[0]]
    for prev, cur in zip(calls, calls[1:]):
        gap = code[prev.end():cur.start()]
        if len(gap) <= _CHARCODE_JOIN_MAX_GAP and _CHARCODE_JOIN_ALLOWED.match(gap):
            group.append(cur)
        else:
            flush(group)
            group = [cur]
    flush(group)

    return results


def _to_text(b: bytes) -> Optional[str]:
    """字节转文本（utf-8 优先，latin-1 兜底）。"""
    for enc in ("utf-8", "latin-1"):
        try:
            return b.decode(enc)
        except Exception:
            continue
    return None


def _printable_ratio(t: str) -> float:
    if not t:
        return 0.0
    ok = sum(1 for ch in t if ch >= " " and ch != "\x7f")
    return ok / len(t)


# 解码原语注册表（名称, 函数, 返回类型）
_PRIMITIVES: List[Tuple[str, object]] = [
    ("base64", _fn_base64, "bytes"),
    ("hex", _fn_hex, "bytes"),
    ("rot13", _fn_rot13, "str"),
    ("urldecode", _fn_urldecode, "str"),
]


# ============================================================
# 链式解码（纯静态、深度受限）
# ============================================================

def decode_recursive(
    text: str,
    depth: int = 0,
    visited: Optional[set] = None,
    chain_prefix: Optional[List[str]] = None,
) -> List[Tuple[str, str]]:
    """对单段文本做链式解码探测。

    visited 跨递归层共享，用于阻断"对合运算回到原文"的回路：
    rot13 是自逆运算（连续两次回到原文），若不阻断，原始字符串会被当成
    解码结果输出（如 URL 编码串经 rot13→rot13 变回原文后被误报为已解码）。

    Returns:
        [(解码明文, 方法链字符串), ...]  例如 ("<?php eval(...)", "base64→inflate")
        仅包含"可打印且长度>5"的结果；以 seen 去重；深度/数量受常量限制。
    """
    results: List[Tuple[str, str]] = []
    seen: set = set()
    if visited is None:
        visited = set()
    visited.add(text)

    def add(t: str, chain: List[str]) -> bool:
        if t in seen or t in visited or len(results) >= MAX_RESULTS:
            return False
        seen.add(t)
        visited.add(t)
        results.append((t, "→".join(chain)))
        return True

    if depth > MAX_DECODE_DEPTH:
        return results

    for name, fn, ret_type in _PRIMITIVES:
        try:
            out = fn(text)
        except Exception:
            continue
        if out is None or out == text:
            continue

        prefix = list(chain_prefix or [])

        if ret_type == "bytes":
            txt = _to_text(out)
            if txt and _printable_ratio(txt) >= PRINTABLE_RATIO and len(txt) > 5:
                chain = prefix + [name]
                if add(txt, chain) and depth < MAX_DECODE_DEPTH:
                    results.extend(decode_recursive(txt, depth + 1, visited, chain))
            # 若字节流为压缩数据，尝试 inflate
            zb = _try_inflate(out)
            if zb is not None:
                ztxt = _to_text(zb)
                if ztxt and _printable_ratio(ztxt) >= PRINTABLE_RATIO and len(ztxt) > 5:
                    chain = prefix + [name + "→inflate"]
                    if add(ztxt, chain) and depth < MAX_DECODE_DEPTH:
                        results.extend(decode_recursive(ztxt, depth + 1, visited, chain))

            # P1-2：既非可打印文本也非压缩数据时，尝试单字节 XOR 还原。
            # 仅 depth==0 触发（不做递归放大），长度受限，且结果须命中危险关键词。
            if (depth == 0 and len(out) <= XOR_MAX_LEN
                    and (not txt or _printable_ratio(txt) < 0.7)):
                xr = _try_xor_bruteforce(out)
                if xr is not None:
                    xtxt, xkey = xr
                    chain = prefix + [name + f"→xor(0x{xkey:02x})"]
                    if add(xtxt, chain) and depth < MAX_DECODE_DEPTH:
                        results.extend(decode_recursive(xtxt, depth + 1, visited, chain))
        else:  # str（rot13 / urldecode）
            if _printable_ratio(out) >= PRINTABLE_RATIO and len(out) > 5:
                chain = prefix + [name]
                if add(out, chain) and depth < MAX_DECODE_DEPTH:
                    results.extend(decode_recursive(out, depth + 1, visited, chain))

    # 封顶，避免递归 extend 绕过 add() 内的上限检查导致结果膨胀
    return results[:MAX_RESULTS]


# ============================================================
# 候选提取（直接从源码，不依赖被截断的 regex 匹配）
# ============================================================

def _looks_encoded(s: str) -> bool:
    """
    启发式判断字符串是否"像被编码的荷载"（base64 / urlsafe-base64 / hex）。
    用于候选提取，避免对普通短字符串无谓解码，也避免漏掉 <200 字符的恶意 base64。
    """
    t = s.strip()
    if len(t) < 16:
        return False
    # 标准 base64：仅含 A-Za-z0-9+/=。
    # 不再要求长度是 4 的倍数：无填充（unpadded）base64 在真实样本中很常见，
    # 原判定会直接漏掉这类载荷。补齐填充由 _fn_base64 负责。
    # 放宽后会有更多普通长字符串进入解码尝试，但下游 RELEVANT_KEYWORDS 门控
    # 会滤除解不出危险语义的噪声，不会污染注入内容。
    if re.fullmatch(r"[A-Za-z0-9+/=]+", t):
        return True
    # URL-safe base64（同样放宽填充约束）
    if re.fullmatch(r"[A-Za-z0-9_-]+", t):
        return True
    # 十六进制：仅含 0-9A-Fa-f，长度 ≥32 且偶数（奇数长度无法按字节解码）
    if re.fullmatch(r"[0-9A-Fa-f]+", t) and len(t) >= 32 and len(t) % 2 == 0:
        return True
    # URL 百分号编码：含至少一个 %XX 转义序列（如 eval%28%24_POST...）
    if "%" in t and re.search(r"%[0-9A-Fa-f]{2}", t):
        return True
    return False


def extract_candidates(code: str) -> List[Tuple[str, int, bool]]:
    """
    从源码提取待解码候选（纯静态、零执行）。

    Returns:
        [(候选字符串, 字符偏移, 是否解码函数字面量), ...]
    """
    cands: List[Tuple[str, int, bool]] = []

    # 1) 引号字符串：若"看起来像编码"（base64/hex）则视为候选
    #    —— 用形态启发式替代死板的长度阈值，可捕获 88~120 字符的恶意 base64 赋值。
    for m in re.finditer(r"""['"]([^'"]{16,})['"]""", code):
        s = m.group(1)
        if _looks_encoded(s):
            cands.append((s, m.start(1), False))

    # 2) 长十六进制 blob（0x 前缀）
    for m in re.finditer(r"\b0x[0-9A-Fa-f]{32,}\b", code):
        cands.append((m.group(0)[2:], m.start(), False))

    # 3) 解码函数"字面量参数"（P1-1·ast 核心）——优先提取
    #    注：DECODE_FNS 已包成 (?:...)，此处 group(1)=引号串、group(2)=内部内容。
    for m in re.finditer(
        DECODE_FN_RE.pattern + r"\s*\(\s*(['\"]([^'\"]{8,})['\"])\s*\)", code
    ):
        cands.append((m.group(2), m.start(2), True))

    return cands


def extract_dynamic_args(code: str) -> List[dict]:
    """
    提取"解码函数 + 运行时变量参数"的位置（无法静态还原，交 LLM）。
    例：base64_decode($x)、gzinflate(some_var)
    """
    dyn: List[dict] = []
    # 解码函数后紧跟 $变量 / (函数调用 / 标识符（非常量字面量）→ 运行时依赖，无法静态还原
    for m in re.finditer(DECODE_FN_RE.pattern + r"\s*\(\s*([\$\(A-Za-z_])", code):
        line = code[: m.start()].count("\n") + 1
        snippet = code[m.start(): m.start() + 48].replace("\n", " ")
        dyn.append({"line": line, "snippet": snippet})
    return dyn


# ============================================================
# 数据结构
# ============================================================

@dataclass
class DecodeItem:
    line: int
    text: str
    method: str
    relevant: bool               # 是否命中危险关键词 / 来自解码函数字面量
    confidence: str = "medium"   # high | medium（仅 relevant 时有效）


@dataclass
class DecodeReport:
    items: List[DecodeItem] = field(default_factory=list)
    dynamic_args: List[dict] = field(default_factory=list)
    has_decoded: bool = False
    confidence: str = "low"      # high | medium | low

    def to_prompt_context(self, max_items: int = 8, max_text: int = 400) -> str:
        """
        生成可注入 LLM Prompt 的解码参考文本。
        仅包含 relevant 项 + dynamic_args 说明，避免良性噪声。
        无相关内容时返回空串（调用方据此判断无需注入）。
        """
        relevant = [it for it in self.items if it.relevant]
        if not relevant and not self.dynamic_args:
            return ""

        lines = ["## 程序化解码参考（引擎确定性还原，非 LLM 推断）",
                 "> 以下为对代码中硬编码荷载的标准算法解码结果，请直接作为 [DE_OBFUSCATE] 还原的 ground truth 参考；"
                 "解码明文中的关键逻辑必须被 [[HL]] 标记。"]
        for it in relevant[:max_items]:
            snippet = it.text if len(it.text) <= max_text else (it.text[:max_text] + " …(截断)")
            lines.append(f"- [L{it.line}] ({it.method}, 置信度:{it.confidence}) {snippet}")

        if self.dynamic_args:
            lines.append("")
            lines.append("### 运行时依赖型解码（参数非字面量，无法静态还原）")
            lines.append("> 以下处需 LLM 结合上下文推断，并标注「需运行时验证」：")
            for d in self.dynamic_args[:10]:
                lines.append(f"- L{d['line']}: `{d['snippet']}`")

        return "\n".join(lines)


# ============================================================
# 主入口
# ============================================================

def decode_code(code: str) -> DecodeReport:
    """
    对整段代码做程序化解码分析。

    Args:
        code: 待分析的源码文本（视为不可信恶意样本）

    Returns:
        DecodeReport（含相关解码项、运行时依赖项、整体置信度）
    """
    report = DecodeReport()

    if not code or not code.strip():
        return report

    seen_text: set = set()
    for text, pos, is_decode_fn in extract_candidates(code):
        line = code[:pos].count("\n") + 1
        try:
            decodes = decode_recursive(text, 0)
        except Exception:
            decodes = []

        for dtxt, chain in decodes:
            if dtxt in seen_text:
                continue
            # 相关性只认 RELEVANT_KEYWORDS 命中，避免把 base64 字面量解码出的
            # rot13 变体/乱码误判为相关而注入 LLM 造成噪声。
            if not RELEVANT_KEYWORDS.search(dtxt):
                continue
            seen_text.add(dtxt)
            confidence = "high" if STRONG_EXEC.search(dtxt) else "medium"
            report.items.append(DecodeItem(
                line=line, text=dtxt, method=chain,
                relevant=True, confidence=confidence,
            ))
            if len(report.items) >= MAX_RESULTS:
                break
        if len(report.items) >= MAX_RESULTS:
            break

    # ── P1-2 通道二：PowerShell -EncodedCommand（base64 → UTF-16LE）──
    if len(report.items) < MAX_RESULTS:
        for payload, pos in extract_ps_encoded(code):
            if len(report.items) >= MAX_RESULTS:
                break
            txt = _fn_ps_encoded(payload)
            if not txt or txt in seen_text or not RELEVANT_KEYWORDS.search(txt):
                continue
            seen_text.add(txt)
            line = code[:pos].count("\n") + 1
            report.items.append(DecodeItem(
                line=line, text=txt, method="powershell-enc",
                relevant=True,
                confidence="high" if STRONG_EXEC.search(txt) else "medium",
            ))

    # ── P1-2 通道三：chr()/fromCharCode() 数字码拼接还原 ──
    if len(report.items) < MAX_RESULTS:
        for pos, txt in extract_charcode_sequences(code):
            if len(report.items) >= MAX_RESULTS:
                break
            if txt in seen_text or not RELEVANT_KEYWORDS.search(txt):
                continue
            seen_text.add(txt)
            line = code[:pos].count("\n") + 1
            report.items.append(DecodeItem(
                line=line, text=txt, method="charcode",
                relevant=True,
                confidence="high" if STRONG_EXEC.search(txt) else "medium",
            ))

    report.dynamic_args = extract_dynamic_args(code)
    report.has_decoded = any(it.relevant for it in report.items)
    if any(it.confidence == "high" for it in report.items):
        report.confidence = "high"
    elif report.items:
        report.confidence = "medium"
    else:
        report.confidence = "low"

    return report


# ============================================================
# 便捷函数
# ============================================================

def decode_to_context(code: str) -> str:
    """便捷：直接返回可注入 Prompt 的解码参考文本（空串表示无需注入）。"""
    return decode_code(code).to_prompt_context()
