#!/usr/bin/env python3
"""
ShellSentry-AI 输入处理器 v1.0
==============================
全内存流安全隔离输入管道。

安全边界：
  - 全程内存处理，严禁木马文件落盘
  - 路径穿越防御：剥离 ../ ..\\ 及绝对路径符号
  - 编码回退链：UTF-8 → GBK → latin-1（绝不抛异常）
  - ZIP 内存解压：遍历脚本文件合并，严禁落盘
  - 文件大小上限：50MB（含解压后单文件上限）

支持文件类型：
  WebShell 脚本：.php .jsp .asp .aspx .py .ps1 .sh
  通用文本：     .txt .log .conf .ini .cfg .xml .json .yaml .yml
  Java 相关：    .java .jspx .war
  压缩包：       .zip（内存解压遍历）
"""
import io
import os
import re
import zipfile
from typing import Tuple, List, Dict, Optional
from dataclasses import dataclass, field

# ============================================================
# 常量配置
# ============================================================
MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB 文件上限
MAX_DECODED_CHARS = 5_000_000     # 解码后最多 500 万字符（防内存炸弹）
MAX_ZIP_FILES = 200               # ZIP 内最多遍历 200 个文件（防 ZIP 炸弹）
MAX_ZIP_FILE_SIZE = 10 * 1024 * 1024  # ZIP 内单文件上限 10MB

# 允许审计的脚本/文本扩展名
ALLOWED_EXTENSIONS = {
    # WebShell 高危脚本
    ".php", ".phtml", ".php3", ".php4", ".php5", ".php7", ".phar",
    ".jsp", ".jspx", ".java",
    ".asp", ".aspx", ".asmx", ".ashx", ".ascx",
    ".py", ".pyw",
    ".ps1", ".psm1", ".psd1",
    ".sh", ".bash", ".zsh", ".ksh",
    # 通用文本/配置
    ".txt", ".log", ".conf", ".ini", ".cfg",
    ".xml", ".json", ".yaml", ".yml",
    ".htm", ".html", ".xhtml", ".svg",
    ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx",
    ".pl", ".pm", ".cgi", ".rb", ".vbs", ".vbe", ".wsf", ".bat", ".cmd",
    ".cs",
    # 压缩包
    ".zip",
}

# 拒绝的二进制/可执行文件（即使绕过也会被编码检测拦截）
BLOCKED_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".so", ".dylib", ".elf", ".bin",
    ".pyc", ".class", ".jar", ".war", ".apk", ".dex",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico",
    ".mp3", ".mp4", ".avi", ".mov", ".pdf", ".doc", ".docx",
}

# 路径穿越特征模式
PATH_TRAVERSAL_PATTERNS = [
    re.compile(rb"\.\.[/\\]"),       # ../
    re.compile(rb"\.\.[/\\]\."),     # ../.
    re.compile(rb"^[A-Za-z]:[/\\]"), # C: 盘符绝对路径 (Windows)
    re.compile(rb"^[/\\]"),          # / 绝对路径 (Unix)
]


@dataclass
class InputResult:
    """输入处理结果"""
    success: bool
    filename: str = ""
    source_type: str = ""           # "file" | "paste"
    code_content: str = ""
    encoding_used: str = ""
    file_count: int = 1             # ZIP 解压后文件数
    original_size: int = 0          # 原始字节数
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


# ============================================================
# 文件名安全过滤
# ============================================================

def sanitize_filename(filename: str) -> Tuple[str, Optional[str]]:
    """
    防路径穿越：对上传文件名进行严格安全过滤。

    处理：
      1. 剥离所有 ../ ..\\ 路径穿越序列
      2. 剥离盘符绝对路径 (C: D: 盘符格式)
      3. 剥离 Unix 绝对路径前缀
      4. 移除非法字符
      5. 限制文件名长度

    Returns:
        (safe_filename, warning_message_or_None)
    """
    original = filename
    warnings = []

    # 1. 替换反斜杠为正斜杠（统一处理）
    cleaned = filename.replace("\\", "/")

    # 2. 剥离盘符 (C:/ D:/)
    cleaned = re.sub(r"^[A-Za-z]:/", "", cleaned)

    # 3. 逐步剥离所有 ../ 序列（循环直到不再变化）
    prev = None
    while prev != cleaned:
        prev = cleaned
        cleaned = re.sub(r"(^|/)\.\.(/|$)", "/", cleaned)
    # 再处理 .. 不带斜杠的情况
    prev = None
    while prev != cleaned:
        prev = cleaned
        cleaned = cleaned.replace("/..", "/").replace("../", "")

    # 4. 去除连续的斜杠
    cleaned = re.sub(r"/{2,}", "/", cleaned)

    # 5. 去除开头的斜杠（防止绝对路径引用）
    cleaned = cleaned.lstrip("/")

    # 6. 移除文件名中的非法字符（保留 Unicode 字母、数字、._-/）
    cleaned = re.sub(r"[^\w\.\-/一-鿿぀-ゟ゠-ヿ\s]", "_", cleaned)

    # 7. 限制文件名长度（保留扩展名）
    if len(cleaned) > 200:
        name_part, dot, ext = cleaned.rpartition(".")
        cleaned = name_part[:195] + dot + ext

    # 8. 空文件名保护
    if not cleaned or cleaned.startswith("."):
        cleaned = "uploaded_file" + (cleaned if cleaned.startswith(".") else "")

    if cleaned != original:
        warnings.append(f"文件名已安全过滤: '{original}' → '{cleaned}'")

    if not warnings:
        return cleaned, None
    return cleaned, "; ".join(warnings)


def validate_extension(filename: str) -> Tuple[bool, str]:
    """
    验证文件扩展名是否在允许审计范围内。

    Returns:
        (is_valid, reason)
    """
    ext = os.path.splitext(filename)[1].lower()

    if not ext:
        return False, f"文件缺少扩展名，无法判断文件类型"

    if ext in BLOCKED_EXTENSIONS:
        return False, f"不支持的文件类型 ({ext})：二进制/可执行文件不在审计范围内"

    if ext in ALLOWED_EXTENSIONS:
        return True, ""

    # 未在名单中的扩展名 — 宽松通过（可能为新类型脚本）
    return True, f"未知文件类型 ({ext})，将尝试以文本方式审计"


# ============================================================
# 编码检测与回退解码
# ============================================================

def detect_and_decode(raw_bytes: bytes) -> Tuple[str, str, List[str]]:
    """
    UTF-8 → GBK → latin-1 逐级回退解码。

    策略：
      1. 优先 UTF-8（覆盖 99% 现代脚本）
      2. 回退 GBK（中文/日韩恶意脚本常见编码）
      3. 最终回退 latin-1（保底，绝不抛异常 — 将字节映射到 U+0000-U+00FF）

    Returns:
        (decoded_text, encoding_used, warnings)
    """
    warnings = []

    # ── 尝试 UTF-8 ──
    try:
        text = raw_bytes.decode("utf-8")
        # 验证：检查是否包含 Replacement Character (U+FFFD)，若有说明解码不完全正确
        if "�" not in text:
            return text, "utf-8", warnings
        warnings.append("UTF-8 解码存在替换字符 (U+FFFD)，尝试 GBK 回退")
    except UnicodeDecodeError:
        warnings.append("UTF-8 解码失败，尝试 GBK 回退")

    # ── 尝试 GBK/GB18030 ──
    for enc in ("gb18030", "gbk", "gb2312"):
        try:
            text = raw_bytes.decode(enc)
            if "�" not in text:
                return text, enc, warnings
        except (UnicodeDecodeError, UnicodeError):
            continue
    warnings.append("GBK 系列解码不完全，回退至 latin-1 保底")

    # ── 保底：latin-1（ISO-8859-1）绝不抛异常 ──
    # latin-1 将每个字节 1:1 映射到 Unicode 码点，保证数据完整不丢
    text = raw_bytes.decode("latin-1")
    warnings.append("已使用 latin-1 保底解码（原始字节 1:1 映射），可能存在乱码")
    return text, "latin-1", warnings


# ============================================================
# ZIP 内存解压处理
# ============================================================

def extract_zip_in_memory(zip_bytes: bytes, source_name: str = "") -> Dict[str, str]:
    """
    在内存中完全解压 ZIP 文件，遍历提取所有可审计脚本内容。

    安全措施：
      - 全程使用 io.BytesIO，绝不落盘
      - 限制遍历文件数（防 ZIP 炸弹）
      - 限制单文件大小
      - 跳过目录条目
      - 跳过不允许的文件扩展名

    Args:
        zip_bytes: ZIP 文件的原始字节
        source_name: 来源文件名（用于日志）

    Returns:
        {filename: code_content, ...}
        （空 dict 表示 ZIP 内无可审计文件）

    Raises:
        ValueError: ZIP 格式损坏或文件数超限
    """
    results = {}
    file_count = 0

    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
            for entry in zf.infolist():
                # 跳过目录
                if entry.is_dir():
                    continue

                file_count += 1
                if file_count > MAX_ZIP_FILES:
                    raise ValueError(
                        f"ZIP 内文件数超过上限 ({MAX_ZIP_FILES})，疑似 ZIP 炸弹攻击，已拒绝处理"
                    )

                # 安全过滤文件名
                safe_name, _ = sanitize_filename(entry.filename)
                is_valid, reason = validate_extension(safe_name)
                if not is_valid:
                    continue

                # 检查解压后大小
                if entry.file_size > MAX_ZIP_FILE_SIZE:
                    results[f"{safe_name}.truncated"] = (
                        f"[ShellSentry] 文件过大 ({entry.file_size} bytes)，"
                        f"超过 ZIP 内单文件上限 ({MAX_ZIP_FILE_SIZE} bytes)，已跳过\n"
                    )
                    continue

                if entry.file_size == 0:
                    continue

                # 在内存中读取
                try:
                    with zf.open(entry, "r") as f:
                        raw = f.read()
                except Exception as e:
                    results[f"{safe_name}.error"] = (
                        f"[ShellSentry] ZIP 内文件读取失败: {e}\n"
                    )
                    continue

                # 解码
                text, enc, warnings = detect_and_decode(raw)
                results[safe_name] = text

    except zipfile.BadZipFile:
        raise ValueError("ZIP 文件格式损坏或不是有效 ZIP 文件")

    return results


# ============================================================
# 主处理流水线
# ============================================================

# ============================================================
# 恶意代码预处理分行管道
# ============================================================

# ── 语言判定辅助（与 regex_scanner.detect_language_hints 映射口径一致）──
# 注意：键为【不含点】的扩展名（rsplit('.',1)[-1] 结果）
# 缩进敏感语言：绝不可用花括号重排，否则破坏语义与行号
_INDENT_SENSITIVE_EXT = {"py", "pyw", "pyc", "yaml", "yml", "rb"}
# 花括号块语言：压缩态下可按花括号安全重排
_BRACE_LANGUAGE_EXT = {
    "php", "phtml", "php3", "php4", "php5", "php7", "phar",
    "jsp", "jspx", "java", "war",
    "asp", "aspx", "asmx", "ashx", "ascx",
    "js", "vbs", "ps1", "psm1", "sh", "bash", "zsh", "c", "cpp", "cs",
}


def _detect_lang_from_filename(filename: str) -> str:
    """
    按【扩展名】判定语言，替代原先的子串猜语言。
    返回 'php' / 'java' / 'asp' / 'python' / 'js' / ... / 'generic'。
    """
    ext = filename.lower().rsplit(".", 1)[-1] if "." in filename else ""
    if ext in _INDENT_SENSITIVE_EXT:
        return "python" if ext in ("py", "pyw", "pyc") else "indent_sensitive"
    if ext in _BRACE_LANGUAGE_EXT:
        if ext in ("php", "phtml", "php3", "php4", "php5", "php7", "phar"):
            return "php"
        if ext in ("jsp", "jspx", "java", "war"):
            return "java"
        if ext in ("asp", "aspx", "asmx", "ashx", "ascx"):
            return "asp"
        return "brace"
    return "generic"


def _looks_compressed(code: str) -> bool:
    """
    判断是否近似【单行/压缩】载荷（需要拆行规范化）。
    满足之一即视为压缩态：
      1. 整段基本无换行（≤2 行）；
      2. 平均行长极大（>200 字符/行），典型 minify 特征。
    已结构化的多行源码视为非压缩，应原样保留。
    """
    stripped = code.strip()
    if not stripped:
        return False
    lines = stripped.split("\n")
    if len(lines) <= 2:
        return True
    avg_len = len(stripped) / len(lines)
    return avg_len > 200


def _strip_highlight_residue(text: str) -> str:
    """抹掉大模型偶尔带入的高亮标签残渣（不改动任何代码结构）。"""
    return (
        text.replace("[[HL]]", "").replace("[[/HL]]", "")
        .replace("{{HL}}", "").replace("{{/HL}}", "")
    )


def _reflow_brace_language(code: str) -> str:
    """
    仅对【花括号语言】的压缩载荷做安全拆行 + 层级缩进。
    输入应已确认为压缩态（_looks_compressed 通过）。
    """
    formatted = code.strip()

    # ── Step 1: 物理定界符安全切行 ──
    if "<%" in formatted:
        formatted = re.sub(r"(<[^%]+%>)", r"\1\n", formatted)
        formatted = re.sub(r"(%>)", r"%>\n", formatted)
        formatted = re.sub(r"(<%[!%=]?)", r"\n\1", formatted)
    # JSP XML 语法（<jsp:root> / <jsp:directive.page/> / <jsp:declaration> /
    # <jsp:scriptlet> / </jsp:root>）—— 冰蝎、哥斯拉等 JSP 内存马的主流形态。
    # 此类样本不含 <% %> 定界符，若不单独处理，整个 <jsp:root …> 头部会与首个
    # Java 语句挤在同一行（实测 300+ 字符），导致：① 可读性差；② 送模型的代码
    # 行号锚点落在巨长行上，[[HL]] 高亮回填与实际语句错位。
    # 仅按标签边界切分，不改写标签语法、不改动任何内容字节。
    # 属性段长度设上界（{0,500}）：属性值不会超过此长度，但可避免在
    # 「大量 <jsp: 但后续无 >」的畸形超长输入上出现无界回溯扫描。
    if "<jsp:" in formatted:
        formatted = re.sub(r"(<jsp:[\w.]+[^>]{0,500}?/>)", r"\1\n", formatted)     # 自闭合
        formatted = re.sub(r"(</?jsp:[\w.]+[^>]{0,500}?>)", r"\n\1\n", formatted)  # 开/闭标签
    if "<?php" in formatted:
        formatted = re.sub(r"<\?php", "<?php\n", formatted)
    formatted = re.sub(r";(?![\n\s])", ";\n", formatted)
    formatted = re.sub(r"{(?![\n\s])", "{\n", formatted)
    formatted = re.sub(r"}(?![\n\s])", "}\n", formatted)

    formatted = _strip_highlight_residue(formatted)

    # ── Step 2: 动态层级缩进计算 ──
    raw_lines = [line.strip() for line in formatted.split("\n") if line.strip()]
    indented_lines = []
    indent_level = 0
    indent_string = "    "  # 标准 4 空格缩进

    for line in raw_lines:
        # 闭括号/闭标签开头 → 先回缩一级
        if (line.startswith("}") or line.startswith("%>")
                or line.startswith(")") or line.startswith("]")):
            indent_level = max(0, indent_level - 1)

        indented_lines.append(f"{indent_string * indent_level}{line}")

        # 开括号/开标签结尾 → 下一级缩进 +1
        if (line.endswith("{") or line.endswith("<%")
                or line.endswith("<%!")):
            indent_level += 1

    return "\n".join(indented_lines)


def pre_format_malware_code(raw_code: str, filename: str = "") -> str:
    """
    将单行/压缩的恶意代码载荷规范化为多行语法块。

    安全约束（修复审计项 2.4）：
      - 按【扩展名】判定语言，杜绝 "eval/java" 子串误判导致跨语言破坏；
      - 仅当代码近似【单行/压缩】时才做拆行重排，已结构化的多行源码原样保留；
      - 对【缩进敏感】语言（Python / YAML 等）永不执行花括号重排，避免破坏
        语义结构与报告行号一致性。
    """
    if not raw_code:
        return raw_code

    lang = _detect_lang_from_filename(filename)

    # 缩进敏感语言：只做高亮残渣清理，绝不重排（保持原始缩进与行号）
    if lang in ("python", "indent_sensitive"):
        return _strip_highlight_residue(raw_code.strip())

    # 已知花括号语言：仅压缩态才重排
    if lang in ("php", "java", "asp", "brace"):
        if _looks_compressed(raw_code):
            return _reflow_brace_language(raw_code)
        return _strip_highlight_residue(raw_code.strip())

    # 通用/未知类型：仅当压缩且确实含花括号语言标记时才重排，避免误伤
    if _looks_compressed(raw_code):
        snippet = raw_code[:2000]
        if ("<?php" in snippet) or ("<%" in snippet) or ("{" in snippet):
            return _reflow_brace_language(raw_code)

    # 其余：仅清理高亮残渣，保持原始结构
    return _strip_highlight_residue(raw_code.strip())


class InputHandler:
    """
    输入处理器 — 全内存流安全隔离管道。

    使用示例：
        handler = InputHandler()
        result = handler.process_upload("shell.php", file_bytes)
        if result.success:
            print(result.code_content)
    """

    @staticmethod
    def process_upload(filename: str, file_bytes: bytes) -> InputResult:
        """
        处理文件上传：安全过滤 → 扩展名验证 → 编码解码 → (ZIP 展开)。

        全程内存处理，绝不落盘。
        """
        result = InputResult(
            success=False,
            filename=filename,
            source_type="file",
            original_size=len(file_bytes),
        )

        # ── 0. 大小检查 ──
        if len(file_bytes) > MAX_FILE_SIZE:
            result.errors.append(
                f"文件过大 ({len(file_bytes)} bytes)，上限为 {MAX_FILE_SIZE} bytes (50MB)"
            )
            return result
        if len(file_bytes) == 0:
            result.errors.append("文件为空，请上传有效代码文件")
            return result

        # ── 1. 文件名安全过滤 ──
        safe_name, warn = sanitize_filename(filename)
        result.filename = safe_name
        if warn:
            result.warnings.append(warn)

        # ── 2. 扩展名验证 ──
        is_valid, reason = validate_extension(safe_name)
        if not is_valid:
            result.errors.append(reason)
            return result
        if reason:
            result.warnings.append(reason)

        # ── 3. ZIP 内存解压分支 ──
        if safe_name.lower().endswith(".zip"):
            try:
                zip_results = extract_zip_in_memory(file_bytes, safe_name)
            except ValueError as e:
                result.errors.append(str(e))
                return result

            if not zip_results:
                result.errors.append("ZIP 压缩包内未找到可审计的脚本文件")
                return result

            # 合并所有文件内容，添加文件分隔标记
            merged_parts = []
            for fname, content in zip_results.items():
                merged_parts.append(
                    f"{'='*60}\n"
                    f"📄 [ZIP] {fname}\n"
                    f"{'='*60}\n"
                    f"{content}\n"
                )

            result.code_content = "\n".join(merged_parts)
            result.file_count = len(zip_results)
            result.encoding_used = "utf-8/gbk (多文件)"
            result.success = True
            result.warnings.append(
                f"ZIP 解压完成：共 {len(zip_results)} 个文件合并审计"
            )

            # 截断保护
            if len(result.code_content) > MAX_DECODED_CHARS:
                result.code_content = result.code_content[:MAX_DECODED_CHARS]
                result.warnings.append(
                    f"合并内容超过 {MAX_DECODED_CHARS} 字符，已截断"
                )

            return result

        # ── 4. 编码解码 ──
        text, enc, warnings = detect_and_decode(file_bytes)
        result.code_content = text
        result.encoding_used = enc
        result.warnings.extend(warnings)

        # ── 5. 截断保护 ──
        if len(result.code_content) > MAX_DECODED_CHARS:
            result.code_content = result.code_content[:MAX_DECODED_CHARS]
            result.warnings.append(
                f"文件内容超过 {MAX_DECODED_CHARS} 字符，已截断"
            )

        # ── 6. 空内容检查 ──
        if not result.code_content.strip():
            result.errors.append("文件内容为空或仅含空白字符")
            return result

        result.success = True
        return result

    @staticmethod
    def process_paste(code_text: str) -> InputResult:
        """
        处理纯文本粘贴输入。

        支持大尺寸文本（前端 textarea 粘贴），同样走内存流水线。
        """
        result = InputResult(
            success=False,
            filename="粘贴代码",
            source_type="paste",
            original_size=len(code_text.encode("utf-8", errors="replace")),
        )

        # ── 空内容检查 ──
        if not code_text or not code_text.strip():
            result.errors.append("粘贴内容为空，请输入代码片段")
            return result

        # ── 截断保护 ──
        if len(code_text) > MAX_DECODED_CHARS:
            result.code_content = code_text[:MAX_DECODED_CHARS]
            result.warnings.append(
                f"粘贴内容超过 {MAX_DECODED_CHARS} 字符，已截断"
            )
        else:
            result.code_content = code_text

        result.encoding_used = "utf-8 (前端传入)"
        result.success = True
        return result
