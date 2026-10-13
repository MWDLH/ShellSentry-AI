"""High-value composite behavior analysis layered on top of the existing rules."""

from __future__ import annotations

import re
from typing import Iterable

from .models import ArtifactProfile, DeterministicVerdict, Evidence, Finding
from .regex_scanner import suppress_cross_language_matches


SOURCE = re.compile(
    r"\$_(?:GET|POST|REQUEST|COOKIE|FILES)|Request\s*[.(\[]|request\.(?:args|form|values|query|body)|"
    r"req\.(?:query|body|params|cookies)|document\.(?:URL|location|cookie)|window\.location|"
    r"location\.(?:hash|search)|URLSearchParams|localStorage|sessionStorage|process\.argv|stdin|ReadLine|"
    # P3 第二批：PHP 输入流（冰蝎 / 哥斯拉的核心投递通道，此前完全脱钩）、
    # WSGI 请求环境。注意 SOURCE 本身不构成风险信号，必须与执行落点组合才成链，
    # 因此良性 API 服务读取 php://input 不会被单独抬升。
    r"php://(?:input|stdin)|environ\.get\(|environ\[|"
    # P3 第三批：Perl CGI 参数、Node 请求体、反弹 Shell 的远端命令入口。
    # 反弹类样本的"输入"不是 HTTP 参数而是网络流读取（$stream.Read / sock.gets），
    # 此前完全脱钩，导致 PowerShell/Ruby 反弹拿不到 source 端证据。
    r"CGI->new|\bparam\s*\(\s*['\"]|req\.on\s*\(\s*['\"]data|"
    r"\.GetStream\s*\(|"
    r"\b(?:stream|reader|sock|socket|client|conn)\s*\.\s*(?:Read|ReadLine|gets|recv)\s*\(",
    re.I,
)
# 说明（P3 第一批）：本组正则按"写法"枚举，而非按语义归纳，因此每换一种方言就会脱钩。
# 这是刻意维持的取向——本工具的核心深度分析由 LLM 承担，本地层只负责提供可复现的
# 锚点与基线判定，不追求穷举。补词时须先在良性对照上验证无误命中再纳入。
#
# 动态代码 / 命令执行落点。
# P3 补充：
#   - .NET 进程创建：此前只认字面形式 `Process.Start`，实例写法
#     （`new System.Diagnostics.Process()` + `p.Start()`）完全脱钩，导致 ASPX 一句话判无异常；
#     刻意不用泛化的 `\w+\.Start\(`，否则会误命中 timer.Start() 等良性调用。
#   - PowerShell `-EncodedCommand`：传递编码命令执行。
#   - 管道到解释器：`curl … | bash` / `| python` / `| perl`，Shell 侧最常见的投递链路。
EXECUTION = re.compile(
    r"\b(?:eval|assert|system|exec|passthru|shell_exec|popen|proc_open)\s*\(|"
    r"Runtime\.getRuntime\(\)\.exec|new\s+ProcessBuilder|subprocess\.(?:Popen|run|call)|os\.system|"
    r"child_process\.(?:exec|execSync|spawn)|Process\.Start|Invoke-Expression|\bIEX\s*\(|"
    r"WScript\.Shell.*\.(?:Run|Exec)|Kernel32|CreateProcess|"
    r"new\s+System\.Diagnostics\.Process|\.StartInfo\.FileName|"
    r"-EncodedCommand|"
    # PowerShell 的 `iex $data`（无括号写法）此前不匹配 `\bIEX\s*\(`，纯反弹样本因此丢失执行端。
    r"\biex\s+|"
    r"\|\s*(?:ba|z|k|d)?sh\b|\|\s*python\d?\b|\|\s*perl\b|\|\s*powershell\b|\|\s*ruby\b",
    re.I,
)
# P3 第二批：以下原语**单独出现几乎都是良性**的——工厂模式用 `newInstance()`、
# 加密库用 `Cipher.getInstance`、编码工具用 `b64decode`，直接纳入上面的正则会大规模误报。
# 因此单独成组：**仅当样本同时存在外部可控输入（SOURCE）时才计入**。
# 也就是说，本地层判的不是"用了什么词"，而是"外部数据能否驱动这些能力"——
# 这是确定性层唯一比 LLM 更可靠的信号，也正是它该承担的锚点职责。
TAINTED_EXECUTION = re.compile(
    r"\.newInstance\s*\(|\bdefineClass\s*\(|\.invoke\s*\(|"
    r"create_function\s*\(|call_user_func(?:_array)?\s*\(|"
    # .NET 反射加载（冰蝎 ASPX 的核心落点）：Assembly.Load(byte[]) + CreateInstance。
    r"\bAssembly\.Load\s*\(|CreateInstance\s*\(",
    re.I,
)
TAINTED_DECODE = re.compile(
    r"BASE64Decoder|decodeBuffer|Base64\.get(?:Mime)?Decoder|"
    r"\bCipher\.getInstance|\.doFinal\s*\(|SecretKeySpec|"
    r"openssl_(?:de|en)crypt|mcrypt_decrypt|"
    r"b64decode|b85decode|a85decode|codecs\.decode|"
    # 第三批：Node crypto 解密与 .NET 对称解密写出（此前 JS 加密 WebShell 的解码环节完全脱钩）
    r"createDecipher(?:iv)?\s*\(|TransformFinalBlock\s*\(",
    re.I,
)

# 编码 / 解码 / 还原操作。
# P3 补充 Shell 侧 `base64 -d` / `--decode`：此前只有函数形式（base64_decode / atob /
# FromBase64String），命令行形式完全脱钩，使 `curl … | base64 -d | bash` 的解码环节丢失。
# 注意不放宽 SHELL 字段去认裸 "bash"—— shebang `#!/bin/bash` 会全量误命中。
DECODE = re.compile(
    r"base64_(?:decode|decode64)|atob\s*\(|FromBase64String|EncodedCommand|gzinflate|gzuncompress|"
    r"Convert\.FromBase64String|String\.fromCharCode|charCodeAt|\b(?:xor|rot13)\b|"
    r"base64\s+-(?:d|D|--decode)",
    re.I,
)
NETWORK = re.compile(
    r"\b(?:fetch|sendBeacon|XMLHttpRequest|WebClient|Invoke-WebRequest|Invoke-RestMethod|curl|wget)\b|"
    r"requests\.(?:get|post)|urllib|HttpClient|Socket\s*\(|new\s+WebSocket|\.connect\s*\(|"
    # 第三批：反弹 Shell 与下载器的实际通道写法。Bash /dev/tcp、Ruby TCPSocket、
    # PowerShell Net.Sockets.TCPClient、VBScript MSXML2.XMLHTTP 此前均完全脱钩，
    # 使"网络"这一维度在四种方言下集体缺失。
    r"/dev/(?:tcp|udp)|TCPSocket|TCPServer|TCPClient|Net\.Sockets|XMLHTTP|ServerXMLHTTP|WinHttp",
    re.I,
)
DOWNLOAD = re.compile(
    r"DownloadString|DownloadFile|Invoke-WebRequest|\b(?:curl|wget)\b|requests\.get|urllib\.request|"
    # VBScript 下载器：XMLHTTP + responseText 是该语言唯一的远程取内容写法
    r"XMLHTTP|ServerXMLHTTP|\.responseText",
    re.I,
)
# 反弹 Shell 的远端命令入口：从 socket 流读取并赋值给变量（Ruby `cmd = s.gets`、
# PowerShell `$d = $stream.Read(...)`）。裸 `.gets` 在 Ruby 中多用于读文件，
# 因此该组只在已确认存在网络通道时才计入外部输入（见 analyze_behaviors）。
SOCKET_INPUT = re.compile(
    r"\b\w+\s*=\s*\w+\s*\.\s*(?:gets|read|recv|readline)\s*[(\s]",
    re.I,
)
SHELL = re.compile(
    r"/bin/(?:ba)?sh|cmd\.exe|powershell(?:\.exe)?|CreateProcess|ProcessBuilder|child_process|subprocess|"
    # Ruby 的 IO.popen / Open3、VBScript 的 WScript.Shell：本地 Shell 能力在该方言下的写法。
    # 单独出现不产生判定（须与网络能力及重定向特征组合），正常运维脚本不受影响。
    r"IO\.popen|Open3\b|WScript\.Shell",
    re.I,
)
# 需搭配 Shell 或下载能力才成立的执行写法。VBScript 的 `oShell.Run "cmd …"` 与
# `WScript.Shell` 创建常跨语句，单行写法无法命中；但裸 `.Run(` / `.Exec(` 在 VBA/COM
# 中极为常见，直接纳入 EXECUTION 会大规模误报，故仅在已确认 Shell 或下载能力时并入。
COND_EXECUTION = re.compile(
    # VBScript 的过程调用可省略括号：`oShell.Run "cmd.exe /c " & payload`，
    # 因此后随字符须同时接受左括号与引号，否则该方言零命中。
    r"[A-Za-z_$]\w*[Ss]hell\s*\.\s*(?:Run|Exec)\s*[\(\"']|ExecuteGlobal\s*\(",
    re.I,
)
BROWSER_SOURCE = re.compile(r"location\.(?:hash|search)|document\.(?:URL|cookie)|window\.name|URLSearchParams|localStorage|sessionStorage", re.I)
BROWSER_SINK = re.compile(r"\.innerHTML\s*=|\.outerHTML\s*=|document\.write\s*\(|insertAdjacentHTML\s*\(|dangerouslySetInnerHTML|eval\s*\(", re.I)
BROWSER_EXFIL = re.compile(r"fetch\s*\(|sendBeacon\s*\(|XMLHttpRequest|new\s+Image\s*\(|\.src\s*=|WebSocket\s*\(", re.I)
XSS_PAYLOAD = re.compile(
    r"javascript\s*:|</(?:script|style|textarea)>\s*<(?:script|img|svg)|"
    r"<(?:img|svg|iframe|body|input)[^>]+on(?:error|load|focus|mouseover|animationstart)\s*=",
    re.I,
)
PERSISTENCE = re.compile(r"schtasks|CurrentVersion\\Run|crontab|/etc/cron|systemctl\s+enable|LaunchAgents|Startup", re.I)


def _line_for(code: str, match: re.Match[str]) -> int:
    return code.count("\n", 0, match.start()) + 1


# 单一能力模式最多保留的证据条数。此前只取首个命中，含多个 sink 的样本只报一处，
# 行为链描述不完整；全量收集后设上限，避免证据膨胀挤占统计与提示词预算。
MAX_EVIDENCE_PER_PATTERN = 3


def _collect_evidence(
    code: str,
    pattern: re.Pattern[str],
    rule_id: str,
    category: str,
    severity: str,
    description: str,
    confidence: float,
    limit: int = MAX_EVIDENCE_PER_PATTERN,
) -> list[Evidence]:
    """收集某能力模式在代码中的全部命中（受 limit 限制），按出现顺序返回。"""
    lines = code.splitlines()
    items: list[Evidence] = []
    for match in pattern.finditer(code):
        line = _line_for(code, match)
        source_line = lines[line - 1] if 0 < line <= len(lines) else ""
        items.append(Evidence(
            source="behavior",
            rule_id=rule_id,
            category=category,
            severity=severity,
            confidence=confidence,
            description=description,
            line_start=line,
            line_end=line,
            snippet=source_line.strip()[:180],
        ))
        if len(items) >= limit:
            break
    return items


def _evidence(code: str, pattern: re.Pattern[str], rule_id: str, category: str, severity: str, description: str, confidence: float) -> Evidence | None:
    """保留原语义：仅返回首个命中，用于行为链成立与否的存在性判断。"""
    items = _collect_evidence(
        code, pattern, rule_id, category, severity, description, confidence, limit=1
    )
    return items[0] if items else None


def _finding(
    finding_id: str,
    title: str,
    category: str,
    severity: str,
    confidence: float,
    artifact_type: str,
    description: str,
    evidence: Iterable[Evidence | None],
    behavior_chain: list[str],
    false_positive_notes: list[str] | None = None,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        title=title,
        category=category,
        severity=severity,
        confidence=confidence,
        artifact_type=artifact_type,
        description=description,
        evidence=[item for item in evidence if item is not None],
        behavior_chain=behavior_chain,
        false_positive_notes=false_positive_notes or [],
    )


def analyze_behaviors(code: str, profile: ArtifactProfile) -> list[Finding]:
    findings: list[Finding] = []
    # 全量收集（受 MAX_EVIDENCE_PER_PATTERN 限制），用于构造完整证据链
    source_items = _collect_evidence(code, SOURCE, "FLOW-SOURCE", "external_input", "medium", "发现外部可控输入源", 0.82)
    network_items = _collect_evidence(code, NETWORK, "FLOW-NET", "network", "medium", "发现网络通信能力", 0.7)
    if network_items:
        # socket 读取只有在确认存在网络通道时才是"远端可控输入"。
        # 否则 Ruby 读文件 `line = fh.gets` 会被误当成外部输入，把运维脚本抬成反弹链。
        source_items += _collect_evidence(
            code, SOCKET_INPUT, "FLOW-SOCKET-INPUT", "external_input", "medium",
            "从网络流读取远端可控数据", 0.8, limit=2,
        )
    execution_items = _collect_evidence(code, EXECUTION, "FLOW-EXEC", "code_execution", "critical", "发现动态代码或系统命令执行落点", 0.9)
    decoding_items = _collect_evidence(code, DECODE, "FLOW-DECODE", "obfuscation", "medium", "发现编码、解码或字符串还原操作", 0.72)

    # P3 第二批：次级原语（newInstance / defineClass / invoke / create_function / Cipher /
    # BASE64Decoder / openssl_decrypt / b64decode）单独出现多为良性元编程或加密工具，
    # 因此仅在已确认存在外部可控输入时才并入，避免工厂模式与加密库被误抬为行为链。
    if source_items:
        execution_items += _collect_evidence(
            code, TAINTED_EXECUTION, "FLOW-EXEC-TAINTED", "code_execution", "critical",
            "外部输入可驱动反射加载或动态调用", 0.88, limit=2,
        )
        decoding_items += _collect_evidence(
            code, TAINTED_DECODE, "FLOW-DECODE-TAINTED", "obfuscation", "medium",
            "外部输入参与解密或解码还原", 0.7, limit=2,
        )
    # 下载 / Shell 能力提前收集：供 COND_EXECUTION 判定，也避免后续重复收集
    download_items = _collect_evidence(code, DOWNLOAD, "FLOW-DOWNLOAD", "download", "high", "发现下载或远程内容获取", 0.8)
    shell_items = _collect_evidence(code, SHELL, "FLOW-SHELL", "shell", "high", "发现系统 Shell 或进程启动能力", 0.82)
    if shell_items or download_items:
        # 已确认存在 Shell 或远程取内容能力时，才把 `.Run(` / `.Exec(` 这类
        # 弱执行写法计入执行落点，避免 VBA/COM 良性调用被当成执行能力。
        execution_items += _collect_evidence(
            code, COND_EXECUTION, "FLOW-EXEC-COND", "code_execution", "critical",
            "在 Shell 或下载能力上下文中出现进程启动或脚本执行调用", 0.85, limit=2,
        )

    # 行为链成立条件仍为"是否存在"，与改动前完全一致，仅证据内容更完整
    source = source_items[0] if source_items else None
    execution = execution_items[0] if execution_items else None
    decoding = decoding_items[0] if decoding_items else None
    network = network_items[0] if network_items else None

    if source and execution:
        findings.append(_finding(
            "BEHAV-EXEC-CHAIN", "外部输入到动态执行行为链", "code_execution", "critical", 0.96,
            "malicious_code", "外部输入能够进入代码或命令执行落点，是 WebShell 与恶意脚本的核心行为链。",
            source_items + execution_items, ["外部输入", "数据传播", "动态代码或命令执行"],
        ))

    if decoding and execution:
        findings.append(_finding(
            "BEHAV-OBF-EXEC", "解码后动态执行", "obfuscation", "critical", 0.91,
            "malicious_code", "编码或混淆操作与动态执行同时存在，符合隐藏载荷后执行的行为。",
            decoding_items + execution_items, ["编码或混淆", "运行时还原", "动态执行"],
            ["打包器或兼容性代码可能使用相似能力，需结合输入来源复核"],
        ))

    download = download_items[0] if download_items else None
    if download and execution:
        findings.append(_finding(
            "BEHAV-DOWNLOAD-EXEC", "下载并执行行为链", "code_execution", "critical", 0.94,
            "malicious_code", "远程内容获取后进入执行能力，符合下载器和投递脚本的典型链路。",
            download_items + execution_items, ["远程下载", "载荷获取", "执行"],
        ))

    shell = shell_items[0] if shell_items else None
    if network and shell and (
        # 仅以显式重定向/交互式终端特征作为反弹判据。TCPSocket、Net.Sockets 等
        # 只是"连接能力"，运维脚本做端口探测时同样具备，纳入会把正常脚本判成反弹。
        re.search(r"(?:/dev/tcp|/dev/udp|dup2|pty\.spawn|nc\s+-e|bash\s+-i|socket.*connect)",
                  code, re.I | re.S)
    ):
        findings.append(_finding(
            "BEHAV-REVERSE-SHELL", "反向 Shell 行为链", "reverse_shell", "critical", 0.95,
            "malicious_code", "网络连接、Shell 启动与输入输出重定向同时存在。",
            network_items + shell_items, ["建立外连", "启动 Shell", "重定向交互通道"],
        ))

    browser_source_items = _collect_evidence(code, BROWSER_SOURCE, "WEB-SOURCE", "browser_input", "medium", "读取浏览器可控输入或敏感存储", 0.78)
    browser_sink_items = _collect_evidence(code, BROWSER_SINK, "WEB-DOM-SINK", "xss", "high", "将内容写入危险 DOM 或动态执行落点", 0.86)
    browser_source = browser_source_items[0] if browser_source_items else None
    browser_sink = browser_sink_items[0] if browser_sink_items else None
    if browser_source and browser_sink:
        findings.append(_finding(
            "BEHAV-DOM-XSS", "浏览器输入进入危险 DOM Sink", "xss", "high", 0.9,
            "vulnerable_source", "浏览器可控数据未经明确净化进入 HTML 或脚本执行位置，构成 DOM XSS 风险。",
            browser_source_items + browser_sink_items, ["浏览器可控输入", "缺少可见净化", "危险 DOM 写入"],
            ["若调用路径中存在可信净化器，应降低风险并人工确认"],
        ))

    xss_payload_items = _collect_evidence(code, XSS_PAYLOAD, "WEB-XSS-PAYLOAD", "xss", "high", "发现典型 XSS 注入载荷结构", 0.9)
    xss_payload = xss_payload_items[0] if xss_payload_items else None
    if xss_payload:
        findings.append(_finding(
            "BEHAV-XSS-PAYLOAD", "XSS 攻击载荷", "xss", "high", 0.9,
            "attack_payload", "代码包含用于突破 HTML 上下文或通过事件处理器执行脚本的载荷结构。",
            xss_payload_items, ["突破 HTML 上下文", "触发浏览器脚本执行"],
            ["安全测试样例也可能包含该载荷，应结合文件用途区分攻击与测试"],
        ))

    credential_items = _collect_evidence(code, re.compile(r"document\.cookie|localStorage|sessionStorage", re.I), "WEB-CREDENTIAL", "credential_access", "high", "读取浏览器凭据或会话存储", 0.86)
    exfil_items = _collect_evidence(code, BROWSER_EXFIL, "WEB-EXFIL", "exfiltration", "high", "发现浏览器端数据外传通道", 0.82)
    credential = credential_items[0] if credential_items else None
    exfil = exfil_items[0] if exfil_items else None
    if credential and exfil:
        findings.append(_finding(
            "BEHAV-BROWSER-STEAL", "浏览器凭据读取并外传", "credential_theft", "critical", 0.95,
            "malicious_code", "读取 Cookie 或浏览器存储后通过网络通道发送，符合会话窃取行为。",
            credential_items + exfil_items, ["读取会话凭据", "构造外传请求", "发送至远端"],
        ))

    persistence_items = _collect_evidence(code, PERSISTENCE, "FLOW-PERSIST", "persistence", "high", "发现启动项、计划任务或服务持久化操作", 0.8)
    persistence = persistence_items[0] if persistence_items else None
    if persistence and (execution or download):
        findings.append(_finding(
            "BEHAV-PERSISTENCE", "载荷持久化行为", "persistence", "high", 0.88,
            "malicious_code", "持久化机制与执行或载荷获取能力同时存在。",
            persistence_items + execution_items + download_items, ["准备载荷", "注册持久化", "后续自动执行"],
        ))

    return findings


def deterministic_verdict(findings: list[Finding], regex_scan: dict) -> DeterministicVerdict:
    if any(item.severity == "critical" and item.confidence >= 0.9 for item in findings):
        top = max(findings, key=lambda item: item.confidence)
        return DeterministicVerdict("malicious", round(top.confidence * 100), top.confidence, top.title)

    external_critical = any(
        match.get("severity") == "critical" and match.get("taint") == "external"
        for match in regex_scan.get("matches", [])
    )
    if external_critical:
        return DeterministicVerdict("malicious", 94, 0.94, "外部输入可达高危执行落点")

    if findings:
        top = max(findings, key=lambda item: item.confidence)
        score = min(89, max(35, round(top.confidence * 100)))
        return DeterministicVerdict("suspicious", score, top.confidence, top.title)

    if regex_scan.get("critical_count", 0) or regex_scan.get("high_count", 0):
        return DeterministicVerdict("suspicious", 65, 0.65, "存在高危单点能力，但尚未形成可确认行为链")
    if regex_scan.get("medium_count", 0):
        return DeterministicVerdict("suspicious", 42, 0.55, "存在需要语义复核的中危静态特征")
    return DeterministicVerdict("no_indication", 10, 0.7, "本地静态层未发现明确恶意证据，不等同于确认安全")


def enrich_regex_scan(code: str, profile: ArtifactProfile, regex_scan: dict) -> tuple[dict, list[Finding], DeterministicVerdict]:
    findings = analyze_behaviors(code, profile)
    enriched = dict(regex_scan)
    matches = list(enriched.get("matches", []))
    triggered = set(enriched.get("triggered_rules", []))
    categories = dict(enriched.get("matches_by_category", {}))
    severities = dict(enriched.get("matches_by_severity", {}))

    for finding in findings:
        for evidence in finding.evidence:
            matches.append({
                "rule_id": evidence.rule_id,
                "line_number": evidence.line_start,
                "matched_text": evidence.snippet,
                "category": evidence.category,
                "severity": evidence.severity,
                "description": evidence.description,
                "language": profile.language,
                "tags": ["composite_behavior", finding.artifact_type],
                "cwe": "",
                "taint": evidence.taint,
                "confidence": evidence.confidence,
            })
            triggered.add(evidence.rule_id)
            categories[evidence.category] = categories.get(evidence.category, 0) + 1
            severities[evidence.severity] = severities.get(evidence.severity, 0) + 1

    # 合并复合命中后再做一次跨语言归因去重：复合命中（FLOW-*）是"原生锚点"，
    # 而 scan() 内的跨语言策略在它们并入之前就跑了。有移除时从最终 matches
    # 重算全部统计，避免与累计计数不一致。
    matches, _cross_dropped = suppress_cross_language_matches(matches, enriched.get("language_hints"))
    if _cross_dropped:
        triggered, categories, severities = set(), {}, {}
        for m in matches:
            triggered.add(m["rule_id"])
            categories[m["category"]] = categories.get(m["category"], 0) + 1
            severities[m["severity"]] = severities.get(m["severity"], 0) + 1
        enriched["cross_language_suppressed"] = int(enriched.get("cross_language_suppressed", 0)) + _cross_dropped

    enriched["matches"] = matches
    enriched["triggered_rules"] = sorted(triggered)
    enriched["matches_by_category"] = categories
    enriched["matches_by_severity"] = severities
    enriched["total_matches"] = len(matches)
    for severity in ("critical", "high", "medium", "low"):
        enriched[f"{severity}_count"] = int(severities.get(severity, 0))
    enriched["behavior_findings"] = [item.to_dict() for item in findings]
    enriched["artifact"] = profile.to_dict()
    assessment = deterministic_verdict(findings, enriched)
    enriched["deterministic_verdict"] = assessment.to_dict()
    base_summary = enriched.get("summary", "")
    behavior_summary = ", ".join(item.title for item in findings) or "无组合行为链"
    enriched["summary"] = f"{base_summary}\n组合行为分析: {behavior_summary}".strip()
    return enriched, findings, assessment

