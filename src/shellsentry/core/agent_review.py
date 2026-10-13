"""Evidence-grounded model review and strict verdict parsing."""

from __future__ import annotations

import json
import re
from typing import Any

from .models import AgentVerdict, clamp_confidence
from .prompts import clip_excerpt, split_report_sections


# ── 第一轮报告节选策略 ──
# 复核阶段拿到的 first_report 可能是几万字符的长报告。此前用 first_report[-12000:]
# 从「尾部」截取，等于系统性丢掉报告开头的 [IMAGE]（定性画像/家族/置信度）和
# [DE_OBFUSCATE]（还原出的真实代码），只留下结尾的处置建议 —— 复核看不到首轮
# 到底是凭什么下的结论，就只能照抄首轮结论，误报根本降不下来。
# 改为按标签优先级节选：结论段与证据段完整保留，代码还原段与处置建议段让位。

REPORT_TAG_ORDER = ("IMAGE", "DE_OBFUSCATE", "C2_INFO", "METADATA_BEHAVIOR", "PLAYBOOK")
# 复核做判定必须看到的段落：定性结论、C2、行为链与证据表
REPORT_ESSENTIAL_TAGS = ("IMAGE", "C2_INFO", "METADATA_BEHAVIOR")
REVIEW_REPORT_BUDGET = 12000          # 注入复核 prompt 的报告预算
DEOBFUSCATE_EXCERPT_CAP = 6000        # 还原代码段上限（还原结论通常落在段尾）
PLAYBOOK_EXCERPT_CAP = 1500           # 处置建议段上限（对判定无价值）
PREFIX_EXCERPT_CAP = 800              # 标签之外的开头散文字上限
# 复核侧注入代码的预算。此前直接 numbered[:16000] 从头部砍，且不标注可见范围，
# 却要求复核逐条定性全量正则命中 —— 与首轮"要求模型定性它看不到的行"是同一类幻觉源。
REVIEW_CODE_BUDGET = 16000


def select_review_report_excerpt(report: str, budget: int = REVIEW_REPORT_BUDGET) -> str:
    """按标签优先级节选第一轮报告，供反向复核使用。

    优先级：IMAGE / C2_INFO / METADATA_BEHAVIOR 完整保留 → DE_OBFUSCATE 保留尾部
    → PLAYBOOK 保留头部 → 三者都放不下时对必保段做中段省略，绝不整段丢弃结论。
    报告本身未超预算、或无标签可识别时，返回原文/沿用原尾部截断，不会比改动前更差。
    """
    if not report:
        return ""
    if len(report) <= budget:
        return report

    prefix, sections, tail = split_report_sections(report)
    if not sections:
        return report[-budget:]

    header = (
        "（以下为第一轮报告节选：[IMAGE]/[C2_INFO]/[METADATA_BEHAVIOR] 完整保留；"
        "[DE_OBFUSCATE] 可能仅保留尾部还原结果；[PLAYBOOK] 处置建议可能被省略。"
        "被省略的内容不代表首轮未分析，严禁据此推断首轮漏报。）"
    )
    prefix_part = clip_excerpt(prefix, PREFIX_EXCERPT_CAP, "head")
    body_budget = budget - len(header) - len(prefix_part) - 400  # 预留尾部残余与间隔离
    if body_budget < 1200:
        body_budget = 1200

    essential = [(tag, body) for tag, body, _ in sections if tag in REPORT_ESSENTIAL_TAGS]
    optional = [(tag, body) for tag, body, _ in sections if tag not in REPORT_ESSENTIAL_TAGS]
    essential_total = sum(len(body) for _, body in essential)

    rendered: dict[str, str] = {}
    if essential_total <= body_budget:
        used = 0
        for tag, body in essential:
            rendered[tag] = body
            used += len(body)
        remain = body_budget - used
        for tag, body in optional:
            if tag == "DE_OBFUSCATE":
                cap, mode = DEOBFUSCATE_EXCERPT_CAP, "tail"
            elif tag == "PLAYBOOK":
                cap, mode = PLAYBOOK_EXCERPT_CAP, "head"
            else:
                cap, mode = 2000, "head"
            cap = max(0, min(cap, remain))
            rendered[tag] = clip_excerpt(body, cap, mode)
            remain -= len(rendered[tag])
    else:
        # 必保段本身就超预算：按占比等比压缩，三段都保留（中段省略），
        # 保证复核仍能同时看到"结论 + C2 + 行为链"，而不是只剩结论。
        for tag, body in essential:
            share = max(400, int(body_budget * len(body) / max(1, essential_total)))
            rendered[tag] = clip_excerpt(body, share, "middle")
        for tag, body in optional:
            rendered[tag] = ""

    parts = [header]
    if prefix_part:
        parts.append(prefix_part)
    for tag, _, _ in sections:
        text = rendered.get(tag, "")
        if not text:
            continue
        parts.append(f"[{tag}]\n{text}\n[/{tag}]")
    if tail.strip():
        parts.append(clip_excerpt(tail, 1000, "head"))
    return "\n\n".join(parts)


REVIEW_SYSTEM_PROMPT = """你是恶意代码审计的最终复核 Agent。你的首要目标是降低误报，同时不能把未覆盖的未知代码误判为安全。

你会收到原始代码、确定性静态证据、程序化解码结果和第一轮模型报告。请独立复核，不得盲从第一轮报告或规则严重度。

必须遵守：
1. 正则命中只是线索。逐条判断是否位于注释、字符串、测试代码、固定常量、安全封装或不可达路径。
2. 允许在规则完全未命中时，根据明确的跨行语义行为链判定恶意，但必须引用真实代码位置和行为。
3. 只有危险 API、import、网络请求或编码函数单独出现时，不足以判定恶意。
4. 区分 malicious_code、attack_payload、vulnerable_source、dual_use_tool、benign_code 和 unknown。
5. 区分 XSS 攻击载荷、存在 XSS 漏洞的代码与正常前端逻辑。
6. 不得捏造代码中不存在的函数、地址、密钥、木马家族、CVE 或运行时行为。
7. 缺少证据时输出 unknown 或 suspicious，不得因为规则零命中而输出 benign。
8. benign 只用于能够解释代码合法目的、且已排除关键恶意行为链的情况。
9. 输出严格 JSON，不输出 Markdown、代码围栏或额外说明。

JSON Schema：
{
  "verdict": "malicious|suspicious|benign|unknown",
  "confidence": 0.0,
  "artifact_type": "malicious_code|attack_payload|vulnerable_source|dual_use_tool|benign_code|unknown",
  "summary": "一句话结论",
  "behavior_chain": ["步骤1", "步骤2"],
  "evidence": ["L行号: 可核验证据"],
  "counter_evidence": ["支持良性或降低置信度的证据"],
  "uncertainties": ["仍无法静态确认的事项"]
}
"""


def build_review_prompt(
    code: str,
    filename: str,
    regex_scan: dict[str, Any] | None,
    first_report: str,
    decode_context: str = "",
    first_report_visible_end_line: int | None = None,
) -> str:
    """构建反向复核 Prompt。

    first_report_visible_end_line: 第一轮模型实际看到的代码最后一行（展示预算推导）。
        第一轮与复核轮的代码可见范围必须对齐，否则复核会去"复核"一个它自己也看不到的行号，
        只能靠猜 —— 与首轮同一类幻觉来源。
    """
    evidence = regex_scan or {}
    numbered = "\n".join(f"L{index}: {line}" for index, line in enumerate(code.splitlines(), 1))
    total_lines = code.count("\n") + 1

    # 复核侧代码可见范围：与首轮同一套逻辑（按预算裁剪并回退到完整行），
    # 否则会出现"复核被要求定性它自己也看不到的行"，与首轮同一类幻觉来源。
    code_display = numbered
    review_visible_end_line = None
    if len(numbered) > REVIEW_CODE_BUDGET:
        cut = numbered[:REVIEW_CODE_BUDGET].rfind("\n")
        code_display = numbered[:cut] if cut > 0 else numbered[:REVIEW_CODE_BUDGET]
        line_nums = [int(n) for n in re.findall(r"^L(\d+):", code_display, re.M)]
        review_visible_end_line = max(line_nums) if line_nums else None

    # 命中按复核可见范围裁剪：看不见的行不注入，避免"逐条定性"变成凭空编造
    matches = list(evidence.get("matches", []))
    hidden_matches = 0
    if review_visible_end_line is not None:
        kept = [m for m in matches if int(m.get("line_number", 0)) <= review_visible_end_line]
        hidden_matches = len(matches) - len(kept)
        matches = kept
    evidence_view = {
        "artifact": evidence.get("artifact", {}),
        "deterministic_verdict": evidence.get("deterministic_verdict", {}),
        "behavior_findings": evidence.get("behavior_findings", [])[:12],
        "matches": matches[:40],
    }

    visibility_note = ""
    if first_report_visible_end_line is not None:
        visibility_note += (
            f"\n可见范围提示：第一轮模型仅看到原始代码第 1–{first_report_visible_end_line} 行。"
            f"第一轮报告中超出该范围的行号未经代码核实，不得采信为证据，"
            f"须写入 uncertainties（例如「L{first_report_visible_end_line + 1}+ 超出首轮展示范围，需完整代码复核」）。\n"
        )
    if review_visible_end_line is not None:
        visibility_note += (
            f"\n复核可见范围：下方代码块仅包含原始代码第 1–{review_visible_end_line} 行"
            f"（全文共 {total_lines} 行）。已剔除该范围之外的正则命中 {hidden_matches} 条；"
            f"严禁引用第 {review_visible_end_line + 1} 行及之后的内容作为证据，"
            f"相关不确定性请写入 uncertainties。\n"
        )

    return f"""文件名：{filename}

确定性证据：
{json.dumps(evidence_view, ensure_ascii=False, indent=2)}

程序化解码参考：
{decode_context or '无'}

第一轮模型报告：
{select_review_report_excerpt(first_report) if first_report else '第一轮未产生有效报告'}
{visibility_note}
原始代码（{f"仅第 1–{review_visible_end_line} 行" if review_visible_end_line is not None else "全文"}）：
{code_display}

请执行反向复核：先尝试证明第一轮结论是误报，再尝试证明存在真实恶意行为链，最后按 Schema 输出唯一 JSON 对象。"""


def parse_agent_verdict(text: str) -> AgentVerdict:
    if not text or "[ERROR]" in text:
        return AgentVerdict(summary="模型复核不可用")
    candidate = text.strip()
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", candidate, re.I | re.S)
    if fenced:
        candidate = fenced.group(1)
    else:
        start, end = candidate.find("{"), candidate.rfind("}")
        if start >= 0 and end > start:
            candidate = candidate[start:end + 1]
    try:
        data = json.loads(candidate)
    except (json.JSONDecodeError, TypeError):
        return AgentVerdict(summary="模型复核输出无法解析", uncertainties=[candidate[:300]])

    verdict = str(data.get("verdict", "unknown")).lower()
    if verdict not in {"malicious", "suspicious", "benign", "unknown"}:
        verdict = "unknown"
    return AgentVerdict(
        verdict=verdict,
        confidence=clamp_confidence(data.get("confidence")),
        artifact_type=str(data.get("artifact_type", "unknown"))[:80],
        summary=str(data.get("summary", ""))[:500],
        behavior_chain=[str(item)[:300] for item in data.get("behavior_chain", [])[:12]],
        evidence=[str(item)[:500] for item in data.get("evidence", [])[:20]],
        counter_evidence=[str(item)[:500] for item in data.get("counter_evidence", [])[:12]],
        uncertainties=[str(item)[:500] for item in data.get("uncertainties", [])[:12]],
        model_reviewed=True,
    )

