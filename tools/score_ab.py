"""A/B 验收集离线评分器（只读，不调用任何 API）。

用途：用户在 Web UI 上跑完 zz_samples/ab/ 下的样本后，本脚本读取本地
历史落盘 JSON，对照答案卡（zz_samples/ab/README.md）自动打分，输出
「静态基线 vs AI 结论 vs 标准答案」三方对照表。

数据来源：%LOCALAPPDATA%/ShellSentry/history/*.json（由 paths.history_dir() 决定）
  关键字段：
    report.raw_ai_output                  AI 原始输出全文（含各标签段）
    report.agent_verdict.*                AI 结构化结论
    report.regex_scan.deterministic_verdict  静态层基线
    report.done.*                         融合后的最终风险与完成状态

用法：
    python tools/score_ab.py                 # 自动扫描历史目录
    python tools/score_ab.py <file.json>    # 指定某个历史文件
    python tools/score_ab.py --all-history  # 连非 A/B 样本一起列出

退出码：0 = 全部通过；1 = 存在未达标项；2 = 没有可评分的历史记录
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from shellsentry import paths  # noqa: E402


# ---------------------------------------------------------------- 答案卡

# 主样本后门的 9 个锚点。判定采用「任一别名命中即算」，避免模型用同义表述
# （例如写"异或"不写 XOR、写"shutdown 钩子"不写 register_shutdown_function）
# 时产生假阴性 —— 评的是"是否识别出该能力"，不是"是否复述了同一串字符"。
ANCHORS = [
    ("会话密钥协商", ["md5", "会话密钥", "negotiatekey", "session", "会话"]),
    ("外部输入 POST/COOKIE", ["$_post", "$_cookie", "post 参数", "post参数", "外部输入", "用户输入"]),
    ("base64 解码", ["base64"]),
    ("循环异或还原", ["xor", "异或", "逐字节"]),
    ("eval 动态执行", ["eval"]),
    ("shell_exec 命令执行", ["shell_exec", "shell exec", "命令执行", "system("]),
    ("php://input 落地", ["php://input", "原始流", "原始请求体"]),
    ("fsockopen 回连", ["fsockopen", "回连", "外联", "c2", "127.0.0.1", "8443"]),
    ("启动钩子注册", ["register_shutdown_function", "shutdown", "启动钩子", "无条件执行"]),
]

# 重点锚点：README 指定必须盯住的两条（eval + shell_exec）
CRITICAL_ANCHORS = {"eval 动态执行", "shell_exec 命令执行"}

# 期望结论
EXPECT = {
    "ab_bench_php_tail_backdoor.php": "malicious",
    "ab_bench_php_clean_control.php": "benign",
    "ab_bench_php_single_line_small.php": "malicious",
    "ab_bench_php_single_line_huge.php": "malicious",
}

BENIGN_WORDS = {"benign", "clean", "no_indication", "none"}
MALICIOUS_WORDS = {"malicious", "suspicious"}

# 良性对照里若出现这些词，说明模型做了具体指控 → 疑似注意力稀释导致过度解读
OVERREAD_HINTS = ["webshell", "后门", "恶意", "攻击", "c2", "回连", "shell_exec", "eval("]

# 否定式表述不算指控（"未发现恶意行为"是正确结论，不是过度解读）。
# 检测前先按否定短语切段，只保留否定词之后的短窗之外的文本。
NEGATION_PATTERN = re.compile(
    r"(?:未发现|未检测|不存在|没有发现|无|非|排除|不属于|未见|并非|不构成)"
    r"[^。；;\n]{0,12}"
)


# ---------------------------------------------------------------- 读取

def load_history(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def verdict_text(rep):
    """把该次审计里所有可被模型自由表述的文本合并，作为"模型看到了什么"的证据面。"""
    parts = []
    parts.append(rep.get("raw_ai_output") or "")
    av = rep.get("agent_verdict") or {}
    for k in ("summary", "verdict", "artifact_type"):
        if av.get(k):
            parts.append(str(av[k]))
    for lst in ("behavior_chain", "evidence", "counter_evidence", "uncertainties"):
        for item in av.get(lst) or []:
            parts.append(item if isinstance(item, str) else json.dumps(item, ensure_ascii=False))
    return "\n".join(parts)


def norm(s):
    return (s or "").lower()


# ---------------------------------------------------------------- 评分

def score(path):
    doc = load_history(path)
    rep = doc.get("report") or {}
    fname = doc.get("filename") or "?"
    expect = EXPECT.get(fname)

    text = verdict_text(rep)
    low = norm(text)
    av = rep.get("agent_verdict") or {}
    det = (rep.get("regex_scan") or {}).get("deterministic_verdict") or {}
    done = rep.get("done") or {}
    final_verdict = (av.get("verdict") or done.get("verdict") or "").lower()

    row = {
        "file": os.path.basename(path),
        "filename": fname,
        "ts": doc.get("timestamp", "")[:19],
        "expect": expect or "(非 A/B 样本)",
        "ai_verdict": av.get("verdict") or "-",
        "ai_conf": av.get("confidence"),
        "static_verdict": det.get("verdict") or "-",
        "static_score": det.get("risk_score"),
        "model_reviewed": av.get("model_reviewed"),
        "raw_len": len(rep.get("raw_ai_output") or ""),
        "chain": len(av.get("behavior_chain") or []),
        "evidence": len(av.get("evidence") or []),
        "truncated": done.get("report_truncated"),
        "has_error": done.get("has_error"),
        "empty_output": done.get("empty_output"),
        "flags": [],
    }

    # 事故态：AI 根本没产出内容 → 本条不具评分意义
    if not (rep.get("raw_ai_output") or "").strip():
        row["flags"].append("空输出(AI 未产出内容，本条不可用于评分)")
        return row, None

    if expect is None:
        return row, None

    # 结论正确性
    if expect == "benign":
        ok = final_verdict in BENIGN_WORDS
        row["flags"].append("结论正确" if ok else f"*** 误报：期望 benign，实得 {final_verdict or '空'} ***")
        # 剔除"未发现…""无…""非…"等否定式窗口后再找指控词
        scrubbed = NEGATION_PATTERN.sub(" ", low)
        hits = [w for w in OVERREAD_HINTS if w in scrubbed]
        if hits:
            row["flags"].append("*** 过度解读：出现指控词 " + ",".join(hits[:5]) + " ***")
    else:
        ok = final_verdict in MALICIOUS_WORDS
        row["flags"].append("结论正确" if ok else f"*** 漏报：期望 malicious，实得 {final_verdict or '空'} ***")

    # 锚点覆盖率（仅主样本）
    if fname == "ab_bench_php_tail_backdoor.php":
        hit, miss = [], []
        for name, aliases in ANCHORS:
            (hit if any(a in low for a in aliases) else miss).append(name)
        row["anchor_hit"] = len(hit)
        row["anchor_miss"] = miss
        row["anchor_total"] = len(ANCHORS)
        lost_critical = [m for m in miss if m in CRITICAL_ANCHORS]
        if lost_critical:
            row["flags"].append("*** 关键锚点未识别：" + ",".join(lost_critical) + " ***")
        else:
            row["flags"].append("关键锚点(eval/shell_exec)均被识别")
    return row, ok


# ---------------------------------------------------------------- 输出

def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    show_all = "--all-history" in sys.argv

    if args:
        files = args
    else:
        hdir = paths.history_dir()
        if not os.path.isdir(hdir):
            print("历史目录不存在:", hdir)
            return 2
        files = [os.path.join(hdir, f) for f in sorted(os.listdir(hdir)) if f.endswith(".json")]

    rows, judged = [], []
    for f in files:
        try:
            row, ok = score(f)
        except Exception as exc:  # 单条损坏不应中断整体评分
            rows.append({"file": os.path.basename(f), "filename": "(解析失败)", "flags": [str(exc)[:60]]})
            continue
        rows.append(row)
        if ok is not None:
            judged.append((row["filename"], ok))

    if not rows:
        print("没有可评分的历史记录。")
        return 2

    print("=" * 104)
    print("A/B 验收集 · 离线评分（数据源：%s）" % os.path.dirname(files[0]))
    print("=" * 104)
    hdr = "%-36s %-11s %-6s %-11s %-6s %-7s %s"
    print(hdr % ("样本", "AI 结论", "置信", "静态基线", "分值", "AI文本", "复核"))
    print("-" * 104)
    for r in rows:
        if r["filename"] == "(非 A/B 样本)" and not show_all:
            continue
        print(hdr % (
            r["filename"][:36],
            str(r.get("ai_verdict", "-"))[:11],
            str(r.get("ai_conf", "-"))[:6],
            str(r.get("static_verdict", "-"))[:11],
            str(r.get("static_score", "-"))[:6],
            str(r.get("raw_len", "-"))[:7],
            "是" if r.get("model_reviewed") else "否",
        ))
        if r.get("anchor_total"):
            print("      锚点覆盖: %d/%d" % (r["anchor_hit"], r["anchor_total"]), end="")
            if r["anchor_miss"]:
                print("  未命中: " + ", ".join(r["anchor_miss"]))
            else:
                print("  (全中)")
        if r.get("truncated") is not None or r.get("has_error"):
            print("      完成态: truncated=%s has_error=%s empty_output=%s"
                  % (r.get("truncated"), r.get("has_error"), r.get("empty_output")))
        for fl in r["flags"]:
            print("      - " + fl)
    print("-" * 104)

    if not judged:
        print("\n未匹配到任何 A/B 样本的历史记录。请在 Web UI 跑完 zz_samples/ab/ 下的样本后重试。")
        print("（当前历史里的样本：%s）" % ", ".join(sorted({r["filename"] for r in rows})))
        return 2

    bad = [n for n, ok in judged if not ok]
    print("\n结论判定: %d/%d 正确" % (len(judged) - len(bad), len(judged)))
    if bad:
        print("未达标:", ", ".join(bad))
        return 1
    print("全部达标。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
