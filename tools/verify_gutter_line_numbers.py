"""守卫：反混淆面板的行号栏必须保留模型的【原始跳号行号】。

缺陷（2026-10-09 用户连续反馈"行号还是漂移"）：
  installDecodedGutterGuard 的 MutationObserver 回调调用了**无参**
  syncDecodedGutter()，它按textContent 行数重推 1..N 连续序号，
  把 renderHighlightedCode 精心算出的原始行号（如 1,3,3,4 ——模型
  省略了注释行与空行）全部抹平。于是：
    · 行号栏与「深度分析」引用的真实行号对不上
    · 用户看到行号连续但点不中代码位置

为什么必须浏览器实测：Node 校验脚本没有 MutationObserver，
这个缺陷在纯单元测试里**永远不会暴露**。

本守卫用跳号样本走完整线上时序：
  observer 先注册 → 写入代码 → 显式同步 → 观察器回调
判据：观察器回调后行号栏必须与原始行号**逐行完全一致**。
"""
import html as H
import json
import os
import re
import shutil
import subprocess
import tempfile

CHROME_CANDIDATES = [
    r"C:/Program Files/Google/Chrome/Application/chrome.exe",
    r"C:/Program Files (x86)/Google/Chrome/Application/chrome.exe",
    r"C:/Program Files/Microsoft/Edge/Application/msedge.exe",
]
BASE = "http://127.0.0.1:" + os.environ.get("SHELLSENTRY_TEST_PORT", "8809")
# 仓库根目录：与本脚本位置相对推导，避免硬编码绝对路径（便于他人 clone 后运行）
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_STATIC = os.path.join(ROOT, "src", "shellsentry", "web", "static")
TARGET = os.path.join(_STATIC, "_guard_lineno.html")
DE = os.path.join(ROOT, "zz_samples", ".real_deob_snapshot.txt")
RV = os.path.join(_STATIC, "scripts", "report-view.js")


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def cut_fn(src, header):
    """按花括号配平截取完整函数体（签名行本身以 { 结尾，不能按行首匹配）。"""
    i = src.index(header)
    depth = 0
    for k in range(i, len(src)):
        if src[k] == "{":
            depth += 1
        elif src[k] == "}":
            depth -= 1
            if depth == 0:
                return src[i:k + 1].replace("export function", "function", 1)
    return src[i:i + 2500].replace("export function", "function", 1)


PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8">
<link rel="stylesheet" href="/static/styles/app.css"></head>
<body style="margin:0;background:#0f1115">
<div class="code-view decoded-view">
<div class="line-numbers" id="lineNumbers"></div>
<pre class="decoded-code" id="decodedCode"><code></code></pre>
</div>
<pre id="__r__" style="display:none"></pre>
<script>window.onerror=function(m,u,l){document.getElementById('__r__').textContent='E:'+m+' @'+l;};</script>
<script>
function byId(id){return document.getElementById(id);}
__FNS__
__CACHE_DECL__
const g=byId('lineNumbers'), c=byId('decodedCode');
const NUMS=__NUMS__, HTML=__HTML__;

// —— 与线上完全一致的时序 ——
let syncing=false;
__OBSERVER__          // ← 从report-view.js 原样抽取的真实回调
observer.observe(c,{childList:true,characterData:true,subtree:true});
observer.observe(g,{childList:true,characterData:true});
c.innerHTML=HTML;                        // 渲染（触发观察器）
__CACHE_ASSIGN__
syncDecodedGutter(NUMS);
__CACHE_ASSIGN__                          // 模拟面板切走再切回
syncDecodedGutter(__CACHE_ARG__);

const out={};
setTimeout(()=>{
  out.expected=NUMS;
  out.after=g.textContent;
  out.preserved=(g.textContent===NUMS);
  const codeLines=(c.textContent||'').split('\\n').length;
  out.rowsOk=(g.textContent.split('\\n').length===codeLines);
  const ns=NUMS.split('\\n').map(Number);
  out.hasGaps=ns.some((v,i)=>i>0 && v!==ns[i-1]+1);
  document.getElementById('__r__').textContent='R:'+JSON.stringify(out);
},700);
</script></body></html>"""


def extract_observer(rv):
    """原样抽取线上 MutationObserver 声明（不重写回调，否则测的就不是线上代码）。"""
    i = rv.index("const observer = new MutationObserver(")
    j = rv.index("});", i) + 3
    return rv[i:j]


def extract_cache_decl(rv):
    i = rv.index("let decodedNumbersCache")
    return rv[i:rv.index("\n", i)]


def build():
    de = open(DE, encoding="utf-8").read()
    lines, nums = [], []
    for k, raw in enumerate(de.split("\n")):
        m = re.match(r"^\[LINE_(\d+)\]", raw)
        num = int(m.group(1)) if m else 0
        if k % 3 == 1:            # 制造跳号：模拟模型省略注释行
            lines.append("   // …… 省略的注释行 ……")
            nums.append(str(num + 1))
            continue
        body = raw[m.end():] if m else raw
        body = body.replace("[[HL]]", '<span class="hl">').replace("[[/HL]]", "</span>")
        lines.append(esc(body))
        nums.append(str(num))

    rv = open(RV, encoding="utf-8").read()
    fns = "\n".join(cut_fn(rv, h) for h in (
        "export function syncDecodedGutter(",
        "export function alignDecodedGutterHeight(",
        "export function syncDecodedScroll(",
    ))
    cache_decl = extract_cache_decl(rv)
    cache_name = re.search(r"let (\w+)", cache_decl).group(1)
    return (PAGE.replace("__FNS__", fns)
                .replace("__OBSERVER__", extract_observer(rv))
                .replace("__CACHE_DECL__", cache_decl)
                .replace("__CACHE_ASSIGN__", "%s = NUMS;" % cache_name)
                .replace("__CACHE_ARG__", cache_name)
                .replace("__NUMS__", json.dumps("\n".join(nums)))
                .replace("__HTML__", json.dumps("<code>" + "\n".join(lines) + "</code>")))


def main():
    chrome = next((c for c in CHROME_CANDIDATES if os.path.exists(c)), None)
    if not chrome:
        print("SKIP：未找到 Chrome/Edge")
        return 0
    if not os.path.exists(DE):
        print("SKIP：缺少样本快照 %s" % DE)
        return 0
    with open(TARGET, "w", encoding="utf-8") as f:
        f.write(build())
    prof = tempfile.mkdtemp(prefix="gn_")
    try:
        r = subprocess.run(
            [chrome, "--headless=new", "--disable-gpu", "--no-sandbox",
             f"--user-data-dir={prof}", "--window-size=1400,900",
             "--virtual-time-budget=5000", "--dump-dom", f"{BASE}/static/_guard_lineno.html"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
        m = re.search(r"R:(\{.*?\})</pre>", r.stdout, re.S)
        if not m:
            got = re.search(r'id="__r__"[^>]*>([^<]*)', r.stdout)
            print("FAIL 测量失败：%s" % (got.group(1)[:200] if got else "无 DOM"))
            return 1
        d = json.loads(H.unescape(m.group(1)))
    finally:
        shutil.rmtree(prof, ignore_errors=True)
        if os.path.exists(TARGET):
            os.remove(TARGET)

    checks = [
        ("样本确实含跳号行号（否则测不出问题）", d["hasGaps"], True),
        ("行号栏行数 == 代码区行数", d["rowsOk"], True),
        ("观察器回调后仍保留原始跳号行号", d["preserved"], True),
    ]
    failed = 0
    for name, got, want in checks:
        ok = got == want
        failed += 0 if ok else 1
        print("%s %s" % ("PASS " if ok else "FAIL ", name))
    if not d["preserved"]:
        print("       期望前12: %s" % d["expected"].split("\n")[:12])
        print("       实际前12: %s" % d["after"].split("\n")[:12])
    print("-" * 70)
    print("结论：%s" % ("原始行号未被破坏 OK" if failed == 0 else "%d 项失败 NG" % failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())