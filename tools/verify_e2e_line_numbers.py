"""端到端验证：用真实报告走完整 HTTP 链路，核对反混淆面板的行号。

验证两件事（都是用户实际反馈的现象）：
  1. 行号栏显示的是**原始跳号行号**，不是 1..N 连续序号
  2. 深度分析（META_BEHAVIOR）引用的每个 L{x} 都能在行号栏里找到
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

CHROME = r"C:/Program Files/Google/Chrome/Application/chrome.exe"
PORT = os.environ.get("SHELLSENTRY_TEST_PORT", "8809")
BASE = "http://127.0.0.1:" + PORT
# 仓库根目录：与本脚本位置相对推导，避免硬编码绝对路径（便于他人 clone 后运行）
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE = os.path.join(ROOT, "zz_samples", "bx_php.php")


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def post_stream(code, name):
    b = "----e2e"
    payload = (("--%s\r\nContent-Disposition: form-data; name=\"file\"; filename=\"%s\"\r\n"
                "Content-Type: application/octet-stream\r\n\r\n" % (b, name)).encode()
               + code.encode() + ("\r\n--%s--\r\n" % b).encode())
    r = urllib.request.Request(BASE + "/api/audit/stream", data=payload, method="POST")
    r.add_header("Content-Type", "multipart/form-data; boundary=%s" % b)
    text, buf, done = "", "", {}
    with urllib.request.urlopen(r, timeout=900) as resp:
        while True:
            c = resp.read(4096)
            if not c:
                break
            buf += c.decode("utf-8", "replace")
            while "\n\n" in buf:
                blk, buf = buf.split("\n\n", 1)
                ev = ""
                for line in blk.splitlines():
                    if line.startswith("event: "):
                        ev = line[7:].strip()
                    elif line.startswith("data: ") and ev in ("stream", "done"):
                        try:
                            o = json.loads(line[6:])
                        except Exception:
                            continue
                        if ev == "stream":
                            text += o.get("text", "")
                        else:
                            done = o
    return text, done


def cut_fn(src, header):
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


def main():
    code = open(SAMPLE, encoding="utf-8").read()
    print("=== 端到端：真实报告 + 真实前端渲染 ===")
    t0 = time.time()
    text, done = post_stream(code, os.path.basename(SAMPLE))
    print("  审计完成 %.1fs | 报告 %d 字符 | verdict=%s" % (
        time.time() - t0, len(text), done.get("verdict")))

    m = re.search(r"\[DE_OBFUSCATE\](.*?)(?:\[/DE_OBFUSCATE\]|\[C2_INFO\]|\[METADATA_BEHAVIOR\])",
                  text, re.S)
    if not m:
        print("FAIL 报告里没有 [DE_OBFUSCATE] 段")
        return 1
    de = m.group(1).strip()

    # 用真实 renderHighlightedCode 生成 numbers 与 html
    rv = open(os.path.join(ROOT, "src", "shellsentry", "web", "static", "scripts", "report-view.js"),
              encoding="utf-8").read()
    ut = open(os.path.join(ROOT, "src", "shellsentry", "web", "static", "scripts", "utils.js"),
              encoding="utf-8").read()
    esc_fn = cut_fn(ut, "export function escapeHtml")
    rend = cut_fn(rv, "function renderHighlightedCode")
    sync = cut_fn(rv, "export function syncDecodedGutter(")
    align = cut_fn(rv, "export function alignDecodedGutterHeight(")
    syncsc = cut_fn(rv, "export function syncDecodedScroll(")
    cache_decl = rv[rv.index("let decodedNumbersCache"):]
    cache_decl = cache_decl[:cache_decl.index("\n")]
    cache_name = re.search(r"let (\w+)", cache_decl).group(1)
    obs = rv[rv.index("const observer = new MutationObserver("):
             rv.index("});", rv.index("const observer = new MutationObserver(")) + 3]

    lines, nums = [], []
    for raw in de.split("\n"):
        mm = re.match(r"^\[LINE_(\d+)\]", raw)
        body = raw[mm.end():] if mm else raw
        body = body.replace("[[HL]]", '<span class="hl">').replace("[[/HL]]", "</span>")
        lines.append(esc(body))
        nums.append(str(int(mm.group(1)) if mm else 0))
    if not any(nums):
        print("  （该样本 DE 段无 [LINE_x] 标签，跳过行号核对）")
        return 0

    page = """<!DOCTYPE html><html><head><meta charset="utf-8">
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
__ESC__
__REND__
__SYNC__
__ALIGN__
__SYNCSC__
__CACHE_DECL__
const g=byId('lineNumbers'), c=byId('decodedCode');
let syncing=false;
__OBS__
observer.observe(c,{childList:true,characterData:true,subtree:true});
observer.observe(g,{childList:true,characterData:true});
const rendered=renderHighlightedCode(__DE__,[]);
c.innerHTML='<code>'+rendered.html+'</code>';
__CACHE_NAME__=rendered.numbers;
syncDecodedGutter(rendered.numbers);
if(c.addEventListener)c.addEventListener('scroll',syncDecodedScroll,{passive:true});
setTimeout(()=>{
  const out={expected:rendered.numbers, after:g.textContent,
             preserved:(g.textContent===rendered.numbers)};
  out.nums=g.textContent.split('\\n').map(Number);
  document.getElementById('__r__').textContent='R:'+JSON.stringify(out);
},800);
</script></body></html>"""
    tgt = os.path.join(ROOT, "src", "shellsentry", "web", "static", "_e2e_lineno.html")
    page = (page.replace("__ESC__", esc_fn).replace("__REND__", rend)
                .replace("__SYNC__", sync).replace("__ALIGN__", align)
                .replace("__SYNCSC__", syncsc).replace("__CACHE_DECL__", cache_decl)
                .replace("__CACHE_NAME__", cache_name)
                .replace("__OBS__", obs)
                .replace("__DE__", json.dumps(de)))
    with open(tgt, "w", encoding="utf-8") as f:
        f.write(page)
    prof = tempfile.mkdtemp(prefix="e2e_")
    try:
        r = subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--no-sandbox",
                            f"--user-data-dir={prof}", "--window-size=1400,900",
                            "--virtual-time-budget=5000", "--dump-dom",
                            f"{BASE}/static/_e2e_lineno.html"],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=120)
        m2 = re.search(r"R:(\{.*?\})</pre>", r.stdout, re.S)
        if not m2:
            got = re.search(r'id="__r__"[^>]*>([^<]*)', r.stdout)
            print("FAIL 渲染失败：%s" % (got.group(1)[:200] if got else "无 DOM"))
            return 1
        d = json.loads(m2.group(1).replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">"))
    finally:
        shutil.rmtree(prof, ignore_errors=True)
        if os.path.exists(tgt):
            os.remove(tgt)

    got_nums = d["nums"]
    meta = re.search(r"\[METADATA_BEHAVIOR\](.*)", text, re.S)
    refs = sorted({int(x) for x in re.findall(r"\bL(\d+)\b", meta.group(1))}) if meta else []
    orphan = [x for x in refs if x not in got_nums]
    gaps = any(got_nums[i] != got_nums[i - 1] + 1 for i in range(1, len(got_nums)))

    print()
    print("  行号栏前12     :", got_nums[:12])
    print("  原始行号是否保留:", "是 OK" if d["preserved"] else "否 NG")
    print("  是否含跳号      :", "是（模型省略了部分行）" if gaps else "否（本样本连续）")
    print("  深度分析引用    :", refs)
    print("  行号栏中找不到  :", orphan if orphan else "无 OK")
    print()
    ok = d["preserved"] and not orphan
    print("结论：%s" % ("端到端行号一致 OK" if ok else "存在不一致 NG"))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())