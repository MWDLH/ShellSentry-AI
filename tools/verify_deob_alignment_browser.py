"""守卫：反混淆面板行号必须与代码逐行对齐。

## 为什么不能用 Range.getBoundingClientRect()
文本被 <mark> 切分时，同一行的多个文本节点会共享同一个 top，
据此算出的"行距=0"是假象（本项目已踩两次）。
可靠做法：把 <code> 的 scrollHeight 减去上下 padding，除以行数 = 平均行高；
平均行高必须恒等于 line-height，否则说明有行盒被撑高。

## 覆盖的真实缺陷（均已修复）
  1. .danger-token 的 padding:1px 2px → 行盒被撑高 → 每遇高亮就累积错位
     （用户现象"又对齐又对不齐"：只有含高亮的行会偏）
  2. .line-numbers 的 padding-top 曾被补偿到 18px → 行高统一后补偿过头
     → 恒定 4px 错位

判据四条全过才算对齐：
  A. 平均行高 == line-height（±0.5px）—— 保证没有行被撑高
  B. 首行偏差 ≤1px—— 行号栏 padding 与代码区一致
  C. 两侧可滚范围相等 —— 滚到底不漂
  D. 行数一致 —— 保证一一对应
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
PORT = os.environ.get("SHELLSENTRY_TEST_PORT", "8812")
BASE = "http://127.0.0.1:" + PORT
# 仓库根目录：与本脚本位置相对推导，避免硬编码绝对路径（便于他人 clone 后运行）
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_STATIC = os.path.join(ROOT, "src", "shellsentry", "web", "static")
TARGET = os.path.join(_STATIC, "_ga.html")
FIXTURE = os.path.join(ROOT, "zz_samples", ".real_deob_snapshot.txt")
RV = os.path.join(_STATIC, "scripts", "report-view.js")
UT = os.path.join(_STATIC, "scripts", "utils.js")

PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8">
<link rel="stylesheet" href="/static/styles/app.css"></head>
<body style="margin:0;background:#0f1115">
<div class="code-view decoded-view" style="height:520px">
<div class="line-numbers" id="lineNumbers"></div>
<pre class="decoded-code" id="decodedCode"><code id="holder"></code></pre>
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
var NL=String.fromCharCode(10);
var g=byId('lineNumbers'), c=byId('decodedCode'), holder=byId('holder');
var rendered=renderHighlightedCode(__DE__,[]);
holder.innerHTML=rendered.html;
syncDecodedGutter(rendered.numbers);
setTimeout(function(){
  var cs=getComputedStyle(c), gs=getComputedStyle(g);
  var pt=parseFloat(cs.paddingTop)||0, pb=parseFloat(cs.paddingBottom)||0;
  var gpt=parseFloat(gs.paddingTop)||0;
  var lh=parseFloat(gs.lineHeight)||20;
  var n=rendered.numbers.split(NL).length;
  var avg=(c.scrollHeight-pt-pb)/n;
  // 首行 y：取【第一行】的首个文本片段的 glyph 顶部。
  // 注意不能简单跳过含换行的节点 —— 那样会拿到中间某行（空行），
  // 得出几百 px 的假偏差。必须按 NL 切分后取第一段。
  // 必须对【代码区与行号栏】各测一次再相减：只测代码区、拿"行号栏盒顶 + padding"
  // 当基准是错的（行号 glyph 在行盒内有半行距偏移），会漏掉恒定错位。
  function firstGlyphTop(root){
    var w=document.createTreeWalker(root,NodeFilter.SHOW_TEXT), nd;
    while((nd=w.nextNode())){
      var v=nd.nodeValue||'';
      if(v.length===0) continue;
      var parts=v.split(NL);
      var seg=parts[0];
      if(seg.length>0){
        var r=document.createRange();
        r.setStart(nd,0); r.setEnd(nd,Math.max(seg.length,1));
        return r.getBoundingClientRect().top;
      }
      // parts[0] 为空说明该节点以换行开头，落到下一行
      if(parts.length>1 && parts[1].length>0){
        var r2=document.createRange();
        r2.setStart(nd,1); r2.setEnd(nd,Math.min(parts[1].length+1,v.length));
        return r2.getBoundingClientRect().top;
      }
    }
    return null;
  }
  var top0=firstGlyphTop(holder);
  var gtop0=firstGlyphTop(g);
  var fd=(top0===null||gtop0===null)?999:+(top0-gtop0).toFixed(2);
  document.getElementById('__r__').textContent='R:'+JSON.stringify({
    rows:n, gutter:(g.textContent||'').split(NL).length,
    lh:lh, avg:+avg.toFixed(3), fd:fd,
    pt:pt, pb:pb, gpt:gpt,
    marks:holder.querySelectorAll('mark').length,
    sd:(c.scrollHeight-c.clientHeight)-(g.scrollHeight-g.clientHeight)
  });
},700);
</script></body></html>"""


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


def build():
    rv = open(RV, encoding="utf-8").read()
    ut = open(UT, encoding="utf-8").read()
    de = open(FIXTURE, encoding="utf-8").read()
    de = "\n".join(l for l in de.split("\n") if not l.startswith("#"))
    return (PAGE.replace("__ESC__", cut_fn(ut, "export function escapeHtml"))
                .replace("__REND__", cut_fn(rv, "function renderHighlightedCode"))
                .replace("__SYNC__", cut_fn(rv, "export function syncDecodedGutter("))
                .replace("__ALIGN__", cut_fn(rv, "export function alignDecodedGutterHeight("))
                .replace("__SYNCSC__", cut_fn(rv, "export function syncDecodedScroll("))
                .replace("__DE__", json.dumps(de)))


def run(chrome, label, height):
    with open(TARGET, "w", encoding="utf-8") as f:
        f.write(build())
    prof = tempfile.mkdtemp(prefix="ga_")
    try:
        r = subprocess.run(
            [chrome, "--headless=new", "--disable-gpu", "--no-sandbox",
             f"--user-data-dir={prof}", f"--window-size=1400,{height}",
             "--virtual-time-budget=5000", "--dump-dom", f"{BASE}/static/_ga.html"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
        m = re.search(r"R:(\{.*?\})</pre>", r.stdout, re.S)
        if not m:
            got = re.search(r'id="__r__"[^>]*>([^<]*)', r.stdout)
            return None, "测量失败：%s" % (got.group(1)[:200] if got else "无 DOM")
        d = json.loads(H.unescape(m.group(1)))
        h_ok = abs(d["avg"] - d["lh"]) < 0.5
        f_ok = abs(d["fd"]) <= 0.5
        s_ok = d["sd"] == 0
        r_ok = d["rows"] == d["gutter"]
        ok = h_ok and f_ok and s_ok and r_ok
        msg = ("行高%s=%.1f/%s 首行%s=%+.1f pad %s/%s vs %s 滚底%s=%+d 行数%s=%d/%d 高亮=%d" % (
            "OK" if h_ok else "NG", d["avg"], d["lh"],
            "OK" if f_ok else "NG", d["fd"], d["pt"], d["pb"], d["gpt"],
            "OK" if s_ok else "NG", d["sd"],
            "OK" if r_ok else "NG", d["rows"], d["gutter"], d["marks"]))
        return ok, "%-10s %s" % (label, msg)
    finally:
        shutil.rmtree(prof, ignore_errors=True)
        if os.path.exists(TARGET):
            os.remove(TARGET)


def main():
    chrome = next((c for c in CHROME_CANDIDATES if os.path.exists(c)), None)
    if not chrome:
        print("SKIP：未找到 Chrome/Edge")
        return 0
    if not os.path.exists(FIXTURE):
        print("SKIP：缺少夹具 %s" % FIXTURE)
        return 0

    print("=" * 104)
    print("反混淆面板行号对齐 —— 真实浏览器实测")
    print("=" * 104)
    failed = 0
    for h in (900, 700, 1100):
        ok, msg = run(chrome, "视口%d" % h, h)
        if ok is None:
            print("FAIL " + msg)
            failed += 1
            continue
        if not ok:
            failed += 1
        print("%s %s" % ("PASS " if ok else "FAIL ", msg))
    print("-" * 104)
    print("结论：%s" % ("全部对齐 OK" if failed == 0 else "%d 个场景失败 NG" % failed))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())