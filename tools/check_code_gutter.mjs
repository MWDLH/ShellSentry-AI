// 代码反混淆面板 · 行号跟随体检（真实浏览器，CDP 驱动）
//
// 为什么需要它：这类缺陷在任何静态检查里都看不出来 —— CSS 语法合法、
// 单元测试全绿、页面照常渲染，只是滚动时代码在动、行号不动。
// 2026-09-20 的实际缺陷：
//   · .code-view 是 overflow:hidden 的两列网格，只有 <pre> 自带滚动条；
//     行号栏 overflow:hidden 不会跟随 → 滚动后行号停在原处，与代码彻底错位；
//   · 行号栏被裁（clientHeight 445 / scrollHeight 1108，54 行只显示 22 行），
//     被裁掉的行号永远进不了视野，用户看到的就是"行标显示不全"。
// 修复后不变量：
//   1. 代码区滚动 → 行号栏 scrollTop 同步；
//   2. 两侧【视觉行位】零误差（同一行的行号与代码 y 坐标相等）；
//   3. 两侧【可滚范围】相等 —— 含"超长行触发横向滚动条"的场景，
//      此时 <pre> 可见高度少一条滚动条的量，行号栏必须等量补偿。
//
// 用法（需要本地服务已在运行，且历史里有至少一条带反混淆内容的任务）：
//   node tools/check_code_gutter.mjs
//   node tools/check_code_gutter.mjs http://127.0.0.1:9000
//   CHROME_PATH=/path/to/chrome node tools/check_code_gutter.mjs
//
// 退出码：0 = 全部通过；1 = 存在失败项；2 = 环境不可用（无浏览器/无样本）
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const args = process.argv.slice(2);
const url = args.find(a => !a.startsWith("--")) || "http://127.0.0.1:8765";
const PORT = 9600 + Math.floor(Math.random() * 100);

function findChrome() {
  if (process.env.CHROME_PATH && existsSync(process.env.CHROME_PATH)) return process.env.CHROME_PATH;
  const bases = [
    process.env.LOCALAPPDATA && join(process.env.LOCALAPPDATA, "ms-playwright"),
    process.env.HOME && join(process.env.HOME, ".cache", "ms-playwright")
  ].filter(Boolean);
  for (const base of bases) {
    if (!existsSync(base)) continue;
    for (const dir of readdirSync(base).filter(d => d.startsWith("chromium"))) {
      for (const rel of ["chrome-win64/chrome.exe", "chrome-linux/chrome", "chrome-mac/Chromium.app/Contents/MacOS/Chromium"]) {
        const p = join(base, dir, rel);
        if (existsSync(p)) return p;
      }
    }
  }
  return null;
}

const chromePath = findChrome();
if (!chromePath) {
  console.error("未找到 Chromium。请设置 CHROME_PATH 环境变量指向浏览器可执行文件。");
  process.exit(2);
}

const profile = mkdtempSync(join(tmpdir(), "ssgutter-"));
const chrome = spawn(chromePath, [
  "--headless=new", `--remote-debugging-port=${PORT}`, `--user-data-dir=${profile}`,
  "--no-first-run", "--no-default-browser-check", "--disable-gpu", url
], { stdio: "ignore" });

const sleep = ms => new Promise(r => setTimeout(r, ms));

async function firstPageTarget() {
  for (let i = 0; i < 60; i++) {
    try {
      const list = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
      const page = list.find(t => t.type === "page" && t.webSocketDebuggerUrl);
      if (page) return page;
    } catch (_) { /* 尚未就绪 */ }
    await sleep(500);
  }
  throw new Error("Chrome DevTools 端点未就绪");
}

class CDP {
  constructor(ws) { this.ws = ws; this.seq = 0; this.pending = new Map(); }
  static async connect(targetUrl) {
    const ws = new WebSocket(targetUrl);
    await new Promise((res, rej) => { ws.onopen = res; ws.onerror = rej; });
    const client = new CDP(ws);
    ws.onmessage = ev => {
      const msg = JSON.parse(ev.data);
      const slot = msg.id && client.pending.get(msg.id);
      if (!slot) return;
      client.pending.delete(msg.id);
      msg.error ? slot.rej(new Error(JSON.stringify(msg.error))) : slot.res(msg.result);
    };
    return client;
  }
  send(method, params = {}) {
    const id = ++this.seq;
    return new Promise((res, rej) => { this.pending.set(id, { res, rej }); this.ws.send(JSON.stringify({ id, method, params })); });
  }
  async evaluate(expression) {
    const r = await this.send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.text || "页面脚本异常");
    return r.result.value;
  }
}

// 页面内工具：按文本行取屏幕坐标，用于逐行比对行号栏与代码区
const HELPERS = `
  const firstY = (el) => { const r = document.createRange(); r.selectNodeContents(el);
    const t = [...r.getClientRects()]; return t.length ? Math.round(t[0].top) : null; };
  const lastY = (el) => { const r = document.createRange(); r.selectNodeContents(el);
    const t = [...r.getClientRects()]; return t.length ? Math.round(t[t.length - 1].top) : null; };
`;

const main = async () => {
  const cdp = await CDP.connect((await firstPageTarget()).webSocketDebuggerUrl);
  await cdp.send("Runtime.enable");
  await cdp.send("Page.enable");
  await cdp.send("Emulation.setDeviceMetricsOverride", { width: 1432, height: 768, deviceScaleFactor: 1, mobile: false });
  await cdp.send("Page.navigate", { url });
  await sleep(2500);

  const loaded = await cdp.evaluate(`(() => {
    const item = document.querySelector(".history-item[data-task-id]");
    if (!item) return null;
    item.click();
    return item.dataset.displayName || item.dataset.taskId;
  })()`);
  if (!loaded) {
    console.error("历史里没有可加载的任务，无法体检。请先跑一次审计。");
    chrome.kill(); process.exit(2);
  }
  await sleep(4000);
  await cdp.evaluate(`(() => { const t = document.querySelector('[data-section-tab="restoration"]'); if (t) t.click(); })()`);
  await sleep(800);

  const probe = await cdp.evaluate(`(() => {
    ${HELPERS}
    const code = document.getElementById("decodedCode");
    const gutter = document.getElementById("lineNumbers");
    if (!code || !gutter) return { fatal: "找不到代码反混淆节点" };
    const codeLines = (code.textContent || "").split("\\n").length;
    const gutterLines = (gutter.textContent || "").split("\\n").length;
    return {
      task: ${JSON.stringify(loaded)},
      codeLines, gutterLines,
      firstCodeY: firstY(code), firstGutterY: firstY(gutter),
      listenerBound: typeof code.onscroll !== "undefined"
    };
  })()`);
  if (probe.fatal) { console.error(probe.fatal); chrome.kill(); process.exit(2); }
  if (probe.codeLines < 2) {
    console.error(`加载的任务「${probe.task}」没有反混淆内容（${probe.codeLines} 行），无法体检。`);
    chrome.kill(); process.exit(2);
  }

  const scrolled = await cdp.evaluate(`(async () => {
    ${HELPERS}
    const code = document.getElementById("decodedCode");
    const gutter = document.getElementById("lineNumbers");
    code.scrollTop = 400;
    await new Promise(r => setTimeout(r, 250));
    const mid = { codeTop: code.scrollTop, gutterTop: gutter.scrollTop,
                  codeY: firstY(code), gutterY: firstY(gutter) };
    code.scrollTop = 999999;
    await new Promise(r => setTimeout(r, 250));
    const view = document.querySelector(".code-view");
    return {
      mid,
      bottom: { codeTop: code.scrollTop, gutterTop: gutter.scrollTop,
                codeLastY: lastY(code), gutterLastY: lastY(gutter),
                gutterLastVisible: (lastY(gutter) ?? Infinity) < view.getBoundingClientRect().bottom },
      maxCode: code.scrollHeight - code.clientHeight,
      maxGutter: gutter.scrollHeight - gutter.clientHeight
    };
  })()`);

  // 场景二：注入超长行，触发横向滚动条后再比对（此时 <pre> 可见高度会少一条滚动条）
  const wide = await cdp.evaluate(`(async () => {
    ${HELPERS}
    const code = document.getElementById("decodedCode");
    const gutter = document.getElementById("lineNumbers");
    code.querySelector("code").insertAdjacentHTML("beforeend", "\\n// " + "A".repeat(400));
    await new Promise(r => setTimeout(r, 400));
    code.scrollTop = 999999;
    await new Promise(r => setTimeout(r, 250));
    return {
      hasScrollbar: code.scrollWidth > code.clientWidth,
      codeClientH: code.clientHeight, gutterClientH: gutter.clientHeight,
      maxCode: code.scrollHeight - code.clientHeight,
      maxGutter: gutter.scrollHeight - gutter.clientHeight,
      codeLastY: lastY(code), gutterLastY: lastY(gutter)
    };
  })()`);

  const checks = [
    ["行号数量等于代码行数", probe.codeLines === probe.gutterLines, `行号 ${probe.gutterLines} vs 代码 ${probe.codeLines}`],
    ["初始状态两侧首行对齐", Math.abs(probe.firstGutterY - probe.firstCodeY) <= 1, `行号 ${probe.firstGutterY} vs 代码 ${probe.firstCodeY}`],
    ["代码滚动时行号跟随", scrolled.mid.gutterTop === scrolled.mid.codeTop && scrolled.mid.gutterTop > 0,
      `行号 scrollTop=${scrolled.mid.gutterTop} 代码 scrollTop=${scrolled.mid.codeTop}`],
    ["滚动后两侧行位零误差", Math.abs(scrolled.mid.gutterY - scrolled.mid.codeY) <= 1, `差 ${Math.abs(scrolled.mid.gutterY - scrolled.mid.codeY)}px`],
    ["两侧可滚范围相等", scrolled.maxCode === scrolled.maxGutter, `代码 ${scrolled.maxCode} vs 行号 ${scrolled.maxGutter}`],
    ["滚到底后末行零误差", Math.abs(scrolled.bottom.gutterLastY - scrolled.bottom.codeLastY) <= 1,
      `差 ${Math.abs(scrolled.bottom.gutterLastY - scrolled.bottom.codeLastY)}px`],
    ["最后的行号能进入视野", scrolled.bottom.gutterLastVisible === true, "末行行号仍在容器之外"],
    ["超长行两侧可滚范围仍相等", wide.maxCode === wide.maxGutter, `代码 ${wide.maxCode} vs 行号 ${wide.maxGutter}`],
    ["超长行末行零误差", Math.abs(wide.gutterLastY - wide.codeLastY) <= 1, `差 ${Math.abs(wide.gutterLastY - wide.codeLastY)}px`]
  ];

  console.log(`任务「${probe.task}」 · ${probe.codeLines} 行 · ${url}`);
  let failed = 0;
  for (const [name, ok, detail] of checks) {
    console.log(`${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : ` — ${detail}`}`);
    if (!ok) failed += 1;
  }
  console.log(`实测: 可视高 代码=${wide.codeClientH} 行号=${wide.gutterClientH}（横向滚动条占高差）`);
  console.log(`code gutter probe: PASS=${checks.length - failed} FAIL=${failed}`);

  chrome.kill();
  process.exit(failed ? 1 : 0);
};

main().catch(err => { console.error("体检失败:", err.message); chrome.kill(); process.exit(2); });
