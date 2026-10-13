// 真实浏览器布局体检：验证"滚动容器底边不得越出视口"这一不变量。
//
// 为什么需要它：这类缺陷在任何静态检查里都看不出来 —— CSS 语法合法、单元测试全绿、
// 页面照常渲染，只是滚动条悄悄少了一段可滚距离。2026-09-20 的事故就是它：
// .app-shell 缺 grid-template-rows，内容 1005px 时行高被撑到 984px，
// #workbench 底边掉到窗口外 216px，可滚距离从 295px 缩到 79px，
// 用户表现为"滚不到底、下面的内容看不到"。
//
// 用法（需要本地服务已在运行）：
//   node tools/check_layout.mjs                      # 默认 http://127.0.0.1:8765
//   node tools/check_layout.mjs http://127.0.0.1:9000 --width=1280 --height=720
//   CHROME_PATH=/path/to/chrome node tools/check_layout.mjs
//
// 退出码非 0 表示布局契约被破坏。自动探测 ms-playwright / 常见安装路径下的 Chromium。
import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const args = process.argv.slice(2);
const url = args.find(a => !a.startsWith("--")) || "http://127.0.0.1:8765";
const opt = name => {
  const hit = args.find(a => a.startsWith(`--${name}=`));
  return hit ? Number(hit.split("=")[1]) : null;
};
const WIDTH = opt("width") || 1432;
const HEIGHT = opt("height") || 768;
const PORT = 9400 + Math.floor(Math.random() * 100);

function findChrome() {
  if (process.env.CHROME_PATH && existsSync(process.env.CHROME_PATH)) return process.env.CHROME_PATH;
  const candidates = [
    process.env.LOCALAPPDATA && join(process.env.LOCALAPPDATA, "ms-playwright"),
    process.env.HOME && join(process.env.HOME, ".cache", "ms-playwright"),
    process.env.HOME && join(process.env.HOME, "Library", "Caches", "ms-playwright")
  ].filter(Boolean);
  for (const base of candidates) {
    if (!existsSync(base)) continue;
    for (const dir of readdirSync(base).filter(d => d.startsWith("chromium"))) {
      for (const rel of ["chrome-win64/chrome.exe", "chrome-linux/chrome", "chrome-mac/Chromium.app/Contents/MacOS/Chromium"]) {
        const p = join(base, dir, rel);
        if (existsSync(p)) return p;
      }
    }
  }
  for (const p of ["/usr/bin/google-chrome", "/usr/bin/chromium", "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"]) {
    if (existsSync(p)) return p;
  }
  return null;
}

const chromePath = findChrome();
if (!chromePath) {
  console.error("未找到 Chromium。请设置 CHROME_PATH 环境变量指向浏览器可执行文件。");
  process.exit(2);
}

const profile = mkdtempSync(join(tmpdir(), "sslayout-"));
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
    } catch (_) { /* 浏览器尚未就绪 */ }
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

const PROBE = `(() => {
  const wb = document.getElementById("workbench");
  if (!wb) return { fatal: "找不到 #workbench" };
  const shell = document.querySelector(".app-shell"), workspace = document.querySelector(".workspace");
  const bottom = el => el ? Math.round(el.getBoundingClientRect().bottom) : null;
  const sidebar = document.querySelector(".sidebar");
  const list = document.querySelector(".history-list");
  const settings = [...document.querySelectorAll(".sidebar-action")].pop();
  return {
    viewportH: innerHeight,
    shellBottom: bottom(shell), workspaceBottom: bottom(workspace),
    workspaceOverflow: workspace ? getComputedStyle(workspace).overflow : null,
    gridRows: shell ? getComputedStyle(shell).gridTemplateRows : null,
    workbenchBottom: bottom(wb), workbenchClientH: wb.clientHeight, workbenchScrollH: wb.scrollHeight,
    scrollTop: wb.scrollTop,
    sidebarBottom: bottom(sidebar),
    historyListScrollable: list ? list.scrollHeight > list.clientHeight : null,
    historyListItems: list ? list.children.length : 0,
    settingsBottom: settings ? Math.round(settings.getBoundingClientRect().bottom) : null
  };
})()`;

const main = async () => {
  const cdp = await CDP.connect((await firstPageTarget()).webSocketDebuggerUrl);
  await cdp.send("Runtime.enable");
  await cdp.send("Page.enable");
  await cdp.send("Emulation.setDeviceMetricsOverride", { width: WIDTH, height: HEIGHT, deviceScaleFactor: 1, mobile: false });
  await cdp.send("Page.navigate", { url });
  await sleep(2500);

  const before = await cdp.evaluate(PROBE);
  if (before.fatal) throw new Error(before.fatal);

  // 滚到极限，检查最后一段内容是否真的能进视野
  const after = await cdp.evaluate(`(async () => {
    const wb = document.getElementById("workbench");
    const prev = wb.style.scrollBehavior; wb.style.scrollBehavior = "auto";
    wb.scrollTop = 999999;
    await new Promise(r => setTimeout(r, 200));
    wb.style.scrollBehavior = prev;
    const active = document.querySelector(".report-section[data-section-panel].active");
    return { scrollTop: wb.scrollTop, maxScroll: wb.scrollHeight - wb.clientHeight,
             activePanelBottom: active ? Math.round(active.getBoundingClientRect().bottom) : null,
             workbenchBottom: Math.round(wb.getBoundingClientRect().bottom) };
  })()`);

  const checks = [
    ["workspace 底边不越出视口", (before.workspaceBottom ?? Infinity) <= before.viewportH + 1, `${before.workspaceBottom} > ${before.viewportH}`],
    ["workbench 底边不越出视口", (before.workbenchBottom ?? Infinity) <= before.viewportH + 1, `${before.workbenchBottom} > ${before.viewportH}`],
    ["workspace 裁切溢出", before.workspaceOverflow === "hidden", `overflow=${before.workspaceOverflow}`],
    ["grid 行高已确定（非 auto 撑高）", !/\\d+px/.test(before.gridRows || "") || before.gridRows === `${before.viewportH}px`, `grid-template-rows=${before.gridRows}`],
    ["滚到底后末段内容可见", (after.activePanelBottom ?? Infinity) <= before.viewportH + 1, `面板底边 ${after.activePanelBottom} > 视口 ${before.viewportH}`],
    ["侧栏底边不越出视口", (before.sidebarBottom ?? Infinity) <= before.viewportH + 1, `${before.sidebarBottom} > ${before.viewportH}`],
    ["模型设置始终可见", (before.settingsBottom ?? Infinity) <= before.viewportH + 1, `底边 ${before.settingsBottom} > 视口 ${before.viewportH}`]
  ];

  console.log(`viewport ${WIDTH}x${HEIGHT} · ${url}`);
  let failed = 0;
  for (const [name, ok, detail] of checks) {
    console.log(`${ok ? "PASS" : "FAIL"} ${name}${ok ? "" : ` — ${detail}`}`);
    if (!ok) failed += 1;
  }
  console.log(`实测: 行高=${before.gridRows} workbench=${before.workbenchClientH}/${before.workbenchScrollH}px 可滚=${after.maxScroll}px`);
  console.log(`实测: 侧栏底=${before.sidebarBottom} 任务=${before.historyListItems}条 列表可滚=${before.historyListScrollable} 模型设置底=${before.settingsBottom}`);
  console.log(`layout probe: PASS=${checks.length - failed} FAIL=${failed}`);

  chrome.kill();
  process.exit(failed ? 1 : 0);
};

main().catch(err => { console.error("探针失败:", err.message); chrome.kill(); process.exit(2); });
