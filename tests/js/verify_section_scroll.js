// 回归：切换 section 必须保留各自的阅读位置（同一任务内来回切换不回到顶部）。
//
// 事故（2026-10-09 用户反馈）：selectSection() 里无条件执行
// `scroll.scrollTop = 0`，导致在「深度分析 / 应急响应」等大模块之间切换时
// 每次都被拉回顶部，对比查看两份长报告必须重新滚回原处。
// 而「代码反混淆」面板内部的代码区是独立滚动容器，所以没暴露这个问题。
//
// 本守卫直接对 report-view.js 做静态断言 —— 它依赖浏览器 DOM，
// 无法在Node 里实例化运行，因此验证的是「代码里不再有无条件归零 +
// 存在位置记忆与恢复逻辑」这些可静态核对的性质。
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "../..");
const src = fs.readFileSync(
  path.join(root, "src", "shellsentry", "web", "static", "scripts", "report-view.js"),
  "utf8"
);

let pass = 0;
let fail = 0;
function check(name, ok, detail = "") {
  if (ok) { pass += 1; console.log(`PASS ${name}`); }
  else { fail += 1; console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
}

// 取 selectSection 方法体
const start = src.indexOf("selectSection(name) {");
const end = src.indexOf("\n  exportMarkdown", start) > 0
  ? src.indexOf("\n  exportMarkdown", start)
  : src.indexOf("\n  }\n", start) + 4;
const body = src.slice(start, end > start ? end : start + 900);

check("selectSection 中不再出现无条件 scrollTop = 0",
  !/scroll\.scrollTop\s*=\s*0\s*;?\s*$/m.test(body.replace(/\/\/[^\n]*/g, "")) &&
  !/const scroll = byId\("workbench"\); if \(scroll\) scroll\.scrollTop = 0;/.test(body),
  "仍存在强制归零语句");

check("切换前会记录当前面板位置",
  /this\.sectionScroll\[\s*this\.activeSection\s*\]\s*=\s*scroll\.scrollTop/.test(body),
  "未找到位置记录逻辑");

check("切换后恢复目标面板位置",
  /this\.sectionScroll\[name\]/.test(body) && /scroll\.scrollTop\s*=\s*remembered/.test(body),
  "未找到位置恢复逻辑");

check("记录了 activeSection 以便下次记旧位置",
  /this\.activeSection\s*=\s*name/.test(body));

check("有下一帧校正（应对面板 display 切换后的布局延迟）",
  /requestAnimationFrame/.test(body) && /_scrollToken/.test(body));

check("requestAnimationFrame 有能力检测（Node/降级环境无此 API）",
  /typeof requestAnimationFrame\s*===\s*["']function["']/.test(body),
  "缺少 typeof 检测会让异常冒到调用方 —— verify_gutter.js 曾被此打断");

// 新任务必须清空记忆，否则会带上一个任务的进度
const startFn = src.slice(src.indexOf("start()"), src.indexOf("start()") + 220);
const resetFn = src.slice(src.indexOf("reset()"), src.indexOf("reset()") + 420);
check("start() 清空位置记忆（新任务不带旧进度）",
  /this\.sectionScroll\s*=\s*\{\}/.test(startFn));
check("reset() 清空位置记忆",
  /this\.sectionScroll\s*=\s*\{\}/.test(resetFn));
check("构造函数初始化 sectionScroll 与 _scrollToken",
  /this\.sectionScroll\s*=\s*\{\}/.test(src.slice(0, src.indexOf("setSource"))) &&
  /this\._scrollToken\s*=\s*0/.test(src));

console.log(`\nsection scroll memory: PASS=${pass} FAIL=${fail}`);
process.exitCode = fail === 0 ? 0 : 1;