// 回归：代码反混淆模块的行号必须与[METADATA_BEHAVIOR] 同源，且滚动不错位。
//
// 事故（2026-10-09 用户实测）：模块显示的行号与代码对不上，滚动时更明显。
// 根因有两处：
//   1. renderHighlightedCode 正确算出了**原始行号**（可跳号，如 1,2,4,5 —— 模型只
//      输出关键行，省略了注释行），但 renderDeobfuscation 把 rendered.numbers
//      **丢掉了**，紧接着 syncDecodedGutter() 又按 code.textContent 的行数
//      生成 1..N 连续序号覆盖行号栏 → **两套坐标系打架**。
//   2. gutter 行数与 code 行数不一致时，滚动同步依赖 scrollTop 相等；
//      但若 gutter 内容行数与 code 不同，浏览器可滚范围不同，
//      scrollTop 相等也不代表**视觉位置**对齐 → 滚动时错位。
//
// 本守卫断言「代码行的 [LINE_x] 标签 ↔ 行号栏数字」逐行一致——
// 这是用户唯一真正在意的视觉契约。
const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "../..");
const reportView = fs.readFileSync(
  path.join(root, "src", "shellsentry", "web", "static", "scripts", "report-view.js"), "utf8");

let pass = 0, fail = 0;
function check(name, ok, detail = "") {
  if (ok) { pass += 1; console.log(`PASS ${name}`); }
  else { fail += 1; console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
}

// 1) renderDeobfuscation 必须用上 rendered.numbers，不能丢掉原始行号
const m = reportView.match(/renderDeobfuscation\(\)\s*\{[\s\S]*?\n  \}/);
const body = m ? m[0] : "";
check("renderDeobfuscation 可解析", Boolean(m));
check("使用了 rendered.numbers（原始行号）",
  /rendered\.numbers/.test(body) || /setDecodedNumbers\(/.test(body),
  "原始行号被丢弃，随后被 syncDecodedGutter 生成的 1..N 覆盖");

// 2) syncDecodedGutter 必须支持外部传入行号
const g = reportView.match(/export function syncDecodedGutter\([\s\S]*?\n\}/);
const gBody = g ? g[0] : "";
check("syncDecodedGutter 可解析", Boolean(g));
check("syncDecodedGutter 接受行号参数（可选）",
  /function syncDecodedGutter\(/.test(gBody) && /numbers/i.test(gBody),
  "没有参数入口，只能从 textContent 派生，无法承载跳号行号");

// 3) 行号栏必须有可滚动溢出能力，否则无法跟随 scrollTop
const css = fs.readFileSync(
  path.join(root, "src", "shellsentry", "web", "static", "styles", "app.css"), "utf8");
const gutterRule = (css.match(/\.line-numbers\s*\{[\s\S]*?\}/) || [""])[0];
check("行号栏 overflow 为 auto/hidden（可脚本滚动）",
  /overflow\s*:\s*(auto|hidden|scroll)/.test(gutterRule),
  gutterRule.slice(0, 120).replace(/\s+/g, " "));

// 3b) 代码区不得自动换行：一旦 pre-wrap 产生折行，视觉行数多于逻辑行，
//     行号栏（pre，每行固定 20px）与代码区（折行后行高不同）必然错位。
const decodedRule = (css.match(/\.decoded-code\s*\{[\s\S]*?\}/) || [""])[0];
check("代码区不自动换行（white-space 不含 pre-wrap）",
  decodedRule.length > 0 && !/white-space\s*:\s*pre-wrap/.test(decodedRule),
  "pre-wrap 会让长行折行，行号栏按固定行高对齐 → 滚动时错位：" +
  decodedRule.slice(0, 100).replace(/\s+/g, " "));

// 3c) 行高必须一致，否则 scrollTop 相等≠视觉对齐。
//     注意 .decoded-code 的 font 继承自共享规则
//     `.code-view pre,.decoded-code,.compare-grid pre{...}`，不能只看它自己的规则块。
const gFont = /font:\s*([\d.]+px\/\d+px)/.exec(gutterRule);
const sharedRule = (css.match(/\.code-view pre\s*,[^}]*\}/) || [""])[0];
const dFont = /font:\s*([\d.]+px\/\d+px)/.exec(decodedRule)
  || /font:\s*([\d.]+px\/\d+px)/.exec(sharedRule);
check("代码区与行号栏行高一致（滚动才能逐行对齐）",
  Boolean(gFont && dFont && gFont[1] === dFont[1]),
  `行号栏 ${gFont ? gFont[1] : "?"} vs 代码区 ${dFont ? dFont[1] : "?"}`);

// 4) 滚动同步必须有容错：两边行数不一致时也要保证可滚范围一致
check("存在按内容高度对齐行号栏高度的逻辑",
  /alignDecodedGutterHeight/.test(reportView));
check("同步滚动偏移", /gutter\.scrollTop\s*=\s*offset/.test(reportView));

// 5) 逐行一致性断言（真实契约）：用一段跳号样本跑一遍渲染函数
const utils = fs.readFileSync(
  path.join(root, "src", "shellsentry", "web", "static", "scripts", "utils.js"), "utf8");

// 抽取 renderHighlightedCode 做最小复现。
// 必须按"下一个顶层 function/export 声明"截断，否则会把 parseC2 等
// 带 export 的后续函数一起切进来，导致 CJS 里出现 export 语法错误。
const fnStart = reportView.indexOf("function renderHighlightedCode");
let cut = reportView.length;
for (const marker of ["\nexport function ", "\nfunction ", "\nexport class "]) {
  const idx = reportView.indexOf(marker, fnStart + 10);
  if (idx > fnStart && idx < cut) cut = idx;
}
const fnSrc = reportView.slice(fnStart, cut);
const escSrc = utils.slice(utils.indexOf("export function escapeHtml"));
const escBody = escSrc.slice(0, escSrc.indexOf("\n}") + 2)
  .replace("export function", "function");

// 用项目内的 .workbuddy 临时目录，避免写到系统 temp（Node fs shim 限制）
const tmpDir = path.join(root, ".workbuddy", "test-tmp");
fs.mkdirSync(tmpDir, { recursive: true });
const tmpFile = path.join(tmpDir, "deob-render-under-test.cjs");
fs.writeFileSync(tmpFile, `${escBody}\n${fnSrc}\nmodule.exports = renderHighlightedCode;\n`);
const render = require(tmpFile);

// 构造与真实报告同型的数据：模型省略了注释行，行号跳号
const SAMPLE = [
  "[LINE_1]<%@ page import=\"java.io.*\"%>",
  "[LINE_2]<%!",
  "[LINE_4]    class MemshellLoader extends ClassLoader {",
  "[LINE_9]        return super.defineClass(b, 0, b.length);",
  "[LINE_18]        String c2_host = \"192.168.43.110\";",
].join("\n");

const out = render(SAMPLE, []);
const nums = out.numbers.split("\n");
const tags = [...SAMPLE.matchAll(/\[LINE_(\d+)\]/g)].map(x => Number(x[1]));
// numbers 是字符串数组，比较时统一转数字（行号栏本来就以文本渲染）
const numVals = nums.map(Number);
check("行号栏逐行等于代码的 [LINE_x] 标签",
  JSON.stringify(tags) === JSON.stringify(numVals),
  `代码标签 ${JSON.stringify(tags)} vs 行号栏 ${JSON.stringify(numVals)}`);
check("行号栏保留跳号（不重排为 1..N）",
  numVals.length === tags.length && numVals[3] === 9,
  `第4 行应为原始行号 9，实际 ${numVals[3]}`);

console.log(`\ndeob line-number coherence: PASS=${pass} FAIL=${fail}`);
process.exitCode = fail === 0 ? 0 : 1;