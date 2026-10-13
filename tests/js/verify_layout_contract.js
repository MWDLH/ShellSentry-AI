// 布局契约静态守卫。
//
// 背景（真实事故，2026-09-20 定位）：
//   .app-shell 是 grid，只声明了列，没有声明行。缺省 grid-auto-rows:auto 时，
//   单行高度由内容决定 —— 实测报告内容 1005px 时行高变成 984px，远超 768px 视口。
//   于是 .workspace / #workbench 的盒子底边落到窗口下方 216px：
//     · 容器自身有一截永远在屏幕外，它的滚动条同步被裁；
//     · 可滚动距离从应有的 295px 缩到 79px；
//     · 结果就是"滚不到底、下面的内容看不到"，且静态层面完全看不出异常。
//   该缺陷长期潜伏，因为内容短于视口时（AI 面板为空的那段时间）不会显形。
//
// 因此把这条不变量固化成断言：改动滚动相关 CSS 时，本脚本必须仍然通过。
const fs = require("fs");
const path = require("path");
const root = process.argv[2] || path.resolve(__dirname, "../..");
const cssPath = path.join(root, "src", "shellsentry", "web", "static", "styles", "app.css");
const css = fs.readFileSync(cssPath, "utf8");

// 剥掉 @media 块（含嵌套大括号），只校验基础规则。
// 移动端覆盖会把 .app-shell 的列改成 1fr，若混在一起会误判桌面结构。
function stripMedia(cssText) {
  let out = "", i = 0;
  while (i < cssText.length) {
    const at = cssText.indexOf("@media", i);
    if (at < 0) { out += cssText.slice(i); break; }
    out += cssText.slice(i, at);
    let depth = 0, j = cssText.indexOf("{", at);
    if (j < 0) break;
    for (; j < cssText.length; j++) {
      if (cssText[j] === "{") depth += 1;
      else if (cssText[j] === "}") { depth -= 1; if (depth === 0) { j += 1; break; } }
    }
    i = j;
  }
  return out;
}

// 去掉注释后按选择器聚合声明（后出现的覆盖先出现的）。
function collect(cssText) {
  const clean = stripMedia(cssText).replace(/\/\*[\s\S]*?\*\//g, "");
  const map = new Map();
  const re = /([^{}]+)\{([^{}]*)\}/g;
  let match;
  while ((match = re.exec(clean))) {
    const decls = {};
    for (const part of match[2].split(";")) {
      const at = part.indexOf(":");
      if (at > 0) decls[part.slice(0, at).trim().toLowerCase()] = part.slice(at + 1).trim();
    }
    for (const selector of match[1].split(",").map(x => x.trim()).filter(Boolean)) {
      map.set(selector, Object.assign(map.get(selector) || {}, decls));
    }
  }
  return map;
}

const rules = collect(css);
let failures = 0;
const check = (name, ok, detail) => {
  if (ok) console.log(`PASS layout ${name}`);
  else { failures += 1; console.error(`FAIL layout ${name}${detail ? ` — ${detail}` : ""}`); }
};
const decl = (selector, prop) => (rules.get(selector) || {})[prop];

// 1. 核心不变量：.app-shell 的行尺寸必须是"确定值"，不能留给 auto 按内容撑。
const rows = decl(".app-shell", "grid-template-rows") || "";
check("app-shell has definite row sizing", /minmax\(\s*0\s*,/.test(rows) || /^\s*100%\s*$/.test(rows),
  `grid-template-rows=${JSON.stringify(rows)}（必须是 minmax(0,1fr) 或 100%，缺省则被内容撑高）`);
check("app-shell keeps viewport height", decl(".app-shell", "height") === "100%",
  `height=${JSON.stringify(decl(".app-shell", "height"))}`);
check("app-shell is a two-column grid", /grid/.test(decl(".app-shell", "display") || "") &&
  (decl(".app-shell", "grid-template-columns") || "").includes("minmax(0,1fr)"),
  `columns=${JSON.stringify(decl(".app-shell", "grid-template-columns"))}`);

// 2. 滚动容器链：workspace 裁切、workspace-scroll 承担纵向滚动。
check("workspace clamps overflow", decl(".workspace", "overflow") === "hidden",
  `overflow=${JSON.stringify(decl(".workspace", "overflow"))}`);
check("workspace fills its row", decl(".workspace", "height") === "100%",
  `height=${JSON.stringify(decl(".workspace", "height"))}`);
check("workspace-scroll owns vertical scrolling", decl(".workspace-scroll", "overflow-y") === "auto",
  `overflow-y=${JSON.stringify(decl(".workspace-scroll", "overflow-y"))}`);
check("workspace-scroll can shrink", decl(".workspace-scroll", "min-height") === "0",
  `min-height=${JSON.stringify(decl(".workspace-scroll", "min-height"))}`);

// 3. 侧栏同样受行高约束，历史列表内部滚动而非把页面撑高。
check("sidebar history list scrolls internally",
  ["auto", "scroll"].includes(decl(".history-list", "overflow") || (decl(".history-list", "overflow-y") || "")),
  `overflow=${JSON.stringify(decl(".history-list", "overflow"))}`);

// 4. 侧栏内部滚动契约：历史条目再多，底部的连接状态 / 模型设置也不得被顶出视野。
//    依赖后代 overflow 的隐式行为不够 —— 必须显式声明，否则与 .app-shell 是同一种脆弱模式。
check("sidebar itself can shrink", decl(".sidebar", "min-height") === "0",
  `min-height=${JSON.stringify(decl(".sidebar", "min-height"))}（默认 auto 会被内容顶高）`);
check("sidebar footer never shrinks",
  /(^|\s)0\s+0\s+auto(\s|$)/.test(decl(".sidebar-footer", "flex") || "") || decl(".sidebar-footer", "flex-shrink") === "0",
  `flex=${JSON.stringify(decl(".sidebar-footer", "flex"))}`);
check("history section grows and shrinks",
  /^1\s+1\s+/.test(decl(".history-section", "flex") || "") && decl(".history-section", "min-height") === "0",
  `flex=${JSON.stringify(decl(".history-section", "flex"))} min-height=${JSON.stringify(decl(".history-section", "min-height"))}`);
check("history list fills and shrinks",
  /^1\s+1\s+/.test(decl(".history-list", "flex") || "") && decl(".history-list", "min-height") === "0",
  `flex=${JSON.stringify(decl(".history-list", "flex"))} min-height=${JSON.stringify(decl(".history-list", "min-height"))}`);

// 5. 代码反混淆面板：行号栏与代码区必须共享同一个滚动偏移。
//    背景（真实缺陷，2026-09-20）：两列结构里只有 <pre> 自带滚动条，
//    行号栏 overflow:hidden 不会跟随 —— 滚动代码后行号纹丝不动、彻底错位，
//    且被裁掉的行号永远进不了视野。修复靠 report-view.js 同步 scrollTop，
//    而同步成立的【前提】是两侧行高严格相等：行高一旦不同，scrollHeight 就会
//    失配，滚动后行号逐行漂移。这个前提在 CSS 里看不见摸不着，必须钉死。
const lineHeightOf = selector => {
  const font = decl(selector, "font") || "";
  const shorthand = /\/\s*([\d.]+)px/.exec(font);              // font: 12px/20px ...
  if (shorthand) return Number(shorthand[1]);
  const lh = decl(selector, "line-height") || "";
  return /^[\d.]+px$/.test(lh) ? Number.parseFloat(lh) : NaN;
};
const gutterLH = lineHeightOf(".line-numbers");
const codeLH = lineHeightOf(".code-view pre");
check("gutter line-height is definite", Number.isFinite(gutterLH), `font=${JSON.stringify(decl(".line-numbers", "font"))}`);
check("code pane line-height is definite", Number.isFinite(codeLH), `font=${JSON.stringify(decl(".code-view pre", "font"))}`);
check("gutter and code share one line-height", gutterLH === codeLH,
  `gutter=${gutterLH}px code=${codeLH}px（不相等则滚动同步会逐行漂移）`);
check("gutter clips without showing a scrollbar", decl(".line-numbers", "overflow") === "hidden",
  `overflow=${JSON.stringify(decl(".line-numbers", "overflow"))}（需保持可脚本滚动的隐藏态）`);
check("gutter keeps opaque background", !!decl(".line-numbers", "background"),
  "行号栏必须有背景色，否则代码内容会在其下方透出");

console.log(`layout contract: PASS=${17 - failures} FAIL=${failures}`);
process.exitCode = failures ? 1 : 0;
