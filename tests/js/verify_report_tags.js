// 回归：模型漏写闭合标签时，前端必须仍能提取各段内容。
// 事故（2026-10-08）：5 条真实样本里 4 条缺 [/IMAGE]，严格匹配导致
// 该面板显示"暂无内容"，把模型格式疏忽放大成"工具没检出"的误读。
//
// 注意：本守卫用动态 import 加载 utils.js（它是 ESM），因此整体包在
// async main() 里；Node 进程内无法 spawn 子进程（本机返回 EBUSY），
// 不能退化成 spawn 方式调用其它校验脚本。
const path = require("path");
const { pathToFileURL } = require("url");

const root = path.resolve(__dirname, "../..");
const utilsPath = path.join(root, "src", "shellsentry", "web", "static", "scripts", "utils.js");

let pass = 0;
let fail = 0;
function check(name, ok, detail = "") {
  if (ok) { pass += 1; console.log(`PASS ${name}`); }
  else { fail += 1; console.log(`FAIL ${name}${detail ? ` — ${detail}` : ""}`); }
}

const WF = `[IMAGE]
- **定性标签**：测试
- **技术家族**：Behinder
[/IMAGE]
[DE_OBFUSCATE]
[LINE_1]<?php eval(\[1]); ?>
[/DE_OBFUSCATE]
[C2_INFO]
None
[/C2_INFO]
[METADATA_BEHAVIOR]
### 核心
- eval
[/METADATA_BEHAVIOR]
[PLAYBOOK]
### 1. IOC
**[恶意文件]**　　a.php
[/PLAYBOOK]`;

const MISSING_CLOSE = `[IMAGE]
- **定性标签**：PHP WebShell
[DE_OBFUSCATE]
[LINE_1]<?php eval(1); ?>
[/DE_OBFUSCATE]
[METADATA_BEHAVIOR]
### 研判
L1 || eval || RCE
[/METADATA_BEHAVIOR]`;

async function main() {
  const { parseTaggedReport } = await import(pathToFileURL(utilsPath).href);

  const a = parseTaggedReport(WF);
  check("闭合完整时 IMAGE 正确", a.image.includes("Behinder"), JSON.stringify(a.image));
  check("闭合完整时 PLAYBOOK 正确", a.response.includes("a.php"));
  check("闭合完整时 METADATA 正确", a.metadata.includes("eval"));
  check("闭合完整时 decoded 剥离 LINE 标签", !a.decoded.includes("[LINE_"), a.decoded);

  const b = parseTaggedReport(MISSING_CLOSE);
  check("未闭合 IMAGE 仍能提取", b.image.includes("PHP WebShell"), JSON.stringify(b.image));
  check("未闭合 IMAGE 不吞掉下一段", !b.image.includes("eval"), b.image);
  check("未闭合时 DE_OBFUSCATE 正常", b.decoded.includes("eval"), b.decoded);
  check("未闭合时 METADATA 正常", b.metadata.includes("RCE"), b.metadata);

  const c = parseTaggedReport("[IMAGE]\n- x\n[/IMAGE]\n[METADATA_BEHAVIOR]\n### 核心\n- 最后内容");
  check("末段未闭合取到文末", c.metadata.includes("最后内容"), JSON.stringify(c.metadata));

  const d = parseTaggedReport("没有任何标签的自由文本。");
  check("无标签时不误抓内容", d.image === "" && d.response === "" && d.metadata === "");

  const e = parseTaggedReport("[image]\n- lowercase\n[/image]");
  check("小写标签仍可解析", e.image.includes("lowercase"), JSON.stringify(e.image));

  console.log(`
report tag fallback: PASS=${pass} FAIL=${fail}`);
  process.exitCode = fail === 0 ? 0 : 1;
}

main();
