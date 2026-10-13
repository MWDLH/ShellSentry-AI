const path = require("path");
const { pathToFileURL } = require("url");

(async () => {
  const root = process.argv[2] || path.resolve(__dirname, "../..");
  const moduleUrl = pathToFileURL(path.join(root, "src", "shellsentry", "web", "static", "scripts", "report-view.js")).href;
  const { parseProfile, parseMetadata, parseC2, parsePlaybook, renderHighlightedCode } = await import(moduleUrl);
  let pass = 0, fail = 0;
  const check = (name, condition) => { if (condition) { pass++; console.log(`PASS ${name}`); } else { fail++; console.error(`FAIL ${name}`); } };

  const profile = parseProfile("- **定性标签**：冰蝎 JSP WebShell\n- **技术家族**：Behinder\n- **核心技术栈**：AES、ClassLoader\n- **关联 ATT&CK**：T1505.003");
  check("profile label", profile.label === "冰蝎 JSP WebShell");
  check("profile family", profile.family === "Behinder");
  check("profile ATT&CK", profile.attack === "T1505.003");

  const metadata = parseMetadata("### 核心威胁特征总结\n- **核心危险执行流**：外部输入进入 Runtime.exec\n- **流量加解密与免杀对抗**：AES\n- **敏感输入源与通信通道**：HTTP POST\n- **权限维持与环境劫持**：无\n### 威胁行为研判\nL12 || 命令执行 || 外部输入可达系统命令执行\nL无 || 无 || 无恶意行为");
  check("four-dimension extraction", metadata.dimensions.execution.includes("Runtime.exec") && metadata.dimensions.crypto === "AES");
  check("behavior rows isolated", metadata.behaviors.length === 1 && metadata.behaviors[0].line === "L12");

  check("C2 None hidden", parseC2("None").length === 0);
  const c2 = parseC2("10.0.0.8;443;HTTPS;自定义远控;AES;主动回连");
  check("C2 fields", c2.length === 1 && c2[0].port === "443" && c2[0].conclusion === "主动回连");

  const playbook = parsePlaybook("### 1. IOC 封锁清单\n**[恶意文件]**　　shell.jsp\n### 2. 网络阻断规则\n```snort\nalert http any any -> any any\n```\n### 3. 主机清扫指令\n```bash\nfind /var/www\n```\n### 4. 安服汇报口径\n1.定性结论：已确认恶意。\n2.应急措施：部署网络阻断规则并完成主机排查。");
  check("playbook strict sections", playbook.ioc.includes("shell.jsp") && playbook.network.includes("alert http") && playbook.host.includes("find /var/www"));
  check("report does not leak into network", playbook.report.includes("网络阻断规则") && !playbook.network.includes("应急措施"));

  const highlighted = renderHighlightedCode("[LINE_1]String key = \"abc123456789\";", [{ line: 1, text: "abc123456789", category: "crypto_key" }]);
  const repeated = renderHighlightedCode("[LINE_1]String key = \"abc123456789\";", [{ line: 1, text: "abc123456789", category: "crypto_key" }]);
  check("exact deterministic token highlight", highlighted.html.includes('class="danger-token crypto_key">abc123456789</mark>'));
  check("highlight output stable", highlighted.html === repeated.html);

  const compactJsp = renderHighlightedCode(
    '[LINE_1]<%\nString k="e45e329feb5d925b";\nCipher c=Cipher.getInstance("AES");\nc.init(2,new SecretKeySpec(k.getBytes(),"AES"));\n%>',
    [{ line: 1, text: "e45e329feb5d925b", category: "crypto_key" }]
  );
  // 2026-10-09 语义修正：单行文件被后端展开成多行后，模型只输出一次 [LINE_1]，
  // 其余各行都是**原始第 1 行的续行**。行号栏必须沿用同一个原始行号，
  // 否则点击第 3 行会跳到 L3 —— 而原文件根本没有第 3 行。
  check("single-line continuation rows keep the original line number", compactJsp.numbers === "1\n1\n1\n1\n1");
  check("original line hint follows formatted continuation", compactJsp.html.includes('class="danger-token crypto_key">e45e329feb5d925b</mark>'));

  const unmarkedFormatted = renderHighlightedCode(
    '<%\nString k="e45e329feb5d925b";\nnew SecretKeySpec(k.getBytes(),"AES");\n%>',
    [{ line: 1, text: "e45e329feb5d925b", category: "crypto_key" }]
  );
  check("exact hint survives missing model line markers", unmarkedFormatted.html.includes('class="danger-token crypto_key">e45e329feb5d925b</mark>'));

  // P0-3：单行代码文件的行为行按提示词规约首列为「第N/M片」，此前被静默丢弃
  const sliceMetadata = parseMetadata("### 威胁行为研判\n第1/29 片 || eval($__o) 动态执行解密后代码 || RCE 最终落点\nL18-20 || 自定义类加载器 || 突破沙箱\nL无 || 无 || 无恶意行为");
  check("single-line slice locator kept", sliceMetadata.behaviors.length === 2 && sliceMetadata.behaviors[0].line === "第1/29 片");
  check("line-range locator normalized", sliceMetadata.behaviors[1].line === "L18-20");

  // 回归（2026-10-13 真实内存马样本）：模型①把「免杀」误写成「免骂」；②单行文件首列写成「第N/M片 · 名称」
  const evasive = parseMetadata([
    "### 🔒 核心威胁特征总结",
    "- **核心危险执行流**：Base64 解码 → GZIP 解压 → 反射 defineClass",
    "- **流量加解密与免骂对抗**：Base64(GZIP(class)) 双层嵌套",
    "### 📊 威胁行为研判",
    "第1/1 片 · getClassName() || 硬编码 Listener 全限定名 || 伪装为 Spring 组件",
    "第1/1 片 · getListener() || Base64解码+GZIP解压+defineClass || 内存马核心落地点",
  ].join("\n"));
  check("dimension tolerates title typo (免骂)", evasive.dimensions.crypto === "Base64(GZIP(class)) 双层嵌套");
  check("slice locator with code snippet kept", evasive.behaviors.length === 2 && evasive.behaviors[0].line.startsWith("第1/1 片"));
  check("dimension without typo still works", parseMetadata("- **核心危险执行流**：Runtime.exec").dimensions.execution === "Runtime.exec");

  // P0-4：behavior_chain 异常为非数组时，renderProfile 不得让整块面板崩溃
  const { ReportView } = await import(moduleUrl);
  const nodes = {};
  const mkNode = () => ({
    textContent: "", innerHTML: "", hidden: false, disabled: false, scrollTop: 0,
    classList: { toggle() {}, add() {}, remove() {} }, setAttribute() {},
    querySelector(sel) { this._kids = this._kids || {}; return this._kids[sel] || (this._kids[sel] = { textContent: "" }); },
  });
  global.document = {
    getElementById: id => (nodes[id] || (nodes[id] = mkNode())),
    querySelectorAll: () => [],
  };
  const fakeView = Object.create(ReportView.prototype);
  fakeView.profile = { label: "x", family: "y", stack: "z", attack: "w" };
  let crashed = false;
  try {
    ReportView.prototype.renderProfile.call(fakeView, { verdict: "malicious", behavior_chain: "not-an-array", summary: "s" });
  } catch (error) { crashed = true; }
  check("renderProfile tolerates non-array behavior_chain", !crashed && nodes["behaviorChain"].innerHTML.includes("尚未形成可验证的攻击路径"));
  ReportView.prototype.renderProfile.call(fakeView, { verdict: "malicious", behavior_chain: ["a", "b"], summary: "s" });
  check("renderProfile still renders array behavior_chain", (nodes["behaviorChain"].innerHTML.match(/chain-item/g) || []).length === 2);

  // P2：审计失败后的空态文案必须能被 reset() 复位（此前会永久残留错误信息）
  const emptyNode = global.document.getElementById("resultEmpty");
  emptyNode.querySelector("strong").textContent = "审计未完成";
  ReportView.prototype.reset.call(Object.create(ReportView.prototype));
  check("reset restores empty-state text", emptyNode.querySelector("strong").textContent === "等待审计任务");

  console.log(`PASS=${pass} FAIL=${fail}`);
  process.exitCode = fail ? 1 : 0;
})().catch(error => { console.error(error); process.exitCode = 1; });
