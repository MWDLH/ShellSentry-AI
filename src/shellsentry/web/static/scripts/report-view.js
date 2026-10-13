import { escapeHtml, parseTaggedReport, refreshIcons } from "./utils.js";

const VERDICT_META = {
  malicious: { label: "确认恶意", icon: "shield-alert" }, suspicious: { label: "需要复核", icon: "triangle-alert" },
  benign: { label: "确认良性", icon: "shield-check" }, no_indication: { label: "未发现明确恶意证据", icon: "shield-check" },
  unsupported: { label: "当前不支持", icon: "ban" }, unknown: { label: "结论未知", icon: "circle-help" }
};
const DIMENSIONS = [
  ["execution", "核心危险执行流", "terminal"], ["crypto", "流量加解密与免杀对抗", "key-round"],
  ["channel", "敏感输入源与通信通道", "radio-tower"], ["persistence", "权限维持与环境劫持", "pin"]
];

export class ReportView {
  constructor() {
    this.rawOutput = ""; this.staticData = {}; this.finalVerdict = null; this.doneData = {}; this.findings = [];
    this.decodedRaw = "";
    this.profile = {}; this.metadata = emptyMetadata(); this.playbook = emptyPlaybook();
    // 各 section 的阅读位置记忆（key = section name）。
    // 用途：同一任务内来回切换模块时，回到离开时的滚动位置，
    // 而不是每次都被强制拉回顶部。切换任务时由 reset()/start() 清空。
    this.sectionScroll = {};
    this.activeSection = "intent";
    this._scrollToken = 0;
    // 反混淆代码区的**原始行号**（可能跳号，如 1,2,4,5），
    // 由 renderHighlightedCode 产出、renderDeobfuscation 缓存，
    // 供 ensureDecodedGutter 在面板切换时复用，避免退化成 1..N 连续序号。
    this._decodedNumbers = null;
    this.bindControls();
  }
  setSource() {}
  reset() {
    this.rawOutput = ""; this.staticData = {}; this.finalVerdict = null; this.doneData = {}; this.findings = [];
    this.decodedRaw = "";
    // 新任务/重置：阅读位置记忆必须清空，否则会带上一个任务的进度。
    this.sectionScroll = {};
    // 复位空态文案：审计失败时 showAuditError 改写过 strong/p，若不复位，
    // 之后新建任务会永久残留上一条错误信息。
    const empty = byId("resultEmpty");
    empty.querySelector("strong").textContent = "等待审计任务";
    empty.querySelector("p").textContent = "完成分析后，可分别查看攻击意图、代码反混淆、深度分析和应急响应。";
    empty.hidden = false; byId("resultRunning").hidden = true; byId("resultContent").hidden = true; byId("exportButton").disabled = true; this.selectSection("intent");
  }
  start() { this.sectionScroll = {}; this.rawOutput = ""; this.staticData = {}; this.finalVerdict = null; this.doneData = {}; this.findings = []; byId("resultEmpty").hidden = true; byId("resultContent").hidden = true; byId("resultRunning").hidden = false; byId("liveLog").innerHTML = ""; this.setProgress("static", "正在建立静态证据", 12); }
  setStatic(data = {}) { this.staticData = data; this.findings = normalizeFindings(data); this.setProgress("semantic", "静态证据完成，进入语义分析", 34); }
  appendRaw(text = "") { this.rawOutput += text; }
  setProgress(step, message, percent) {
    byId("runningTitle").textContent = message; byId("progressBar").style.width = `${Math.max(4, Math.min(100, percent))}%`;
    const current = ["static", "semantic", "review", "complete"].indexOf(step);
    document.querySelectorAll("#auditSteps li").forEach((item, index) => { item.classList.toggle("active", index === current); item.classList.toggle("done", index < current); });
    const row = document.createElement("div"); row.textContent = `· ${message}`; byId("liveLog").appendChild(row);
  }
  setFinalVerdict(verdict) { this.finalVerdict = verdict; this.setProgress("complete", "复核完成，正在整理结论", 88); }
  complete(doneData = {}) {
    this.doneData = doneData; this.finalVerdict = this.finalVerdict || doneData.agent_verdict || fallbackVerdict(this.staticData, doneData);
    this.render(this.finalVerdict); byId("resultRunning").hidden = true; byId("resultEmpty").hidden = true; byId("resultContent").hidden = false; byId("exportButton").disabled = false;
  }
  loadHistory(record = {}) {
    const payload = record.report || record; this.rawOutput = payload.raw_ai_output || payload.report?.raw_ai_output || ""; this.staticData = payload.regex_scan || payload.report?.regex_scan || {}; this.doneData = payload.done || payload.final_status || {}; this.finalVerdict = payload.agent_verdict || payload.verdict || this.doneData.agent_verdict || null; this.findings = normalizeFindings(this.staticData); this.complete(this.doneData);
  }
  // 重新展示"正在运行"的审计：从后台快照回放进度面板（用户从历史切回本任务的路径）。
  replayRunning(run = {}) {
    byId("resultEmpty").hidden = true; byId("resultContent").hidden = true; byId("resultRunning").hidden = false;
    byId("runningTitle").textContent = run.message || "正在分析";
    byId("progressBar").style.width = `${Math.max(4, Math.min(100, run.percent || 5))}%`;
    const steps = ["static", "semantic", "review", "complete"];
    const current = steps.indexOf(run.step);
    document.querySelectorAll("#auditSteps li").forEach((item, index) => {
      item.classList.toggle("active", index === current);
      item.classList.toggle("done", index < current);
    });
    byId("liveLog").innerHTML = (run.logs || []).map(line => `<div>· ${escapeHtml(line)}</div>`).join("");
  }
  render(verdict) {
    const name = verdict?.verdict || "unknown", meta = VERDICT_META[name] || VERDICT_META.unknown, tags = parseTaggedReport(this.rawOutput);
    byId("verdictHeader").dataset.verdict = name; byId("verdictLabel").textContent = meta.label; byId("verdictSummary").textContent = verdict.summary || "暂无模型结论。"; byId("confidenceValue").textContent = formatConfidence(verdict.confidence); byId("verdictHeader").querySelector(".verdict-icon").innerHTML = `<i data-lucide="${meta.icon}"></i>`;
    this.profile = parseProfile(tags.image); this.renderProfile(verdict);
    this.decodedRaw = tags.decodedRaw || tags.decoded || ""; this.decodedText = cleanDeobfuscated(this.decodedRaw); this.renderDeobfuscation();
    this.metadata = parseMetadata(tags.metadata); this.renderThreatDimensions(); this.renderBehaviorAnalysis();
    this.renderC2(tags.c2); this.responseText = tags.response || ""; this.playbook = parsePlaybook(this.responseText); this.renderResponse();
    this.selectSection("intent"); refreshIcons();
  }
  renderProfile(verdict) {
    byId("intentLabel").textContent = this.profile.label || VERDICT_META[verdict.verdict]?.label || "无法确认";
    byId("intentPurpose").textContent = intentSummary(this.profile, verdict);
    byId("intentFamily").textContent = this.profile.family || "无法确认";
    byId("intentStack").textContent = this.profile.stack || "未提取到明确技术栈";
    byId("intentAttack").textContent = this.profile.attack || "未形成可靠映射";
    // behavior_chain 可能缺失或（异常时）是非数组，直接 .map 会整块面板崩溃。
    const chain = Array.isArray(verdict.behavior_chain) ? verdict.behavior_chain : [];
    byId("behaviorChain").innerHTML = chain.length ? chain.map((item, index) => `<div class="chain-item"><span class="chain-index">${index + 1}</span><div>${escapeHtml(item)}</div></div>`).join("") : emptyState("尚未形成可验证的攻击路径");
  }
  renderDeobfuscation() {
    const raw = this.decodedRaw.trim();
    if (!raw) {
      this._decodedNumbers = null;
      decodedNumbersCache = null;
      byId("decodedCode").innerHTML = `<code>${emptyCodeText("未发现可静态反混淆的代码")}</code>`;
      syncDecodedGutter();
      return;
    }
    const rendered = renderHighlightedCode(raw, this.staticData?.highlight_hints || []);
    // 必须把 rendered.numbers 传给行号栏：模型只输出关键代码段，
    // 行号是**原始行号**且会跳号（如 1,2,4,5 —— 省略了注释行）。
    // 若丢弃它、退回按 textContent 生成 1..N 连续序号，
    // 行号就会与 [METADATA_BEHAVIOR] 引用的真实行号对不上。
    this._decodedNumbers = rendered.numbers;
    decodedNumbersCache = rendered.numbers;
    byId("decodedCode").innerHTML = `<code>${rendered.html}</code>`;
    syncDecodedGutter(rendered.numbers);
  }
  ensureDecodedGutter() {
    // 两个来源都更新：实例字段供本实例使用，模块级缓存供顶层观察器使用。
    // 少了任何一个，面板切换或外部改写时都会退回 1..N 连续序号。
    decodedNumbersCache = this._decodedNumbers;
    syncDecodedGutter(this._decodedNumbers);
  }
  renderThreatDimensions() {
    byId("threatDimensions").innerHTML = DIMENSIONS.map(([key, title, icon]) => { const value = this.metadata.dimensions[key] || "无明确特征"; const empty = isEmptyValue(value); return `<article class="threat-dimension ${empty ? "is-empty" : ""}"><i data-lucide="${icon}"></i><div><h3>${title}</h3><p>${escapeHtml(normalizeEmpty(value))}</p></div></article>`; }).join("");
  }
  renderBehaviorAnalysis() {
    const rows = this.metadata.behaviors;
    byId("behaviorAnalysis").innerHTML = rows.length ? `<table class="behavior-table"><thead><tr><th>关键行号</th><th>行为威胁定性</th><th>危害深度解析</th></tr></thead><tbody>${rows.map(row => `<tr><td><span class="line-ref">${escapeHtml(row.line)}</span></td><td><strong>${escapeHtml(row.threat)}</strong></td><td>${escapeHtml(row.detail)}</td></tr>`).join("")}</tbody></table>` : emptyState("未提取到可验证的核心威胁行为");
  }
  renderC2(raw) {
    const records = parseC2(raw);
    this.c2Markdown = records.map(item => `${[item.ip, item.port].filter(Boolean).join(":")} ${item.protocol} ${item.family} ${item.conclusion}`.trim()).join("\n");
    if (!records.length) { byId("c2Content").innerHTML = emptyState("未发现可验证的硬编码外联或 C2 特征"); return; }
    byId("c2Content").innerHTML = records.map(item => `<article class="trace-card"><div class="trace-endpoint"><i data-lucide="radio-tower"></i><div><span>通信资产</span><strong>${escapeHtml([item.ip, item.port].filter(Boolean).join(":") || "未知")}</strong></div></div><dl><div><dt>协议</dt><dd>${escapeHtml(item.protocol || "未知")}</dd></div><div><dt>远控家族</dt><dd>${escapeHtml(item.family || "无法确认")}</dd></div><div><dt>对抗手法</dt><dd>${escapeHtml(item.evasion || "未识别")}</dd></div></dl><p>${escapeHtml(item.conclusion || "暂无可靠溯源结论")}</p></article>`).join("");
  }
  renderResponse() {
    byId("responseIoc").innerHTML = renderIoc(this.playbook.ioc);
    byId("responseNetwork").innerHTML = renderResponseText(this.playbook.network, "未生成网络阻断规则");
    byId("responseHost").innerHTML = renderResponseText(this.playbook.host, "未生成主机清扫指令");
    byId("responseReport").innerHTML = renderReportText(this.playbook.report);
    byId("responseContent").textContent = this.responseText;
  }
  bindControls() {
    document.querySelectorAll("[data-section-tab]").forEach(button => button.addEventListener("click", () => this.selectSection(button.dataset.sectionTab)));
    document.querySelectorAll("[data-analysis-tab]").forEach(button => button.addEventListener("click", () => { document.querySelectorAll("[data-analysis-tab]").forEach(item => { const selected = item === button; item.classList.toggle("active", selected); item.setAttribute("aria-selected", String(selected)); }); document.querySelectorAll("[data-analysis-panel]").forEach(panel => panel.classList.toggle("active", panel.dataset.analysisPanel === button.dataset.analysisTab)); }));
  }
  selectSection(name) {
    // 切换前先记住「当前」面板的阅读位置
    const scroll = byId("workbench");
    if (scroll && this.activeSection) this.sectionScroll[this.activeSection] = scroll.scrollTop;
    document.querySelectorAll("[data-section-tab]").forEach(button => { const selected = button.dataset.sectionTab === name; button.classList.toggle("active", selected); button.setAttribute("aria-selected", String(selected)); });
    document.querySelectorAll("[data-section-panel]").forEach(panel => panel.classList.toggle("active", panel.dataset.sectionPanel === name));
    if (name === "restoration") this.ensureDecodedGutter();
    this.activeSection = name;
    // 恢复目标面板上次的阅读位置；没访问过则从顶部开始。
    // 旧实现是无条件 scrollTop = 0，导致每次切换模块都被拉回顶部，
    // 对比查看两个长报告时必须重新滚回原处。
    if (scroll) {
      const remembered = this.sectionScroll[name] || 0;
      scroll.scrollTop = remembered;
      // 面板从 display:none 切到可见后，浏览器可能尚未完成布局，
      // 此时写入的 scrollTop 会被钳制回0（表现为"又跳回顶部"）。
      // 用一个自增令牌在下一帧补写一次；期间若又切了别的面板则放弃，避免互相打架。
      // rAF 做能力检测：Node/降级环境没有它，不能让异常冒到调用方
      // （此前 verify_gutter.js 就是被这一行打断的）。
      if (typeof requestAnimationFrame === "function") {
        const token = ++this._scrollToken;
        requestAnimationFrame(() => {
          if (token !== this._scrollToken) return;
          if (scroll.scrollTop !== remembered) scroll.scrollTop = remembered;
        });
      }
    }
  }
  exportMarkdown(filename = "audit-report.md") {
    const v = this.finalVerdict || {}, d = this.metadata.dimensions;
    return `# ShellSentry-AI 审计报告\n\n- 文件：${filename}\n- 判定：${VERDICT_META[v.verdict]?.label || "未知"}\n- 置信度：${formatConfidence(v.confidence)}\n\n## 攻击意图研判\n\n- 定性：${this.profile.label || "无法确认"}\n- 技术家族：${this.profile.family || "无法确认"}\n- 核心技术栈：${this.profile.stack || "无"}\n- ATT&CK：${this.profile.attack || "无"}\n\n${v.summary || "无"}\n\n## 代码反混淆\n\n\`\`\`\n${this.decodedText || "无"}\n\`\`\`\n\n## 威胁特征\n\n${DIMENSIONS.map(([key, title]) => `- ${title}：${normalizeEmpty(d[key])}`).join("\n")}\n\n## 行为分析\n\n${this.metadata.behaviors.map(x => `- ${x.line} | ${x.threat} | ${x.detail}`).join("\n") || "- 无"}\n\n## 威胁溯源\n\n${this.c2Markdown || "未发现可验证的硬编码外联或 C2 特征"}\n\n## 应急响应\n\n### IOC 封锁清单\n${this.playbook.ioc || "无"}\n\n### 网络阻断规则\n${this.playbook.network || "无"}\n\n### 主机清扫指令\n${this.playbook.host || "无"}\n\n### 安服汇报口径\n${this.playbook.report || "无"}\n`;
  }
}

function byId(id) { return document.getElementById(id); }
// 行号栏的唯一真相源：#decodedCode 的【实际文本内容】。
// 不采用"渲染时记住行号、以后回写"的做法 —— 那样仍是两个写入者竞争，
// 谁最后写谁赢（历史缺陷：外部模块用源码行数覆盖，单行载荷只剩 "1"）。
// 改为从代码区派生后，任何外部覆盖都会在下一个变更周期被纠正，
// 行号与代码内容永远同生同灭，不可能再脱节。
export function syncDecodedGutter(numbersOverride) {
  const code = byId("decodedCode"), gutter = byId("lineNumbers");
  if (!code || !gutter) return "";
  const text = code.textContent || "";
  // 优先使用调用方传入的**原始行号**（可能跳号）；
  // 没有才从内容行数派生 1..N（例如空态提示）。
  const expected = numbersOverride
    || (text ? Array.from({ length: text.split("\n").length }, (_, i) => i + 1).join("\n") : "1");
  if (gutter.textContent !== expected) gutter.textContent = expected;
  // 内容一变，代码区的滚动偏移就可能被浏览器重置或钳制，行号栏必须跟上，
  // 否则重新渲染后两侧偏移不一致，立刻表现为错位。
  // 同时重新对齐可滚范围：新内容可能带来或消除横向滚动条。
  alignDecodedGutterHeight();
  syncDecodedScroll();
  return expected;
}
// 行号栏与代码区必须共享同一个【垂直】滚动偏移。
// 结构上它们是 .code-view 网格里的相邻两列，但只有 <pre> 自带滚动条；
// 行号栏是 overflow:hidden，不会自动跟随 —— 结果是滚动代码后行号停在原处，
// 与代码行彻底错位，且被裁掉的那部分行号永远进不了视野（2026-09-20 缺陷）。
// 两者行高一致、行数一致（实测 scrollHeight 相等），所以直接同步绝对值，
// 不需要按比例换算，也就不存在"越滚越漂"的累积误差。
// 横向不参与同步：行号列本就应当固定在左侧，只有代码内容左右移动。
export function syncDecodedScroll() {
  const code = byId("decodedCode"), gutter = byId("lineNumbers");
  if (!code || !gutter) return;
  const offset = code.scrollTop || 0;
  // overflow:hidden 的元素按规范仍可被脚本滚动（只是不向用户暴露滚动条），
  // 因此行号栏无需改动任何样式即可跟随，视觉上仍是"代码区左侧的一列"。
  if (gutter.scrollTop !== offset) gutter.scrollTop = offset;
}
// 两侧的【可滚范围】必须相等，否则滚到极限时行号仍会落后一截。
// 差异只可能来自一处：代码区出现超长行时会多出约 15px 高的横向滚动条，
// 它占掉 <pre> 的可见高度；行号栏没有滚动条，于是可滚范围就少这一条的量
// （实测 code=698 / gutter=683，滚到底末行差 15px）。
// 补偿：给行号栏加一条等高的透明下边框 —— border 计入盒子高度但不计入
// clientHeight，正好把行号栏的可见高度压到与代码区一致。横向滚动条不存在时
// 必须清零，否则会反向错位同样的距离。
export function alignDecodedGutterHeight() {
  const code = byId("decodedCode"), gutter = byId("lineNumbers");
  if (!code || !gutter || !gutter.style) return 0;
  if (typeof getComputedStyle !== "function") return 0;
  const cs = getComputedStyle(code);
  const borderY = (parseFloat(cs.borderTopWidth) || 0) + (parseFloat(cs.borderBottomWidth) || 0);
  // offsetHeight - clientHeight = 纵向 border + 横向滚动条，减去 border 即得滚动条高度
  const bar = Math.max(0, code.offsetHeight - code.clientHeight - borderY);
  const current = parseFloat(getComputedStyle(gutter).borderBottomWidth) || 0;
  if (Math.abs(current - bar) > 0.5) gutter.style.borderBottom = bar > 0 ? `${bar}px solid transparent` : "";
  return bar;
}
// 守护：监听代码区与行号栏的变化，任何一方被改动都立即按真相源重新同步。
// 覆盖三类历史成因：面板延迟渲染、外部模块误写、字体/布局导致的重排。
// 当前渲染实例的原始行号缓存。installDecodedGutterGuard 是模块顶层函数，
// 拿不到 ReportView 实例，因此由 renderDeobfuscation 在此登记，
// 供观察器回调使用（避免用无参调用把跳号行号抹平成1..N）。
let decodedNumbersCache = null;
function installDecodedGutterGuard() {
  // 无 DOM / 无 MutationObserver 的环境（Node 校验脚本）直接跳过，不做副作用
  if (typeof document === "undefined" || typeof MutationObserver === "undefined") return;
  const code = byId("decodedCode"), gutter = byId("lineNumbers");
  if (!code || !gutter) return;
  let syncing = false;
  const observer = new MutationObserver(() => {
    if (syncing) return;
    syncing = true;
    try {
      // 必须回传缓存的原始行号，不能用无参调用。
      // 无参版本会按 textContent 行数重推 1..N 连续序号，把模型给的
      // 跳号行号（如 1,3,3,4 —— 模型省略了注释行/空行）全部抹平，
      // 结果行号与 [METADATA_BEHAVIOR] 引用的真实行号对不上（2026-10-09 缺陷）。
      syncDecodedGutter(decodedNumbersCache);
    } finally { syncing = false; }
  });
  observer.observe(code, { childList: true, characterData: true, subtree: true });
  observer.observe(gutter, { childList: true, characterData: true });
  // 滚动同步：代码区滚动时行号栏跟随。
  // 能力检测是必需的 —— 校验脚本用最小 DOM 桩（只有 getElementById/属性），
  // 没有 addEventListener，不能因此让模块加载失败。
  if (typeof code.addEventListener === "function") code.addEventListener("scroll", syncDecodedScroll, { passive: true });
  // 容器尺寸变化（窗口缩放、面板显隐、字体加载）也会改变横向滚动条的占位，
  // 因此需要重新对齐可滚范围。只观察代码区：对齐动作会改行号栏的边框，
  // 若把行号栏也纳入观察会自触发回调。
  if (typeof ResizeObserver === "function") {
    const observerRO = new ResizeObserver(() => { alignDecodedGutterHeight(); syncDecodedScroll(); });
    observerRO.observe(code);
  }
}
installDecodedGutterGuard();
// 前端版本自检：F12 控制台可见，用于确认浏览器加载的确实是最新构建。
const frontendBuild = typeof document !== "undefined" && document.querySelector
  ? (document.querySelector('meta[name="shellsentry-frontend-build"]')?.content || "unknown")
  : "unknown";
if (typeof console !== "undefined" && console.info) console.info(`[ShellSentry] frontend build=${frontendBuild}`);
function emptyMetadata() { return { dimensions: { execution: "", crypto: "", channel: "", persistence: "" }, behaviors: [] }; }
function emptyPlaybook() { return { ioc: "", network: "", host: "", report: "" }; }
function emptyState(text) { return `<div class="empty-inline"><i data-lucide="circle-minus"></i><span>${escapeHtml(text)}</span></div>`; }
function emptyCodeText(text) { return `<span class="code-empty">${escapeHtml(text)}</span>`; }

export function parseProfile(text = "") {
  const fields = {};
  const aliases = [["label", /定性标签|定性结论|恶意代码定性/], ["family", /技术家族|工具家族/], ["stack", /核心技术栈|关键能力/], ["confidence", /置信度/], ["attack", /关联\s*ATT&CK|ATT&CK/]];
  for (const line of String(text).split("\n")) { const clean = line.replace(/^\s*[-*]\s*/, "").trim(); for (const [key, rx] of aliases) if (rx.test(clean)) { fields[key] = clean.replace(/\*\*/g, "").replace(/^.*?[：:]/, "").replace(/^\[|\]$/g, "").trim(); break; } }
  return fields;
}
function intentSummary(profile, verdict) { const pieces = []; if (profile.label) pieces.push(`研判为${profile.label}`); if (profile.stack) pieces.push(`主要通过${profile.stack}`); return pieces.length ? `${pieces.join("，")}。${verdict.summary || ""}`.trim() : verdict.summary || "暂无攻击意图信息。"; }

export function parseMetadata(text = "") {
  // 维度用"稳定前缀"匹配而非整句：模型偶尔把标题里的字打错（实测出现「流量加解密与免骂对抗」），
  // 精确匹配会让整个维度直接判空。前缀匹配对尾部错别字/措辞微调都容错。
  const result = emptyMetadata(), mapping = [["execution", "核心危险执行流"], ["crypto", "流量加解密"], ["channel", "敏感输入源"], ["persistence", "权限维持"]];
  for (const rawLine of String(text).split("\n")) {
    const line = rawLine.trim(); if (!line) continue;
    // 首列定位符：常规为 L<行号>（L12 / L18-20 / L无）；单行代码文件按提示词规约写作「第N/M片」。
    // 实测模型会写成「第1/1 片 · getClassName()」——片号后还跟了代码片段指代，故片号后允许任意非竖线字符。
    const behavior = line.match(/^(?:L\s*(\d+(?:-\d+)?|无)|(第\s*\d+\s*[\/／]\s*\d+\s*片[^|｜]*?))\s*[|｜]{2}\s*(.*?)\s*[|｜]{2}\s*(.+)$/i);
    if (behavior) {
      const locator = behavior[1] ? `L${behavior[1]}` : behavior[2].trim();
      const isNone = /^无$/i.test(behavior[1] || "") || /^无$/i.test(behavior[3]);
      if (!isNone) result.behaviors.push({ line: locator, threat: behavior[3].trim(), detail: behavior[4].trim() });
      continue;
    }
    for (const [key, title] of mapping) {
      if (!line.includes(title)) continue;
      // 去掉前缀标记与标题（截到第一个冒号为止），兼容"标题：值"与"标题 值"两种写法
      result.dimensions[key] = line.replace(/^[*-]\s*/, "").replace(/\*\*/g, "").replace(/^[^：:]*[：:]\s*/, "").trim();
      break;
    }
  }
  return result;
}

function cleanDeobfuscated(raw) { return String(raw).replace(/\[LINE_\d+\]/g, "").replace(/\[\[\/?HL\]\]/g, "").replace(/^```[^\n]*\n?|```$/gm, "").trim(); }
export function renderHighlightedCode(raw, hints = []) {
  const source = String(raw).replace(/^```[^\n]*\n?|```$/gm, "").trim();
  const rawLines = source.split("\n"), hasMarkers = rawLines.some(line => /^\[LINE_\d+\]/.test(line));
  let visualLine = 0, evidenceLine = null; const numbers = [], output = [];
  for (const rawLine of rawLines) {
    const marker = rawLine.match(/^\[LINE_(\d+)\]/); visualLine += 1;
    // 注意：此处【刻意沿用】上一行的 evidenceLine，不可重置为 null。
    // 压缩成单行的样本经后端分行后，模型通常只在首行输出一次 [LINE_1]，
    // 其后所有续行同属原始第 1 行 —— 重置会导致续行上的静态高亮全部丢失。
    // （回归用例见 tests/js/verify_report_parsing.js:
    //   "original line hint follows formatted continuation"）
    if (marker) evidenceLine = Number(marker[1]); else if (!hasMarkers) evidenceLine = visualLine;
    // 行号栏必须显示**原始行号**，而不是视觉序号。
    // 模型只输出关键代码段、会省略注释行与空行，原始行号会跳号
    // （实测 DE 为 1,2,4,5,...,18 —— L3/L14 等被省略）；
    // 若显示 1..N 连续序号，就与 [METADATA_BEHAVIOR] 引用的真实行号对不上。
    // 无 marker 时（理论上不该出现）退回视觉序号，保证列数与代码行数一致。
    numbers.push(hasMarkers && evidenceLine != null ? String(evidenceLine) : String(visualLine));
    const taggedLine = rawLine.replace(/^\[LINE_\d+\]/, "");
    const modelTokens = [...taggedLine.matchAll(/\[\[HL\]\]([\s\S]*?)\[\[\/HL\]\]/g)].map(match => ({ text: match[1], category: "model" }));
    const line = taggedLine.replace(/\[\[\/?HL\]\]/g, "");
    const deterministic = hints.filter(item => {
      const text = String(item.text || "");
      return text && (Number(item.line) === evidenceLine || (!hasMarkers && taggedLine.includes(text)));
    }).map(item => ({ text: String(item.text || ""), category: String(item.category || "static") }));
    const ranges = [];
    for (const token of [...deterministic, ...modelTokens]) {
      if (!token.text) continue;
      let start = 0;
      while ((start = line.indexOf(token.text, start)) >= 0) { ranges.push({ start, end: start + token.text.length, category: token.category }); start += Math.max(1, token.text.length); }
    }
    ranges.sort((a, b) => a.start - b.start || b.end - a.end);
    const merged = [];
    for (const range of ranges) { const last = merged[merged.length - 1]; if (last && range.start < last.end) { if (range.end > last.end) last.end = range.end; } else merged.push({ ...range }); }
    let cursor = 0, html = "";
    for (const range of merged) { html += escapeHtml(line.slice(cursor, range.start)); html += `<mark class="danger-token ${escapeHtml(range.category)}">${escapeHtml(line.slice(range.start, range.end))}</mark>`; cursor = range.end; }
    html += escapeHtml(line.slice(cursor)); output.push(html || " ");
  }
  return { numbers: numbers.join("\n"), html: output.join("\n") };
}

export function parseC2(text = "") {
  const clean = String(text).trim(); if (!clean || /^(none|无|暂无|null|未发现.*)$/i.test(clean)) return [];
  return clean.split("\n").map(line => line.trim()).filter(line => line && !/^#{1,4}/.test(line)).map(line => { const parts = line.replace(/^[-*]\s*/, "").split(";").map(x => x.trim()); return { ip: parts[0] || "", port: parts[1] || "", protocol: parts[2] || "", family: parts[3] || "", evasion: parts[4] || "", conclusion: parts.slice(5).join("；") }; }).filter(item => Object.values(item).some(Boolean));
}

export function parsePlaybook(text = "") {
  const result = emptyPlaybook(), heading = /^\s*(?:#{1,4}\s*)?(?:\[)?([1-4])[.)、．]?\s*(IOC\s*封(?:锁|禁)清单|网络阻断规则|主机清扫指令|安服汇报(?:口径)?)(?:\])?\s*$/i; let active = "";
  const keys = { "1": "ioc", "2": "network", "3": "host", "4": "report" };
  for (const rawLine of String(text).split("\n")) { const match = rawLine.trim().match(heading); if (match) { active = keys[match[1]]; continue; } if (active) result[active] += `${rawLine}\n`; }
  for (const key of Object.keys(result)) result[key] = result[key].trim().replace(/^\[(?:REPORT_TEXT|IOC|NETWORK|HOST)\]\s*/i, "").trim();
  return result;
}
function renderIoc(text) {
  if (!text || isEmptyValue(text)) return emptyState("未提取到可封锁的 IOC"); const rows = [];
  for (const line of text.split("\n")) { const match = line.trim().match(/^\*\*\[?([^*\]]+)\]?\*\*\s*[　\s:：]+\s*(.+)$/); if (match) rows.push(`<div><dt>${escapeHtml(match[1])}</dt><dd>${escapeHtml(match[2])}</dd></div>`); }
  return rows.length ? `<dl class="ioc-list">${rows.join("")}</dl>` : `<div class="response-prose">${renderPlainLines(text)}</div>`;
}
function renderResponseText(text, fallback) { return !text || isEmptyValue(text) ? emptyState(fallback) : `<div class="response-prose">${renderFencedText(text)}</div>`; }
function renderReportText(text) { return !text || isEmptyValue(text) ? emptyState("未生成安服汇报口径") : `<div class="report-prose">${text.split(/\n+/).filter(Boolean).map(line => `<p>${escapeHtml(line.replace(/^[-*]\s*/, ""))}</p>`).join("")}</div>`; }
function renderFencedText(text) { const parts = String(text).split(/```(?:\w+)?\s*\n?/); return parts.map((part, index) => index % 2 ? `<pre><code>${escapeHtml(part.trim())}</code></pre>` : renderPlainLines(part)).join(""); }
function renderPlainLines(text) { return String(text).split("\n").map(x => x.trim()).filter(Boolean).map(line => /^[-*]\s+/.test(line) ? `<p class="response-item">${escapeHtml(line.replace(/^[-*]\s+/, ""))}</p>` : `<p>${escapeHtml(line)}</p>`).join(""); }
function isEmptyValue(value) { return /^(无|none|暂无|null|未发现|未提取到|无明确特征)[。.]?$/i.test(String(value || "").trim()); }
function normalizeEmpty(value) { return isEmptyValue(value) || !String(value || "").trim() ? "无明确特征" : String(value).trim(); }
function fallbackVerdict(data, done) { const d = data?.deterministic_verdict || {}; return { verdict: done?.verdict || d.verdict || "unknown", confidence: done?.confidence ?? d.confidence ?? 0, summary: d.reason || "模型复核未提供有效结论。", behavior_chain: data?.behavior_findings?.[0]?.behavior_chain || [] }; }
function normalizeFindings(data) { const out = []; for (const finding of data?.behavior_findings || []) for (const evidence of finding.evidence || []) out.push({ severity: String(evidence.severity || finding.severity || "medium").toLowerCase(), line: Number(evidence.line_start || 0) }); for (const match of data?.matches || []) out.push({ severity: String(match.severity || "medium").toLowerCase(), line: Number(match.line || match.line_number || match.line_start || 0) }); return out; }
function formatConfidence(value) { const n = Number(value); return Number.isFinite(n) ? `${Math.round(Math.max(0, Math.min(1, n)) * 100)}%` : "--"; }
