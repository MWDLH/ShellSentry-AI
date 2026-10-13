import { apiFetch, consumeSSE, copyText, downloadText, languageFromFilename, refreshIcons, showToast } from "./utils.js";
import { ReportView } from "./report-view.js";
import { SettingsController } from "./settings.js";

const state = {
  file: null,
  filename: "",
  mode: "file",
  auditing: false,
  startedAt: 0,
  timer: null,
  activeTaskId: "",
  modelConfigured: false,
  auditAbort: null,      // 当前审计的 AbortController（用于"取消任务"）
  auditDetached: false,  // 审计转入后台（用户切去看历史）时置真：停止渲染，但连接继续跑
  auditRun: null         // 运行中任务的快照 {taskId, filename, step, message, percent, logs}
};

// 侧栏"最近任务"里代表"运行中任务"的哨兵 ID
const RUNNING_TASK_ID = "__running__";

const elements = {};
let reportView;
let settings;

window.addEventListener("DOMContentLoaded", init);

function init() {
  cacheElements();
  reportView = new ReportView();
  settings = new SettingsController({ onStatusChange: ({ configured }) => { state.modelConfigured = configured; } });
  bindEvents();
  refreshIcons();
  updateSourceState();
  settings.init();
  loadHistory();
  restoreActiveTask();
  installFrontendVersionWatch();
}

// ── 前端版本守卫 ──
// 本地开发最常见的困惑是"改完不知道到底生效没有"。此前指纹只写在 meta 里，
// 必须开 F12 才能看；这里把它显示到侧栏页脚，并在用户回到页面时比对服务端
// 当前指纹 —— 不一致就明确提示刷新。刻意不做轮询，只在获得焦点时检查。
function readFrontendBuild() {
  const meta = document.querySelector('meta[name="shellsentry-frontend-build"]');
  return (meta && meta.content) || "unknown";
}

function installFrontendVersionWatch() {
  const loaded = readFrontendBuild();
  const chip = document.getElementById("frontendBuildChip");
  if (chip) chip.textContent = `build ${loaded}`;
  if (typeof window === "undefined" || typeof fetch !== "function") return;

  let notified = "";
  const check = async () => {
    if (typeof document !== "undefined" && document.hidden) return;
    try {
      const response = await fetch("/", { cache: "no-store" });
      if (!response.ok) return;
      const text = await response.text();
      const match = text.match(/name="shellsentry-frontend-build"\s+content="([^"]+)"/);
      const current = match ? match[1] : "";
      if (!current || current === loaded || current === notified) return;
      notified = current;  // 同一个新版本只提示一次，避免反复打扰
      if (chip) {
        chip.classList.add("stale");
        chip.textContent = `build ${loaded} → ${current}`;
        chip.title = "检测到前端资源已更新，刷新页面后生效";
      }
      showToast("前端资源已更新，刷新页面后生效", "info");
    } catch (_) {
      // 服务未启动或网络异常：本地工具无需因此打扰用户
    }
  };

  window.addEventListener("focus", check);
  if (typeof document !== "undefined" && document.addEventListener) {
    document.addEventListener("visibilitychange", () => { if (!document.hidden) check(); });
  }
}

function cacheElements() {
  [
    "sidebar", "sidebarScrim", "mobileMenuButton", "sidebarClose", "newTaskButton",
    "refreshHistoryButton", "clearHistoryButton", "historyList", "fileInput", "chooseFileButton", "clearSourceButton",
    // 注意：不要在此缓存 "lineNumbers" —— 该元素属于代码反混淆面板，
    // 由 reportView 通过 byId("lineNumbers") 独占维护。曾因在此缓存并被
    // updateSourceState() 写入，导致反混淆面板行号被源码行数覆盖。
    "fileModeButton", "pasteModeButton", "sourceInput", "taskComposer", "pastePanel", "composerTitle", "composerHint",
    "sourceStats", "sourceNotice", "documentName", "documentMeta",
    "auditButton", "exportButton", "workbench", "elapsedTime", "copyDecodedButton", "decodedCode", "responseContent"
  ].forEach(id => { elements[id] = document.getElementById(id); });
}

function bindEvents() {
  elements.newTaskButton.addEventListener("click", newTask);
  elements.refreshHistoryButton.addEventListener("click", loadHistory);
  elements.clearHistoryButton.addEventListener("click", clearAllHistory);
  elements.chooseFileButton.addEventListener("click", () => elements.fileInput.click());
  elements.fileInput.addEventListener("change", () => handleFile(elements.fileInput.files[0]));
  elements.clearSourceButton.addEventListener("click", newTask);
  elements.fileModeButton.addEventListener("click", () => switchMode("file"));
  elements.pasteModeButton.addEventListener("click", () => switchMode("paste"));
  elements.sourceInput.addEventListener("input", () => {
    if (state.mode === "paste") {
      state.file = null;
      state.filename = elements.sourceInput.value.trim() ? "pasted-code.txt" : "";
    }
    updateSourceState();
  });
  elements.sourceInput.addEventListener("keydown", handleEditorKeydown);
  elements.auditButton.addEventListener("click", () => { if (state.auditing) cancelAudit(); else startAudit(); });
  elements.exportButton.addEventListener("click", exportReport);
  elements.copyDecodedButton.addEventListener("click", () => copyText(reportView.decodedText || "", "反混淆代码已复制").catch(() => showToast("复制失败", "error")));
  elements.mobileMenuButton.addEventListener("click", openSidebar);
  elements.sidebarClose.addEventListener("click", closeSidebar);
  elements.sidebarScrim.addEventListener("click", closeSidebar);

  for (const event of ["dragenter", "dragover"]) {
    document.addEventListener(event, dragEvent => {
      dragEvent.preventDefault();
      if (!state.auditing) elements.taskComposer.classList.add("dragging");
    });
  }
  for (const event of ["dragleave", "drop"]) {
    document.addEventListener(event, dragEvent => {
      dragEvent.preventDefault();
      elements.taskComposer.classList.remove("dragging");
    });
  }
  document.addEventListener("drop", event => {
    if (!state.auditing) handleFile(event.dataTransfer?.files?.[0]);
  });
}

function switchMode(mode) {
  state.mode = mode;
  const paste = mode === "paste";
  elements.fileModeButton.classList.toggle("active", !paste);
  elements.pasteModeButton.classList.toggle("active", paste);
  elements.fileModeButton.setAttribute("aria-selected", String(!paste));
  elements.pasteModeButton.setAttribute("aria-selected", String(paste));
  elements.sourceInput.readOnly = !paste && Boolean(state.file);
  if (paste && !elements.sourceInput.value) {
    state.file = null;
    state.filename = "";
    elements.sourceInput.focus();
  }
  elements.pastePanel.hidden = !paste;
  updateSourceState();
}

async function handleFile(file) {
  if (!file) return;
  if (file.size > 50 * 1024 * 1024) {
    showToast("文件超过 50 MB 上限", "error");
    return;
  }
  state.file = file;
  state.filename = file.name;
  state.mode = "file";
  elements.fileModeButton.classList.add("active");
  elements.pasteModeButton.classList.remove("active");
  elements.sourceInput.readOnly = true;
  const binaryContainer = /\.(zip)$/i.test(file.name);
  if (binaryContainer) {
    elements.sourceInput.value = "该压缩包将在服务端内存中展开并逐个审计其中的文本脚本。\n压缩包内容不会在界面中预览，也不会执行。";
  } else {
    try {
      elements.sourceInput.value = await file.text();
    } catch (_) {
      elements.sourceInput.value = "无法在浏览器中预览该文件，仍可提交后端进行类型检测。";
    }
  }
  updateSourceState();
  reportView.setSource(elements.sourceInput.value);
  reportView.reset();
}

function updateSourceState() {
  const text = elements.sourceInput.value;
  const lineCount = text ? text.split("\n").length : 1;
  // 注意：#lineNumbers 是【代码反混淆面板】的行号栏（与 #decodedCode 同级），
  // 由 reportView 独占维护（renderDeobfuscation 写入，selectSection("restoration")
  // 时按记忆值自愈）。此处绝不可写入 —— 审计结束的 finally 也会调用本函数，
  // 会用「源码行数」覆盖反混淆面板行号，单行载荷（源码 1 行 / 反混淆后 N 行）
  // 时表现为行号栏只剩“1”。源码面板自身没有行号栏，行数统计由下方 #sourceStats 呈现。
  elements.sourceStats.textContent = `${text ? lineCount : 0} 行 · ${text.length.toLocaleString("zh-CN")} 字符`;
  elements.taskComposer.classList.toggle("has-source", Boolean(text || state.file));
  elements.composerTitle.textContent = state.filename || "添加待审计脚本";
  elements.composerHint.textContent = state.filename ? `${languageFromFilename(state.filename)} · ${state.file ? formatBytes(state.file.size) : "粘贴内容"}` : "拖放文件到此处，或选择文件 / 粘贴代码";
  // 审计进行中时该按钮是「取消任务」，必须可点；空闲时按有无输入禁用。
  elements.auditButton.disabled = state.auditing ? false : (!state.file && !text.trim());
  elements.documentName.textContent = state.filename || "未命名审计";
  elements.documentMeta.textContent = state.filename
    ? `${languageFromFilename(state.filename)} · ${state.file ? formatBytes(state.file.size) : "粘贴内容"}`
    : "选择文件或粘贴代码";
  reportView?.setSource(text);
}

function handleEditorKeydown(event) {
  if (event.key !== "Tab" || elements.sourceInput.readOnly) return;
  event.preventDefault();
  const start = elements.sourceInput.selectionStart;
  const end = elements.sourceInput.selectionEnd;
  elements.sourceInput.setRangeText("    ", start, end, "end");
  elements.sourceInput.dispatchEvent(new Event("input"));
}

async function startAudit() {
  if (state.auditing) return;
  if (!state.file && !elements.sourceInput.value.trim()) return;
  // 未配置/未启用大模型：直接提示去配置，不再做任何"无模型简易审计"。
  if (!state.modelConfigured) {
    showToast("未配置大模型 API，请先在「模型设置」中配置并启用后重试", "error");
    return;
  }
  state.auditing = true;
  state.auditDetached = false;
  state.startedAt = Date.now();
  state.activeTaskId = "";
  state.auditAbort = new AbortController();
  state.auditRun = { taskId: "", filename: state.filename || "未命名审计", step: "static", message: "正在建立静态证据", percent: 12, logs: [] };
  setAuditButtonRunning(true);
  elements.sourceInput.readOnly = true;
  elements.sourceNotice.textContent = "静态扫描 + Agent 复核";
  reportView.start();
  elements.pastePanel.hidden = true;
  startTimer();
  void loadHistory();   // 让"最近任务"顶部立即出现"运行中"条目，切走后也点得回来

  const formData = new FormData();
  if (state.file) formData.append("file", state.file, state.file.name);
  else formData.append("code_text", elements.sourceInput.value);

  let receivedDone = false;
  let streamError = null;
  try {
    const response = await fetch("/api/audit/stream", { method: "POST", body: formData, signal: state.auditAbort.signal });
    await consumeSSE(response, (event, data) => {
      updateAuditRun(event, data);   // 始终维护后台快照（转入后台后切回来才能回放进度）
      // 用户切去查看历史 → 审计转入后台：不再渲染，仅记录终态（完成后刷新历史列表即可）。
      if (state.auditDetached) {
        if (event === "done") receivedDone = true;
        else if (event === "error") streamError = new Error(data.message || "审计流异常");
        return;
      }
      if (event === "init") {
        state.activeTaskId = data.task_id || state.activeTaskId;
        reportView.setStatic(data.regex_evidence || data.regex_scan || {});
      } else if (event === "progress") {
        // 进度换算与快照统一放在 updateAuditRun 里，这里只负责渲染，保证两侧一致。
        reportView.setProgress(state.auditRun.step, state.auditRun.message, state.auditRun.percent);
      } else if (event === "stream") {
        reportView.appendRaw(data.text || "");
      } else if (event === "verdict") {
        reportView.setFinalVerdict(data);
      } else if (event === "done") {
        receivedDone = true;
        reportView.complete(data);
        // 优先用后端给出的具体原因：它会区分"模型未产出内容"与"调用报错"，
        // 二者都会退化为静态判定，但用户需要知道到底发生了什么。
        if (data.has_error) showToast(data.message || "模型分析不可用，当前展示静态判定", "error");
        // 报告触达模型输出上限被截断：末尾章节（通常是处置建议）可能不闭合，
        // 面板会显示为空。明确告知，避免被误读成"没检测到"。
        // empty_output 是另一种情况（正文一个字都没有），此时上面已给出更准确的提示，
        // 不能再叠加一句"报告被截断"，否则两句提示互相矛盾。
        if (data.report_truncated && !data.empty_output) {
          showToast("AI 报告已达输出长度上限被截断，末尾章节可能不完整", "info");
        }
      } else if (event === "error") {
        streamError = new Error(data.message || "审计流异常");
      }
    });
    if (streamError) throw streamError;
    if (!receivedDone) throw new Error("审计流提前结束，未收到最终状态");
    showToast(state.auditDetached ? "后台审计完成，可在最近任务中查看" : "审计完成", "success");
  } catch (error) {
    if (error && error.name === "AbortError") {
      // 用户主动取消：丢弃半截结果，不展示未完成的报告
      if (!state.auditDetached) reportView.reset();
      showToast("已取消审计", "info");
    } else if (state.auditDetached) {
      // 后台失败：不污染当前正在查看的历史视图
      showToast(error.message || "审计流异常", "error");
    } else {
      showAuditError(error.message);
    }
  } finally {
    state.auditing = false;
    state.auditAbort = null;
    state.auditRun = null;   // 移除"最近任务"里的"运行中"条目
    stopTimer();
    setAuditButtonRunning(false);
    if (state.auditDetached) {
      elements.auditButton.disabled = false;   // 后台任务结束，恢复可点，别卡住界面
    } else {
      elements.sourceInput.readOnly = state.mode === "file" && Boolean(state.file);
      updateSourceState();
    }
    void loadHistory();      // 完成 / 取消 / 失败后统一刷新列表
  }
}

// 维护"运行中任务"的后台快照：即使当前正在看历史（已转入后台）也要持续更新，
// 这样用户从"最近任务"点回本任务时才能回放出正确的进度。
function updateAuditRun(event, data) {
  const run = state.auditRun;
  if (!run) return;
  if (event === "init") {
    run.taskId = data.task_id || run.taskId;
  } else if (event === "progress") {
    // 阶段基准（须单调递增）：静态 34 → 分片 36~58 → 综合 62 → 复核 72 → 完成 88
    const review = data.mode === "agent_review";
    let percent;
    if (review) percent = 72;
    else if (data.mode === "synthesis") percent = 62;
    else if (data.total > 0 && data.completed > 0) percent = 36 + Math.round((data.completed / data.total) * 22);
    else if (data.mode === "chunked") percent = 36;
    else percent = 43;
    run.step = review ? "review" : "semantic";
    run.message = data.message || "继续分析";
    run.percent = percent;
    run.logs.push(run.message);
  }
}

// 审计进行中时，把「开始审计」按钮切成「取消任务」（不换图标，避免动 lucide 的替换逻辑）。
function setAuditButtonRunning(running) {
  const btn = elements.auditButton;
  const span = btn.querySelector("span");
  if (span) span.textContent = running ? "取消任务" : "开始审计";
  btn.classList.toggle("danger", running);
  if (running) btn.disabled = false;
}

// 取消当前审计：二次确认 → 中断连接（服务端 finally 会释放任务锁），再请求服务端兜底解锁。
async function cancelAudit() {
  if (!state.auditing) return;
  if (!window.confirm("确定中断当前审计？未完成的分析结果不会被保存。")) return;
  try { state.auditAbort?.abort(); } catch (_) {}
  try { await apiFetch("/api/task/cancel", { method: "POST" }); } catch (_) {}
}

function showAuditError(message) {
  document.getElementById("resultRunning").hidden = true;
  document.getElementById("resultEmpty").hidden = false;
  document.getElementById("resultEmpty").querySelector("strong").textContent = "审计未完成";
  document.getElementById("resultEmpty").querySelector("p").textContent = message;
  showToast(message, "error");
}

function startTimer() {
  stopTimer();
  const tick = () => {
    const seconds = Math.max(0, Math.floor((Date.now() - state.startedAt) / 1000));
    elements.elapsedTime.textContent = `${String(Math.floor(seconds / 60)).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;
  };
  tick();
  state.timer = window.setInterval(tick, 1000);
}
function stopTimer() { if (state.timer) window.clearInterval(state.timer); state.timer = null; }

function newTask() {
  // 审计进行中也允许新建视图：审计转入后台继续跑，稍后可从历史里打开结果。
  if (state.auditing && !window.confirm("当前审计仍在进行，确定清空当前视图？审计会转入后台继续。")) return;
  if (state.auditing) {
    if (!state.auditDetached) showToast("当前审计已转入后台运行，完成后可在最近任务中查看", "info");
    state.auditDetached = true;
  }
  state.file = null;
  state.filename = "";
  state.mode = "file";
  state.activeTaskId = "";
  elements.fileInput.value = "";
  elements.sourceInput.value = "";
  elements.sourceInput.readOnly = false;
  elements.sourceNotice.textContent = "本地静态分析";
  document.querySelectorAll(".history-item").forEach(item => item.classList.remove("active"));
  switchMode("file");
  reportView.reset();
  updateSourceState();
  closeSidebar();
}

async function loadHistory() {
  try {
    const records = await apiFetch("/api/history");
    renderHistory(records || []);
  } catch (error) {
    elements.historyList.innerHTML = '<div class="history-empty">无法加载本地历史记录。</div>';
  }
}

function renderHistory(records) {
  const items = Array.isArray(records) ? records.slice() : [];
  // 运行中的任务置顶显示，避免它"凭空消失"；点击可切回实时视图。
  if (state.auditRun) {
    items.unshift({
      task_id: RUNNING_TASK_ID,
      display_name: state.auditRun.filename || "未命名审计",
      filename: state.auditRun.filename || "未命名审计",
      timestamp: "",
      running: true,
    });
  }
  if (!items.length) {
    elements.historyList.innerHTML = '<div class="history-empty">暂无审计记录<br>新任务会显示在这里</div>';
    return;
  }
  elements.historyList.innerHTML = items.map(record => {
    if (record.running) {
      return `
    <div class="history-item running active" role="button" tabindex="0" data-task-id="${RUNNING_TASK_ID}" data-display-name="${escapeAttribute(record.display_name)}">
      <span class="history-file-icon"><i data-lucide="loader"></i></span>
      <span class="history-copy"><strong>${escapeText(record.display_name)}</strong><span>审计进行中…</span></span>
    </div>`;
    }
    return `
    <div class="history-item ${record.task_id === state.activeTaskId ? "active" : ""}" role="button" tabindex="0" data-task-id="${escapeAttribute(record.task_id)}" data-display-name="${escapeAttribute(record.display_name || record.filename || "未命名")}">
      <span class="history-file-icon"><i data-lucide="file-code-2"></i></span>
      <span class="history-copy"><strong>${escapeText(record.display_name || record.filename || "未命名")}</strong><span>${formatHistoryDate(record.timestamp)}</span></span>
      <span class="history-actions"><button class="history-action rename" type="button" title="重命名" aria-label="重命名"><i data-lucide="pencil"></i></button><button class="history-action delete" type="button" title="删除任务" aria-label="删除任务"><i data-lucide="trash-2"></i></button></span>
    </div>`;
  }).join("");
  elements.historyList.querySelectorAll(".history-item").forEach(item => {
    const isRunning = item.dataset.taskId === RUNNING_TASK_ID;
    item.addEventListener("click", event => {
      if (!isRunning && (event.target.closest(".history-actions") || event.target.closest(".history-rename-input"))) return;
      if (isRunning) { openRunningTask(); return; }
      openHistory(item.dataset.taskId);
    });
    item.addEventListener("keydown", event => {
      if (event.key !== "Enter" || event.target.closest("input")) return;
      if (isRunning) openRunningTask(); else openHistory(item.dataset.taskId);
    });
    const renameBtn = item.querySelector(".history-action.rename");
    if (renameBtn) renameBtn.addEventListener("click", () => beginHistoryRename(item));
    const deleteBtn = item.querySelector(".history-action.delete");
    if (deleteBtn) deleteBtn.addEventListener("click", () => deleteHistory(item.dataset.taskId));
  });
  refreshIcons(elements.historyList);
}

// 从历史切回"正在运行的审计"：恢复实时渲染 + 回放进度面板。
function openRunningTask() {
  if (!state.auditing) return;
  state.auditDetached = false;
  reportView.replayRunning(state.auditRun || {});
  elements.documentName.textContent = (state.auditRun && state.auditRun.filename) || "未命名审计";
  elements.documentMeta.textContent = "审计进行中";
}

async function openHistory(taskId) {
  // 审计进行中也允许查看历史详情：把审计转入后台（停止渲染，连接继续跑），互不影响。
  // 提示只在"第一次"转后台时弹一次，之后来回切换不再重复打扰。
  if (state.auditing) {
    if (!state.auditDetached) showToast("当前审计已转入后台运行，完成后可在最近任务中查看", "info");
    state.auditDetached = true;
  }
  try {
    const record = await apiFetch(`/api/history/${encodeURIComponent(taskId)}`);
    state.activeTaskId = taskId;
    state.file = null;
    state.filename = record.filename || record.report?.filename || "历史审计";
    elements.sourceInput.value = "";
    elements.sourceInput.readOnly = true;
    elements.sourceNotice.textContent = "历史记录不保存样本源码";
    updateSourceState();
    document.querySelectorAll(".history-item").forEach(item => item.classList.toggle("active", item.dataset.taskId === taskId));
    reportView.loadHistory(record);
    elements.documentName.textContent = record.display_name || state.filename;
    elements.documentMeta.textContent = "历史审计 · 源码未落盘";
    closeSidebar();
  } catch (error) { showToast(error.message, "error"); }
}

async function deleteHistory(taskId) {
  if (!window.confirm("删除这条本地审计记录？")) return;
  try {
    await apiFetch(`/api/history/${encodeURIComponent(taskId)}`, { method: "DELETE" });
    if (state.activeTaskId === taskId) newTask();
    await loadHistory();
  } catch (error) { showToast(error.message, "error"); }
}

function beginHistoryRename(item) {
  if (item.querySelector(".history-rename-input")) return;
  const copy = item.querySelector(".history-copy");
  const original = item.dataset.displayName || "未命名";
  const input = document.createElement("input");
  input.className = "history-rename-input";
  input.type = "text";
  input.maxLength = 80;
  input.value = original;
  copy.querySelector("strong").hidden = true;
  copy.insertBefore(input, copy.firstChild);
  input.focus(); input.select();
  let finished = false;
  const finish = async save => {
    if (finished) return; finished = true;
    const name = input.value.trim();
    if (!save || !name || name === original) { input.remove(); copy.querySelector("strong").hidden = false; return; }
    try {
      await apiFetch(`/api/history/${encodeURIComponent(item.dataset.taskId)}`, { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ name }) });
      if (state.activeTaskId === item.dataset.taskId) elements.documentName.textContent = name;
      showToast("任务已重命名", "success");
      await loadHistory();
    } catch (error) { input.remove(); copy.querySelector("strong").hidden = false; showToast(error.message, "error"); }
  };
  input.addEventListener("keydown", event => { if (event.key === "Enter") { event.preventDefault(); finish(true); } else if (event.key === "Escape") { event.preventDefault(); finish(false); } });
  input.addEventListener("blur", () => finish(true));
}

async function clearAllHistory() {
  if (!window.confirm("清空全部本地审计历史？此操作不会删除模型配置或其他文件。")) return;
  try {
    await apiFetch("/api/clear-history", { method: "POST" });
    if (state.activeTaskId) newTask();
    await loadHistory();
    showToast("本地历史已清空", "success");
  } catch (error) { showToast(error.message, "error"); }
}

async function restoreActiveTask() {
  try {
    const data = await apiFetch("/api/task/active");
    if (data.active) showToast("检测到正在运行的审计任务，完成后可在最近任务中查看", "info");
  } catch (_) {}
}

function exportReport() {
  const filename = `${(state.filename || "audit").replace(/[^\w.-]+/g, "_")}.report.md`;
  downloadText(filename, reportView.exportMarkdown(state.filename || "未命名"));
}

function openSidebar() { elements.sidebar.classList.add("open"); elements.sidebarScrim.classList.add("open"); }
function closeSidebar() { elements.sidebar.classList.remove("open"); elements.sidebarScrim.classList.remove("open"); }

function formatBytes(bytes) {
  if (!Number.isFinite(bytes)) return "未知大小";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}
function formatHistoryDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "日期未知";
  const year = date.getFullYear();
  const month = String(date.getMonth() + 1).padStart(2, "0");
  const day = String(date.getDate()).padStart(2, "0");
  return `${year}-${month}-${day}`;
}
function escapeText(value) {
  const node = document.createElement("div");
  node.textContent = value;
  return node.innerHTML;
}
function escapeAttribute(value) { return escapeText(value).replace(/"/g, "&quot;"); }
