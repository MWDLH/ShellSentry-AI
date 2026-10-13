export function escapeHtml(value = "") {
  return String(value).replace(/[&<>'"]/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"
  })[char]);
}

export async function apiFetch(url, options = {}) {
  const response = await fetch(url, options);
  const contentType = response.headers.get("content-type") || "";
  const payload = contentType.includes("application/json") ? await response.json() : await response.text();
  if (!response.ok) {
    const detail = typeof payload === "object" ? payload.detail || payload.message : payload;
    throw new Error(detail || `请求失败 (${response.status})`);
  }
  return payload;
}

export function refreshIcons(root = document) {
  if (window.lucide) window.lucide.createIcons({ attrs: { "aria-hidden": "true" }, root });
}

// 通知图标：类型 -> lucide 名称（三种均已随 vendor 打包）
const TOAST_ICONS = { success: "circle-check", error: "circle-alert", info: "info" };

export function showToast(message, type = "info") {
  const region = document.getElementById("toastRegion");
  if (!region) return;
  const toast = document.createElement("div");
  toast.className = `toast ${type}`;
  toast.setAttribute("role", "status");
  const icon = TOAST_ICONS[type] || TOAST_ICONS.info;
  toast.innerHTML = `<i data-lucide="${icon}"></i><div class="toast-body">${escapeHtml(message)}</div>`;
  region.appendChild(toast);
  refreshIcons(toast);
  // 先播退场动画再移除，避免"啪"地消失
  const dismiss = () => {
    toast.classList.add("leaving");
    window.setTimeout(() => toast.remove(), 220);
  };
  window.setTimeout(dismiss, 3600);
}

export function formatDate(value) {
  if (!value) return "时间未知";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "时间未知";
  const now = new Date();
  const sameDay = date.toDateString() === now.toDateString();
  return sameDay
    ? date.toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit" })
    : date.toLocaleDateString("zh-CN", { month: "2-digit", day: "2-digit" });
}

export function languageFromFilename(filename = "") {
  const extension = filename.toLowerCase().split(".").pop();
  const labels = {
    php: "PHP", phtml: "PHP", jsp: "JSP", jspx: "JSP", java: "JAVA",
    asp: "ASP", aspx: "ASPX", cs: "C#", py: "PYTHON", pyw: "PYTHON",
    ps1: "POWERSHELL", psm1: "POWERSHELL", sh: "SHELL", bash: "SHELL",
    zsh: "SHELL", js: "JS", mjs: "JS", cjs: "JS", jsx: "JSX",
    ts: "TS", tsx: "TSX", html: "HTML", htm: "HTML", xhtml: "HTML",
    svg: "SVG", pl: "PERL", pm: "PERL", cgi: "CGI", rb: "RUBY",
    vbs: "VBS", vbe: "VBS", wsf: "WSF", bat: "BATCH", cmd: "BATCH",
    json: "JSON", xml: "XML", yaml: "YAML", yml: "YAML", zip: "ZIP"
  };
  return labels[extension] || "TEXT";
}

export async function consumeSSE(response, onEvent) {
  if (!response.ok) {
    let detail = `请求失败 (${response.status})`;
    try { detail = (await response.json()).detail || detail; } catch (_) {}
    throw new Error(detail);
  }
  if (!response.body) throw new Error("浏览器不支持流式响应");

  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8");
  let buffer = "";

  while (true) {
    const { value, done } = await reader.read();
    buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
    const blocks = buffer.split(/\r?\n\r?\n/);
    buffer = blocks.pop() || "";
    for (const block of blocks) parseEventBlock(block, onEvent);
    if (done) break;
  }
  if (buffer.trim()) parseEventBlock(buffer, onEvent);
}

function parseEventBlock(block, onEvent) {
  let event = "message";
  const dataLines = [];
  for (const line of block.split(/\r?\n/)) {
    if (line.startsWith("event:")) event = line.slice(6).trim();
    if (line.startsWith("data:")) dataLines.push(line.slice(5).trimStart());
  }
  if (!dataLines.length) return;
  const raw = dataLines.join("\n");
  let data = raw;
  try { data = JSON.parse(raw); } catch (_) {}
  onEvent(event, data);
}

// 报告标签顺序。用于未闭合时的兜底截断 —— 见parseTaggedReport 注释。
const REPORT_TAGS = ["IMAGE", "DE_OBFUSCATE", "C2_INFO", "METADATA_BEHAVIOR", "PLAYBOOK"];

export function parseTaggedReport(raw = "") {
  // 优先严格匹配 [TAG]…[/TAG]；匹配不到时退化为"从 [TAG] 取到下一个标签（或文末）"。
  //
  // 为什么需要兜底（2026-10-08 实测）：模型偶尔漏写闭合标签（5 条样本里 4 条
  // 缺 [/IMAGE]）。严格匹配会把整个面板判为空，用户看到"暂无内容"，
  // 等于把模型的格式疏忽放大成"工具没检出任何东西"的误读。
  // 后端 split_report_sections 早就有同样的容错，这里补齐前端，两侧行为一致。
  const extract = tag => {
    const match = raw.match(new RegExp(`\\[${tag}\\]([\\s\\S]*?)\\[\\/${tag}\\]`, "i"));
    if (match) return match[1].trim();
    const openIdx = raw.search(new RegExp(`\\[${tag}\\]`, "i"));
    if (openIdx < 0) return "";
    const bodyStart = openIdx + tag.length + 2;
    // 截到下一个报告标签的开标签（未闭合时它的内容属于下一段）
    let end = raw.length;
    for (const other of REPORT_TAGS) {
      if (other === tag) continue;
      const idx = raw.search(new RegExp(`\\[${other}\\]`, "i"));
      if (idx > bodyStart && idx < end) end = idx;
    }
    return raw.slice(bodyStart, end).trim();
  };
  const decodedRaw = extract("DE_OBFUSCATE");
  return {
    image: extract("IMAGE"),
    decodedRaw,
    decoded: cleanDecoded(decodedRaw),
    metadata: extract("METADATA_BEHAVIOR"),
    c2: extract("C2_INFO"),
    response: extract("PLAYBOOK")
  };
}

function cleanDecoded(value) {
  return value
    .replace(/\[LINE_\d+\]/g, "")
    .replace(/\[\[\/?HL\]\]/g, "")
    .trim();
}

export function textToHtml(text = "") {
  if (!text.trim()) return '<div class="empty-inline">暂无内容</div>';
  const safe = escapeHtml(text);
  const lines = safe.split("\n");
  let html = "";
  let listOpen = false;
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line) {
      if (listOpen) { html += "</ul>"; listOpen = false; }
      continue;
    }
    if (/^#{1,4}\s+/.test(line)) {
      if (listOpen) { html += "</ul>"; listOpen = false; }
      html += `<h3>${line.replace(/^#{1,4}\s+/, "")}</h3>`;
    } else if (/^[-*]\s+/.test(line) || /^\d+[.)]\s+/.test(line)) {
      if (!listOpen) { html += "<ul>"; listOpen = true; }
      html += `<li>${line.replace(/^([-*]|\d+[.)])\s+/, "")}</li>`;
    } else {
      if (listOpen) { html += "</ul>"; listOpen = false; }
      html += `<p>${line.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")}</p>`;
    }
  }
  if (listOpen) html += "</ul>";
  return html;
}

export function downloadText(filename, content) {
  const blob = new Blob([content], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export async function copyText(value, successMessage = "已复制") {
  await navigator.clipboard.writeText(value || "");
  showToast(successMessage, "success");
}
