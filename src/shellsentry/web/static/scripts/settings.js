import { apiFetch, escapeHtml, refreshIcons, showToast } from "./utils.js";

export class SettingsController {
  constructor({ onStatusChange } = {}) {
    this.onStatusChange = onStatusChange;
    this.configs = [];
    this.drawer = document.getElementById("settingsDrawer");
    this.scrim = document.getElementById("drawerScrim");
    this.form = document.getElementById("configForm");
    this.feedback = document.getElementById("configFeedback");
    this.bind();
  }

  bind() {
    document.getElementById("settingsButton").addEventListener("click", () => this.open());
    document.getElementById("closeSettingsButton").addEventListener("click", () => this.close());
    this.scrim.addEventListener("click", () => this.close());
    document.getElementById("addConfigButton").addEventListener("click", () => this.edit());
    document.getElementById("testConfigButton").addEventListener("click", () => this.test());
    document.getElementById("detectOllamaButton").addEventListener("click", () => this.detectOllama());
    this.form.addEventListener("submit", event => {
      event.preventDefault();
      this.save();
    });
  }

  async init() {
    try {
      const data = await apiFetch("/api/config/llm");
      this.configs = data.configs || [];
      this.render();
      this.updateGlobalStatus(data);
    } catch (error) {
      this.updateGlobalStatus({ effective_api_source: "none" });
    }
  }

  async open() {
    await this.init();
    this.drawer.classList.add("open");
    this.scrim.classList.add("open");
    this.drawer.setAttribute("aria-hidden", "false");
  }

  close() {
    this.drawer.classList.remove("open");
    this.scrim.classList.remove("open");
    this.drawer.setAttribute("aria-hidden", "true");
  }

  render() {
    const list = document.getElementById("configList");
    if (!this.configs.length) {
      list.innerHTML = '<div class="config-empty">尚未配置模型。添加兼容 OpenAI 接口的云端或本地模型。</div>';
      return;
    }
    list.innerHTML = this.configs.map(config => `
      <div class="config-item ${config.enabled ? "enabled" : ""}" data-config-id="${escapeHtml(config.id)}">
        <div>
          <strong>${escapeHtml(config.name || config.model_name)}</strong>
          <span>${escapeHtml(config.model_name)} · ${escapeHtml(config.base_url)}</span>
        </div>
        <div class="config-item-actions">
          <button type="button" data-action="toggle" title="${config.enabled ? "停用" : "启用"}" aria-label="${config.enabled ? "停用" : "启用"}"><i data-lucide="${config.enabled ? "toggle-right" : "toggle-left"}"></i></button>
          <button type="button" data-action="edit" title="编辑" aria-label="编辑"><i data-lucide="pencil"></i></button>
          <button type="button" data-action="delete" title="删除" aria-label="删除"><i data-lucide="trash-2"></i></button>
        </div>
      </div>`).join("");
    list.querySelectorAll("[data-config-id]").forEach(item => {
      const id = item.dataset.configId;
      item.querySelector('[data-action="toggle"]').addEventListener("click", () => this.toggle(id));
      item.querySelector('[data-action="edit"]').addEventListener("click", () => this.edit(this.configs.find(config => config.id === id)));
      item.querySelector('[data-action="delete"]').addEventListener("click", () => this.remove(id));
    });
    refreshIcons(list);
  }

  edit(config = null) {
    const isExisting = Boolean(config?.id);
    this.form.hidden = false;
    document.getElementById("configId").value = config?.id || "";
    document.getElementById("configName").value = config?.name || "";
    document.getElementById("configBaseUrl").value = config?.base_url || "https://api.openai.com/v1";
    // 已有配置不回填 api_key：后端返回的是掩码（如 sk-1****cdef），回填后保存会把
    // 掩码当成新 Key 覆盖真实值。留空 = 沿用已保存的 Key；仅新建时才回填
    // （含 Ollama 探测填入的 "ollama" 占位）。
    const keyInput = document.getElementById("configApiKey");
    keyInput.value = isExisting ? "" : (config?.api_key || "");
    // 已有配置允许留空（后端沿用原 Key），故不用 required 卡住提交；新建仍必填。
    keyInput.required = !isExisting;
    keyInput.placeholder = isExisting ? "留空则沿用已保存的 Key" : "仅保存在本机";
    document.getElementById("configModelName").value = config?.model_name || "";
    this.hideFeedback();
    document.getElementById("configName").focus();
  }

  payload() {
    return {
      id: document.getElementById("configId").value.trim(),
      name: document.getElementById("configName").value.trim(),
      base_url: document.getElementById("configBaseUrl").value.trim(),
      api_key: document.getElementById("configApiKey").value.trim(),
      model_name: document.getElementById("configModelName").value.trim()
    };
  }

  async save() {
    try {
      await apiFetch("/api/config/llm", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(this.payload())
      });
      this.showFeedback("配置已保存并启用", "success");
      showToast("模型配置已保存", "success");
      await this.init();
      window.setTimeout(() => { this.form.hidden = true; }, 700);
    } catch (error) {
      this.showFeedback(error.message, "error");
    }
  }

  async test() {
    const button = document.getElementById("testConfigButton");
    button.disabled = true;
    this.showFeedback("正在测试连接…");
    try {
      const result = await apiFetch("/api/config/llm/test", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(this.payload())
      });
      this.showFeedback(result.message || (result.success ? "连接成功" : "连接失败"), result.success ? "success" : "error");
    } catch (error) {
      this.showFeedback(error.message, "error");
    } finally {
      button.disabled = false;
    }
  }

  async detectOllama() {
    const button = document.getElementById("detectOllamaButton");
    const target = document.getElementById("ollamaResults");
    const baseUrl = document.getElementById("ollamaUrl").value.trim().replace(/\/$/, "");
    button.disabled = true;
    target.hidden = false;
    target.textContent = "正在探测本地模型…";
    try {
      const data = await apiFetch(`/api/ollama/models?base_url=${encodeURIComponent(baseUrl)}`);
      const models = data.models || [];
      if (!models.length) {
        target.textContent = "未发现可用模型，请确认 Ollama 已启动。";
        return;
      }
      target.innerHTML = models.map(model => `<button class="ollama-result" type="button" data-model="${escapeHtml(model.name)}"><strong>${escapeHtml(model.name)}</strong><span>${escapeHtml(model.size || "")}</span></button>`).join("");
      target.querySelectorAll("[data-model]").forEach(item => item.addEventListener("click", () => {
        this.edit({ name: `Ollama ${item.dataset.model}`, base_url: `${baseUrl}/v1`, api_key: "ollama", model_name: item.dataset.model });
      }));
    } catch (error) {
      target.textContent = error.message;
    } finally {
      button.disabled = false;
    }
  }
  async toggle(id) {
    try {
      await apiFetch("/api/config/llm/toggle", {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id })
      });
      await this.init();
    } catch (error) { showToast(error.message, "error"); }
  }

  async remove(id) {
    const config = this.configs.find(item => item.id === id);
    if (!window.confirm(`删除模型配置“${config?.name || id}”？`)) return;
    try {
      await apiFetch(`/api/config/llm/${encodeURIComponent(id)}`, { method: "DELETE" });
      showToast("配置已删除", "success");
      await this.init();
    } catch (error) { showToast(error.message, "error"); }
  }

  showFeedback(message, type = "") {
    this.feedback.hidden = false;
    this.feedback.className = `form-feedback ${type}`;
    this.feedback.textContent = message;
  }

  hideFeedback() { this.feedback.hidden = true; }

  updateGlobalStatus(data) {
    const configured = data.effective_api_source && data.effective_api_source !== "none";
    const label = configured ? (data.effective_model || "模型已配置") : "未配置模型";
    document.getElementById("modelStatusText").textContent = label;
    document.querySelectorAll("#modelStatus .connection-dot, #connectionDot").forEach(dot => {
      dot.classList.toggle("online", configured);
      dot.classList.toggle("offline", !configured);
    });
    this.onStatusChange?.({ configured, label });
  }
}