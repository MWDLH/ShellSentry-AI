#!/usr/bin/env python3
"""
ShellSentry-AI API 配置管理器 v4.0
==================================
多 API 配置管理：支持同时配置多个云端/本地大模型。

优先级:
  1. 用户启用的自定义 API（多个中第一个 enabled=true）
  2. 环境变量回退

存储格式 (config.json):
  {
    "configs": [
      {"id": "xxx", "name": "My DeepSeek", "base_url": "...", ...}
    ],
    "active_id": "xxx"  // 当前启用的配置 ID
  }
"""
import json
import os
import re
import uuid
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass, asdict
from .paths import config_file

# ============================================================
CONFIG_FILE = config_file()
DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL_NAME = "gpt-4o"


# ============================================================
@dataclass
class ApiConfig:
    """单个 API 配置"""
    id: str = ""
    name: str = ""               # 显示名称，如 "DeepSeek Cloud"
    base_url: str = DEFAULT_BASE_URL
    api_key: str = ""
    model_name: str = DEFAULT_MODEL_NAME
    enabled: bool = False
    created_at: str = ""
    updated_at: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        # 移除空 id（新建时）
        if not d.get("id"):
            d.pop("id", None)
        return d

    def to_safe_dict(self) -> dict:
        d = self.to_dict()
        key = d.get("api_key", "")
        if key and len(key) > 8:
            d["api_key"] = key[:4] + "****" + key[-4:]
        elif key:
            d["api_key"] = "****"
        return d

    @classmethod
    def from_dict(cls, data: dict) -> "ApiConfig":
        return cls(
            id=data.get("id", ""),
            name=data.get("name", ""),
            base_url=data.get("base_url", DEFAULT_BASE_URL),
            api_key=data.get("api_key", ""),
            model_name=data.get("model_name", DEFAULT_MODEL_NAME),
            enabled=data.get("enabled", False),
            created_at=data.get("created_at", ""),
            updated_at=data.get("updated_at", ""),
        )

    @classmethod
    def create_new(cls, name: str = "", base_url: str = DEFAULT_BASE_URL,
                   api_key: str = "", model_name: str = DEFAULT_MODEL_NAME) -> "ApiConfig":
        now = datetime.now().isoformat()
        return cls(
            id=str(uuid.uuid4())[:8],
            name=name or "New API",
            base_url=base_url,
            api_key=api_key,
            model_name=model_name,
            enabled=False,
            created_at=now,
            updated_at=now,
        )


# 掩码 Key 判定：to_safe_dict() 生成的脱敏值必定包含 "****"。
# 真实 API Key（OpenAI 兼容体系）由字母数字与 -_+/= 组成，不含 '*'，
# 因此以 "****" 判定"这是脱敏占位符而非真实 Key"。
_MASK_MARKER = "****"


def is_masked_api_key(value: str) -> bool:
    """判断一个 api_key 是否为掩码占位符（应视为"不修改已保存的 Key"）。"""
    return _MASK_MARKER in (value or "")


# ============================================================
# Base URL 归一化
# ============================================================
# 为什么要归一化：OpenAI SDK 会在 base_url 后自行拼接 /chat/completions。
# 若用户把完整路径填进来（例如某网关的 https://host/v1/chat/completions），
# 实际请求就会变成 .../chat/completions/chat/completions → 必然 404。
# 实测踩过：用户填 https://opencode.ai/zen/go/v1/chat/completions 一直报 404，
# 根因就是这里。统一在入口剥掉尾部端点路径，让两种填法都能工作。
_BASE_URL_TAIL_RE = re.compile(
    r"/(?:chat/completions|completions|responses|messages|embeddings|models)/?$",
    re.IGNORECASE,
)


def normalize_base_url(url: str) -> str:
    """把用户填写的 base_url 归一化成 SDK 可用的根地址。

    处理三种常见填法（都归一到 ``.../v1``）::

        https://api.deepseek.com            -> https://api.deepseek.com
        https://host/v1/                    -> https://host/v1
        https://host/v1/chat/completions    -> https://host/v1

    也容忍结尾多斜杠、缺 ``/v1``（不强行补——不同网关的根路径约定不同，
    擅自补 ``/v1`` 反而会打错，见fallback 逻辑）。
    """
    u = (url or "").strip()
    if not u:
        return ""
    u = u.rstrip("/")
    prev = None
    while prev != u:                      # 反复剥离，容忍重复填写
        prev = u
        u = _BASE_URL_TAIL_RE.sub("", u).rstrip("/")
    return u


# 某些网关在 Cloudflare 后面，会对非浏览器 UA 直接返回 403（error code 1010）。
# 实测踩过：opencode.ai 不带浏览器 UA 时 models 列表与 chat 请求全部 403。
_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


def default_headers_for(base_url: str) -> dict:
    """按网关补齐必要的请求头。

    - 统一带浏览器 UA，规避 Cloudflare 类防护拦截（对官方 API 无副作用）
    - OpenCode Go 要求 ``x-opencode-session``，缺失会返回 400 MissingSessionID
    """
    headers = {"User-Agent": _BROWSER_UA}
    if "opencode.ai" in (base_url or "").lower():
        headers["x-opencode-session"] = uuid.uuid4().hex
    return headers


# ============================================================
class ApiConfigManager:
    """多 API 配置管理器 v4.0"""

    # ── 持久化 ──

    @staticmethod
    def _load_all() -> dict:
        """加载原始 JSON 数据"""
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {"configs": [], "active_id": ""}

    @staticmethod
    def _save_all(data: dict) -> bool:
        try:
            CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            return True
        except IOError:
            return False

    # ── 查询 ──

    @staticmethod
    def list_all() -> List[ApiConfig]:
        """列出所有配置"""
        data = ApiConfigManager._load_all()
        return [ApiConfig.from_dict(c) for c in data.get("configs", [])]

    @staticmethod
    def get_enabled() -> Optional[ApiConfig]:
        """获取当前启用的配置"""
        for cfg in ApiConfigManager.list_all():
            if cfg.enabled and cfg.api_key:
                return cfg
        return None

    @staticmethod
    def get_by_id(config_id: str) -> Optional[ApiConfig]:
        for cfg in ApiConfigManager.list_all():
            if cfg.id == config_id:
                return cfg
        return None

    # ── 增删改 ──

    @staticmethod
    def save(config: ApiConfig) -> bool:
        """创建或更新一个配置。无 id 则新建；有 id 则更新。"""
        data = ApiConfigManager._load_all()
        configs = data.get("configs", [])

        now = datetime.now().isoformat()
        config.updated_at = now

        if not config.id:
            config.id = str(uuid.uuid4())[:8]
            config.created_at = now

        # 查找并更新
        found = False
        for i, c in enumerate(configs):
            if c.get("id") == config.id:
                configs[i] = config.to_dict()
                found = True
                break

        if not found:
            configs.append(config.to_dict())

        # 如果启用当前配置，禁用其他
        if config.enabled:
            for c in configs:
                if c.get("id") != config.id:
                    c["enabled"] = False

        data["configs"] = configs
        return ApiConfigManager._save_all(data)

    @staticmethod
    def delete(config_id: str) -> bool:
        data = ApiConfigManager._load_all()
        before = len(data.get("configs", []))
        data["configs"] = [c for c in data.get("configs", []) if c.get("id") != config_id]
        if data.get("active_id") == config_id:
            data["active_id"] = ""
        return ApiConfigManager._save_all(data) if len(data["configs"]) != before else True

    @staticmethod
    def toggle(config_id: str) -> Optional[bool]:
        """切换指定配置的启用状态。返回新状态。"""
        cfg = ApiConfigManager.get_by_id(config_id)
        if cfg is None:
            return None
        cfg.enabled = not cfg.enabled
        ApiConfigManager.save(cfg)
        return cfg.enabled

    @staticmethod
    def _load_env_config() -> Optional[Dict[str, str]]:
        """从环境变量加载"""
        auth_token = ""
        for key in ("TRUSTOKEN_API_KEY", "ANTHROPIC_AUTH_TOKEN", "DEEPSEEK_API_KEY", "OPENAI_API_KEY"):
            val = os.environ.get(key, "").strip()
            if val: auth_token = val; break
        if not auth_token:
            return None
        base_url = ""
        for key in ("TRUSTOKEN_BASE_URL", "ANTHROPIC_BASE_URL", "DEEPSEEK_BASE_URL", "OPENAI_BASE_URL"):
            val = os.environ.get(key, "").strip()
            if val: base_url = val; break
        if base_url and "/anthropic" in base_url:
            base_url = base_url.replace("/anthropic", "/v1")
        elif not base_url:
            base_url = "https://api.deepseek.com/v1"
        # 环境变量同样可能被填成完整端点，统一归一化避免 404
        base_url = normalize_base_url(base_url)
        model = ""
        for key in ("TRUSTOKEN_MODEL", "ANTHROPIC_MODEL", "DEEPSEEK_MODEL", "OPENAI_MODEL"):
            val = os.environ.get(key, "").strip()
            if val: model = val; break
        return {"base_url": base_url, "api_key": auth_token,
                "model_name": model or "deepseek-v4-pro"}

    # ── 核心: 获取有效配置 ──

    @staticmethod
    def get_client_config() -> Optional[Dict[str, str]]:
        """
        1. 用户启用的自定义 API
        2. 环境变量
        """
        enabled = ApiConfigManager.get_enabled()
        if enabled:
            return {"base_url": enabled.base_url, "api_key": enabled.api_key,
                    "model_name": enabled.model_name}
        env = ApiConfigManager._load_env_config()
        if env:
            return env
        return None

    @staticmethod
    def get_effective_source() -> str:
        if ApiConfigManager.get_enabled():
            return "custom"
        if ApiConfigManager._load_env_config():
            return "environment"
        return "none"

    # ── 连通性测试 ──

    @staticmethod
    def test_connectivity(base_url: str, api_key: str, model_name: str) -> Dict[str, Any]:
        if not base_url or not api_key or not model_name:
            return {"success": False, "message": "请填写完整的配置信息"}
        # 归一化：用户可能把完整端点路径填进 Base URL，
        # 而 SDK 会再拼一次 /chat/completions，导致 404。
        base_url = normalize_base_url(base_url)
        if not base_url:
            return {"success": False, "message": "Base URL 无效"}
        try:
            from openai import OpenAI
        except ImportError:
            return {"success": False, "message": "未安装 openai 库"}
        try:
            client = OpenAI(
                base_url=base_url,
                api_key=api_key,
                timeout=15.0,
                default_headers=default_headers_for(base_url),
            )
            resp = client.chat.completions.create(
                model=model_name,
                messages=[{"role": "user", "content": "hi"}],
                max_tokens=5,
            )
            reply = resp.choices[0].message.content if resp.choices else ""
            return {"success": True, "message": f"连接成功！回复: {reply[:50] if reply else '(空)'}"}
        except Exception as e:
            msg = str(e)
            if "401" in msg: return {"success": False, "message": "认证失败 (401): API Key 无效"}
            if "404" in msg: return {"success": False, "message": f"端点未找到 (404): {base_url}（请确认该网关的 Base URL 与模型名）"}
            if "403" in msg: return {"success": False, "message": f"访问被拒 (403): {base_url}（部分网关会拦截非浏览器 UA）"}
            if "429" in msg: return {"success": False, "message": "请求超限 (429)"}
            if "timeout" in msg.lower(): return {"success": False, "message": "连接超时"}
            return {"success": False, "message": f"失败: {msg[:200]}"}

    # ── Ollama 探测 ──

    @staticmethod
    def detect_ollama_models(base_url: str = "http://127.0.0.1:11434") -> List[Dict[str, str]]:
        try:
            import urllib.request
            req = urllib.request.Request(f"{base_url.rstrip('/')}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode())
                    return [{"name": m.get("name", "?"), "size": f"{m.get('size',0)/1e9:.1f}GB"}
                            for m in data.get("models", [])]
        except Exception:
            pass
        return []
