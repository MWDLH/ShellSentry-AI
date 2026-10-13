#!/usr/bin/env python3
"""
ShellSentry-AI Server v1.0 — 恶意代码语义审计沙箱
==============================================================
架构：FastAPI + uvicorn（对齐 BidGuard-AI 家族架构）
前端：纯 HTML/JS 单页应用（index.html）
后端占位：所有 AI 检测、正则扫描、联网查询均预留清晰接口
继承自 BidGuard-AI 的家族设计：
  - 亮色专业商务主题 (Light Mode)
  - 侧边栏 API 配置中心（Base URL / API Key / Model Name）
  - 任务管理与历史记录
  - 状态机锁死逻辑
"""
import asyncio
import base64
import hashlib
import json
import os
import re
import threading
import uuid
import socket
import webbrowser
from pathlib import Path
from typing import Optional
import uvicorn
from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

# ShellSentry-AI 内部模块
from ..config import ApiConfigManager, ApiConfig, is_masked_api_key
from ..core.ai_client import SemanticEngine
from ..core.artifact_router import route_bytes, route_text
from ..core.behavior_analyzer import enrich_regex_scan
from ..core.decoder import decode_code
from ..core.input_handler import InputHandler, MAX_FILE_SIZE, pre_format_malware_code
from ..core.regex_scanner import RegexScanner
from ..paths import history_dir
from .task_state import task_state_manager

# ============================================================
# 配置
# ============================================================
BASE_DIR = Path(__file__).parent
app = FastAPI(title="ShellSentry-AI", version="1.0")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

# 请求体上限：50MB 文件 + multipart/form-data 开销 ≈ 55MB
_MAX_REQUEST_BODY = MAX_FILE_SIZE + (5 * 1024 * 1024)

# ── CORS ──
# 本工具是「本地优先」设计：服务只绑定 127.0.0.1，前端所有请求都是相对路径
# （/api/...），资源全部本地打包，无任何 CDN 或跨源调用。
# 因此**不需要**放开跨源。此前写的是 allow_origins=["*"] + allow_credentials=True
# ——该组合本身矛盾（浏览器会拒绝），且一旦有人把host 改成 0.0.0.0 暴露到
# 局域网，任意网站都能跨源调用本机 API（读取审计历史、写入配置）。
# 现改为：仅允许本机来源，且不带凭据。
_ALLOWED_ORIGINS = [
    "http://127.0.0.1",
    "http://localhost",
    "http://[::1]",
]
app.add_middleware(
    CORSMiddleware,
    # 端口在运行时才确定（_select_port 会避开占用端口），
    # 故按「前缀匹配」放行本机任意端口；正则形式不会误伤其它主机。
    allow_origin_regex=r"^https?://(127\.0\.0\.1|localhost|\[::1\])(:\d+)?$",
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type"],
)


# ── 请求体大小限制中间件 ──
from .middleware import MaxBodySizeMiddleware, NoStoreFrontendMiddleware

app.add_middleware(MaxBodySizeMiddleware, max_size=_MAX_REQUEST_BODY)

# ── 前端资源禁用缓存：保证修复后的 JS/CSS 立即生效 ──
app.add_middleware(NoStoreFrontendMiddleware)

# ============================================================
# 历史记录管理
# ============================================================
HISTORY_DIR = history_dir()

def ensure_history_dir():
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)

def _strip_code_content(report):
    """
    持久化前剔除样本源码，避免恶意代码落盘。

    兑现 input_handler / server 文档中"严禁木马文件落盘"的安全承诺：
    历史记录只保留研判报告与元数据，不含被分析的原始代码。
    """
    if not isinstance(report, dict):
        return report
    safe = dict(report)
    safe.pop("code_content", None)
    safe.pop("code_content_b64", None)
    # 兼容旧格式：report 内可能嵌套一份 AI 研判 dict
    if isinstance(safe.get("report"), dict):
        inner = dict(safe["report"])
        inner.pop("code_content", None)
        inner.pop("code_content_b64", None)
        safe["report"] = inner
    return safe

def save_history(task_id: str, filename: str, report: dict):
    """保存审计历史记录 — 仅持久化研判报告与元数据，样本源码不落盘。"""
    ensure_history_dir()
    record = {
        "task_id": task_id,
        "filename": filename,
        "report": _strip_code_content(report),
        "timestamp": __import__("datetime").datetime.now().isoformat(),
    }
    filepath = HISTORY_DIR / f"{task_id}.json"
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(record, f, ensure_ascii=False, indent=2)

_TASK_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}")

def _history_filepath(task_id: str) -> Path:
    """把 task_id 解析为历史记录文件路径；非法 id（含目录穿越字符）直接拒绝。

    合法 id 由服务端生成（uuid 片段），因此限定为 [A-Za-z0-9_-]。
    此前 GET/DELETE 直接拼接 task_id 形成路径，``..%5Cconfig`` 之类可越权
    读取/删除数据目录外的文件（实测能读到明文 API Key）。
    """
    if not _TASK_ID_RE.fullmatch(task_id or ""):
        raise HTTPException(status_code=400, detail="任务 ID 无效")
    return HISTORY_DIR / f"{task_id}.json"

def load_history(task_id: str) -> Optional[dict]:
    """加载单个历史记录 — 自动解码 Base64 混淆的代码内容"""
    filepath = _history_filepath(task_id)
    if filepath.exists():
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
        # 解码 Base64
        if "code_content_b64" in data and "code_content" not in data:
            try:
                data["code_content"] = base64.b64decode(
                    data.pop("code_content_b64")
                ).decode("utf-8")
            except Exception:
                data["code_content"] = ""
        return data
    return None

def list_all_history() -> list:
    """列出所有历史记录"""
    ensure_history_dir()
    results = []
    for filepath in sorted(HISTORY_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            # 兼容旧格式（明文 code_content）和新格式（Base64 code_content_b64）
            if "code_content_b64" in data:
                data.pop("code_content_b64", None)  # 列表不需要完整代码
            ts = data.get("timestamp", "")
            # 兜底：如果存的是UUID格式，改用文件修改时间
            if not ts or len(ts) < 10 or "-" not in ts[:4]:
                import datetime as _dt
                ts = _dt.datetime.fromtimestamp(filepath.stat().st_mtime).isoformat()
            results.append({
                "task_id": data.get("task_id"),
                "filename": data.get("filename"),
                "display_name": data.get("display_name") or data.get("filename"),
                "timestamp": ts,
            })
        except Exception:
            continue
    return results

def clear_history():
    """清除所有历史记录"""
    ensure_history_dir()
    for filepath in HISTORY_DIR.glob("*.json"):
        filepath.unlink()

# ============================================================
# API 路由
# ============================================================

# 前端资源指纹：任一文件改动即产生新的 build 号，入口脚本 URL 随之变化，
# 浏览器无法再使用旧副本。与 NoStoreFrontendMiddleware 配合（后者负责
# /static/* 子资源），形成"改了就一定生效"的双保险。
#
# 覆盖范围用目录遍历而非硬编码清单：早期版本的清单里漏掉了 app.css，
# 结果改样式后 build 号不变、刷新也不一定生效，排查成本极高。
# 现在静态目录下任何文件新增/改动/删除都必然改变指纹。
_STATIC_ROOT = BASE_DIR / "static"


def frontend_build_tag(static_root: Optional[Path] = None) -> str:
    """静态资源整体指纹（size + mtime_ns 哈希），12 位十六进制短标识。"""
    root = Path(static_root) if static_root is not None else _STATIC_ROOT
    digest = hashlib.sha256()
    for path in sorted((p for p in root.rglob("*") if p.is_file()), key=lambda p: p.as_posix()):
        rel = path.relative_to(root).as_posix()
        try:
            stat = path.stat()
            digest.update(f"{rel}:{stat.st_size}:{stat.st_mtime_ns}".encode("utf-8"))
        except OSError:
            # 文件在遍历期间消失等竞态：至少把路径计入，保证结果稳定可复现。
            digest.update(rel.encode("utf-8"))
    return digest.hexdigest()[:12]


# HTML 里形如 href="/static/styles/app.css" 或 src="/static/scripts/app.js" 的引用
_STATIC_REF = re.compile(r'(["\'])(/static/)([^"\']+)\1')


def _cache_bust_html(html: str, build: str) -> str:
    """给页面内所有 /static/ 引用追加 ?v=<build>。

    早期只给 app.js 追加，漏掉的 app.css 在个别浏览器里仍是"改了不生效"的来源。
    幂等：若引用已带查询串则先剥掉，重复调用不会叠加出 ?v=a?v=b。
    """

    def replace(match: "re.Match[str]") -> str:
        quote, prefix, path = match.group(1), match.group(2), match.group(3)
        clean = path.split("?", 1)[0].split("#", 1)[0]
        if not clean:
            return match.group(0)
        return f"{quote}{prefix}{clean}?v={build}{quote}"

    return _STATIC_REF.sub(replace, html)


def render_index(build: Optional[str] = None) -> str:
    """读取 index.html，注入版本参数与构建指纹 meta。

    单独抽出来便于测试直接断言产物，而不必起 HTTP 服务。
    """
    html_path = _STATIC_ROOT / "index.html"
    with open(html_path, "r", encoding="utf-8") as f:
        html = f.read()
    tag = build or frontend_build_tag()
    html = _cache_bust_html(html, tag)
    if "</head>" in html:
        html = html.replace(
            "</head>",
            f'<meta name="shellsentry-frontend-build" content="{tag}"></head>',
            1,
        )
    return html


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    """服务前端页面（注入构建指纹，杜绝旧脚本驻留浏览器）"""
    return render_index()


@app.post("/api/audit/stream")
async def audit_code_stream(
    file: UploadFile = File(None),
    code_text: str = Form(""),
):
    """
    🚀 AI 深度语义审计流式接口 (SSE)

    与 /api/audit 相同的输入处理流水线，但返回 SSE 事件流：
      - event: init      → 任务初始化 (task_id, 文件信息, 正则摘要)
      - event: progress  → 审计进度通知
      - event: tag_switch → 切换到新面板标签 (IMAGE/DE_OBFUSCATE/THREAT/PLAYBOOK)
      - event: chunk     → 流式文本追加到当前面板
      - event: tag_done  → 当前面板完成
      - event: done      → 审计完成
      - event: error     → 异常错误

    前端通过 fetch + ReadableStream 解析 SSE 事件，实时渲染到四段面板。
    """
    import datetime as dt_mod

    task_id = str(uuid.uuid4())[:8]

    # ══════════════════════════════════════════════════════════
    # 第一阶段：输入处理（复用 InputHandler）
    # ══════════════════════════════════════════════════════════
    input_result = None

    if file and file.filename:
        try:
            file_bytes = await file.read()
            await file.close()
            artifact_profile = route_bytes(file.filename, file_bytes)
            if not artifact_profile.supported:
                raise HTTPException(status_code=415, detail=artifact_profile.reason)
            input_result = InputHandler.process_upload(file.filename, file_bytes)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"文件读取失败: {str(e)}")
    elif code_text.strip():
        input_result = InputHandler.process_paste(code_text)
    else:
        raise HTTPException(status_code=400, detail="请上传文件或粘贴代码")

    if not input_result.success:
        raise HTTPException(status_code=400, detail="; ".join(input_result.errors))

    # ── 恶意代码预处理分行（按扩展名判定语言，避免跨语言破坏）──
    clean_code_stream = pre_format_malware_code(
        input_result.code_content, filename=input_result.filename
    )

    # ══════════════════════════════════════════════════════════
    # 第二阶段：正则初筛
    # ══════════════════════════════════════════════════════════
    artifact_profile = route_text(input_result.filename, clean_code_stream)
    regex_result = RegexScanner.scan_to_dict(
        clean_code_stream,
        filename=input_result.filename,
    )
    regex_result, behavior_findings, deterministic_assessment = enrich_regex_scan(
        clean_code_stream, artifact_profile, regex_result
    )

    # ── 程序化纯解码层（零执行）：对硬编码荷载做确定性还原，
    #    作为 [DE_OBFUSCATE] 反混淆的 ground truth 注入 LLM 提示词。
    #    良性代码返回空串，不注入；全程标准算法解码，绝不执行样本代码。
    #    P3-2：一次性计算解码报告，复用其置信度（high/medium/low）供后端确定性置信度使用。
    _dec_report = decode_code(clean_code_stream)
    decode_ctx = _dec_report.to_prompt_context()
    decode_conf = _dec_report.confidence

    # ══════════════════════════════════════════════════════════
    # 第三阶段：加载 API 配置
    # ══════════════════════════════════════════════════════════
    api_config = ApiConfigManager.get_client_config()

    # ══════════════════════════════════════════════════════════
    # 封装 SSE 流生成器（含状态锁定闭环 + 原始输出收集）
    # ══════════════════════════════════════════════════════════
    async def sse_event_stream():
        raw_ai_output = ""   # 收集带伪标签的原始 AI 输出（供历史回放）
        final_verdict = None
        final_status = None
        # P2-4：并发审计不再互相抢占（抢占会让先发任务拿到后发任务的
        # API 配置）。未获得锁时直接提示，不进入审计流程也不解锁。
        if task_state_manager.lock(task_id, api_config) is None:
            active = task_state_manager.get_active_dict()
            remain = int(active.get("remaining_seconds", 0)) if active else 0
            yield SemanticEngine._format_sse("error", {
                "message": (
                    f"已有审计任务正在运行（剩余约 {remain} 秒），"
                    "请等待其完成后再发起新的审计"
                ),
            })
            return

        try:
            engine = SemanticEngine(api_config)
            async for sse_msg in engine.audit_stream(
                code=clean_code_stream,
                filename=input_result.filename,
                regex_scan=regex_result,
                decode_ctx=decode_ctx,
                decode_confidence=decode_conf,
            ):
                # 收集模型报告与最终判定，供无源码历史回放。
                try:
                    import json as _json
                    event_name = ""
                    event_data = None
                    for line in sse_msg.split("\n"):
                        if line.startswith("event: "):
                            event_name = line[7:].strip()
                        elif line.startswith("data: "):
                            event_data = _json.loads(line[6:])
                    if event_name == "stream" and event_data and event_data.get("text"):
                        raw_ai_output += event_data["text"]
                    elif event_name == "verdict":
                        final_verdict = event_data
                    elif event_name == "done":
                        final_status = event_data
                except Exception:
                    pass
                yield sse_msg

            # 保存历史（仅报告+元数据，不含样本源码，兑现"不落盘"承诺）
            save_history(
                task_id,
                input_result.filename,
                {
                    "task_id": task_id,
                    "filename": input_result.filename,
                    "input": {
                        "filename": input_result.filename,
                        "source_type": input_result.source_type,
                        "encoding_used": input_result.encoding_used,
                    },
                    "regex_scan": regex_result,
                    "raw_ai_output": raw_ai_output,
                    "agent_verdict": final_verdict,
                    "done": final_status,
                    "decode_confidence": decode_conf,
                    "source": "stream",
                    "timestamp": dt_mod.datetime.now().isoformat(),
                },
            )
        except Exception as e:
            yield SemanticEngine._format_sse("error", {
                "message": f"审计流异常: {str(e)}",
            })
        finally:
            task_state_manager.unlock(task_id)

    return StreamingResponse(
        sse_event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # 禁用 Nginx 缓冲
        },
    )


@app.get("/api/history")
async def get_history():
    """获取历史记录列表"""
    return JSONResponse(list_all_history())

@app.get("/api/history/{task_id}")
async def get_history_detail(task_id: str):
    """获取单个历史记录详情"""
    history = load_history(task_id)
    if not history:
        raise HTTPException(status_code=404, detail="未找到该审计记录")
    return JSONResponse(history)

@app.post("/api/clear-history")
async def clear_all_history():
    """清除所有历史记录"""
    clear_history()
    return JSONResponse({"success": True, "message": "历史记录已清除"})

@app.delete("/api/history/{task_id}")
async def delete_history(task_id: str):
    """删除单个历史任务"""
    filepath = _history_filepath(task_id)
    if not filepath.exists():
        raise HTTPException(status_code=404, detail="未找到该审计记录")
    filepath.unlink()
    return JSONResponse({"success": True, "message": "已删除"})

@app.patch("/api/history/{task_id}")
async def rename_history(task_id: str, request: Request):
    """Rename the local display label without changing the source filename or task id."""
    filepath = _history_filepath(task_id)
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="请求体必须是合法 JSON")
    name = str(payload.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="任务名称不能为空")
    if len(name) > 80 or any(ord(char) < 32 for char in name):
        raise HTTPException(status_code=400, detail="任务名称最多 80 个字符且不能包含控制字符")
    if not filepath.is_file():
        raise HTTPException(status_code=404, detail="未找到该审计记录")
    try:
        with open(filepath, "r", encoding="utf-8") as handle:
            record = json.load(handle)
        record["display_name"] = name
        temp_path = filepath.with_suffix(".json.tmp")
        with open(temp_path, "w", encoding="utf-8") as handle:
            json.dump(record, handle, ensure_ascii=False, indent=2)
        os.replace(temp_path, filepath)
    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(status_code=500, detail=f"重命名失败: {error}")
    return JSONResponse({"success": True, "display_name": name})

@app.get("/api/check")
async def health_check():
    """健康检查 + API 诊断"""
    client_cfg = ApiConfigManager.get_client_config()
    source = ApiConfigManager.get_effective_source()

    return JSONResponse({
        "status": "ok",
        "version": "1.0",
        "diagnostics": {
            "api_source": source,
            "effective_model": client_cfg["model_name"] if client_cfg else None,
        },
    })


@app.get("/api/ollama/models")
async def detect_ollama_models(base_url: str = "http://127.0.0.1:11434"):
    """
    探测本地 Ollama 实例的可用模型列表。

    Query params:
        base_url: Ollama 服务地址，默认 http://127.0.0.1:11434

    Returns:
        {"success": true, "models": [{"name": "...", "size": "..."}]}
    """
    models = ApiConfigManager.detect_ollama_models(base_url)
    return JSONResponse({
        "success": True,
        "base_url": base_url,
        "models": models,
        "count": len(models),
    })


@app.get("/api/task/active")
async def get_active_task():
    """
    获取当前活跃审计任务状态。

    Returns:
        null                       - 无活跃任务
        {task_id, status, ...}     - 活跃任务详情（含超时倒计时）
    """
    active = task_state_manager.get_active_dict()
    return JSONResponse({"active": active})


@app.post("/api/task/cancel")
async def cancel_active_task():
    """取消当前活跃审计任务：强制释放任务锁。

    前端点「取消任务」时会中断 SSE 连接，服务端生成器的 finally 本就会解锁；
    这里是兜底——万一连接断开未被及时察觉，也不会把后续任务卡在 423 上。
    注意：本端点在"有任务运行"时也必须可用，因此**不**走 _guard_config_mutation。
    """
    active = task_state_manager.get_active()
    if active is None:
        return JSONResponse({"success": True, "cancelled": False, "message": "当前没有正在运行的审计任务"})
    task_state_manager.unlock(active.task_id)
    return JSONResponse({"success": True, "cancelled": True, "task_id": active.task_id})


# ============================================================
# 配置守卫依赖
# ============================================================

from .middleware import guard_config_mutation

def _guard_config_mutation():
    guard_config_mutation(task_state_manager)

# ============================================================
# API 配置管理路由（继承 BidGuard-AI）
# ============================================================

@app.get("/api/config/llm")
async def get_llm_config():
    """获取所有 API 配置 + 当前生效源"""
    try:
        configs = ApiConfigManager.list_all()
        effective = ApiConfigManager.get_client_config()
        source = ApiConfigManager.get_effective_source()

        return JSONResponse({
            "success": True,
            "configs": [c.to_safe_dict() for c in configs],
            "effective_api_source": source,
            "effective_model": effective["model_name"] if effective else None,
        })
    except Exception as e:
        return JSONResponse({"success": False, "detail": str(e)})

@app.post("/api/config/llm")
async def save_llm_config(request: Request):
    """创建或更新 API 配置"""
    _guard_config_mutation()
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="请求体必须是合法 JSON")

    config_id = (data.get("id") or "").strip()
    name = (data.get("name") or "").strip()
    base_url = (data.get("base_url") or "").strip()
    api_key = (data.get("api_key") or "").strip()
    model_name = (data.get("model_name") or "").strip()

    if not base_url or not model_name:
        raise HTTPException(status_code=400, detail="Base URL 和 Model Name 均为必填项")

    # 掩码 Key 回退：前端编辑已有配置时不回填真实 Key（掩码回填会被当成新 Key
    # 覆盖真实值）。因此这里把"空 key"或"**** 掩码"都视为沿用已保存的 Key。
    if config_id and (not api_key or is_masked_api_key(api_key)):
        existing = ApiConfigManager.get_by_id(config_id)
        if existing and existing.api_key:
            api_key = existing.api_key
    # 仍为空或仍是掩码：无可沿用的真实 Key（新建未填，或原配置已不存在）
    if not api_key or is_masked_api_key(api_key):
        raise HTTPException(status_code=400, detail="API Key 为必填项")

    if config_id:
        existing = ApiConfigManager.get_by_id(config_id)
        if existing:
            existing.name = name or existing.name
            existing.base_url = base_url
            existing.api_key = api_key
            existing.model_name = model_name
            existing.enabled = True
            ApiConfigManager.save(existing)
            return JSONResponse({"success": True, "message": "配置已更新",
                                 "config": existing.to_safe_dict()})

    # 新建
    cfg = ApiConfig.create_new(name=name or model_name, base_url=base_url,
                                api_key=api_key, model_name=model_name)
    cfg.enabled = True
    ApiConfigManager.save(cfg)
    return JSONResponse({"success": True, "message": "配置已创建",
                         "config": cfg.to_safe_dict()})

@app.post("/api/config/llm/test")
async def test_llm_connectivity(request: Request):
    """测试 API 连通性"""
    _guard_config_mutation()
    try:
            data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="请求体必须是合法 JSON")
    
    config_id = (data.get("id") or "").strip()
    base_url = (data.get("base_url") or "").strip()
    api_key = (data.get("api_key") or "").strip()
    model_name = (data.get("model_name") or "").strip()

    if not base_url or not model_name:
        raise HTTPException(status_code=400, detail="Base URL 和 Model Name 均为必填项")

    # 编辑已有配置时前端不回填真实 Key：空/掩码时用已保存的 Key 测试连通性。
    if config_id and (not api_key or is_masked_api_key(api_key)):
        existing = ApiConfigManager.get_by_id(config_id)
        if existing and existing.api_key:
            api_key = existing.api_key

    if not api_key or is_masked_api_key(api_key):
        raise HTTPException(status_code=400, detail="API Key 为必填项")

    result = ApiConfigManager.test_connectivity(base_url, api_key, model_name)
    return JSONResponse(result)

@app.post("/api/config/llm/toggle")
async def toggle_llm_config(request: Request):
    """切换指定 API 配置的启用/停用状态"""
    _guard_config_mutation()
    try:
        data = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="请求体必须是合法 JSON")
    config_id = (data.get("id") or "").strip()
    if not config_id:
        raise HTTPException(status_code=400, detail="缺少配置 ID")
    new_state = ApiConfigManager.toggle(config_id)
    if new_state is None:
        raise HTTPException(status_code=404, detail="配置不存在")
    return JSONResponse({
        "success": True,
        "id": config_id,
        "enabled": new_state,
        "message": f"API 已{'启用' if new_state else '停用'}",
    })


@app.delete("/api/config/llm/{config_id}")
async def delete_llm_config(config_id: str):
    """删除指定 API 配置"""
    _guard_config_mutation()
    ApiConfigManager.delete(config_id)
    return JSONResponse({"success": True, "message": "配置已删除"})

# ============================================================
# 启动
# ============================================================

def _select_port(preferred: int) -> int:
    """Use the preferred local port when available, otherwise let the OS choose."""
    if preferred == 0:
        return 0
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind(("127.0.0.1", preferred))
    except OSError:
        return 0
    finally:
        probe.close()
    return preferred


async def main(port: int = 8765, open_browser: bool = True):
    config = uvicorn.Config(app, host="127.0.0.1", port=_select_port(port))
    server = uvicorn.Server(config)
    
    original_startup = server.startup
    
    async def patched_startup(sockets: list[socket.socket] | None = None):
        await original_startup(sockets)
        for s in server.servers:
            for sock in s.sockets:
                actual_port = sock.getsockname()[1]
                url = f"http://127.0.0.1:{actual_port}"
                print(json.dumps({"type": "http_start", "port": actual_port, "url": url}), flush=True)
                if open_browser:
                    threading.Thread(target=webbrowser.open, args=(url,), daemon=True).start()
                return
    
    server.startup = patched_startup
    await server.serve()

if __name__ == "__main__":
    asyncio.run(main())
