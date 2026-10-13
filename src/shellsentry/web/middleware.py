#!/usr/bin/env python3
"""
ShellSentry-AI 中间件模块 v1.0
==============================
请求体大小限制 + 审计期间配置变更守卫 + 前端资源禁用缓存。
"""
from fastapi import HTTPException, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse


class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    """拒绝超过上限的请求体（防 OOM）"""

    def __init__(self, app, max_size: int):
        super().__init__(app)
        self.max_size = max_size

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                cl = int(content_length)
                if cl > self.max_size:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "success": False,
                            "detail": (
                                f"请求体过大 ({cl} bytes)，"
                                f"上限为 {self.max_size} bytes (~50MB)"
                            ),
                        },
                    )
            except ValueError:
                pass
        return await call_next(request)


class NoStoreFrontendMiddleware(BaseHTTPMiddleware):
    """前端资源（页面与 /static）禁用浏览器缓存。

    本地工具的前端脚本与后端源码同目录加载，一旦浏览器把旧版 JS 缓存在内存里，
    缺陷修复在用户侧就"看起来没生效"（典型：行号栏被旧逻辑覆盖的缺陷反复出现）。
    no-store 让每次加载都回源，成本是本地几毫秒，收益是修复即时可见。

    仅作用于 `/` 与 `/static/*`，不影响 /api/* 与 SSE 流式响应。
    """

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        path = request.url.path
        if path == "/" or path.startswith("/static/"):
            response.headers["cache-control"] = "no-store, must-revalidate"
            response.headers["pragma"] = "no-cache"
        return response


def guard_config_mutation(task_state_manager):
    """如果当前有活跃审计任务，拒绝配置变更。"""
    if task_state_manager.is_locked():
        active = task_state_manager.get_active()
        raise HTTPException(
            status_code=423,
            detail=(
                f"🔒 审计任务进行中 (task: {active.task_id})，"
                f"已运行 {active.elapsed:.0f}s / {active.timeout_seconds}s，"
                f"请等待审计完成或超时熔断后再修改配置"
            ),
        )
