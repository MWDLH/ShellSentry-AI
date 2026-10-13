#!/usr/bin/env python3
"""模型能力自检 —— 换模型/换网关后先跑这个，避免再次踩「推理模型 max_tokens 陷阱」。

背景（2026-09-19 事故）：
  deepseek-v4-pro 这类推理模型的思维链 `reasoning_content` **计入 max_tokens**。
  审计任务的思维链实测约需 9,500 token，当时下发的 max_tokens=8192 在思维链阶段
  就被耗尽，正文一个 token 都没写出来 → UI 四个面板全空，且 finish_reason=length
  被上报成"报告被截断"，用户误以为是"没检测到问题"。

本脚本做的事：
  1. 用当前配置（config.json 里 enabled 的那条）发一次极小的真实请求；
  2. 打印 finish_reason、思维链长度、正文长度、usage 里的 reasoning_tokens / text_tokens；
  3. 据此判断该模型是否为推理模型，并给出「可否下发 max_tokens」的结论。

用法：
    ./.venv/Scripts/python.exe tools/check_model_capability.py

注意：会产生一次极小的真实 API 调用（几十个 token）。不打印 API Key。
"""
import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from openai import AsyncOpenAI  # noqa: E402

from shellsentry import paths  # noqa: E402

MSGS = [
    {"role": "system", "content": "你是安全审计助手。只回答一句话。"},
    {"role": "user", "content": "用一句话说明 php://input 是什么。"},
]


async def probe(client: AsyncOpenAI, model: str, label: str, **kwargs):
    print("=" * 68)
    print(f"[{label}] 下发参数: {kwargs or '（无采样参数）'}")
    try:
        stream = await client.chat.completions.create(
            model=model, messages=MSGS, stream=True, **kwargs
        )
        content, reasoning, finish, usage = [], [], None, None
        async for ch in stream:
            if getattr(ch, "usage", None):
                usage = ch.usage.model_dump()
            if not ch.choices:
                continue
            c0 = ch.choices[0]
            if getattr(c0, "finish_reason", None):
                finish = c0.finish_reason
            d = c0.delta
            if d is None:
                continue
            if getattr(d, "content", None):
                content.append(d.content)
            if getattr(d, "reasoning_content", None):
                reasoning.append(d.reasoning_content)
        c, r = "".join(content), "".join(reasoning)
        detail = (usage or {}).get("completion_tokens_details") or {}
        print(f"  finish_reason={finish}")
        print(f"  思维链 {len(r)} 字符 | 正文 {len(c)} 字符")
        if usage:
            print(f"  usage: completion={usage.get('completion_tokens')} "
                  f"reasoning_tokens={detail.get('reasoning_tokens')} "
                  f"text_tokens={detail.get('text_tokens')}")
        if not c:
            print("  !! 正文为空 —— 该参数组合在此模型上不可用")
        return {"finish": finish, "reasoning_chars": len(r), "content_chars": len(c),
                "has_reasoning": bool(r)}
    except Exception as e:
        print(f"  !! 异常 {type(e).__name__}: {str(e)[:300]}")
        return None


async def main():
    cfg_path = paths.config_file()
    cfg = json.load(open(cfg_path, encoding="utf-8"))
    enabled = [c for c in cfg.get("configs", []) if c.get("enabled")]
    if not enabled:
        print(f"未找到启用的 API 配置（{cfg_path}），请先在 UI 里配置并启用。")
        return
    entry = enabled[0]
    print(f"配置: {entry.get('name')} | 网关 {entry.get('base_url')} | 模型 {entry.get('model_name')}")
    print()

    client = AsyncOpenAI(base_url=entry["base_url"], api_key=entry["api_key"], timeout=120.0)
    model = entry["model_name"]

    base = await probe(client, model, "基准：不下发采样参数")
    if base is None:
        print("\n基准请求失败，无法继续判断。")
        return

    print()
    if base["has_reasoning"]:
        print(">>> 判定：**推理模型**（返回了 reasoning_content 思维链）")
        print("    结论：不要下发 max_tokens —— 思维链计入该额度，固定上限可能被它吃光，")
        print("          导致正文为空、四个面板全空且不报错。")
        with_limit = await probe(client, model, "危险验证：下发 max_tokens=512", max_tokens=512)
        if with_limit and with_limit["content_chars"] == 0:
            print("\n    ↑ 已复现：小额度被思维链吃光，正文为空。")
    else:
        print(">>> 判定：**非推理模型**（无思维链）")
        print("    结论：可按需下发 max_tokens；默认仍不下发，保持与其他模型一致的行为。")


if __name__ == "__main__":
    asyncio.run(main())
