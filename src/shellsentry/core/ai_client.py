#!/usr/bin/env python3
"""
ShellSentry-AI 语义审计引擎 v1.0
===============================
异步滑动窗口切片 + 并发 LLM 调用 + SSE 流式输出。

架构：
  - ChunkingPipeline: 自适应滑动窗口切片（15-20% 重叠）
  - AIClient:          OpenAI 兼容客户端封装（默认 + 自定义 API 切换）
  - SemanticEngine:    审计编排器（小文件单包 / 大文件分片聚合）

性能优化：
  - 小文件 (< 15KB): 禁止切片，单次全量推送
  - 大文件 (>=15KB): 按函数块切割，Semaphore(10) 并发分析
  - 上下文重叠: 每个 Chunk 保留前一个 Chunk 结尾 100-150 字
"""
import asyncio
import json
import time
import logging
from typing import Optional, Dict, Any, List, AsyncGenerator, Tuple, NamedTuple
from openai import AsyncOpenAI
from .agent_review import REVIEW_SYSTEM_PROMPT, build_review_prompt, parse_agent_verdict
from .models import DeterministicVerdict, fuse_verdicts
from .prompts import SMALL_FILE_THRESHOLD  # 单一真相源：与 CODE_DISPLAY_BUDGET 必须保持对齐
from .prompts import extract_malware_family  # 从 [IMAGE] 段回填木马家族名
from .regex_scanner import compute_audit_confidence, derive_risk_level

logger = logging.getLogger("shellsentry.ai_client")

# ============================================================
# 配置常量
# ============================================================
# SMALL_FILE_THRESHOLD 定义在 prompts.py（与 CODE_DISPLAY_BUDGET 同源，
# 保证"判定为小文件"与"实际能全量展示"不会再次漂移）
CHUNK_TARGET_MIN = 900              # 目标最小 Chunk 字符数
# 目标最大 Chunk 字符数：1600 → 3200（2026-10-08 性能优化）
#
# 为什么改：实测大文件 token 构成为 输入:输出 = 87:1，输入侧占绝对大头，
# 而输入的大头是 SYSTEM_PROMPT 被逐片重复发送（32 片时占输入 70.9%）。
# 因此降低**分片数量**是唯一有效的杠杆，与输出侧怎么写无关。
# 实测 single_line_huge（46452 字符）：32 片 → 16 片，输入 token -42%，
# 串行批次 4 → 2（MAX_CONCURRENT=10），耗时约减半。
#
# 为什么不是 4000+：收益递减（12 片仅再省 11%），且单片过大会让模型
# 分析粒度变粗，跨函数控制流更容易漏判。3200 对当前模型仍是很轻的上下文。
CHUNK_TARGET_MAX = 3200             # 目标最大 Chunk 字符数
OVERLAP_MIN = 100                   # 最小重叠字符数
OVERLAP_MAX = 150                   # 最大重叠字符数
MAX_CONCURRENT = 10                 # asyncio.Semaphore 并发上限
LLM_TIMEOUT = 120                   # 单次 LLM 调用超时（秒）
LLM_MODEL_FALLBACK = "gpt-4o"      # 默认模型
DEFAULT_BASE_URL = "https://api.openai.com/v1"

# ── 采样参数（此前完全未设置，实际吃各家模型的默认 temperature≈1.0）──
# 主分析：低随机性。审计报告是结构化伪标签输出，同一份代码两次跑出不同结论
#   会让"复核"失去参照物，也让用户无法复现结论。0.2 保留必要的语义发散，
#   同时显著收敛措辞漂移与编造概率。
LLM_TEMPERATURE_MAIN = 0.2
# 反向复核：完全确定性。复核的任务是"证伪/证实"，需要稳定的判定边界，
#   随机性只会带来复核结论抖动（同一份报告两次复核给出不同 verdict）。
LLM_TEMPERATURE_REVIEW = 0.0
# 输出上限：**默认不下发**（None = 省略该键，交给网关按模型自身额度处理）。
#
# ⚠️ 严重回归教训（2026-09-19）：此前设为 8192，导致推理模型全量失效。
#    对 deepseek-v4-pro 这类推理模型，思维链 reasoning_content **计入 max_tokens**。
#    实测同一份真实 prompt：
#        下发 max_tokens=8192  → finish_reason=length，reasoning_tokens=8192，
#                                text_tokens=None，正文 content **0 字符**
#        不下发                → finish_reason=stop，completion_tokens=10945
#                                （思维链 9516 + 正文 3151），报告完整
#    即：审计任务的思维链约需 9500 token，8192 的额度在思维链阶段就被耗尽，
#    模型来不及写正文 → 四个面板全空且不报错。**推理模型的思维链长度不可控，
#    任何固定上限都可能被思维链吃光，因此不能对该类模型下发 max_tokens。**
#
#    保留此常量作为可选开关：仅当确认目标模型为非推理模型、且需要硬性限制输出
#    长度时才显式设值。截断感知能力不依赖它——finish_reason="length" 的检测与
#    空输出兜底始终生效（见 audit_stream）。
LLM_MAX_TOKENS: Optional[int] = None


# ============================================================
# ChunkingPipeline — 自适应滑动窗口切片器
# ============================================================

class ChunkMeta(NamedTuple):
    """单个分片的定位元信息。

    为什么不只用 start_line：
      超长**单行**文件（混淆 WebShell 常见形态）只能按字符窗口切分，
      所有分片的 start_line 都等于 1。旧实现据此在 prompt 里写
      "本分片覆盖原始文件第 1–1 行"，模型于是把分片序号当成行号，
      凭空写出 "L3–L221" 之类根本不存在的行区间（实测 29 片全为 L1，
      模型仍据此声称可见 L3–L221）。因此必须显式告知切片形态。
    """

    text: str
    start_line: int          # 主体首个内容行的绝对行号（1-based）
    single_line_slice: bool  # True=该分片是同一物理行的字符切片，行号不具区分度
    slice_index: int         # 单行文件内的分片序号（0-based）；非单行切片为 -1
    slice_total: int         # 单行文件总分片数；非单行切片为 -1


class ChunkingPipeline:
    """
    自适应滑动窗口切片器。

    策略：
      1. 优先在函数/类边界（空行、}`、{` 等）切割
      2. 回退到自然行边界
      3. 每个 Chunk 500-800 字
      4. 相邻 Chunk 重叠 100-150 字（防控制流断裂）
    """

    @staticmethod
    def split_by_function_blocks(code: str) -> List[Tuple[str, int]]:
        """
        按函数块边界粗切分。
        识别：
          - 空行分隔
          - PHP function/class 边界
          - Java class/method 边界
          - Python def/class 边界
          - C-style 函数闭合 } 后跟空行

        Returns:
            [(block_text, offset), ...]  offset 为该 block 在 code 中的字符偏移（用于回溯绝对行号）
        """
        if not code or len(code) <= CHUNK_TARGET_MAX:
            return [(code, 0)] if code else []

        blocks = []
        current = []
        offset = 0       # 当前 block 起始字符偏移（相对 code）
        cursor = 0       # 已消费字符偏移（含每行后的换行符）
        lines = code.split("\n")
        depth = 0  # 大括号深度

        for line in lines:
            line_len = len(line)
            if not current:
                offset = cursor  # 新 block 从本行起始
            current.append(line)
            depth += line.count("{") - line.count("}")

            # 在函数/类块结束时切割（深度归零 + 空行）
            is_empty = line.strip() == ""
            is_block_end = depth <= 0 and (
                line.strip().startswith("}") or
                line.strip().startswith(")") or
                line.strip() == ""
            )

            if is_block_end and len("\n".join(current)) >= CHUNK_TARGET_MIN:
                blocks.append(("\n".join(current), offset))
                current = []

            # 消费本行 + 后续换行符
            cursor += line_len + 1

        # 剩余内容
        if current:
            blocks.append(("\n".join(current), offset))

        return blocks if blocks else [(code, 0)]

    @staticmethod
    def chunk_code(code: str) -> List[ChunkMeta]:
        """
        主入口：将代码切分为重叠 Chunk。

        Returns:
            [ChunkMeta, ...]
            text: 分片文本
            start_line: 该 Chunk 主体在原始 code 中的绝对起始行号（1-based）。
                       用于让 [LINE_X] 标注与全局正则行号对齐，实现分片正则锚定（修复 2.2）。
            single_line_slice / slice_index / slice_total: 单行文件被按字符窗口切分时，
                       行号失去区分度，用这三个字段如实描述"这是第几片字符切片"，
                       避免模型把分片序号误当行号（见 ChunkMeta 注释里的事故记录）。
        """
        if not code or not code.strip():
            return []

        text = code.strip()
        text_offset = code.find(text)  # text 在 code 中的起始字符偏移

        def line_of(char_off: int) -> int:
            """将 text 内字符偏移转换为 code 内绝对行号（1-based）"""
            return code[:text_offset + char_off].count("\n") + 1

        # ── 小代码直接返回（不分片，行号天然可用）──
        if len(text) <= CHUNK_TARGET_MAX:
            return [ChunkMeta(text=text, start_line=line_of(0),
                              single_line_slice=False, slice_index=-1, slice_total=-1)]

        # ── 先按函数块粗切（带偏移）──
        blocks = ChunkingPipeline.split_by_function_blocks(text)

        # ── 超长块再按自然边界二次切分 ──
        raw: List[Tuple[str, int]] = []  # (chunk_text, offset_in_text)
        for block_text, block_off in blocks:
            if len(block_text) <= CHUNK_TARGET_MAX:
                raw.append((block_text, block_off))
                continue
            # 按自然行切分，保持 900-1600 字
            lines = block_text.split("\n")
            sub: List[str] = []
            sub_off = block_off
            for line in lines:
                if len(line) > CHUNK_TARGET_MAX:
                    # 超长单行（混淆 WebShell 的一行流 payload 常见）：
                    # 原实现只按自然行累积，整行会被 append 后一次性产出，
                    # 形成一个远超预算的巨型 Chunk —— 模型拿到后仍然看不全，
                    # 且会让单次请求体积失控。此处按字符窗口强制切段。
                    if sub:
                        carried = "\n".join(sub)
                        raw.append((carried, sub_off))
                        sub_off += len(carried) + 1
                        sub = []
                    for start in range(0, len(line), CHUNK_TARGET_MAX):
                        raw.append((line[start:start + CHUNK_TARGET_MAX], sub_off + start))
                    sub_off += len(line) + 1
                    continue
                sub.append(line)
                sub_text = "\n".join(sub)
                if len(sub_text) >= CHUNK_TARGET_MAX:
                    raw.append((sub_text, sub_off))
                    # 保留最后 2-3 行作为下一次的前导上下文
                    keep = min(3, len(sub))
                    drop = sub[:-keep]
                    drop_len = len("\n".join(drop))
                    # 关键：sub_off 必须用「运行中的累积偏移」而非 block_off，
                    # 否则重置尾部后会丢失此前已累积的偏移，导致绝对行号错位。
                    sub_off = sub_off + drop_len + (1 if drop else 0)
                    sub = sub[-keep:] if keep else []
            if sub:
                sub_text = "\n".join(sub)
                # 合并到上一个 chunk（如果太小）
                if len(sub_text) < CHUNK_TARGET_MIN and raw:
                    prev_text, prev_off = raw[-1]
                    raw[-1] = (prev_text + "\n" + sub_text, prev_off)
                else:
                    raw.append((sub_text, sub_off))

        # ── 添加上下文重叠（15-20%，仅作前缀，不改主体行号）──
        overlapped: List[Tuple[str, int]] = []
        for i, (chunk, off) in enumerate(raw):
            if i > 0:
                prev = raw[i - 1][0]
                overlap_len = min(OVERLAP_MAX, max(OVERLAP_MIN, int(len(chunk) * 0.18)))
                if len(prev) > overlap_len:
                    overlap_text = prev[-overlap_len:]
                    # 从上一个 Chunk 最后一个换行后开始截取（保持完整性）
                    nl_pos = overlap_text.find("\n")
                    if nl_pos > 0 and nl_pos < len(overlap_text) // 2:
                        overlap_text = overlap_text[nl_pos + 1:]
                    chunk = f"// ... 上文延续 (Chunk {i}) ...\n{overlap_text}\n// ... 本 Chunk 开始 ...\n{chunk}"
            # off 保持为主体绝对起始行号（重叠前缀为显式标注的上下文，行号略有偏移属预期）
            overlapped.append((chunk, off))

        # ── 最终合并过小的相邻 Chunk（保留前者起始行号）──
        merged: List[Tuple[str, int]] = []
        for chunk, off in overlapped:
            if merged and len(chunk) < CHUNK_TARGET_MIN:
                ptext, poff = merged[-1]
                merged[-1] = (ptext + "\n" + chunk, poff)
            else:
                merged.append((chunk, off))

        # ── 单行文件判定 ──
        # 只有 1 个物理行时无法用行号定位：所有分片的 start_line 都是 1，
        # 行号对模型不再有区分度。此时显式标记为"字符切片"，
        # 由 prompt 如实告知模型按分片序号描述位置，禁止推断行区间。
        is_single_line = "\n" not in text
        total = len(merged)

        metas: List[ChunkMeta] = []
        for idx, (chunk, off) in enumerate(merged):
            metas.append(ChunkMeta(
                text=chunk,
                start_line=line_of(off),
                single_line_slice=is_single_line,
                slice_index=idx if is_single_line else -1,
                slice_total=total if is_single_line else -1,
            ))
        return metas


# ============================================================
# AIClient — OpenAI 兼容客户端封装
# ============================================================

class AIClient:
    """
    OpenAI 兼容 API 客户端。

    支持：
      - 流式 / 非流式调用
      - 动态 API 切换（默认 vs 自定义配置）
      - 超时与异常优雅降级
    """

    def __init__(self, api_config: Optional[Dict[str, str]] = None):
        """
        Args:
            api_config: {"base_url": "...", "api_key": "...", "model_name": "..."}
                        如果为 None 或不完整，使用默认配置
        """
        self.api_config = api_config or {}
        self.base_url = (self.api_config.get("base_url") or DEFAULT_BASE_URL).rstrip("/")
        self.api_key = self.api_config.get("api_key") or ""
        self.model_name = self.api_config.get("model_name") or LLM_MODEL_FALLBACK
        self._client = None  # 缓存的 AsyncOpenAI 实例（懒初始化）
        # 最近一次「流式」调用是否因输出上限触顶被截断（finish_reason == "length"）。
        # 仅由 chat_stream 串行写入，分片并发的 chat() 不写，避免竞态。
        self.last_stream_truncated = False
        # 最近一次流式调用的 finish_reason（"stop"/"length"/None）。
        # 用于区分「正文被截断」与「思维链耗尽额度、正文为空」两种情况。
        self.last_finish_reason: Optional[str] = None

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    # ── 采样参数装配与兼容降级 ──

    @staticmethod
    def _completion_kwargs(
        temperature: Optional[float],
        max_tokens: Optional[int],
    ) -> Dict[str, Any]:
        """装配可选采样参数。值为 None 时「不传该键」而不是传 null，
        避免个别 OpenAI 兼容网关把显式 null 当非法值拒绝。"""
        kwargs: Dict[str, Any] = {}
        if temperature is not None:
            kwargs["temperature"] = temperature
        if max_tokens is not None:
            kwargs["max_tokens"] = max_tokens
        return kwargs

    @staticmethod
    def _is_unsupported_param_error(exc: BaseException) -> bool:
        """判断是否为「网关不认识 temperature / max_tokens」的参数类报错。

        少数推理型或自建网关模型不接受这两个参数（或只接受 max_completion_tokens）。
        命中时降级为不带采样参数重试一次，保证本次审计仍能出结果——
        不能因为新增参数把原本能跑通的模型打挂。
        """
        status = getattr(exc, "status_code", None)
        if status is not None and status not in (400, 404, 422):
            return False
        text = str(getattr(exc, "body", "") or exc).lower()
        return any(key in text for key in ("temperature", "max_tokens", "max_completion_tokens"))

    def _get_client(self) -> AsyncOpenAI:
        """
        延迟初始化并缓存 AsyncOpenAI 客户端。

        使用异步客户端 + 全程 await/async for，确保网络 I/O 不阻塞事件循环，
        从而使 SemanticEngine 的 asyncio.Semaphore(10) 分片并发真正生效
        （修复 2.1：原先的同步 OpenAI 客户端会冻结事件循环，导致分片被串行执行）。
        """
        if self._client is None:
            # base_url 必须归一化：用户可能把完整端点路径（如 .../v1/chat/completions）
            # 填进来，而 SDK 会再拼一次 /chat/completions → 必然 404（实测踩过）。
            # default_headers 补浏览器 UA（规避 Cloudflare 403 / error 1010）
            # 与网关自定义头（如 OpenCode Go 要求的 x-opencode-session）。
            from ..config import normalize_base_url, default_headers_for
            _url = normalize_base_url(self.base_url) or self.base_url
            self._client = AsyncOpenAI(
                base_url=_url,
                api_key=self.api_key,
                timeout=LLM_TIMEOUT,
                default_headers=default_headers_for(_url),
            )
        return self._client

    async def chat_stream(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = LLM_TEMPERATURE_MAIN,
        # 默认不下发（见 LLM_MAX_TOKENS 注释）。此处写死 None 而非引用常量：
        # Python 默认参数在函数定义时求值，引用常量会造成"改常量却无效果"的错觉。
        # 实际控制点在 audit_stream 的显式传参（运行时读取常量）。
        max_tokens: Optional[int] = None,
    ) -> AsyncGenerator[str, None]:
        """
        流式聊天 — 返回 token 级别的文本流（异步非阻塞）。

        Yields:
            每次 yield 一个 token 片段（字符串）
        """
        if not self.is_configured:
            yield "[ERROR] API 未配置，请在侧边栏设置 Base URL / API Key / Model Name"
            return

        self.last_stream_truncated = False
        try:
            async for token in self._stream_once(messages, temperature, max_tokens, allow_retry=True):
                yield token
        except Exception as e:
            yield f"\n[ERROR] AI 引擎异常: {str(e)}\n"

    async def _stream_once(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float],
        max_tokens: Optional[int],
        allow_retry: bool,
    ) -> AsyncGenerator[str, None]:
        """单次流式调用（含一次「去掉采样参数」的兼容重试）。"""
        client = self._get_client()
        kwargs = self._completion_kwargs(temperature, max_tokens)
        try:
            # AsyncOpenAI：create 返回协程，await 后得到异步流；
            # async for 逐 token 产出，全程不阻塞事件循环，流式推送语义与改动前一致。
            stream = await client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                stream=True,
                timeout=LLM_TIMEOUT,
                **kwargs,
            )
        except Exception as e:
            if allow_retry and self._is_unsupported_param_error(e):
                logger.warning("网关不支持 temperature/max_tokens，降级为不带采样参数重试: %s", e)
                async for token in self._stream_once(messages, None, None, False):
                    yield token
                return
            raise

        truncated = False
        last_finish = None
        async for chunk in stream:
            if not chunk.choices:
                continue
            choice = chunk.choices[0]
            # 触达输出上限时 OpenAI 兼容接口回 finish_reason="length"，
            # 此时报告尾部标签多半不闭合，需要如实上报给前端，而不是假装完整。
            # 注意：推理模型的思维链同样计入上限，因此 length 也可能意味着
            # 「思维链耗尽额度、正文一个字都没写」——由 audit_stream 结合
            # 正文是否为空来区分这两种情况。
            if getattr(choice, "finish_reason", None):
                last_finish = choice.finish_reason
                if last_finish == "length":
                    truncated = True
            delta = choice.delta
            if delta and delta.content:
                yield delta.content
        self.last_stream_truncated = truncated
        self.last_finish_reason = last_finish

    async def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float] = LLM_TEMPERATURE_MAIN,
        # 同上：默认不下发，避免推理模型思维链耗尽额度导致正文为空
        max_tokens: Optional[int] = None,
    ) -> str:
        """
        非流式聊天 — 返回完整回复（异步非阻塞，支持真并发）。
        """
        if not self.is_configured:
            return "[ERROR] API 未配置"

        try:
            return await self._complete_once(messages, temperature, max_tokens, allow_retry=True)
        except Exception as e:
            return f"[ERROR] AI 引擎异常: {str(e)}\n"

    async def _complete_once(
        self,
        messages: List[Dict[str, str]],
        temperature: Optional[float],
        max_tokens: Optional[int],
        allow_retry: bool,
    ) -> str:
        """单次非流式调用（含一次「去掉采样参数」的兼容重试）。"""
        client = self._get_client()
        kwargs = self._completion_kwargs(temperature, max_tokens)
        try:
            response = await client.chat.completions.create(
                model=self.model_name,
                messages=messages,
                stream=False,
                timeout=LLM_TIMEOUT,
                **kwargs,
            )
        except Exception as e:
            if allow_retry and self._is_unsupported_param_error(e):
                logger.warning("网关不支持 temperature/max_tokens，降级为不带采样参数重试: %s", e)
                return await self._complete_once(messages, None, None, False)
            raise
        return response.choices[0].message.content or ""


# ============================================================
# SemanticEngine — 语义审计编排器
# ============================================================

class SemanticEngine:
    """
    语义审计编排器 — 全流程控制器。

    流程：
      Small File (< 15KB):
        code → [System Prompt + Regex Context + Code] → LLM Stream → SSE

      Large File (>= 15KB):
        code → ChunkingPipeline → Semaphore(10) 并发分析
        → 分片结果聚合 → Synthesis Prompt → LLM Stream → SSE
    """

    def __init__(self, api_config: Optional[Dict[str, str]] = None):
        self.client = AIClient(api_config)
        self.semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    # ── SSE 事件构建 ──

    @staticmethod
    def _format_sse(event: str, data: Any) -> str:
        """格式化为标准 SSE 消息"""
        payload = json.dumps(data, ensure_ascii=False)
        return f"event: {event}\ndata: {payload}\n\n"

    # ── 主入口 ──

    async def audit_stream(
        self,
        code: str,
        filename: str = "unknown.txt",
        regex_scan: Optional[Dict[str, Any]] = None,
        decode_ctx: str = "",
        decode_confidence: str = "low",
        hl_seed_ctx: Optional[str] = None,
    ) -> AsyncGenerator[str, None]:
        """（hl_seed_ctx：可选的强制标红种子上下文；None 时按 regex_scan 自动生成）"""
        """
        主审计流 — 异步生成器，逐个 yield SSE 事件字符串。

        使用方式（FastAPI）：
            return StreamingResponse(
                engine.audit_stream(code, filename, regex_scan),
                media_type="text/event-stream",
            )
        """
        from .prompts import (
            SYSTEM_PROMPT,
            build_user_prompt, build_chunk_prompt, build_synthesis_prompt,
            build_hl_seed_context, code_visibility,
        )

        task_id = f"audit-{int(time.time()*1000)}"
        code_len = len(code)
        is_small = code_len < SMALL_FILE_THRESHOLD
        # 首轮模型实际能看到的范围（行维度 + 字符维度）。
        # 小文件已在 CODE_DISPLAY_BUDGET 侧对齐保证全文可见，此处仅作防御性校验：
        # 一旦仍然被截断（未来预算变更/极端输入），仍能收窄正则锚点并提示复核阶段。
        _vis = code_visibility(code) if is_small else None
        _visible_end_line = _vis.end_line if _vis and _vis.truncated else None

        # 强制标红种子：从正则命中提取 code_execution / obfuscation 类高危构造，
        # 作为 [DE_OBFUSCATE] 的 [[HL]] 强制约束（纯后端 prompt 级，零执行）。
        # 调用方显式传入时以其为准，否则按 regex_scan 自动生成。
        if hl_seed_ctx is None:
            hl_seed_ctx = build_hl_seed_context(regex_scan)

        # ── SSE: init 事件 ──
        init_data = {
            "task_id": task_id,
            "filename": filename,
            "code_length": code_len,
            "mode": "small_file" if is_small else "chunked",
            "chunk_count": 1 if is_small else 0,
            # 实际覆盖观测：模型真正看到了多少行，而不是"假设它看到了全部"。
            # 这三个字段让漏报排查不再依赖猜测。
            "code_total_lines": code.count("\n") + 1,
            "code_display_lines": (
                _vis.total_lines if _vis and not _vis.truncated
                else (_vis.end_line if _vis else None)
            ),
            "display_truncated": bool(_vis.truncated) if _vis else False,
            "regex_summary": regex_scan.get("summary", "") if regex_scan else "",
            "regex_evidence": {
                "artifact": (regex_scan or {}).get("artifact", {}),
                "deterministic_verdict": (regex_scan or {}).get("deterministic_verdict", {}),
                "behavior_findings": (regex_scan or {}).get("behavior_findings", [])[:20],
                "matches": (regex_scan or {}).get("matches", [])[:80],
                "total_matches": (regex_scan or {}).get("total_matches", 0),
            },
        }
        yield self._format_sse("init", init_data)

        has_error = False  # 追踪全流程错误
        empty_output = False  # 模型未产出任何正文（区别于"调用报错"）
        final_report_text = ""
        # 最终报告（流式）是否触达输出上限被截断；分片阶段的截断不计入（并发写会相互覆盖）。
        report_truncated = False

        try:
            if is_small:
                # ══════════════════════════════════════════
                # 小文件路径：单次全量推送
                # ══════════════════════════════════════════
                user_prompt = build_user_prompt(code, filename, regex_scan, code_len, decode_ctx, hl_seed_ctx)
                messages = [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ]

                # 进度通知
                yield self._format_sse("progress", {
                    "message": "小文件模式：正在执行全局语义审计...",
                    "mode": "small_file",
                })

                # 流式推送：直接转发 LLM 原始 token，不做服务端标签解析
                # 前端负责标签识别、剥离、面板路由，彻底避免服务端解析乱序
                raw_buf = ""
                full_text = ""
                async for token in self.client.chat_stream(
                    messages, temperature=LLM_TEMPERATURE_MAIN, max_tokens=LLM_MAX_TOKENS
                ):
                    raw_buf += token
                    full_text += token
                    # 每积累少量字符就推送一次（流式但不过于碎片化）
                    if len(raw_buf) >= 15:
                        yield self._format_sse("stream", {"text": raw_buf})
                        raw_buf = ""
                # 推送尾部残余
                if raw_buf:
                    yield self._format_sse("stream", {"text": raw_buf})
                # B1 修复：检测 LLM 返回的错误哨兵，正确置位错误标志
                final_report_text = full_text
                # getattr 兜底：自定义/替换过的 client 可能没有该属性，不能让审计流因此中断
                report_truncated = bool(getattr(self.client, "last_stream_truncated", False))
                if "[ERROR]" in full_text:
                    has_error = True
                elif not full_text.strip():
                    # 一个字都没产出：推理模型的思维链耗尽输出额度时的典型形态
                    # （finish_reason=length 且 reasoning_tokens 占满上限）。
                    # 必须显式失败——否则用户看到"审计完成"+四个空面板，
                    # 会把"模型没说话"误读成"没检测到问题"，这是最危险的静默失效。
                    has_error = True
                    empty_output = True
                    logger.warning("主分析未产出任何内容（finish_reason=%s, truncated=%s）",
                                   getattr(self.client, "last_finish_reason", None), report_truncated)

            else:
                # ══════════════════════════════════════════
                # 大文件路径：切片 → 并发 → 聚合
                # ══════════════════════════════════════════
                chunks = ChunkingPipeline.chunk_code(code)
                # 单行文件切片标记：分片阶段与综合阶段都必须告知模型
                # "行号无区分度"，否则它会把分片编号当行号（实测综合报告
                # 里出现过 L66/L396/L482/L592/L636，而文件物理上只有 1 行）。
                # 单行文件（未经 pre_format 规范化的、真正的单行）标记：
                # 仅用于 prompt 措辞，让模型明白行号无区分度。
                # 注意：绝大多数"上传的是单行文件"的场景会在进入本函数前
                # 被 pre_format_malware_code 重排成多行（实测 1 行 → 701 行），
                # 此时本标记为 False —— 这是正确行为，不是缺陷。
                _is_single_line_slice = bool(chunks) and chunks[0].single_line_slice

                # 更新 chunk_count
                init_data["chunk_count"] = len(chunks)
                yield self._format_sse("init", init_data)

                yield self._format_sse("progress", {
                    "message": f"大文件模式：已切分为 {len(chunks)} 个 Chunk，并发审计中...",
                    "mode": "chunked",
                    "chunk_count": len(chunks),
                })

                # 并发分析各分片（修复 2.2：透传 filename / regex_scan / start_line）
                tasks = [
                    self._analyze_chunk_with_progress(
                        idx, chunk_meta, len(chunks), filename, regex_scan, decode_ctx, hl_seed_ctx
                    )
                    for idx, chunk_meta in enumerate(chunks)
                ]

                # 流式推送各分片进度
                chunk_findings = []
                for coro in asyncio.as_completed(tasks):
                    idx, result = await coro
                    chunk_findings.append((idx, result))
                    # B1 修复：分片返回 [ERROR] 哨兵时置位错误标志
                    if "[ERROR]" in result:
                        has_error = True
                    yield self._format_sse("progress", {
                        "message": f"Chunk {idx+1}/{len(chunks)} 完成",
                        "chunk_index": idx,
                        "completed": len(chunk_findings),
                        "total": len(chunks),
                    })

                # 按索引排序
                chunk_findings.sort(key=lambda x: x[0])
                ordered_findings = [f for _, f in chunk_findings]

                # 综合定性
                yield self._format_sse("progress", {
                    "message": "所有分片审计完成，正在生成综合定性报告...",
                    "mode": "synthesis",
                })

                synth_prompt = build_synthesis_prompt(
                    filename, code_len, ordered_findings, regex_scan, code, decode_ctx, hl_seed_ctx,
                    single_line_slice=_is_single_line_slice,
                )
                messages = [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": synth_prompt},
                ]

                # 流式推送综合报告（直接转发原始 token）
                #注：2026-10-08 撤除了此处的「单行文件行号清洗」。
                # 原因：服务端 pre_format_malware_code 会先把单行压缩代码
                # 规范化成多行（实测 1 行 → 701 行）再送入引擎，
                # 因此 chunk_code 永远不会把它判为 single_line_slice，
                # 该清洗分支属**永不执行的死代码**；一旦在真单行场景生效，
                # 又会把模型对规范化代码的**真实行号引用**误删。
                raw_buf = ""
                synth_full = ""
                async for token in self.client.chat_stream(
                    messages, temperature=LLM_TEMPERATURE_MAIN, max_tokens=LLM_MAX_TOKENS
                ):
                    raw_buf += token
                    synth_full += token
                    if len(raw_buf) >= 15:
                        yield self._format_sse("stream", {"text": raw_buf})
                        raw_buf = ""
                if raw_buf:
                    yield self._format_sse("stream", {"text": raw_buf})
                # B1 修复：综合阶段错误哨兵检测
                report_truncated = bool(getattr(self.client, "last_stream_truncated", False))
                if "[ERROR]" in synth_full:
                    has_error = True
                elif not synth_full.strip():
                    has_error = True
                    empty_output = True
                    logger.warning("综合阶段未产出任何内容（finish_reason=%s, truncated=%s）",
                                   getattr(self.client, "last_finish_reason", None), report_truncated)

            # ── Agent 反向复核与最终融合 ──
            _audit_conf = compute_audit_confidence(regex_scan, decode_confidence)
            _static_data = (regex_scan or {}).get("deterministic_verdict", {})
            _static = DeterministicVerdict(
                verdict=_static_data.get("verdict", "suspicious" if _audit_conf >= 0.5 else "no_indication"),
                risk_score=int(_static_data.get("risk_score", round(_audit_conf * 100))),
                confidence=float(_static_data.get("confidence", _audit_conf)),
                reason=_static_data.get("reason", "静态证据融合"),
            )
            _agent = None
            if self.client.is_configured and final_report_text and not has_error:
                yield self._format_sse("progress", {
                    "message": "主分析完成，正在进行反向证伪与误报复核...",
                    "mode": "agent_review",
                })
                _review_text = await self.client.chat(
                    [
                        {"role": "system", "content": REVIEW_SYSTEM_PROMPT},
                        {"role": "user", "content": build_review_prompt(
                            code, filename, regex_scan, final_report_text, decode_ctx,
                            # 对齐首轮可见范围：避免复核引用首轮也没看到的行号而凭空判断
                            first_report_visible_end_line=_visible_end_line,
                        )},
                    ],
                    # 复核是判定环节，取确定性解码，避免同一份报告两次复核给出不同结论
                    temperature=LLM_TEMPERATURE_REVIEW,
                )
                _agent = parse_agent_verdict(_review_text)
            _final = fuse_verdicts(_static, _agent)
            _risk_map = {
                "malicious": "高危",
                "suspicious": "中危",
                "benign": "安全",
                "no_indication": "未发现明确威胁",
                "unknown": "未知",
                "unsupported": "不支持",
            }
            _risk_level = _risk_map.get(_final.verdict, derive_risk_level(regex_scan))

            # done 文案分级：把"模型没说话"和"调用报错"区分开，
            # 二者在前端都会退化为静态判定，但原因与处置完全不同。
            if empty_output:
                _done_message = (
                    "模型未产出报告内容（推理模型的思维链可能已耗尽输出额度），"
                    "当前仅展示静态判定"
                )
            elif has_error:
                _done_message = "审计完成（存在错误，请检查 API 配置）"
            elif report_truncated:
                _done_message = "审计完成（报告触达输出上限被截断，末尾章节可能不完整）"
            else:
                _done_message = "审计完成"

            yield self._format_sse("verdict", _final.to_dict())
            yield self._format_sse("done", {
                "success": not has_error,
                "task_id": task_id,
                "filename": filename,
                "message": _done_message,
                "has_error": has_error,
                # 前端据此区分"模型没产出"与"报告被截断"，避免把空面板误读成"没检测到"
                "empty_output": empty_output,
                # 前端据此提示"末尾章节可能缺失"，而不是让用户看到一个空面板以为是没检测到
                "report_truncated": report_truncated,
                "confidence": _final.confidence,
                "risk_level": _risk_level,
                "verdict": _final.verdict,
                "agent_verdict": _final.to_dict(),
                "deterministic_verdict": _static.to_dict(),
                "attack_profile": {
                    "confidence": _final.confidence,
                    # 从 [IMAGE] 段确定性回填木马家族（Behinder/冰蝎/Metasploit…）。
                    # 该字段此前恒为空串 —— 模型明明在 [IMAGE] 里写了家族，
                    # 却没有任何代码把它取出来（2026-10-07 实测 7/7 条全空）。
                    # 只认"技术家族"那一行，并排除"无（未匹配冰蝎…）"这类否定表述。
                    "family": extract_malware_family(final_report_text),
                    "label": _final.artifact_type,
                },
                "risk_assessment": {
                    "overall_risk": _risk_level,
                    "malicious_probability": _final.confidence if _final.verdict == "malicious" else 0.0,
                    "risk_score": int(round(_final.confidence * 100)),
                },
            })

        except Exception as e:
            logger.exception("SemanticEngine audit_stream 异常")
            yield self._format_sse("error", {
                "message": f"审计引擎异常: {str(e)}",
            })

    async def _analyze_chunk_with_progress(
        self, idx: int, chunk_meta: "ChunkMeta", total: int,
        filename: str = "", regex_scan: Optional[Dict[str, Any]] = None,
        decode_ctx: str = "", hl_seed_ctx: str = "",
    ) -> Tuple[int, str]:
        """分析单个 Chunk（内部方法，供 asyncio.as_completed 使用）
        修复 2.2：透传 filename / regex_scan / start_line，使分片获得正则锚定。
        decode_ctx / hl_seed_ctx: 全局确定性解码参考与强制标红种子，透传给分片 Prompt。
        """
        from .prompts import SYSTEM_PROMPT, build_chunk_prompt
        async with self.semaphore:
            prompt = build_chunk_prompt(
                chunk_meta.text, idx, total, filename, regex_scan,
                start_line=chunk_meta.start_line,
                decode_ctx=decode_ctx, hl_seed_ctx=hl_seed_ctx,
                single_line_slice=chunk_meta.single_line_slice,
                slice_index=chunk_meta.slice_index,
                slice_total=chunk_meta.slice_total,
            )
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ]
            result = await self.client.chat(messages, temperature=LLM_TEMPERATURE_MAIN)
            return idx, result


# ============================================================
# 便捷函数
# ============================================================

async def stream_audit(
    code: str,
    filename: str = "unknown.txt",
    regex_scan: Optional[Dict[str, Any]] = None,
    api_config: Optional[Dict[str, str]] = None,
    decode_ctx: str = "",
    decode_confidence: str = "low",
    hl_seed_ctx: Optional[str] = None,
) -> AsyncGenerator[str, None]:
    """
    便捷函数：创建 SemanticEngine 并流式审计。

    使用示例：
        @app.post("/api/audit/stream")
        async def audit_stream(file: UploadFile = File(...)):
            code = (await file.read()).decode("utf-8")
            return StreamingResponse(
                stream_audit(code, file.filename, None, api_config),
                media_type="text/event-stream",
            )
    """
    engine = SemanticEngine(api_config)
    # 全部使用关键字实参：此前第 5 个位置实参（hl_seed_ctx）会被
    # audit_stream 的 decode_confidence 形参接收，导致高亮种子丢失且
    # 解码置信度被污染。
    async for sse_event in engine.audit_stream(
        code=code,
        filename=filename,
        regex_scan=regex_scan,
        decode_ctx=decode_ctx,
        decode_confidence=decode_confidence,
        hl_seed_ctx=hl_seed_ctx,
    ):
        yield sse_event
