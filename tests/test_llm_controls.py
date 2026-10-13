"""大模型侧微调的回归测试。

覆盖：
  1. 采样参数：主分析 temperature=0.2 / 复核 temperature=0.0；
     **默认不下发 max_tokens**（推理模型的思维链计入该额度，固定上限会把正文挤成空）
  2. 输出上限：finish_reason="length" 时 done 事件上报 report_truncated
  3. 空输出兜底：模型一个字都没产出时必须显式失败，不得静默返回空面板
  4. 兼容降级：网关不认识 temperature/max_tokens 时自动去掉参数重试，不得直接失败
  5. 复核上下文：第一轮报告按标签节选，结论段与证据段必须保留
"""

import json
import unittest
from types import SimpleNamespace
from typing import Any, AsyncGenerator, List, Optional

from shellsentry.core.ai_client import (
    AIClient,
    CHUNK_TARGET_MAX,
    ChunkingPipeline,
    LLM_MAX_TOKENS,
    LLM_TEMPERATURE_MAIN,
    LLM_TEMPERATURE_REVIEW,
    SemanticEngine,
)
from shellsentry.core.prompts import (
    CHUNK_FINDINGS_BUDGET,
    CODE_DISPLAY_BUDGET,
    SMALL_FILE_THRESHOLD,
    SYSTEM_PROMPT,
    build_chunk_prompt,
    build_synthesis_prompt,
    code_visibility,
    compress_chunk_findings,
    extract_malware_family,
)
from shellsentry.core.agent_review import (
    REVIEW_REPORT_BUDGET,
    build_review_prompt,
    select_review_report_excerpt,
)


class FakeAPIError(Exception):
    """模拟 OpenAI 兼容网关的 400 参数错误。"""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code
        self.body = {"error": {"message": message}}


class FakeCompletions:
    def __init__(self, owner: "FakeSDK"):
        self.owner = owner

    async def create(self, **kwargs):
        self.owner.calls.append(kwargs)
        if self.owner.exc is not None and not self.owner.exc_raised:
            self.owner.exc_raised = True
            raise self.owner.exc
        if kwargs.get("stream"):
            return self.owner._stream(kwargs)
        return SimpleNamespace(
            choices=[SimpleNamespace(
                message=SimpleNamespace(content=self.owner.completion_text),
                finish_reason="stop",
            )]
        )


class FakeSDK:
    """最小 AsyncOpenAI 替身：记录调用参数、可复现流式截断与参数类报错。"""

    def __init__(self, tokens: Optional[List[str]] = None, finish_reason: Optional[str] = None,
                 exc: Optional[BaseException] = None, completion_text: str = "{}"):
        self.chat = SimpleNamespace(completions=FakeCompletions(self))
        self.calls: List[dict] = []
        self.tokens = tokens or ["a", "b"]
        self.finish_reason = finish_reason
        self.exc = exc
        self.exc_raised = False
        self.completion_text = completion_text

    async def _stream(self, kwargs) -> AsyncGenerator[Any, None]:
        for index, token in enumerate(self.tokens):
            last = index == len(self.tokens) - 1
            yield SimpleNamespace(choices=[SimpleNamespace(
                delta=SimpleNamespace(content=token),
                finish_reason=self.finish_reason if last else None,
            )])


def make_client(**sdk_kwargs) -> AIClient:
    client = AIClient({"api_key": "test-only", "model_name": "fake-model"})
    client._client = FakeSDK(**sdk_kwargs)
    return client


class SamplingParameterTests(unittest.IsolatedAsyncioTestCase):
    async def test_temperature_is_sent_but_max_tokens_is_not(self):
        """回归防护：默认绝不下发 max_tokens。

        2026-09-19 事故：显式下发 max_tokens=8192 后，deepseek-v4-pro 这类推理模型
        的思维链（reasoning_content）计入该额度，实测思维链需约 9500 token，
        结果 8192 全被思维链吃光、正文 0 字符 → 四个面板全空且不报错。
        任何形式的"给推理模型设固定输出上限"都必须先经过这条断言。
        """
        client = make_client()
        text = "".join([t async for t in client.chat_stream([{"role": "user", "content": "hi"}])])

        self.assertEqual(text, "ab")
        kwargs = client._client.calls[0]
        self.assertEqual(kwargs["temperature"], LLM_TEMPERATURE_MAIN)
        self.assertNotIn("max_tokens", kwargs, "默认不得下发 max_tokens（推理模型会被思维链吃光）")
        self.assertIsNone(LLM_MAX_TOKENS, "LLM_MAX_TOKENS 默认必须为 None")
        self.assertLess(LLM_TEMPERATURE_MAIN, 0.5, "主分析必须低随机性以保证结论可复现")

    async def test_explicit_max_tokens_is_still_honored(self):
        """保留能力：显式传值时照常下发（供非推理模型按需启用）。"""
        client = make_client()
        async for _ in client.chat_stream(
            [{"role": "user", "content": "hi"}], max_tokens=4096
        ):
            pass
        self.assertEqual(client._client.calls[0]["max_tokens"], 4096)

    async def test_review_temperature_is_deterministic(self):
        client = make_client(completion_text='{"verdict":"benign"}')
        await client.chat([{"role": "user", "content": "x"}], temperature=LLM_TEMPERATURE_REVIEW)

        self.assertEqual(client._client.calls[0]["temperature"], LLM_TEMPERATURE_REVIEW)
        self.assertEqual(LLM_TEMPERATURE_REVIEW, 0.0, "复核必须完全确定性")

    async def test_length_finish_reason_marks_truncated(self):
        client = make_client(finish_reason="length")
        async for _ in client.chat_stream([{"role": "user", "content": "hi"}]):
            pass
        self.assertTrue(client.last_stream_truncated)
        self.assertEqual(client.last_finish_reason, "length")

    async def test_normal_finish_reason_is_not_truncated(self):
        client = make_client(finish_reason="stop")
        async for _ in client.chat_stream([{"role": "user", "content": "hi"}]):
            pass
        self.assertFalse(client.last_stream_truncated)
        self.assertEqual(client.last_finish_reason, "stop")

    async def test_unsupported_sampling_param_falls_back_once(self):
        client = make_client(exc=FakeAPIError("unknown parameter: max_tokens"))
        text = "".join(
            [t async for t in client.chat_stream([{"role": "user", "content": "hi"}], max_tokens=8192)]
        )

        # 首次带参数失败 → 二次降级不带参数重试 → 仍产出结果，不因新增参数把模型打挂
        self.assertEqual(text, "ab")
        self.assertEqual(len(client._client.calls), 2)
        self.assertIn("max_tokens", client._client.calls[0])
        self.assertNotIn("max_tokens", client._client.calls[1])
        self.assertNotIn("temperature", client._client.calls[1])

    async def test_non_param_error_is_not_retried(self):
        client = make_client(exc=FakeAPIError("invalid api key", status_code=401))
        text = "".join([t async for t in client.chat_stream([{"role": "user", "content": "hi"}])])

        self.assertIn("[ERROR]", text)
        self.assertEqual(len(client._client.calls), 1)


class SemanticEngineControlTests(unittest.IsolatedAsyncioTestCase):
    class FakeEngineClient:
        is_configured = True

        def __init__(self, truncated: bool = False):
            self.last_stream_truncated = truncated
            self.stream_kwargs: dict = {}
            self.chat_kwargs: dict = {}

        async def chat_stream(self, messages, **kwargs):
            self.stream_kwargs = kwargs
            yield "[IMAGE]\nx\n[/IMAGE]"

        async def chat(self, messages, **kwargs):
            self.chat_kwargs = kwargs
            return json.dumps({"verdict": "benign", "confidence": 0.2, "summary": "ok"})

    async def _run(self, truncated: bool) -> tuple:
        engine = SemanticEngine({"api_key": "test-only"})
        fake = self.FakeEngineClient(truncated=truncated)
        engine.client = fake
        stream = ""
        async for event in engine.audit_stream("const a=1;", "x.js", {
            "deterministic_verdict": {"verdict": "suspicious", "risk_score": 40, "confidence": 0.4},
            "matches": [], "summary": "s",
        }):
            stream += event
        return stream, fake

    async def test_main_and_review_temperatures_are_split(self):
        _, fake = await self._run(False)
        self.assertEqual(fake.stream_kwargs.get("temperature"), LLM_TEMPERATURE_MAIN)
        self.assertEqual(fake.chat_kwargs.get("temperature"), LLM_TEMPERATURE_REVIEW)

    async def test_done_reports_truncation_flag(self):
        stream, _ = await self._run(True)
        self.assertIn('"report_truncated": true', stream)
        self.assertIn("截断", stream)

    async def test_done_flag_false_when_complete(self):
        stream, _ = await self._run(False)
        self.assertIn('"report_truncated": false', stream)

    async def test_empty_model_output_is_reported_as_failure(self):
        """回归防护：模型一个字都没产出时，必须显式失败。

        2026-09-19 事故形态：done 上报 success=True / has_error=False，
        前端只看到四个空面板，用户会把"模型没说话"误读成"没检测到问题"。
        现在必须置 has_error + empty_output，并给出可读原因。
        """
        engine = SemanticEngine({"api_key": "test-only"})

        class SilentClient:
            is_configured = True
            last_stream_truncated = True   # 思维链耗尽额度的典型特征
            last_finish_reason = "length"

            async def chat_stream(self, messages, **kwargs):
                return
                yield  # 不产出任何 token

            async def chat(self, messages, **kwargs):
                return ""

        engine.client = SilentClient()
        stream = ""
        async for event in engine.audit_stream("const a=1;", "x.js", {
            "deterministic_verdict": {"verdict": "suspicious", "risk_score": 40, "confidence": 0.4},
            "matches": [], "summary": "s",
        }):
            stream += event

        self.assertIn('"has_error": true', stream)
        self.assertIn('"empty_output": true', stream)
        self.assertIn('"success": false', stream)
        self.assertIn("未产出", stream, "必须给出可读原因，而不是笼统的『审计完成』")
        # 空输出时不得误报为"报告被截断"（那是另一种情况）
        self.assertNotIn("末尾章节", stream)

    async def test_normal_run_is_not_flagged_as_empty(self):
        stream, _ = await self._run(False)
        self.assertIn('"empty_output": false', stream)
        self.assertIn('"has_error": false', stream)


def _report(image: str = "img", decoded: str = "code", meta: str = "meta",
            playbook: str = "pb", c2: str = "None") -> str:
    return (
        f"[IMAGE]\n{image}\n[/IMAGE]\n"
        f"[DE_OBFUSCATE]\n{decoded}\n[/DE_OBFUSCATE]\n"
        f"[C2_INFO]\n{c2}\n[/C2_INFO]\n"
        f"[METADATA_BEHAVIOR]\n{meta}\n[/METADATA_BEHAVIOR]\n"
        f"[PLAYBOOK]\n{playbook}\n[/PLAYBOOK]"
    )


class ReviewExcerptTests(unittest.TestCase):
    def test_short_report_is_returned_verbatim(self):
        report = _report()
        self.assertEqual(select_review_report_excerpt(report), report)

    def test_untagged_report_falls_back_to_tail_clip(self):
        report = "x" * 30000
        excerpt = select_review_report_excerpt(report)
        self.assertEqual(len(excerpt), REVIEW_REPORT_BUDGET)
        self.assertTrue(excerpt.endswith("x"))

    def test_essential_sections_survive_tail_truncation(self):
        # 构造超长报告：IMAGE 与 METADATA 在头部，DE_OBFUSCATE/PLAYBOOK 极长
        report = _report(
            image="冰蝎 JSPX 后门，密钥协商 + 类加载执行",
            decoded="A" * 40000,
            meta="| JAVA-EXEC-001 | L3 | critical | defineClass |",
            playbook="B" * 20000,
        )
        self.assertGreater(len(report), REVIEW_REPORT_BUDGET)

        excerpt = select_review_report_excerpt(report)
        # 关键：结论段与证据段必须完整保留（旧实现 first_report[-12000:] 会把它们整段砍掉）
        self.assertIn("冰蝎 JSPX 后门", excerpt)
        self.assertIn("JAVA-EXEC-001", excerpt)
        self.assertLessEqual(len(excerpt), REVIEW_REPORT_BUDGET + 200)

    def test_deobfuscate_keeps_tail_and_playbook_is_dropped_when_needed(self):
        report = _report(
            image="I" * 2000,
            decoded="D" * 40000 + "\nFINAL_DECODED_PAYLOAD",
            meta="M" * 3000,
            playbook="P" * 20000,
        )
        excerpt = select_review_report_excerpt(report)
        # 还原结果通常落在段尾，必须保留到
        self.assertIn("FINAL_DECODED_PAYLOAD", excerpt)
        self.assertIn("已省略", excerpt, "节选必须显式标注省略，不能让复核误以为是全文")

    def test_oversized_essential_sections_are_all_kept(self):
        report = _report(
            image="I" * 20000,
            decoded="D" * 100,
            meta="M" * 20000,
            playbook="P" * 100,
        )
        excerpt = select_review_report_excerpt(report)
        # 必保段整体超预算时等比压缩，三段都必须在场
        for tag in ("[IMAGE]", "[C2_INFO]", "[METADATA_BEHAVIOR]"):
            self.assertIn(tag, excerpt)

    def test_unclosed_section_is_still_captured(self):
        # 首轮报告被截断的典型形态：末段没有闭合标签
        report = "[IMAGE]\n结论\n[/IMAGE]\n[METADATA_BEHAVIOR]\n" + "E" * 30000
        excerpt = select_review_report_excerpt(report)
        self.assertIn("结论", excerpt)
        self.assertIn("[METADATA_BEHAVIOR]", excerpt)

    def test_review_prompt_uses_excerpt_not_tail_clip(self):
        report = _report(image="冰蝎 JSPX 后门", decoded="A" * 40000, meta="证据表", playbook="B" * 20000)
        prompt = build_review_prompt("code", "x.jspx", None, report)
        self.assertIn("冰蝎 JSPX 后门", prompt)
        self.assertIn("证据表", prompt)


def _chunk_report(index: int) -> str:
    return (
        f"[IMAGE]\n分片{index}意图 MARKER_{index}\n[/IMAGE]\n"
        f"[DE_OBFUSCATE]\n{'A' * 3000}\n还原结果 TAIL_{index}\n[/DE_OBFUSCATE]\n"
        f"[C2_INFO]\nNone\n[/C2_INFO]\n"
        f"[METADATA_BEHAVIOR]\n分片{index}证据 MARKER_{index}\n[/METADATA_BEHAVIOR]\n"
        f"[PLAYBOOK]\n{'B' * 2000}\n[/PLAYBOOK]"
    )


class SynthesisFindingsTests(unittest.TestCase):
    def test_every_chunk_keeps_a_representative(self):
        findings = [_chunk_report(i) for i in range(12)]
        joined = "\n\n---\n\n".join(
            f"### Chunk {i + 1} 分析结果\n{f}" for i, f in enumerate(findings)
        )
        self.assertGreater(len(joined), CHUNK_FINDINGS_BUDGET)

        text = compress_chunk_findings(findings)
        # 旧实现 joined[:6000] 只能覆盖前几个分片，后半文件的结论整段消失
        self.assertNotIn("MARKER_11", joined[:CHUNK_FINDINGS_BUDGET])
        self.assertIn("MARKER_11", text, "靠后分片的结论必须保留代表，否则综合会漏掉文件后半段")
        self.assertIn("MARKER_0", text)
        self.assertLessEqual(len(text), CHUNK_FINDINGS_BUDGET + 12 * 100 + 50)

    def test_large_chunk_count_still_keeps_last_one(self):
        # 分片数远超预算/单片体积时（真实大文件场景），份额摊薄后仍须每个分片有代表。
        # 早期实现因单片保底 400 字符，37 片合计 14800 超预算后被尾部截断砍掉靠后分片。
        findings = [_chunk_report(i) for i in range(37)]
        text = compress_chunk_findings(findings)

        self.assertIn("MARKER_36", text, "37 个分片时最后一片仍必须有代表")
        self.assertIn("MARKER_0", text)
        self.assertLessEqual(len(text), CHUNK_FINDINGS_BUDGET + 37 * 100 + 50)

    def test_short_findings_are_untouched(self):
        findings = ["[IMAGE]\n小分片\n[/IMAGE]"]
        self.assertEqual(compress_chunk_findings(findings), "### Chunk 1 分析结果\n[IMAGE]\n小分片\n[/IMAGE]")

    def test_empty_findings(self):
        self.assertEqual(compress_chunk_findings([]), "")


class ReviewCodeVisibilityTests(unittest.TestCase):
    @staticmethod
    def _long_code(lines: int = 600) -> str:
        return "\n".join(f"const v{i} = '{'x' * 80}';" for i in range(1, lines + 1))

    def test_oversized_code_annotates_visible_range(self):
        code = self._long_code()
        prompt = build_review_prompt(code, "big.js", None, "[IMAGE]\nx\n[/IMAGE]")

        self.assertIn("复核可见范围", prompt)
        self.assertIn("严禁引用第", prompt)

    def test_out_of_range_matches_are_stripped(self):
        code = self._long_code()
        scan = {
            "matches": [
                {"rule_id": "RULE_VISIBLE", "line_number": 5, "severity": "critical"},
                {"rule_id": "RULE_HIDDEN", "line_number": 580, "severity": "critical"},
            ],
            "deterministic_verdict": {},
        }
        prompt = build_review_prompt(code, "big.js", scan, "[IMAGE]\nx\n[/IMAGE]")

        self.assertIn("RULE_VISIBLE", prompt)
        self.assertNotIn("RULE_HIDDEN", prompt, "看不见的行不得注入，否则复核只能凭空定性")

    def test_short_code_has_no_visibility_note(self):
        scan = {"matches": [{"rule_id": "R1", "line_number": 1, "severity": "high"}], "deterministic_verdict": {}}
        prompt = build_review_prompt("const a=1;", "x.js", scan, "[IMAGE]\nx\n[/IMAGE]")

        self.assertNotIn("复核可见范围", prompt)
        self.assertIn("R1", prompt)


class CoverageVisibilityTests(unittest.TestCase):
    """方案 D：小文件必须真正全文可见，预算与阈值不得再次漂移。"""

    def test_budget_covers_every_small_file(self):
        # 守卫常量关系：展示预算必须 >= 任何 <阈值 文件的标注后长度
        self.assertGreater(CODE_DISPLAY_BUDGET, SMALL_FILE_THRESHOLD)
        worst = 0
        for lines in (1, 50, 200, 400, 800, 1200):
            if lines >= SMALL_FILE_THRESHOLD:
                continue
            body = "\n".join("x" * max(1, (SMALL_FILE_THRESHOLD - lines) // lines)
                             for _ in range(lines))[:SMALL_FILE_THRESHOLD]
            worst = max(worst, len(code_visibility(body).display) if False else
                        len(code_visibility(body).display))
            self.assertFalse(
                code_visibility(body).truncated,
                f"{lines} 行的阈值内文件不应被截断",
            )
        self.assertLessEqual(worst, CODE_DISPLAY_BUDGET)

    def test_no_line_loss_for_typical_small_files(self):
        cases = [(10000, 200), (12000, 250), (14000, 300), (15300, 300), (9000, 1)]
        for size, lines in cases:
            avg = max(1, (size - lines) // lines)
            code = ("\n".join("x" * avg for _ in range(lines)))[:size]
            total = code.count("\n") + 1
            vis = code_visibility(code)
            self.assertFalse(vis.truncated, f"{size} 字符文件不应被截断")
            self.assertEqual(vis.total_lines, total)
            self.assertIn(f"[LINE_{total}]", vis.display, "末行必须可见")

    def test_single_line_overflow_is_flagged_not_silent(self):
        vis = code_visibility("A" * 40000)
        self.assertTrue(vis.truncated)
        self.assertTrue(vis.partial_last_line)
        self.assertEqual(vis.end_line, 1, "必须返回行号，杜绝'行数没超=全文可见'的误判")


class ChunkSplitTests(unittest.TestCase):
    def test_oversized_single_line_is_split(self):
        # 超长单行（混淆马一行流 payload）：不得再产出一个巨型 Chunk。
        # 断言改为"按 CHUNK_TARGET_MAX 推导"，不再写死具体段数 ——
        # 否则每次调整分片常量都会误报（2026-10-08 调整 CHUNK_TARGET_MAX 时踩过）。
        payload = "A" * 40000
        chunks = ChunkingPipeline.chunk_code(payload)
        self.assertGreater(len(chunks), 1, "40000 字符必须被切分")
        self.assertGreaterEqual(len(chunks), 40000 // CHUNK_TARGET_MAX,
                                "分片数不应少于总量/单片上限")
        for meta in chunks:
            # 允许重叠前缀（100~150 字符）与衔接注释带来的少量溢出
            self.assertLessEqual(len(meta.text), CHUNK_TARGET_MAX + 400)

    def test_chunk_size_respects_configured_bound(self):
        """分片尺寸必须跟随 CHUNK_TARGET_MAX，而不是固定值。"""
        chunks = ChunkingPipeline.chunk_code("B" * 40000)
        sizes = [len(m.text) for m in chunks]
        # 正常情况不应超过上限 + 重叠余量
        self.assertLessEqual(max(sizes), CHUNK_TARGET_MAX + 400)
        # 且不应远小于上限（否则说明上限没被真正使用）
        self.assertGreater(min(sizes), CHUNK_TARGET_MAX * 0.3)

    def test_normal_code_keeps_single_chunk(self):
        chunks = ChunkingPipeline.chunk_code("const a = 1;\nconst b = 2;")
        self.assertEqual(len(chunks), 1)

    def test_multi_line_large_file_is_still_covered(self):
        code = "\n".join(f"line{i} = '{'y' * 40}';" for i in range(600))
        chunks = ChunkingPipeline.chunk_code(code)
        self.assertGreater(len(chunks), 5)
        for meta in chunks:
            self.assertGreaterEqual(meta.start_line, 1)
            self.assertLessEqual(len(meta.text), CHUNK_TARGET_MAX + 400)


class SingleLineSliceMetadataTests(unittest.TestCase):
    """超长单行必须被标记为字符切片，且如实告知 prompt（2026-10-07 修复）。

    事故背景：单行文件的 29 个分片 start_line 全是 L1，旧 prompt 却写
    "本分片覆盖原始文件第 1–1 行"，模型据此编出 "L3–L221" 这种
    物理上不存在的行区间，并把它写进 counter_evidence 当作事实。
    """

    def test_single_line_file_is_flagged_as_char_slice(self):
        chunks = ChunkingPipeline.chunk_code("A" * 40000)
        self.assertGreater(len(chunks), 1)
        self.assertTrue(all(m.single_line_slice for m in chunks),
                        "超长单行必须标记为字符切片")
        self.assertEqual({m.start_line for m in chunks}, {1},
                         "单行文件所有分片行号都是 1（这正是必须显式告知模型的原因）")
        self.assertEqual([m.slice_index for m in chunks], list(range(len(chunks))))
        self.assertEqual({m.slice_total for m in chunks}, {len(chunks)})

    def test_multiline_file_is_not_flagged(self):
        code = "\n".join(f"line{i} = '{'y' * 40}';" for i in range(600))
        chunks = ChunkingPipeline.chunk_code(code)
        self.assertFalse(any(m.single_line_slice for m in chunks),
                         "多行文件的行号有效，不得标记为字符切片")
        self.assertTrue(all(m.slice_index == -1 and m.slice_total == -1 for m in chunks))

    def test_small_single_line_file_stays_whole(self):
        """未超预算的单行文件不分片，行号天然可用，不应标记切片。"""
        chunks = ChunkingPipeline.chunk_code("<?php echo 1;")
        self.assertEqual(len(chunks), 1)
        self.assertFalse(chunks[0].single_line_slice)

    def test_prompt_forbids_fabricated_line_numbers(self):
        chunks = ChunkingPipeline.chunk_code("A" * 40000)
        meta = chunks[2]
        prompt = build_chunk_prompt(
            meta.text, 2, len(chunks), "one.php", None,
            start_line=meta.start_line,
            single_line_slice=True, slice_index=meta.slice_index,
            slice_total=meta.slice_total,
        )
        self.assertIn("物理上只有 1 行", prompt)
        self.assertIn("严禁输出 L2/L64/L705 这类行号", prompt)
        self.assertIn(f"第 {meta.slice_index + 1}/{meta.slice_total} 片", prompt)
        # 不得再用"覆盖第 1–1 行"这类会误导模型的措辞
        self.assertNotIn("覆盖原始文件第", prompt)

    def test_prompt_multiline_keeps_line_coordinates(self):
        code = "\n".join(f"line{i} = '{'y' * 40}';" for i in range(600))
        chunks = ChunkingPipeline.chunk_code(code)
        prompt = build_chunk_prompt(chunks[0].text, 0, len(chunks), "m.php", None,
                                   start_line=chunks[0].start_line)
        self.assertIn("覆盖原始文件第", prompt)
        self.assertNotIn("物理上只有 1 行", prompt)

    def test_single_line_slice_keeps_regex_anchor(self):
        """单行切片不得把全文正则命中裁没（实测会退化成"未命中"）。"""
        scan = {"matches": [{"line_number": 1, "rule_id": "PHP-EXEC-001", "severity": "critical",
                             "category": "code_execution", "description": "eval", "matched_text": "eval("}],
                "total_matches": 1, "triggered_rules": ["PHP-EXEC-001"],
                "matches_by_category": {"code_execution": 1},
                "matches_by_severity": {"critical": 1},
                "critical_count": 1, "high_count": 0, "medium_count": 0, "low_count": 0,
                "language_hints": ["php"]}
        chunks = ChunkingPipeline.chunk_code("A" * 40000)
        meta = chunks[0]
        prompt = build_chunk_prompt(
            meta.text, 0, len(chunks), "one.php", scan,
            start_line=meta.start_line,
            single_line_slice=True, slice_index=meta.slice_index, slice_total=meta.slice_total,
        )
        self.assertIn("PHP-EXEC-001", prompt, "单行切片必须保留正则锚点")
        self.assertNotIn("未命中任何特征", prompt)


class MalwareFamilyBackfillTests(unittest.TestCase):
    """attack_profile.family 回填的回归测试。

    两次真实误判（2026-10-07 跑完样本后逐条复核发现）：
      1. 模型写"未见 Behinder 特征"（明确否定），却被回填成 Behinder
         —— 误判方向完全相反，等于把"认不出来"说成"就是冰蝎"。
      2. 模型写"类冰蝎/哥斯拉 WebShell 投递链路"（类比），被回填成具体家族。
    另有一个连带问题：值里带了 30+ 字描述，被整段塞进 family 字段。

    因此判定必须满足：**关键词出现在"家族名本体区"内**
    （剥掉括注、再取第一个分隔符之前），且该值不是否定式。
    """

    def _family_line(self, value):
        return f"[IMAGE]\n- **定性标签**：测试样本\n- **技术家族**：{value}\n[/IMAGE]"

    def test_known_family_is_extracted(self):
        self.assertEqual(extract_malware_family(self._family_line("Behinder / 冰蝎")), "Behinder")

    def test_family_in_name_zone_is_found(self):
        """本体区关键词必须命中：'Behinder / 冰蝎红队武器库' → Behinder。"""
        self.assertEqual(
            extract_malware_family(self._family_line("Behinder / 冰蝎红队武器库")), "Behinder")

    def test_negated_family_yields_empty(self):
        """'未见 Behinder' 是明确否定，绝不能回填成 Behinder。"""
        for value in (
            "无（未匹配冰蝎/哥斯拉/蚁剑等已知指纹）",
            "自定义 WebShell / 未知（未见 Behinder / Godzilla / AntSword 特征）",
            "未知",
            "无（通用 Java 工具类）",
        ):
            self.assertEqual(extract_malware_family(self._family_line(value)), "", value)

    def test_negation_inside_parenthetical_is_ignored(self):
        """否定词在括注里：本体是'自定义 APT'，不能被括注里的'冰蝎'带偏。"""
        self.assertEqual(
            extract_malware_family(self._family_line("自定义 APT/通用攻防后门（未匹配冰蝎/哥斯拉/蚁剑）")),
            "自定义 APT")

    def test_analogy_is_not_a_family_match(self):
        """'类冰蝎'是类比而非归属。"""
        self.assertEqual(
            extract_malware_family(self._family_line("自定义 APT / 红队武器工具，类冰蝎/哥斯拉 WebShell 投递链路")),
            "自定义 APT")

    def test_quoted_类_in_phrase_is_not_analogy(self):
        """'类"一句话木马"变种'里的'类'后接引号，不得被当成类比标记而误杀真值。"""
        self.assertEqual(
            extract_malware_family(
                self._family_line("自定义红队后门（类“一句话木马”变种，未匹配冰蝎/哥斯拉/蚁剑等已知指纹）")),
            "自定义红队后门")

    def test_family_value_is_trimmed_to_name(self):
        """family 必须收敛为名称本体，不能塞入长描述。"""
        got = extract_malware_family(self._family_line("Metasploit/自定义反向Shell"))
        self.assertEqual(got, "Metasploit")

    def test_qualitative_tag_does_not_leak_into_family(self):
        """'定性标签'里提到家族不算归属（它描述的是特征而非家族）。"""
        report = ("[IMAGE]\n- **定性标签**：内存马加载器（具备冰蝎/哥斯拉同类加密投递特征）\n"
                  "- **技术家族**：无\n[/IMAGE]")
        self.assertEqual(extract_malware_family(report), "")

    def test_empty_report_yields_empty(self):
        self.assertEqual(extract_malware_family(""), "")
        self.assertEqual(extract_malware_family("[IMAGE]\n无技术家族字段\n[/IMAGE]"), "")

    def test_only_image_section_is_scoped(self):
        report = ("[IMAGE]\n- **技术家族**：无\n[/IMAGE]\n"
                  "[PLAYBOOK]\n本特征与 Metasploit 家族一致\n[/PLAYBOOK]")
        self.assertEqual(extract_malware_family(report), "")


class SynthesisLineNumberTests(unittest.TestCase):
    """单行文件的行号约束必须覆盖**三处**，缺一就会被编造（2026-10-07 两次踩坑）。

    事故经过：
      1. 只改分片 prompt → 综合报告仍出现 L66/L396/L482（综合阶段没约束）
      2. 分片+综合都加了声明 → 仍出现 L2/L64/L705，
         根因是 SYSTEM_PROMPT 里三处"必须输出行号"是无条件强制，
         与单行声明相互矛盾，模型选了"照规约办事"。
         修复= 在 SYSTEM_PROMPT 增加一条更高优先级的行号铁律。
    """

    def _chunk(self, idx=0, total=29):
        return build_chunk_prompt(
            "x" * 100, idx, total, "huge.php", None,
            start_line=1, single_line_slice=True,
            slice_index=idx, slice_total=total,
        )

    def test_synthesis_prompt_declares_single_line(self):
        findings = [(0, "[IMAGE]\n- **技术家族**：Behinder\n[/IMAGE]")]
        prompt = build_synthesis_prompt("one.php", 45753, findings, None,
                                       single_line_slice=True)
        self.assertIn("物理上只有 1 行", prompt)
        self.assertIn("严禁把分片编号写成行号", prompt)
        self.assertIn("第一列不得填行号", prompt)
        self.assertNotIn("每行 [LINE_X] 是绝对物理行号坐标", prompt)

    def test_synthesis_prompt_normal_file_keeps_line_coords(self):
        findings = [(0, "[IMAGE]\n- **技术家族**：Behinder\n[/IMAGE]")]
        prompt = build_synthesis_prompt("multi.php", 8000, findings, None,
                                       single_line_slice=False)
        self.assertIn("每行 [LINE_X] 是绝对物理行号坐标", prompt)
        self.assertNotIn("物理上只有 1 行", prompt)

    def test_chunk_prompt_forbids_fabricated_lines(self):
        """分片阶段必须点名禁止具体形态（L2/L64/L705），比抽象禁令更有效。"""
        prompt = self._chunk()
        self.assertIn("物理上只有 1 行", prompt)
        self.assertIn("严禁输出 L2/L64/L705 这类行号", prompt)
        self.assertIn("第一列不得填行号", prompt)
        self.assertNotIn("覆盖原始文件第", prompt,
                         "单行切片不得再出现'覆盖第 X–Y 行'这类措辞")

    def test_system_prompt_has_line_number_ironclad_rule(self):
        """SYSTEM_PROMPT 必须有一条优先级高于"必须输出行号"的例外。"""
        self.assertIn("行号引用铁律", SYSTEM_PROMPT)
        self.assertIn("只有 1 行", SYSTEM_PROMPT)
        self.assertIn("凭空编造", SYSTEM_PROMPT)
        # 该铁律必须声明覆盖前面所有行号要求，否则会被规约 3 的强制要求压过
        idx = SYSTEM_PROMPT.find("行号引用铁律")
        rule = SYSTEM_PROMPT[idx:idx + 700]
        self.assertIn("覆盖本规约里所有", rule)

    def test_single_line_table_format_is_exemplified(self):
        """单行场景必须给出**可照抄的表格写法**，否则模型只会照抄多行的 `L18 ||` 示例。

        事故：加完铁律后 L64/L705 消失了，但 METADATA_BEHAVIOR 仍写 `L2 || ...`（5 处）。
        根因是规约与模板里的示例全是多行场景（`L18 ||`/`L24 ||`），
        单行场景没有给替代示范 —— 只说"不要写行号"不足以让模型改变输出格式。
        """
        idx = SYSTEM_PROMPT.find("单行代码（物理上仅 1 行）的表格写法")
        self.assertNotEqual(idx, -1, "必须给出单行场景的表格写法示例")
        sample = SYSTEM_PROMPT[idx:idx + 400]
        self.assertIn("第1/29 片 ||", sample, "必须提供可直接照抄的单行表格示例")
        self.assertIn("严禁写成 `L2 ||", sample)

    def test_template_section_has_single_line_example(self):
        """输出模板段也要有单行示例（三处保持一致，避免模型只看到多行示例）。"""
        idx = SYSTEM_PROMPT.find("[METADATA_BEHAVIOR]\n### 🔒")
        if idx < 0:
            idx = SYSTEM_PROMPT.find("### 🔒 核心威胁特征总结")
        block = SYSTEM_PROMPT[idx:idx + 1600]
        self.assertIn("单行代码（物理仅 1 行）例外", block)
        self.assertIn("第1/29 片 ||", block)


if __name__ == "__main__":
    unittest.main()
