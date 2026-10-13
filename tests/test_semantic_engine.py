import json
import unittest

from shellsentry.core.ai_client import SemanticEngine


REPORT = """[IMAGE]
- result
[/IMAGE]
[DE_OBFUSCATE]
const x = location.hash;
[/DE_OBFUSCATE]
[C2_INFO]
None
[/C2_INFO]
[METADATA_BEHAVIOR]
### result
[/METADATA_BEHAVIOR]
[PLAYBOOK]
None
[/PLAYBOOK]"""


class FakeClient:
    is_configured = True
    last_stream_truncated = False

    def __init__(self, review):
        self.review = review

    # 采样参数（temperature/max_tokens）由编排层显式下发，此处透传记录以便断言
    def __init__(self, review):
        self.review = review
        self.stream_kwargs = {}
        self.chat_kwargs = {}

    async def chat_stream(self, messages, **kwargs):
        self.stream_kwargs = kwargs
        yield REPORT

    async def chat(self, messages, **kwargs):
        self.chat_kwargs = kwargs
        return self.review


class SemanticEngineTests(unittest.IsolatedAsyncioTestCase):
    async def _collect(self, review):
        engine = SemanticEngine({"api_key": "test-only"})
        engine.client = FakeClient(review)
        static_result = {
            "deterministic_verdict": {
                "verdict": "suspicious",
                "risk_score": 72,
                "confidence": 0.72,
                "reason": "DOM XSS behavior chain",
            },
            "matches": [],
            "summary": "test",
        }
        events = []
        async for event in engine.audit_stream(
            "const x=location.hash; document.body.innerHTML=x;",
            "xss.js",
            static_result,
        ):
            events.append(event)
        return "".join(events)

    async def test_emits_agent_verdict_and_done(self):
        review = json.dumps({
            "verdict": "malicious",
            "confidence": 0.91,
            "artifact_type": "vulnerable_source",
            "summary": "DOM XSS",
            "behavior_chain": ["location.hash", "innerHTML"],
            "evidence": ["L1 source and sink"],
            "counter_evidence": [],
            "uncertainties": [],
        })

        stream = await self._collect(review)

        self.assertIn("event: verdict", stream)
        self.assertIn('"verdict": "malicious"', stream)
        self.assertIn("event: done", stream)

    async def test_invalid_review_falls_back_to_static_verdict(self):
        stream = await self._collect("not json")

        self.assertIn("event: verdict", stream)
        self.assertIn('"verdict": "suspicious"', stream)
        self.assertIn("event: done", stream)


if __name__ == "__main__":
    unittest.main()