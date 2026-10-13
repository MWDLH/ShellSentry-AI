"""P1-3 判定融合：静态证据与模型结论冲突时的对称降级。"""

import unittest

from shellsentry.core.models import AgentVerdict, DeterministicVerdict, fuse_verdicts


def _agent(verdict, confidence=0.85, **kwargs):
    return AgentVerdict(verdict=verdict, confidence=confidence, model_reviewed=True, **kwargs)


class DeterministicOnlyTests(unittest.TestCase):
    def test_without_model_review_returns_static(self):
        det = DeterministicVerdict("suspicious", 55, 0.70, "静态理由")
        fused = fuse_verdicts(det, None)
        self.assertEqual(fused.verdict, "suspicious")
        self.assertEqual(fused.confidence, 0.70)
        self.assertEqual(fused.summary, "静态理由")

    def test_unreviewed_agent_is_ignored(self):
        det = DeterministicVerdict("malicious", 90, 0.90, "高置信")
        fused = fuse_verdicts(det, AgentVerdict("benign", 0.9, model_reviewed=False))
        self.assertEqual(fused.verdict, "malicious")


class SymmetricDowngradeTests(unittest.TestCase):
    """模型判清白而静态有可疑证据时，静态证据不得被完全丢弃。"""

    def test_static_suspicious_vs_model_benign(self):
        det = DeterministicVerdict("suspicious", 62, 0.70, "命中 3 条中危规则")
        fused = fuse_verdicts(det, _agent("benign", 0.88))

        self.assertEqual(fused.verdict, "suspicious")
        self.assertTrue(any("静态层结论为 suspicious" in u for u in fused.uncertainties))
        self.assertTrue(any("命中 3 条中危规则" in e for e in fused.evidence), fused.evidence)

    def test_static_malicious_low_confidence_vs_model_benign(self):
        det = DeterministicVerdict("malicious", 78, 0.70, "命中 2 条严重规则")
        fused = fuse_verdicts(det, _agent("benign", 0.90))

        self.assertEqual(fused.verdict, "suspicious")
        self.assertTrue(any("命中 2 条严重规则" in e for e in fused.evidence))

    def test_model_unknown_also_preserves_static_evidence(self):
        det = DeterministicVerdict("suspicious", 60, 0.65, "可疑")
        fused = fuse_verdicts(det, _agent("unknown", 0.30))
        self.assertEqual(fused.verdict, "suspicious")

    def test_confidence_floor_for_suspicious(self):
        det = DeterministicVerdict("suspicious", 62, 0.70, "可疑")
        fused = fuse_verdicts(det, _agent("benign", 0.20))
        self.assertGreaterEqual(fused.confidence, 0.60)


class PreservedBehaviourTests(unittest.TestCase):
    """既有融合语义必须保持不变（回归保护）。"""

    def test_high_confidence_static_malicious_vs_model_benign(self):
        det = DeterministicVerdict("malicious", 92, 0.90, "高置信")
        fused = fuse_verdicts(det, _agent("benign", 0.40))
        self.assertEqual(fused.verdict, "suspicious")
        self.assertGreaterEqual(fused.confidence, 0.72)

    def test_strong_model_vs_empty_static(self):
        det = DeterministicVerdict("no_indication", 0, 0.90, "无命中")
        fused = fuse_verdicts(det, _agent("malicious", 0.90, evidence=["反射加载"]))
        self.assertEqual(fused.verdict, "malicious")

    def test_static_malicious_upgrades_model_suspicious(self):
        det = DeterministicVerdict("malicious", 88, 0.80, "严重")
        fused = fuse_verdicts(det, _agent("suspicious", 0.50))
        self.assertEqual(fused.verdict, "malicious")

    def test_consistent_benign_is_untouched(self):
        det = DeterministicVerdict("benign", 5, 0.95, "无异常")
        fused = fuse_verdicts(det, _agent("benign", 0.92))
        self.assertEqual(fused.verdict, "benign")
        self.assertEqual(fused.uncertainties, [])

    def test_consistent_malicious_gains_no_spurious_evidence(self):
        det = DeterministicVerdict("malicious", 90, 0.90, "严重")
        fused = fuse_verdicts(det, _agent("malicious", 0.95, evidence=["x"]))
        self.assertEqual(fused.evidence, ["x"])


if __name__ == "__main__":
    unittest.main()
