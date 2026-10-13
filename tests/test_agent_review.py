import unittest

from shellsentry.core.agent_review import REVIEW_SYSTEM_PROMPT, parse_agent_verdict


class AgentReviewTests(unittest.TestCase):
    def test_parses_fenced_json_and_clamps_confidence(self):
        verdict = parse_agent_verdict(
            '```json\n{"verdict":"malicious","confidence":1.7,"artifact_type":"attack_payload",'
            '"summary":"xss", "behavior_chain":[], "evidence":["L1"], '
            '"counter_evidence":[], "uncertainties":[]}\n```'
        )
        self.assertEqual(verdict.verdict, "malicious")
        self.assertEqual(verdict.confidence, 1.0)
        self.assertTrue(verdict.model_reviewed)

    def test_invalid_output_is_unknown(self):
        verdict = parse_agent_verdict("not json")
        self.assertEqual(verdict.verdict, "unknown")
        self.assertFalse(verdict.model_reviewed)

    def test_prompt_explicitly_controls_false_positives(self):
        self.assertIn("降低误报", REVIEW_SYSTEM_PROMPT)
        self.assertIn("正则命中只是线索", REVIEW_SYSTEM_PROMPT)
        self.assertIn("不得捏造", REVIEW_SYSTEM_PROMPT)


if __name__ == "__main__":
    unittest.main()
