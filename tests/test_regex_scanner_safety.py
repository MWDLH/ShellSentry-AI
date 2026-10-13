import time
import unittest

from shellsentry.core.regex_scanner import (
    RegexScanner,
    _taint_is_scope_boundary,
    _pattern_exceeds_overlap,
    _FULL_LINE_RULE_IDS,
    build_highlight_hints,
    LONG_LINE_WINDOW,
)


class ScopeBoundaryTests(unittest.TestCase):
    """return/new 语句不得被当作作用域边界（否则清空污点、漏标 external，P1-7）。"""

    def test_statement_lines_are_not_boundaries(self):
        for line in ["return foo(a);", "new Foo();", "throw new RuntimeException(x);", "if (x) {"]:
            self.assertFalse(_taint_is_scope_boundary(line), line)

    def test_real_definitions_are_boundaries(self):
        for line in ["public void run() {", "def foo():", "class A {", "}", "function f() {"]:
            self.assertTrue(_taint_is_scope_boundary(line), line)


class LongLineSafetyTests(unittest.TestCase):
    """超长单行不得触发灾难性回溯 / 跨窗漏检（P1-6、P1-8）。"""

    def test_word_run_without_delimiter_is_fast(self):
        code = "a=" + "B" * 40000          # 修复前 _STRING_ASSIGN_RE/_TAINT_METHOD_DEF_RE ~10s
        start = time.perf_counter()
        RegexScanner.scan(code, "x.php")
        build_highlight_hints(code, [])
        self.assertLess(time.perf_counter() - start, 5.0)

    def test_long_span_pattern_detected_across_window_gap(self):
        # 1100 字符引号载荷，起点落在窗口重叠无法覆盖的间隙 → 修复前漏检、修复后命中
        blob = '"' + "-" * 1100 + '"'
        code = " " * 1300 + blob + " " * 3000
        ids = {m.rule_id for m in RegexScanner.scan(code, "x.php").matches}
        self.assertIn("OBF-002", ids)

    def test_pattern_exceeds_overlap_classifier(self):
        self.assertTrue(_pattern_exceeds_overlap(r"['\"][\x21-\x7E]{1000,}['\"]"))
        self.assertTrue(_pattern_exceeds_overlap(r"['\"][0-9A-Fa-f]{64,}['\"]"))
        self.assertFalse(_pattern_exceeds_overlap(r"['\"][A-Za-z0-9+/=_-]{8,128}['\"]"))
        self.assertFalse(_pattern_exceeds_overlap(r"[\w<>\[\]?]{1,120}"))

    def test_expected_full_line_rules_flagged(self):
        self.assertTrue({"OBF-002", "OBF-005", "OBF-009"}.issubset(_FULL_LINE_RULE_IDS))


if __name__ == "__main__":
    unittest.main()
