"""base_url 归一化与网关请求头（2026-10-09 修复）。

事故：用户配置 OpenCode 网关后「测试联通」一直 404。
实测定位到三个叠加原因：
  1. Base URL 填成了完整端点 https://opencode.ai/zen/go/v1/chat/completions，
     而 OpenAI SDK 会再拼一次 /chat/completions
     → 实际请求 .../chat/completions/chat/completions → **404**
  2. 未设置浏览器 UA，被 Cloudflare 拦截 → **403 error code 1010**
     （实测同一把key，带 UA 返回 200 能拉到模型列表）
  3. OpenCode Go 还要求 x-opencode-session，缺失 → 400 MissingSessionID

前两条已在本模块修复，第三条由 default_headers_for 按域名补齐。
"""
import unittest

from shellsentry.config import default_headers_for, normalize_base_url


class NormalizeBaseUrlTests(unittest.TestCase):
    def test_plain_root_unchanged(self):
        self.assertEqual(normalize_base_url("https://api.deepseek.com"), "https://api.deepseek.com")

    def test_trailing_slash_stripped(self):
        self.assertEqual(normalize_base_url("https://api.deepseek.com/"), "https://api.deepseek.com")

    def test_versioned_path_preserved(self):
        """带 /v1 的根路径必须保留 —— 不能把版本号也剥掉。"""
        self.assertEqual(normalize_base_url("https://opencode.ai/zen/go/v1"), "https://opencode.ai/zen/go/v1")

    def test_full_endpoint_tail_removed(self):
        """核心修复：填了完整端点也能工作（原来必然 404）。"""
        self.assertEqual(
            normalize_base_url("https://opencode.ai/zen/go/v1/chat/completions"),
            "https://opencode.ai/zen/go/v1",
        )

    def test_other_endpoint_tails_removed(self):
        for tail in ("completions", "responses", "messages", "embeddings", "models"):
            self.assertEqual(
                normalize_base_url(f"https://host/v1/{tail}"), "https://host/v1", tail)

    def test_whitespace_and_case_insensitive(self):
        self.assertEqual(
            normalize_base_url("  https://host/v1/Chat/Completions/  "), "https://host/v1")

    def test_repeated_endpoint_is_fully_stripped(self):
        """重复填写（用户复制粘贴出错）也能救回，不留残段。"""
        self.assertEqual(
            normalize_base_url("https://host/v1/chat/completions/chat/completions"),
            "https://host/v1",
        )

    def test_empty_input(self):
        self.assertEqual(normalize_base_url(""), "")
        self.assertEqual(normalize_base_url(None), "")


class GatewayHeaderTests(unittest.TestCase):
    def test_browser_ua_always_present(self):
        """所有网关都补浏览器 UA —— 对官方 API 无副作用。"""
        for url in ("https://api.deepseek.com", "https://api.openai.com/v1", "http://127.0.0.1:11434/v1"):
            self.assertIn("User-Agent", default_headers_for(url), url)

    def test_opencode_requires_session_header(self):
        """OpenCode Go 缺 x-opencode-session 会返回 400 MissingSessionID。"""
        self.assertIn("x-opencode-session", default_headers_for("https://opencode.ai/zen/go/v1"))

    def test_other_gateways_have_no_session_header(self):
        """非 OpenCode 网关不应被塞进无关的请求头。"""
        self.assertNotIn("x-opencode-session", default_headers_for("https://api.deepseek.com"))

    def test_session_id_is_unique_per_call(self):
        a = default_headers_for("https://opencode.ai/zen/go/v1")["x-opencode-session"]
        b = default_headers_for("https://opencode.ai/zen/go/v1")["x-opencode-session"]
        self.assertNotEqual(a, b, "每次请求应为独立会话，否则网关无法正确路由")


class ConnectivityUsesNormalizedUrlTests(unittest.TestCase):
    def test_test_connectivity_normalizes_before_use(self):
        """回归：test_connectivity 必须归一化，否则修复形同虚设。"""
        import inspect

        from shellsentry.config import ApiConfigManager
        src = inspect.getsource(ApiConfigManager.test_connectivity)
        self.assertIn("normalize_base_url", src)
        self.assertIn("default_headers_for", src)


if __name__ == "__main__":
    unittest.main()