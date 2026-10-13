"""前端构建指纹的回归测试。

背景：这套指纹此前零测试覆盖。曾经因为 fingerprint 清单漏掉 app.css，
导致改了样式 build 号却不变，用户侧表现为"改了没生效"，排查成本很高。
这里把"文件变动必须反映到 build 号"、"页面内所有静态引用都必须带版本号"
固化成断言。
"""
import re
import tempfile
import unittest
from pathlib import Path

from shellsentry.web import app as web_app


def _refs(html: str):
    return re.findall(r'["\'](/static/[^"\']+)["\']', html)


class FrontendBuildTests(unittest.TestCase):
    def _build_page(self):
        html = web_app.render_index()
        tag = web_app.frontend_build_tag()
        return html, tag

    def test_index_injects_build_meta(self):
        html, tag = self._build_page()
        meta = re.search(r'<meta name="shellsentry-frontend-build" content="([^"]+)"', html)

        self.assertIsNotNone(meta, "必须注入构建指纹 meta，否则前端自检恒为 unknown")
        self.assertEqual(meta.group(1), tag)
        self.assertNotEqual(tag, "", "指纹不得为空")

    def test_every_static_reference_carries_version(self):
        html, tag = self._build_page()
        refs = _refs(html)

        self.assertTrue(refs, "未找到任何静态引用，正则可能失效")
        for ref in refs:
            self.assertIn(f"?v={tag}", ref, f"缺少版本参数：{ref}")

    def test_stylesheet_is_versioned(self):
        """回归防护：早期只给 app.js 加版本号，漏掉 app.css 导致样式"改了不生效"。"""
        html, tag = self._build_page()
        css_refs = [r for r in _refs(html) if r.endswith(".css?v=" + tag)]

        self.assertTrue(css_refs, f"样式表未被加版本号（app.css 曾漏网）：{_refs(html)}")

    def test_tag_is_stable_without_changes(self):
        self.assertEqual(web_app.frontend_build_tag(), web_app.frontend_build_tag())

    def test_tag_changes_when_file_touched(self):
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            target = root_path / "styles" / "app.css"
            target.parent.mkdir(parents=True)
            target.write_text("body{}", encoding="utf-8")

            before = web_app.frontend_build_tag(root_path)
            # 仅改 mtime、内容不变：指纹必须变化，否则"改了但没生效"无法被察觉
            target.touch()
            import os

            os.utime(target, (1_700_000_100, 1_700_000_100))
            after = web_app.frontend_build_tag(root_path)

            self.assertNotEqual(before, after, "mtime 变化必须产生新指纹")

    def test_new_file_changes_tag(self):
        """新增脚本也要改变指纹 —— 硬编码清单时代的典型失效方式。"""
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            (root_path / "scripts").mkdir()
            (root_path / "scripts" / "app.js").write_text("console.log(1)", encoding="utf-8")

            before = web_app.frontend_build_tag(root_path)
            (root_path / "scripts" / "brand-new.js").write_text("export {};", encoding="utf-8")
            after = web_app.frontend_build_tag(root_path)

            self.assertNotEqual(before, after, "新增静态文件必须产生新指纹")

    def test_cache_busting_is_idempotent(self):
        html = '<link rel="stylesheet" href="/static/styles/app.css">'
        once = web_app._cache_bust_html(html, "aaa")
        twice = web_app._cache_bust_html(once, "bbb")

        self.assertIn("?v=aaa", once)
        self.assertIn("?v=bbb", twice)
        self.assertNotIn("aaa", twice, "重复调用不得叠加出多个版本号")

    def test_served_page_matches_render(self):
        from fastapi.testclient import TestClient

        client = TestClient(web_app.app)
        response = client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("shellsentry-frontend-build", response.text)
        self.assertEqual(
            response.headers.get("cache-control"),
            "no-store, must-revalidate",
            "首页必须禁用缓存，否则修复难以即时生效",
        )


if __name__ == "__main__":
    unittest.main()
