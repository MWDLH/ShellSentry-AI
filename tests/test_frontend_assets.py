import unittest
from html.parser import HTMLParser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "src" / "shellsentry" / "web" / "static"


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.assets = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if values.get("id"):
            self.ids.append(values["id"])
        asset = values.get("src") or values.get("href")
        if asset:
            self.assets.append(asset)


class FrontendAssetTests(unittest.TestCase):
    def test_workspace_has_unique_ids_and_local_assets(self):
        parser = _PageParser()
        parser.feed((STATIC / "index.html").read_text(encoding="utf-8"))

        self.assertEqual(len(parser.ids), len(set(parser.ids)))
        self.assertIn("workbench", parser.ids)
        self.assertIn("settingsDrawer", parser.ids)
        for section_id in ("intentSection", "restorationSection", "analysisSection", "responseSection"):
            self.assertIn(section_id, parser.ids)
        self.assertIn("clearHistoryButton", parser.ids)
        for asset in parser.assets:
            if asset.startswith("/static/"):
                self.assertTrue((STATIC.parent / asset.lstrip("/")).is_file(), asset)

    def test_frontend_uses_modular_local_resources(self):
        parser = _PageParser()
        parser.feed((STATIC / "index.html").read_text(encoding="utf-8"))

        self.assertIn("/static/scripts/app.js", parser.assets)
        self.assertIn("/static/vendor/lucide.min.js", parser.assets)
        self.assertFalse(any(asset.startswith(("http://", "https://")) for asset in parser.assets))

    def test_report_layout_uses_exclusive_sections_and_deobfuscation(self):
        html = (STATIC / "index.html").read_text(encoding="utf-8")
        self.assertEqual(html.count('data-section-tab="'), 4)
        self.assertEqual(html.count('data-section-panel="'), 4)
        self.assertIn("代码反混淆", html)
        self.assertIn("威胁溯源", html)
        self.assertIn("攻击路径模拟", html)
        self.assertEqual(html.count('class="response-index"'), 4)
        self.assertNotIn('id="copyResponseButton"', html)
        self.assertNotIn('data-code-tab="original"', html)


if __name__ == "__main__":
    unittest.main()
