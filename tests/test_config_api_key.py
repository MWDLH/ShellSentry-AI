import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from shellsentry import config as config_module
from shellsentry.config import ApiConfig, ApiConfigManager, is_masked_api_key
from shellsentry.web import app as web_app


REAL_KEY = "sk-realsecret-key-123456"


def _seed(config_path, key=REAL_KEY, name="T"):
    cfg = ApiConfig.create_new(name=name, base_url="https://api.example.com/v1",
                               api_key=key, model_name="m")
    cfg.enabled = True
    ApiConfigManager.save(cfg)
    return cfg


class ConfigApiKeyTests(unittest.TestCase):
    """编辑配置时不得用掩码/空值覆盖已保存的真实 Key（P0-1）。"""

    def test_edit_with_blank_key_keeps_stored_key(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(config_module, "CONFIG_FILE", Path(temp_dir) / "api_config.json"):
                cfg = _seed(Path(temp_dir) / "api_config.json")
                client = TestClient(web_app.app)
                response = client.post("/api/config/llm", json={
                    "id": cfg.id, "name": "T2",
                    "base_url": "https://api.example.com/v1",
                    "api_key": "", "model_name": "m",
                })
                self.assertEqual(response.status_code, 200)
                stored = ApiConfigManager.get_by_id(cfg.id)
                self.assertEqual(stored.api_key, REAL_KEY)
                self.assertEqual(stored.name, "T2")
                # 响应体绝不能回吐真实 Key
                self.assertNotIn("secret", json.dumps(response.json(), ensure_ascii=False))

    def test_edit_with_masked_placeholder_keeps_stored_key(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(config_module, "CONFIG_FILE", Path(temp_dir) / "api_config.json"):
                cfg = _seed(Path(temp_dir) / "api_config.json")
                masked = cfg.to_safe_dict()["api_key"]
                self.assertTrue(is_masked_api_key(masked))  # 掩码确实被判定为掩码
                client = TestClient(web_app.app)
                response = client.post("/api/config/llm", json={
                    "id": cfg.id, "name": "T",
                    "base_url": "https://api.example.com/v1",
                    "api_key": masked, "model_name": "m",
                })
                self.assertEqual(response.status_code, 200)
                self.assertEqual(ApiConfigManager.get_by_id(cfg.id).api_key, REAL_KEY)

    def test_edit_with_new_key_updates_it(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(config_module, "CONFIG_FILE", Path(temp_dir) / "api_config.json"):
                cfg = _seed(Path(temp_dir) / "api_config.json")
                client = TestClient(web_app.app)
                response = client.post("/api/config/llm", json={
                    "id": cfg.id, "name": "T",
                    "base_url": "https://api.example.com/v1",
                    "api_key": "sk-brand-new-key-999", "model_name": "m",
                })
                self.assertEqual(response.status_code, 200)
                self.assertEqual(ApiConfigManager.get_by_id(cfg.id).api_key, "sk-brand-new-key-999")

    def test_new_config_with_blank_key_rejected(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(config_module, "CONFIG_FILE", Path(temp_dir) / "api_config.json"):
                client = TestClient(web_app.app)
                response = client.post("/api/config/llm", json={
                    "id": "", "name": "new",
                    "base_url": "https://api.example.com/v1",
                    "api_key": "", "model_name": "m",
                })
                self.assertEqual(response.status_code, 400)

    def test_is_masked_api_key(self):
        self.assertTrue(is_masked_api_key("sk-r****3456"))
        self.assertTrue(is_masked_api_key("****"))
        self.assertFalse(is_masked_api_key(""))
        self.assertFalse(is_masked_api_key(REAL_KEY))


if __name__ == "__main__":
    unittest.main()
