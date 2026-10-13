import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient
from shellsentry.web import app as web_app


class HistoryRenameTests(unittest.TestCase):
    def test_rename_only_changes_display_name(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            history_dir = Path(temp_dir)
            record_path = history_dir / "task-123.json"
            original = {
                "task_id": "task-123",
                "filename": "original.jsp",
                "timestamp": "2026-08-11T10:00:00",
                "report": {"summary": "kept"},
            }
            record_path.write_text(json.dumps(original), encoding="utf-8")
            with patch.object(web_app, "HISTORY_DIR", history_dir):
                client = TestClient(web_app.app)
                response = client.patch("/api/history/task-123", json={"name": "核心样本复核"})
                listing = client.get("/api/history").json()

            self.assertEqual(response.status_code, 200)
            saved = json.loads(record_path.read_text(encoding="utf-8"))
            self.assertEqual(saved["display_name"], "核心样本复核")
            self.assertEqual(saved["filename"], "original.jsp")
            self.assertEqual(saved["report"], {"summary": "kept"})
            self.assertEqual(listing[0]["display_name"], "核心样本复核")

    def test_rename_rejects_empty_name(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            history_dir = Path(temp_dir)
            (history_dir / "task-123.json").write_text(
                json.dumps({"task_id": "task-123", "filename": "a.jsp"}), encoding="utf-8"
            )
            with patch.object(web_app, "HISTORY_DIR", history_dir):
                response = TestClient(web_app.app).patch("/api/history/task-123", json={"name": "  "})
            self.assertEqual(response.status_code, 400)


class HistoryTraversalTests(unittest.TestCase):
    """task_id 必须限定为安全字符集，禁止越权读取/删除数据目录外的文件（P0-2）。"""

    def _setup(self, temp_dir):
        root = Path(temp_dir)
        history_dir = root / "history"
        history_dir.mkdir()
        secret = root / "config.json"
        secret.write_text(json.dumps({"api_key": "sk-secret-do-not-leak"}), encoding="utf-8")
        return history_dir, secret

    def test_get_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            history_dir, secret = self._setup(temp_dir)
            with patch.object(web_app, "HISTORY_DIR", history_dir):
                response = TestClient(web_app.app).get("/api/history/..%5Cconfig")
            self.assertEqual(response.status_code, 400)
            self.assertNotIn("sk-secret-do-not-leak", response.text)

    def test_delete_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            history_dir, secret = self._setup(temp_dir)
            with patch.object(web_app, "HISTORY_DIR", history_dir):
                response = TestClient(web_app.app).delete("/api/history/..%5Cconfig")
            self.assertEqual(response.status_code, 400)
            self.assertTrue(secret.exists(), "越界目标文件不应被删除")

    def test_rename_rejects_path_traversal(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            history_dir, _ = self._setup(temp_dir)
            with patch.object(web_app, "HISTORY_DIR", history_dir):
                response = TestClient(web_app.app).patch("/api/history/..%5Cconfig", json={"name": "x"})
            self.assertEqual(response.status_code, 400)

    def test_get_valid_id_still_works(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            history_dir = Path(temp_dir)
            (history_dir / "task-abc.json").write_text(
                json.dumps({"task_id": "task-abc", "filename": "ok.jsp"}), encoding="utf-8"
            )
            with patch.object(web_app, "HISTORY_DIR", history_dir):
                response = TestClient(web_app.app).get("/api/history/task-abc")
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json()["filename"], "ok.jsp")


if __name__ == "__main__":
    unittest.main()
