import unittest

from fastapi.testclient import TestClient

from shellsentry.web import app as web_app
from shellsentry.web.task_state import task_state_manager


class TaskCancelTests(unittest.TestCase):
    """取消任务端点：必须在"有任务运行时"也能释放锁（不走 423 守卫）。"""

    def tearDown(self):
        task_state_manager.unlock()   # 防止用例间互相污染

    def test_cancel_with_no_active_task(self):
        task_state_manager.unlock()
        resp = TestClient(web_app.app).post("/api/task/cancel")
        self.assertEqual(resp.status_code, 200)
        self.assertFalse(resp.json()["cancelled"])

    def test_cancel_releases_active_lock(self):
        task_state_manager.lock("t-cancel", {"base_url": "http://x/v1", "api_key": "k", "model_name": "m"})
        self.assertTrue(task_state_manager.is_locked())

        resp = TestClient(web_app.app).post("/api/task/cancel").json()

        self.assertTrue(resp["cancelled"])
        self.assertEqual(resp["task_id"], "t-cancel")
        self.assertFalse(task_state_manager.is_locked())


if __name__ == "__main__":
    unittest.main()
