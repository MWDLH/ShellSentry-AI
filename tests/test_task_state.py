"""P2-4 任务状态锁：并发拒绝、配置快照归属、超时清理。"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from shellsentry.web.task_state import TaskStateManager


class TestConcurrentLock(unittest.TestCase):
    def setUp(self):
        self.mgr = TaskStateManager()

    def tearDown(self):
        self.mgr.unlock()

    def test_second_lock_rejected_while_running(self):
        self.assertIsNotNone(self.mgr.lock("A", {"model": "gpt-a"}))
        self.assertIsNone(self.mgr.lock("B", {"model": "gpt-b"}),
                          "运行中任务未结束时应拒绝新锁定")

    def test_config_snapshot_stays_with_owner(self):
        """核心修复点：被拒绝的并发锁不得篡改运行中任务的配置快照。"""
        self.mgr.lock("A", {"model": "gpt-a"})
        self.mgr.lock("B", {"model": "gpt-b"})
        self.assertEqual(self.mgr.get_config_snapshot(), {"model": "gpt-a"})

    def test_lock_available_again_after_unlock(self):
        self.mgr.lock("A", {})
        self.assertTrue(self.mgr.unlock("A"))
        self.assertIsNotNone(self.mgr.lock("B", {}))

    def test_timed_out_task_is_reclaimed(self):
        first = self.mgr.lock("A", {})
        first.locked_at -= 10_000  # 模拟远超 TTL
        self.assertIsNotNone(self.mgr.lock("B", {}), "超时任务应被自动清理")

    def test_unlock_rejects_foreign_task_id(self):
        self.mgr.lock("A", {})
        self.assertFalse(self.mgr.unlock("B"), "非持有者不得解锁")

    def test_sequential_tasks_all_acquire_lock(self):
        for task_id in ("A", "B", "C"):
            self.assertIsNotNone(self.mgr.lock(task_id, {}))
            self.assertTrue(self.mgr.unlock(task_id))


if __name__ == "__main__":
    unittest.main()
