#!/usr/bin/env python3
"""
ShellSentry-AI 任务状态管理器 v1.0
================================
服务端内存级活跃审计任务状态机。

核心功能：
  - 审计期间锁定 API 配置变更（防并发修改导致审计数据不一致）
  - API 配置快照（审计启动时冻结配置，期间侧边栏变更不影响进行中任务）
  - 超时熔断自动解锁（4 分钟 TTL，防死锁与内存泄漏）
  - 活跃任务追踪与状态查询

设计约束：
  - 全局单例（单进程 FastAPI 内足够）
  - 所有异步流/网络调用必须由调用方用 try-finally 包裹，确保解锁
  - 超时检测在每次 API 入口调用 is_locked() 时触发，无需后台线程
"""
import time
from typing import Optional, Dict, Any
from dataclasses import dataclass

# ============================================================
# 配置
# ============================================================
TASK_TIMEOUT_SECONDS = 240  # 4 分钟超时熔断（大模型审计最长等待）


@dataclass
class TaskState:
    """单个审计任务的运行时状态"""
    task_id: str
    status: str = "idle"        # idle | running | completed | failed | timeout | preempted
    api_config_snapshot: Optional[Dict[str, str]] = None
    locked_at: float = 0.0
    timeout_seconds: int = TASK_TIMEOUT_SECONDS

    @property
    def elapsed(self) -> float:
        """已锁定秒数"""
        if self.locked_at == 0:
            return 0.0
        return time.time() - self.locked_at

    @property
    def is_timed_out(self) -> bool:
        """是否已超时"""
        if self.status != "running":
            return False
        return self.elapsed > self.timeout_seconds

    @property
    def remaining(self) -> float:
        """剩余秒数（用于前端倒计时展示）"""
        if self.status != "running":
            return 0.0
        return max(0.0, self.timeout_seconds - self.elapsed)

    def to_dict(self) -> Dict[str, Any]:
        """序列化为前端可消费的字典"""
        return {
            "task_id": self.task_id,
            "status": self.status,
            "locked_at": self.locked_at,
            "elapsed_seconds": round(self.elapsed, 1),
            "remaining_seconds": round(self.remaining, 1),
            "timeout_seconds": self.timeout_seconds,
            "is_timed_out": self.is_timed_out,
        }


class TaskStateManager:
    """
    任务状态管理器 — 内存级状态机。

    使用模式：
        from task_state_manager import task_state_manager

        # 审计开始
        task_state_manager.lock(task_id, api_config_snapshot)

        try:
            # ... 执行审计流水线 ...
            task_state_manager.unlock(task_id)
        except Exception:
            task_state_manager.mark_failed(task_id)
            raise

    超时机制：
        每次调用 is_locked() / get_active() 时自动检测超时，
        触发即自动熔断释放，无需后台轮询线程。
    """

    def __init__(self):
        self._active_task: Optional[TaskState] = None

    # ══════════════════════════════════════════════════════════
    # 状态查询（含超时自动熔断）
    # ══════════════════════════════════════════════════════════

    def is_locked(self) -> bool:
        """
        检查是否有活跃审计任务。

        每次调用时自动检测超时 — 若超时则触发熔断解锁，
        返回 False，确保系统不会永久死锁。
        """
        if self._active_task is None:
            return False

        if self._active_task.is_timed_out:
            self._force_unlock("timeout")
            return False

        return self._active_task.status == "running"

    def get_active(self) -> Optional[TaskState]:
        """
        获取当前活跃任务状态。

        Returns:
            TaskState 或 None（无活跃任务/已超时熔断）
        """
        if self._active_task is None:
            return None

        if self._active_task.is_timed_out:
            self._force_unlock("timeout")
            return None

        if self._active_task.status == "running":
            return self._active_task

        return None

    def get_active_dict(self) -> Optional[Dict[str, Any]]:
        """获取活跃任务状态字典（供 API 返回）"""
        active = self.get_active()
        if active is None:
            return None
        return active.to_dict()

    def get_config_snapshot(self) -> Optional[Dict[str, str]]:
        """
        获取当前活跃任务的 API 配置快照。

        审计期间侧边栏配置可能被用户修改，但进行中的任务
        始终使用启动时冻结的快照，保证审计数据一致性。

        Returns:
            {"base_url": "...", "api_key": "...", "model_name": "..."}
            或 None
        """
        active = self.get_active()
        if active and active.api_config_snapshot:
            return active.api_config_snapshot
        return None

    # ══════════════════════════════════════════════════════════
    # 锁定 / 解锁操作
    # ══════════════════════════════════════════════════════════

    def lock(
        self,
        task_id: str,
        api_config: Optional[Dict[str, str]] = None,
    ) -> Optional[TaskState]:
        """
        锁定系统进入审计状态。

        P2-4 修复：此前对已有活跃任务一律 _force_unlock("preempted") 抢占，
        造成两个真实问题：
          1. 仍在运行的旧任务，其 finally 中的 unlock(task_id) 因 task_id
             不匹配而变成空操作；
          2. 更严重的是 —— 旧任务仍在流式执行，但 get_config_snapshot()
             返回的是新任务的 API 配置，旧任务会拿着错误的配置继续调用模型。
        现改为：任务仍在运行则拒绝新锁定（返回 None），由调用方提示用户
        「审计进行中」；仅当既有任务已超时（不可能再自行解锁）才强制清理。

        Returns:
            TaskState - 锁定成功
            None      - 已有审计任务正在运行，本次未获得锁
        """
        if self._active_task is not None:
            if self._active_task.is_timed_out:
                self._force_unlock("timeout")
            else:
                return None

        self._active_task = TaskState(
            task_id=task_id,
            status="running",
            api_config_snapshot=api_config,
            locked_at=time.time(),
        )
        return self._active_task

    def unlock(self, task_id: Optional[str] = None) -> bool:
        """
        正常解锁（审计流水线成功完成）。

        Args:
            task_id: 可选的 task_id 校验，防止误解锁其他任务

        Returns:
            True  - 解锁成功
            False - 无活跃任务或 task_id 不匹配
        """
        if self._active_task is None:
            return False

        if task_id is not None and self._active_task.task_id != task_id:
            return False

        self._active_task = None
        return True

    def mark_failed(self, task_id: Optional[str] = None) -> bool:
        """
        标记任务失败并解锁（审计流水线异常中断时调用）。

        与 unlock() 的功能区别：仅语义标记，实际行为相同。
        调用方应在 except 块中使用。
        """
        return self.unlock(task_id)

    # ══════════════════════════════════════════════════════════
    # 内部
    # ══════════════════════════════════════════════════════════

    def _force_unlock(self, reason: str = "unknown") -> None:
        """强制解锁（超时熔断 / 抢占清理）"""
        if self._active_task is not None:
            self._active_task = None


# ════════════════════════════════════════════════════════════
# 全局单例
# ════════════════════════════════════════════════════════════
task_state_manager = TaskStateManager()
