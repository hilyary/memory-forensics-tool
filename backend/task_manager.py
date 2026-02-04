"""
Task Manager - 异步任务管理
"""

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Any, Dict
from datetime import datetime

logger = logging.getLogger(__name__)


class TaskManager:
    """异步任务管理器"""

    def __init__(self, max_workers: int = 4):
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.tasks: Dict[str, Dict] = {}
        self.task_counter = 0

    def submit_task(self, func: Callable, *args, **kwargs) -> str:
        """
        提交异步任务

        Args:
            func: 要执行的函数
            *args: 函数参数
            **kwargs: 函数关键字参数

        Returns:
            任务ID
        """
        self.task_counter += 1
        task_id = f"task_{self.task_counter}"

        self.tasks[task_id] = {
            'id': task_id,
            'status': 'pending',
            'created_at': datetime.now().isoformat(),
            'result': None,
            'error': None
        }

        future = self.executor.submit(self._run_task, task_id, func, *args, **kwargs)

        return task_id

    def _run_task(self, task_id: str, func: Callable, *args, **kwargs) -> Any:
        """运行任务"""
        try:
            self.tasks[task_id]['status'] = 'running'
            self.tasks[task_id]['started_at'] = datetime.now().isoformat()

            result = func(*args, **kwargs)

            self.tasks[task_id]['status'] = 'completed'
            self.tasks[task_id]['completed_at'] = datetime.now().isoformat()
            self.tasks[task_id]['result'] = result

            logger.info(f"任务 {task_id} 完成")
            return result

        except Exception as e:
            self.tasks[task_id]['status'] = 'failed'
            self.tasks[task_id]['completed_at'] = datetime.now().isoformat()
            self.tasks[task_id]['error'] = str(e)

            logger.error(f"任务 {task_id} 失败: {str(e)}")
            raise

    def get_task_status(self, task_id: str) -> Dict:
        """获取任务状态"""
        return self.tasks.get(task_id, {
            'status': 'not_found',
            'error': '任务不存在'
        })

    def cancel_task(self, task_id: str) -> bool:
        """取消任务"""
        if task_id in self.tasks:
            self.tasks[task_id]['status'] = 'cancelled'
            return True
        return False

    def cleanup_completed_tasks(self):
        """清理已完成的任务"""
        to_remove = [
            task_id for task_id, task in self.tasks.items()
            if task['status'] in ['completed', 'failed', 'cancelled']
        ]
        for task_id in to_remove:
            del self.tasks[task_id]

        logger.info(f"清理了 {len(to_remove)} 个已完成的任务")

    def shutdown(self):
        """关闭任务管理器"""
        self.executor.shutdown(wait=True)
        logger.info("任务管理器已关闭")
