#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# JiuZero 2025/6/14

import threading
import queue
from lib.core.log import logger
from lib.core.data import conf
from typing import Iterable, Callable, Any

class Threads:
    def __init__(self, num_threads: int = conf.plugin_threads, name: str = "ThreadingProcessor"):
        """
        初始化线程处理器
        
        :param num_threads: 工作线程数，默认为4
        :param name: 处理器名称，用于日志记录
        """
        self.num_threads = num_threads
        self.name = name
        self._stop_event = threading.Event()
        self._exception_event = threading.Event()

    def _worker(self, task_func: Callable, task_queue: queue.Queue, *args, **kwargs):
        """工作线程函数"""
        while not self._stop_event.is_set() and not self._exception_event.is_set():
            try:
                item = task_queue.get_nowait()
            except queue.Empty:
                break

            try:
                task_func(item, *args, **kwargs)
            except Exception as task_e:
                logger.error(f"Task failed: {task_e}", origin=self.name)
                self._exception_event.set()
                raise
            finally:
                task_queue.task_done()

    def submit(
        self,
        task_func: Callable,
        task_data: Iterable[Any],
        *args,
        **kwargs
    ) -> None:
        """
        并发执行多个任务
        
        :param task_func: 要执行的任务函数
        :param task_data: 任务数据迭代器，每个元素会作为task_func的第一个参数
        :param args: 传递给task_func的额外位置参数
        :param kwargs: 传递给task_func的额外关键字参数
        """
        task_queue = queue.Queue()
        for item in task_data:
            task_queue.put(item)

        threads = []
        for _ in range(min(self.num_threads, len(task_data))):
            thread = threading.Thread(
                target=self._worker,
                args=(task_func, task_queue, *args),
                kwargs=kwargs,
                daemon=True
            )
            thread.start()
            threads.append(thread)

        try:
            # 等待所有任务完成或异常发生
            while any(t.is_alive() for t in threads):
                for t in threads:
                    t.join(timeout=0.1)
                if self._exception_event.is_set():
                    break
        except KeyboardInterrupt:
            logger.warning("Wait for threads...", origin=self.name)
            self._stop_event.set()
            # 等待线程结束
            for t in threads:
                t.join(timeout=0.1)
        except Exception as e:
            logger.error(f"Unexpected error: {e}", origin=self.name)
            self._stop_event.set()
            # 等待线程结束
            for t in threads:
                t.join(timeout=0.1)
        finally:
            self._stop_event.clear()
            self._exception_event.clear()