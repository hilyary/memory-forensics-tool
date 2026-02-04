# This file is Copyright 2025 and licensed under the terms of the Volatility Software License 1.0
# which is available at https://www.volatilityfoundation.org/license/vsl-v1.0
#
"""A custom plugin to recover bash command history using Volatility 2 style method."""

import logging
from typing import List, Iterator, Tuple, Optional

from volatility3.framework import interfaces, symbols
from volatility3.framework.configuration import requirements
from volatility3.framework.interfaces import plugins
from volatility3.framework.objects import utility
from volatility3.framework.symbols import linux
from volatility3.plugins import timeliner
from volatility3.plugins.linux import pslist

logger = logging.getLogger(__name__)


class BashHistory(plugins.PluginInterface, timeliner.TimeLinerInterface):
    """Recovers bash command history from memory using Volatility 2 style scanning."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Linux kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(4, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include (all other processes are excluded)",
                optional=True,
            ),
        ]

    def _generator(self, tasks):
        """Generate bash history entries using memory scanning method."""
        for task in tasks:
            task_name = utility.array_to_string(task.comm)

            # 只检查 bash 相关进程
            if task_name not in ["bash", "sh", "dash"]:
                continue

            task_pid = task.pid
            proc_layer_name = task.add_process_layer()

            if not proc_layer_name:
                continue

            proc_layer = self.context.layers[proc_layer_name]

            # 获取进程的内存区域（堆和可执行区域）
            task_memory_sections = []
            try:
                for section in task.get_process_memory_sections(heap_only=True):
                    task_memory_sections.append(section)
            except Exception as e:
                logger.debug(f"无法获取进程 {task_pid} 的内存区域: {e}")
                continue

            logger.info(f"扫描进程 {task_pid} ({task_name}) 的 bash 历史记录...")

            # 在进程内存中搜索可能的命令历史
            # bash 历史通常存储在堆中，以特定模式存在
            history_entries = self._scan_bash_history(
                self.context,
                proc_layer,
                proc_layer_name,
                task_memory_sections,
                task_pid
            )

            for entry in history_entries:
                yield (0, (task_pid, task_name, entry['time'], entry['command']))

    def _scan_bash_history(
        self,
        context,
        layer,
        layer_name,
        memory_sections,
        pid
    ) -> List[dict]:
        """
        扫描进程内存查找 bash 历史记录。
        使用类似 Volatility 2 的方法：搜索命令字符串模式。
        """
        import re
        from datetime import datetime

        results = []

        try:
            # 读取进程内存数据
            all_data = b''
            for section in memory_sections:
                try:
                    data = layer.read(section[0], section[1] - section[0])
                    all_data += data
                except Exception:
                    continue

            if not all_data:
                return results

            # 解码为文本（忽略错误）
            try:
                text_data = all_data.decode('utf-8', errors='ignore')
            except:
                text_data = all_data.decode('latin-1', errors='ignore')

            # 搜索可能的 bash 命令历史模式
            # bash 历史条目通常包含：
            # - 常见的 bash 命令（ls, cd, cat, grep, etc.）
            # - 路径（/home, /var, /etc, etc.）
            # - 时间戳格式

            # 常见命令模式
            command_patterns = [
                r'(?:^|\n)(ls|cd|cat|grep|find|ssh|sudo|apt|yum|dnf|pip|npm|python|perl|ruby|go|rust|java|mv|cp|rm|mkdir|chmod|chown|tar|zip|unzip|wget|curl|git|vim|nano|less|more|head|tail|ps|top|kill|pkill|systemctl|service|docker|kubectl)\s+[^\n]{1,500}',
                r'(?:^|\n)(?:/(?:usr|bin|home|var|etc|opt|tmp|root)[^\n]{1,500})',
                r'(?:^|\n)(?:https?|ftp)://[^\s\n]{1,500}',
            ]

            # 查找可能的命令
            potential_commands = []
            for pattern in command_patterns:
                matches = re.finditer(pattern, text_data, re.MULTILINE)
                for match in matches:
                    cmd = match.group(0).strip()
                    if len(cmd) > 3 and len(cmd) < 500:  # 合理长度
                        if not any(c in cmd for c in ['\x00', '\x01', '\x02', '\x03', '\x04', '\x05']):
                            potential_commands.append(cmd)

            # 去重并过滤
            seen = set()
            unique_commands = []
            for cmd in potential_commands:
                # 清理命令
                cmd = cmd.strip()
                if cmd and cmd not in seen:
                    # 过滤掉明显的非命令内容
                    if not self._is_likely_command(cmd):
                        continue
                    seen.add(cmd)
                    unique_commands.append(cmd)

            # 限制返回数量
            for cmd in unique_commands[:100]:  # 最多返回 100 条
                results.append({
                    'time': 'N/A',
                    'command': cmd
                })

            logger.info(f"在进程 {pid} 中找到 {len(results)} 条可能的命令历史")

        except Exception as e:
            logger.error(f"扫描进程 {pid} 的 bash 历史时出错: {e}")

        return results

    def _is_likely_command(self, text: str) -> bool:
        """判断文本是否可能是 bash 命令"""
        # 排除明显不是命令的内容
        exclude_patterns = [
            'http://', 'https://', 'ftp://',
            '.so.', '.dll', '.exe',
            'Copyright', 'License', 'WARNING',
            'ERROR', 'FATAL', 'DEBUG',
            '---', '===', '***',
            '\x1b', '[0m', '[31m', '[32m',  # ANSI 颜色代码
        ]

        text_lower = text.lower()
        for pattern in exclude_patterns:
            if pattern.lower() in text_lower:
                return False

        # 包含命令特征
        command_indicators = [
            ' ', '-', '/', '=', '"', "'",
            'ls', 'cd', 'cat', 'grep', 'find',
            'ssh', 'sudo', 'apt', 'yum', 'pip',
            'docker', 'kubectl', 'git'
        ]

        return any(indicator in text for indicator in command_indicators)

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("Process", str),
                ("CommandTime", str),
                ("Command", str),
            ],
            self._generator(
                pslist.PsList.list_tasks(
                    self.context, self.config["kernel"], filter_func=filter_func
                )
            ),
        )

    def generate_timeline(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))

        for row in self._generator(
            pslist.PsList.list_tasks(
                self.context, self.config["kernel"], filter_func=filter_func
            )
        ):
            _depth, row_data = row
            description = f'{row_data[0]} ({row_data[1]}): "{row_data[3]}"'
            # 时间可能不准确，使用当前时间作为占位符
            yield (description, timeliner.TimeLinerType.CREATED, None)


# 导入 renderers
from volatility3.framework import renderers
