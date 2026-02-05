"""
Volatility 3 Wrapper - 封装Volatility 3框架
真正调用 Volatility 3 进行内存分析
"""

import os
import re
import logging
import json
import sys
import shutil
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import subprocess

logger = logging.getLogger(__name__)


class VolatilityWrapper:
    """Volatility 3框架封装类 - 使用真正的 Volatility 3"""

    def __init__(self, image_path: str):
        self.image_path = image_path
        self.image_name = os.path.basename(image_path)
        self._image_info = None

        # 获取项目根目录（兼容 Nuitka/PyInstaller 打包）
        self._project_root = self._get_project_root()

        # 符号表目录 - 独立的用户数据目录，打包后也能正常工作
        self._symbols_dir = self._get_symbols_dir()

        # vol 命令路径 - 跨平台查找
        self._vol_path = self._find_vol_command()

        logger.info(f"项目根目录: {self._project_root}")

    @staticmethod
    def _get_project_root() -> Path:
        """获取项目根目录（兼容 Nuitka/PyInstaller 打包）

        Nuitka 打包后:
        - sys.executable 指向可执行文件
        - __file__ 可能指向临时文件

        PyInstaller 打包后:
        - sys.frozen = True
        - sys.executable 指向可执行文件

        开发模式:
        - 使用 __file__ 获取
        """
        # 检测是否在打包环境中
        is_frozen = getattr(sys, 'frozen', False)

        if is_frozen:
            # 打包环境：可执行文件所在目录
            exe_path = Path(sys.executable)
            if exe_path.is_file():
                # onefile 模式：返回可执行文件所在目录
                return exe_path.parent
            else:
                # onedir 模式：直接返回
                return exe_path
        else:
            # 开发环境：从当前文件向上两级
            return Path(__file__).parent.parent

    def _find_vol_command(self) -> str:
        """查找 vol 命令的路径（跨平台，支持打包环境）

        Returns:
            str: vol 命令的路径，如果找不到则返回 'vol'（让系统在 PATH 中查找）
            None: 表示使用 Python 模块方式调用 (python -m volatility3)
        """
        # 检测是否在打包环境中运行（PyInstaller、cx_Freeze 等）
        is_frozen = getattr(sys, 'frozen', False)

        if is_frozen:
            # 打包后的环境：尝试检测 Volatility 3 是否可用
            # 如果打包时包含了 Volatility 3，使用 python -m volatility3
            # 如果打包时未包含 Volatility 3（最小体积版），尝试使用系统的 vol 命令

            # 首先尝试使用系统的 vol 命令
            vol_path = shutil.which('vol')
            if vol_path:
                logger.info(f"打包环境: 找到系统 vol 命令: {vol_path}")
                return vol_path

            # 检查是否能导入 volatility3（打包时包含了）
            try:
                import volatility3
                logger.info("打包环境: Volatility 3 已打包进可执行文件，将使用 python -m volatility3")
                return None  # 使用 Python 模块方式
            except ImportError:
                logger.warning("打包环境: Volatility 3 未打包，且未找到系统 vol 命令")
                logger.warning("请安装 Volatility 3: pip install volatility3")
                return 'vol'  # 尝试使用系统 PATH 中的 vol

        # 非打包环境（开发模式）
        # 1. 首先尝试使用 shutil.which 在系统 PATH 中查找
        vol_path = shutil.which('vol')
        if vol_path:
            logger.info(f"找到 vol 命令: {vol_path}")
            return vol_path

        # 2. 尝试常见的用户级安装路径
        home = Path.home()
        possible_paths = [
            # macOS/Linux 用户安装路径
            home / '.local' / 'bin' / 'vol',
            home / 'Library' / 'Python' / '3.9' / 'bin' / 'vol',
            home / 'Library' / 'Python' / '3.10' / 'bin' / 'vol',
            home / 'Library' / 'Python' / '3.11' / 'bin' / 'vol',
            home / 'Library' / 'Python' / '3.12' / 'bin' / 'vol',
            # Windows 用户安装路径
            Path(os.environ.get('USERPROFILE', home)) / 'AppData' / 'Local' / 'Programs' / 'Python' / 'Scripts' / 'vol.exe',
            Path(os.environ.get('USERPROFILE', home)) / 'AppData' / 'Roaming' / 'Python' / 'Scripts' / 'vol.exe',
            # 系统级路径（可能需要管理员权限）
            Path('/usr/local/bin/vol'),
            Path('/usr/bin/vol'),
        ]

        for path in possible_paths:
            if path.exists() and os.access(path, os.X_OK):
                logger.info(f"找到 vol 命令: {path}")
                return str(path)

        # 3. 找不到具体路径，返回 'vol' 让 subprocess 在 PATH 中查找
        logger.warning("未找到 vol 命令的具体路径，将依赖系统 PATH")
        return 'vol'

    @staticmethod
    def _get_symbols_dir() -> Path:
        """获取符号表存储目录（独立于 volatility3 安装位置）

        使用用户数据目录存储符号表，确保打包后仍能正常工作：
        - macOS: ~/Library/Application Support/LensAnalysis/symbols
        - Windows: %APPDATA%/LensAnalysis/symbols
        - Linux: ~/.local/share/LensAnalysis/symbols

        Returns:
            Path: 符号表目录的 Path 对象
        """
        import platform
        system = platform.system()

        if system == 'Darwin':  # macOS
            base_dir = Path.home() / 'Library' / 'Application Support' / 'LensAnalysis'
        elif system == 'Windows':
            base_dir = Path(os.environ.get('APPDATA', Path.home() / 'AppData' / 'Roaming')) / 'LensAnalysis'
        else:  # Linux 及其他
            base_dir = Path.home() / '.local' / 'share' / 'LensAnalysis'

        symbols_dir = base_dir / 'symbols'
        symbols_dir.mkdir(parents=True, exist_ok=True)

        return symbols_dir  # 返回 Path 对象而不是字符串

    def _run_volatility(self, plugin_name: str, extra_args: List[str] = None, use_custom_plugins: bool = True, use_symbols: bool = True, symbol_file_path: str = None) -> List[Dict]:
        """
        运行 Volatility 3 命令行工具

        Args:
            plugin_name: 插件名称，如 'windows.pslist.PsList'
            extra_args: 额外的命令行参数
            use_custom_plugins: 是否使用自定义插件目录（默认True）
            use_symbols: 是否使用符号表（默认True，某些插件如banners不需要）
            symbol_file_path: 直接指定符号表文件路径（可选，优先级高于目录扫描）

        Returns:
            解析后的结果列表
        """
        try:
            # 使用动态查找的 vol 命令路径
            vol_path = self._vol_path

            # 设置环境变量，让 Volatility 3 能找到我们的自定义插件
            import os
            env = os.environ.copy()

            # 检测是否在打包环境中
            is_frozen = getattr(sys, 'frozen', False)

            # 构建命令 - 打包环境和开发环境使用不同的方式
            if is_frozen or vol_path is None:
                # 打包环境：使用 python -m volatility3
                # 打包后使用 sys.executable（当前可执行文件对应的 Python）
                python_exe = sys.executable if is_frozen else 'python'
                cmd = [
                    python_exe, '-m', 'volatility3',
                    '-f', self.image_path,
                ]
                logger.info(f"打包环境: 使用 {python_exe} -m volatility3")
            else:
                # 开发环境：使用 vol 命令
                cmd = [
                    vol_path,
                    '-f', self.image_path,
                ]

            # 符号表处理策略（优先使用官方自动下载）
            # Volatility 3.27.0 支持自动从微软官方下载 Windows 符号表
            # 只有在指定了特定符号表文件路径时才使用 -s 参数
            logger.info(f"DEBUG _run_volatility: symbol_file_path={symbol_file_path}, use_symbols={use_symbols}")
            if symbol_file_path and os.path.exists(str(symbol_file_path)):
                # 用户明确指定了符号表文件
                symbol_dir = os.path.dirname(str(symbol_file_path))
                cmd.extend(['-s', symbol_dir])
                logger.info(f"使用指定符号表目录: {symbol_dir}")
            elif not use_symbols:
                # 不需要符号表的插件（如 banners）
                logger.info("插件不需要符号表")
            else:
                # 需要符号表的插件，但未指定路径
                # 策略：首次尝试不指定 -s（让 Volatility 自动下载）
                # 如果失败且是符号表相关错误，会在错误处理中重试
                logger.info(f"使用 Volatility 自动符号表下载（首次尝试）")


            cmd.append(plugin_name)

            if extra_args:
                cmd.extend(extra_args)

            logger.info(f"执行命令: {' '.join(cmd)}")

            # 执行命令，使用自定义环境变量
            result = subprocess.run(
                cmd,
                env=env,
                capture_output=True,
                text=True,
                timeout=300,  # 5分钟超时
                check=False
            )

            # 检查错误
            if result.returncode != 0:
                error_output = result.stderr.lower()
                stdout_output = result.stdout.lower()

                # 检测 NotImplementedError - 插件不支持当前系统版本
                if 'notimplementederror' in error_output or 'not supported' in error_output:
                    logger.error(f"插件不支持当前系统: {result.stderr}")
                    # 提取错误信息中的版本号
                    import re
                    version_match = re.search(r'(\d+\.\d+\s+\d+\.\d+)', result.stderr)
                    version_info = version_match.group(1) if version_match else '未知版本'
                    return [{
                        '_error': 'not_supported',
                        '_message': f'此插件不支持当前系统版本 ({version_info})。\n\n'
                                  f'这通常是 Volatility 3 框架的限制。\n'
                                  f'某些插件不支持旧版本的 Windows（如 Windows 7）。\n\n'
                                  f'建议：\n'
                                  f'• 尝试使用其他替代插件\n'
                                  f'• 对于命令历史，可尝试 cmdline 插件查看进程命令行参数'
                    }]

                # 检测符号表相关的错误关键词
                symbol_errors = [
                    'unsatisfied requirement',
                    'symbol table',
                    'not found',
                    'cannot identify',
                    'no suitable',
                    'symbol table error',
                    'pdb signature not found',
                    'no pdb found'
                ]

                if any(err in error_output or err in stdout_output for err in symbol_errors):
                    # 检查是否是首次尝试（未指定 -s 参数）
                    if use_symbols and not any('-s' in str(arg) for arg in cmd) and not symbol_file_path:
                        logger.warning(f"官方符号表下载失败，尝试使用本地符号表...")
                        # 重试：使用本地符号表目录
                        cmd_with_symbols = [
                            vol_path,
                            '-f', self.image_path,
                            '-s', str(self._symbols_dir),
                            plugin_name
                        ]
                        if extra_args:
                            cmd_with_symbols.extend(extra_args)

                        logger.info(f"重试命令: {' '.join(cmd_with_symbols)}")
                        result = subprocess.run(
                            cmd_with_symbols,
                            env=env,
                            capture_output=True,
                            text=True,
                            timeout=300,
                            check=False
                        )

                        # 如果重试成功，解析输出
                        if result.returncode == 0:
                            logger.info("使用本地符号表成功")
                            return self._parse_text_output(result.stdout, plugin_name)
                        else:
                            logger.error(f"本地符号表也失败: {result.stderr}")
                            # 返回特殊错误标记
                            return [{
                                '_error': 'symbol_not_found',
                                '_message': self._get_symbol_error_message(plugin_name)
                            }]
                    else:
                        logger.error(f"符号表错误: {result.stderr}")
                        # 返回特殊错误标记
                        return [{
                            '_error': 'symbol_not_found',
                            '_message': self._get_symbol_error_message(plugin_name)
                        }]

                logger.warning(f"Volatility 执行失败: {result.stderr}")
                # 如果执行失败，尝试解析文本输出
                return self._parse_text_output(result.stdout, plugin_name)

            # 解析文本输出（Volatility 3 默认是表格格式）
            return self._parse_text_output(result.stdout, plugin_name)

        except subprocess.TimeoutExpired:
            logger.error(f"Volatility 执行超时: {plugin_name}")
            return []
        except Exception as e:
            error_str = str(e)
            logger.error(f"Volatility 执行异常: {error_str}")

            # 检测是否是符号表文件损坏错误（EOFError）
            if 'EOFError' in error_str or 'Compressed file ended' in error_str:
                logger.warning("检测到符号表文件损坏，尝试重新下载...")
                # 删除损坏的符号表文件
                try:
                    import glob
                    # 查找所有可能损坏的符号表文件
                    for symbol_file in glob.glob(str(self._symbols_dir / '**/*.json.xz'), recursive=True):
                        try:
                            # 尝试读取文件，如果失败则删除
                            import lzma
                            with open(symbol_file, 'rb') as f:
                                with lzma.open(f) as zf:
                                    json.load(zf)
                        except:
                            logger.warning(f"删除损坏的符号表文件: {symbol_file}")
                            os.remove(symbol_file)
                except Exception as cleanup_error:
                    logger.warning(f"清理符号表时出错: {cleanup_error}")

                # 重试一次
                try:
                    logger.info(f"重新执行插件: {plugin_name}")
                    return self._run_volatility(plugin_name, extra_args, use_custom_plugins, use_symbols, symbol_file_path)
                except Exception as retry_error:
                    logger.error(f"重试失败: {retry_error}")

            return []

    def _get_symbol_error_message(self, plugin_name: str) -> str:
        """生成符号表错误提示信息"""
        if 'linux' in plugin_name.lower() or '.mac' in plugin_name.lower():
            return (f"未找到匹配的符号表。\n\n"
                    f"此插件需要特定版本的符号表才能正常工作。\n"
                    f"请检查符号表管理器是否已安装对应的符号文件。\n\n"
                    f"提示：\n"
                    f"• Linux: 符号表必须与内核版本完全匹配\n"
                    f"• macOS: 符号表必须与系统版本匹配\n"
                    f"• 可以在工具栏点击「符号表」按钮管理符号文件")

        return "未找到匹配的符号表，请检查符号表是否已安装。"

    def _run_volatility_raw(self, plugin_name: str, extra_args: List[str] = None, use_symbols: bool = False) -> str:
        """
        运行 Volatility 3 命令行工具，返回原始文本输出

        Args:
            plugin_name: 插件名称，如 'windows.pslist.PsList'
            extra_args: 额外的命令行参数
            use_symbols: 是否使用符号表（默认False，banners等插件不需要符号表）

        Returns:
            原始文本输出
        """
        try:
            # 使用动态查找的 vol 命令路径
            vol_path = self._vol_path

            # 检测是否在打包环境中
            is_frozen = getattr(sys, 'frozen', False)

            # 构建命令 - 打包环境和开发环境使用不同的方式
            if is_frozen or vol_path is None:
                # 打包环境：使用 python -m volatility3
                python_exe = sys.executable if is_frozen else 'python'
                cmd = [
                    python_exe, '-m', 'volatility3',
                    '-f', self.image_path,
                ]
            else:
                # 开发环境：使用 vol 命令
                cmd = [
                    vol_path,
                    '-f', self.image_path,
                ]

            # 只有需要符号表的插件才添加 -s 参数
            if use_symbols:
                cmd.extend(['-s', str(self._symbols_dir)])

            # 添加自定义插件目录（如果存在）
            if os.path.exists(self._custom_plugin_dir):
                cmd.extend(['--plugin-dirs', self._custom_plugin_dir])

            cmd.append(plugin_name)

            if extra_args:
                cmd.extend(extra_args)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                check=False
            )

            return result.stdout

        except subprocess.TimeoutExpired:
            logger.error(f"Volatility 执行超时: {plugin_name}")
            return ''
        except Exception as e:
            logger.error(f"Volatility 执行异常: {str(e)}")
            return ''

    def _format_size(self, size_bytes: int) -> str:
        """格式化文件大小"""
        if not size_bytes or size_bytes == 0:
            return '0 B'
        units = ['B', 'KB', 'MB', 'GB', 'TB']
        for i, unit in enumerate(units):
            if size_bytes < 1024.0:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.1f} PB"

    def _parse_text_output(self, output: str, plugin_name: str) -> List[Dict]:
        """
        解析 Volatility 文本输出（制表符分隔的表格格式）
        """
        lines = output.strip().split('\n')
        if len(lines) < 3:
            logger.warning(f"{plugin_name} 输出少于3行: {len(lines)}行")
            if lines:
                logger.warning(f"前5行内容:\n" + "\n".join(lines[:5]))
            return []

        # 调试：对于 printkey 显示原始输出
        if 'printkey' in plugin_name.lower():
            logger.warning(f"printkey 原始输出:\n{output[:1500]}")

        # 找到数据开始的行（跳过 Progress 行和空行）
        data_lines = []
        for line in lines:
            if not line.strip() or line.startswith('Progress'):
                continue
            is_header = self._is_header_row(line, plugin_name)
            # 对于 printkey，记录每一行的处理
            if 'printkey' in plugin_name.lower():
                logger.warning(f"[printkey处理] 行: {line[:60]}, 是否表头: {is_header}")
            # 跳过表头行（检查是否包含连续的表头关键词）
            if is_header:
                continue
            data_lines.append(line)

        # 使用制表符或空格分隔
        results = []
        for line in data_lines:
            # 对于 printkey，跳过 REG_BINARY 的续行（十六进制数据续行）
            # 续行特征：只有2列，且第一列是十六进制数据
            if 'printkey' in plugin_name and len(line.split()) == 2:
                # 检查是否是十六进制续行（第一列都是十六进制字节）
                parts_check = line.split()
                if len(parts_check) == 2:
                    # 检查第一列是否全是十六进制字节（用空格分隔的2位十六进制数）
                    first_col = parts_check[0].split()
                    if all(len(b) == 2 and all(c in '0123456789abcdefABCDEF' for c in b) for b in first_col[:8]):
                        # 这是续行，跳过
                        continue

            if '\t' in line:
                parts = line.split('\t')
            else:
                # 用空格分隔，但保留连续空格作为一个分隔符
                parts = line.split()
                # 如果分割后列数太少，可能是因为列内有多个空格，尝试更智能的分割
                if len(parts) < 3:
                    # 尝试用多个空格作为分隔符（至少2个连续空格）
                    parts = re.split(r'\s{2,}', line.strip())

            if parts and len(parts) >= 2:
                result = self._parse_plugin_result(plugin_name, parts)
                if result:
                    results.append(result)
                else:
                    # 调试：看看为什么解析失败
                    logger.debug(f"解析失败: plugin={plugin_name}, parts={len(parts)}, first_3={parts[:3]}")

        logger.info(f"解析 {plugin_name} 结果: {len(results)} 条记录")
        logger.info(f"  共处理 {len(data_lines)} 行数据")

        # 调试：如果结果为0但有数据行，显示前几行
        if len(results) == 0 and len(data_lines) > 0:
            logger.warning(f"警告: {plugin_name} 有 {len(data_lines)} 行数据但解析出 0 条记录")
            for i, line in enumerate(data_lines[:5]):
                logger.warning(f"  数据行 {i+1}: {line[:100]}")

        return results

    def _is_header_row(self, line: str, plugin_name: str = '') -> bool:
        """判断是否是表头行"""
        # 空行或进度行不是表头
        if not line.strip():
            return False
        if line.startswith('Progress'):
            return False

        # 跳过分隔线（全是由 - 或 = 组成的行）
        stripped = line.strip()
        if all(c in ['-', '='] for c in stripped):
            return True

        # 检查是否包含 Volatility 3 框架信息
        if 'Volatility 3' in line:
            return True

        # 【重要】提前检查注册表相关表头（在 parts 分割之前）
        # 这样可以避免因为空格分割导致检查失败
        if 'Last Write Time' in line or 'Hive Offset' in line or 'Key Name' in line:
            logger.warning(f"[表头检测] 识别为注册表表头行，将跳过: {line[:80]}")
            return True

        # hivelist 表头检查：Offset FileFullPath ...
        if line.startswith('Offset') and ('FileFullPath' in line or 'File' in line):
            logger.warning(f"[表头检测] 识别为 hivelist 表头行，将跳过: {line[:80]}")
            return True

        # 优先用制表符分隔，如果没有制表符则用空格分隔
        if '\t' in line:
            parts = line.split('\t')
        else:
            # 用空格分隔，但保留连续空格作为一个分隔符
            parts = line.split()
            # 如果分割后列数太少，可能是因为列内有多个空格，尝试更智能的分割
            if len(parts) < 3:
                # 尝试用多个空格作为分隔符（至少2个连续空格）
                parts = re.split(r'\s{2,}', line.strip())

        # 检查第一列是否是纯数字（PID）- 如果是，很可能是数据行
        first_part = parts[0].strip() if parts else ''
        if first_part.isdigit():
            return False

        # 检查第一列是否包含日期（数据行的特征，如 2023-05-13 或 2023-05-13 02:51:12）
        # 如果第一列看起来像日期时间，说明是数据行而不是表头
        if re.match(r'^\d{4}-\d{2}-\d{2}', first_part):
            return False

        # 重要：如果第一列包含路径分隔符，很可能是数据行而不是表头
        # 数据行通常包含路径（如 Software\Microsoft\SystemCertificates 或 Microsoft\SystemCertificates）
        # 表头行通常不包含路径分隔符（如 Certificate path, PID, Process Name 等）
        if '\\' in first_part or '/' in first_part:
            return False

        # 特殊检查：如果第一列看起来像进程名（包含.exe或不全是数字/大写字母），很可能是数据行
        # 这个检查必须在表头关键词检查之前进行，否则数据行可能被误认为表头
        if len(parts) > 0:
            first_part = parts[0].strip()
            # 进程名特征：包含.exe，或包含小写字母但不是纯十六进制地址
            if '.exe' in first_part.lower() or (any(c.islower() for c in first_part) and not first_part.startswith('0x')):
                return False

        # 检查是否有常见的表头关键词（扩展列表）
        header_keywords = [
            'PID', 'Process', 'Base', 'Offset', 'Name', 'Path', 'Size', 'Address', 'Time', 'Banner',
            'Device', 'Mount', 'Point', 'Type', 'Interface', 'IP', 'MAC', 'Promiscuous',
            'Function', 'Param', 'Deadline', 'Entry', 'Module', 'Symbol',
            'Proto', 'Local', 'Foreign', 'State', 'LAddr', 'LPort', 'RAddr', 'RPort',
            'Start', 'End', 'Protection', 'Map', 'File', 'output',
            'Ident', 'Filter', 'Context',
            'Index', 'IData', 'Callback', 'Listeners',
            'Socket', 'Member', 'Policy',
            'UID', 'GID', 'PPID', 'Argc', 'Arguments',
            'TID', 'VAD', 'VAD', 'Note',
            'Certificate', 'Section', 'ID',
            'Hive', 'Last', 'Write',
            # PEB 伪装检测关键词
            'EPROCESS', 'SeAudit', 'ImageFileName', 'ImageFilePath', 'Spoofed', 'PEB',
            'PEB_ImageFilePath', 'PEB_CommandLine',
            # 系统调用检测关键词
            'Distinct', 'Implementations', 'Different'
        ]

        # 检查是否包含至少2个表头关键词（只在列名中检查）
        header_as_columns = sum(1 for keyword in header_keywords if any(keyword in part for part in parts))
        if header_as_columns >= 2:
            logger.warning(f"[表头检测] 通过关键词识别为表头行: {line[:80]}, 匹配数={header_as_columns}")
            return True

        # 调试：显示未识别为表头的行
        logger.debug(f"未识别表头行: parts={len(parts)}, header_as_columns={header_as_columns}, parts[:3]={parts[:3] if len(parts) >= 3 else parts}")

        # printkey 插件的特定表头关键词组合
        if 'printkey' in plugin_name:
            # 检查是否同时包含多个 printkey 表头关键词
            printkey_headers = ['Last', 'Write', 'Time', 'Hive', 'Offset', 'Type', 'Key', 'Name', 'Data', 'Volatile']
            matching_count = sum(1 for header in printkey_headers if header in line)
            if matching_count >= 4:  # 如果包含至少4个表头关键词，认为是表头行
                return True

        # 对于只有 2 列的情况（如 banners），检查第二列是否是表头关键词
        if len(parts) == 2:
            second_part = parts[1].strip()
            if second_part in header_keywords:
                return True

        # 检查是否所有列都是表头风格（首字母大写，无数字等）
        # 如果大多数列都是表头风格，则认为是表头行
        if len(parts) >= 3:
            header_style_count = 0
            for part in parts:
                part = part.strip()
                if not part:
                    continue
                # 检查是否是表头风格：包含大写字母、空格、常见表头词，但不包含十六进制地址
                if (any(c.isupper() for c in part) or ' ' in part) and not part.startswith('0x'):
                    header_style_count += 1
            if header_style_count >= len(parts) * 0.7:  # 70%以上列都是表头风格
                return True

        return False

    def _parse_plugin_result(self, plugin_name: str, parts: List[str]) -> Optional[Dict]:
        """根据插件类型解析结果"""

        # Banners 插件 - 读取内核版本信息
        if 'banner' in plugin_name.lower():
            if len(parts) >= 2:
                # banners 输出格式: Offset Banner
                # 例如: 0x4d2c7d0 Darwin Kernel Version 16.7.0: ...
                return {
                    'offset': str(parts[0]),
                    'banner': ' '.join(parts[1:])  # banner 可能包含空格
                }

        # 进程相关插件 (PID PPID ImageFileName Offset Threads Handles SessionId Wow64 CreateTime ExitTime)
        # Windows pslist/psscan/pstree - 只匹配 Windows 插件（格式：windows.pslist.PsList）
        # Volatility 3 输出格式: PID PPID ImageFileName Offset(V) Threads Handles SessionId Wow64 CreateTime ExitTime Audit Cmd Path
        if ('pslist' in plugin_name or 'psscan' in plugin_name or 'pstree' in plugin_name) and 'windows.' in plugin_name.lower():
            if len(parts) >= 11:
                result = {
                    'pid': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'ppid': int(parts[1]) if len(parts) > 1 and str(parts[1]).isdigit() else 0,
                    'name': str(parts[2]).strip() if len(parts) > 2 else '',
                    'threads': int(parts[4]) if len(parts) > 4 and str(parts[4]).isdigit() else 0,
                    'handles': int(parts[5]) if len(parts) > 5 and str(parts[5]).isdigit() else 0,
                    'session_id': str(parts[6]) if len(parts) > 6 else '0',
                    'create_time': str(parts[8]) if len(parts) > 8 else ''
                }
                # 添加额外字段（如果存在）
                if len(parts) > 3:
                    result['offset'] = str(parts[3])
                if len(parts) > 7:
                    result['wow64'] = str(parts[7])
                if len(parts) > 9:
                    result['exit_time'] = str(parts[9])
                if len(parts) > 11:
                    result['command_line'] = str(parts[11])
                return result

        # 命令行插件
        elif 'cmdline' in plugin_name:
            if len(parts) >= 2:
                return {
                    'pid': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'name': str(parts[1]).strip() if len(parts) > 1 else '',
                    'command_line': ' '.join(parts[2:]) if len(parts) > 2 else ''
                }

        # 网络相关插件 - Offset Proto LocalAddr LocalPort ForeignAddr ForeignPort State PID Owner Created
        elif 'netscan' in plugin_name:
            if len(parts) >= 10:
                return {
                    'offset': str(parts[0]),
                    'protocol': str(parts[1]),
                    'local_address': str(parts[2]),
                    'local_port': str(parts[3]),
                    'remote_address': str(parts[4]),
                    'remote_port': str(parts[5]),
                    'state': str(parts[6]),
                    'pid': int(parts[7]) if str(parts[7]).isdigit() else 0,
                    'process_name': str(parts[8]),
                    'create_time': str(parts[9]) if len(parts) > 9 else ''
                }

        # 文件扫描插件 - Offset Name
        elif 'filescan' in plugin_name:
            if len(parts) >= 2:
                return {
                    'offset': str(parts[0]),
                    'file_name': str(parts[1]),
                    'path': str(parts[1]),
                    'size': 0,
                    'number_of_links': 0
                }

        # 注册表插件 - Offset FileFullPath File output
        elif 'hivelist' in plugin_name:
            if len(parts) >= 2:
                # Offset | FileFullPath | File output (Disabled)
                offset = str(parts[0]) if parts[0] else ''
                # 第二列是 FileFullPath (路径)，可能为空
                file_path = str(parts[1]) if len(parts) > 1 and parts[1] else ''
                # 第三列是 File output 状态（如 "Disabled"）
                hive_status = str(parts[2]) if len(parts) > 2 else 'Unknown'

                # 提取名称（路径的最后一部分）
                if file_path:
                    name = file_path.split('\\')[-1]
                else:
                    name = 'Registry Root'
                    file_path = '\\REGISTRY\\MACHINE'

                # 构建 printkey_path - 根据文件名确定
                # 例如：SYSTEM -> 不需要 key（直接访问根目录）
                # 例如：SAM -> 不需要 key（直接访问根目录）
                # 但对于某些 hive，可能需要指定根路径
                if file_path and 'SYSTEM' in file_path.upper():
                    printkey_path = ''  # SYSTEM hive 根目录
                elif file_path and 'SAM' in file_path.upper():
                    printkey_path = ''  # SAM hive 根目录
                elif file_path and 'SOFTWARE' in file_path.upper():
                    printkey_path = ''  # SOFTWARE hive 根目录
                elif file_path and 'SECURITY' in file_path.upper():
                    printkey_path = ''  # SECURITY hive 根目录
                else:
                    printkey_path = ''  # 默认为空，访问根目录

                return {
                    'offset': offset,
                    'name': name,
                    'path': file_path,
                    'hive_type': hive_status,
                    'printkey_path': printkey_path
                }

        # 证书列表插件 - Certificate path, Certificate section, Certificate ID, Certificate name
        elif 'certificates' in plugin_name:
            if len(parts) >= 4:
                return {
                    'path': str(parts[0]),
                    'section': str(parts[1]),
                    'id': str(parts[2]),
                    'name': str(parts[3]) if len(parts) > 3 and parts[3] != '-' else '',
                    'hive': str(parts[0]).split('\\')[0] if '\\' in str(parts[0]) else str(parts[0])
                }

        # 系统调用检测插件 - Function, Distinct Implementations, Total Implementations
        # 格式：NtCreateThread          61
        # 或：NtOpenProcess   2488:firefox.exe, ...  53
        elif 'unhooked_system_calls' in plugin_name:
            if len(parts) >= 3:
                function_name = str(parts[0])
                distinct_impl = str(parts[1])
                total_impl = str(parts[2]) if len(parts) > 2 else ''

                # 检查 distinct_impl 是否是纯数字
                if distinct_impl.isdigit():
                    return {
                        'function': function_name,
                        'distinct_implementations': int(distinct_impl),
                        'total_implementations': int(total_impl) if total_impl.isdigit() else 0,
                        'different_processes': ''
                    }
                else:
                    # 第二列不是数字，说明是进程列表
                    return {
                        'function': function_name,
                        'distinct_implementations': len(distinct_impl.split(',')) if distinct_impl else 0,
                        'total_implementations': int(total_impl) if total_impl.isdigit() else 0,
                        'different_processes': distinct_impl
                    }

        # PEB伪装检测插件 - PID, EPROCESS_ImageFileName, EPROCESS_SeAudit_ImageFileName, PEB_ImageFilePath, PEB_ImageFilePath_Spoofed, PEB_CommandLine_Spoofed
        elif 'pebmasquerade' in plugin_name:
            if len(parts) >= 6:
                return {
                    'offset': str(parts[0]) if not str(parts[0]).isdigit() else '',
                    'pid': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'name': str(parts[1]) if len(parts) > 1 else '',
                    'eprocess_name': str(parts[1]) if len(parts) > 1 else '',
                    'seaudit_name': str(parts[2]) if len(parts) > 2 else '',
                    'peb_path': str(parts[3]) if len(parts) > 3 else '',
                    'path_spoofed': str(parts[4]) if len(parts) > 4 else '',
                    'cmdline_spoofed': str(parts[5]) if len(parts) > 5 else '',
                    'masqueraded': str(parts[4]) if len(parts) > 4 else ''  # 显示是否伪装
                }

        # 恶意代码查找 - Windows (默认，排除Linux和macOS)
        elif 'malfind' in plugin_name and 'linux' not in plugin_name and 'mac' not in plugin_name:
            if len(parts) >= 6:
                return {
                    'pid': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'process_name': str(parts[1]) if len(parts) > 1 else '',
                    'address': str(parts[2]) if len(parts) > 2 else '',
                    'size': int(parts[3]) if len(parts) > 3 and str(parts[3]).isdigit() else 0,
                    'protection': str(parts[4]) if len(parts) > 4 else '',
                    'suspicious': True,
                    'reason': str(parts[5]) if len(parts) > 5 else ''
                }

        # DLL列表插件
        # 有 --pid 时: Base Size Name Path LoadTime (5+ 列)
        # 无 --pid 时: PID Process Base Size Name Path LoadTime (7+ 列)
        elif 'dlllist' in plugin_name:
            if len(parts) >= 5:
                # 检查格式：如果第一列是数字，则是完整格式
                if str(parts[0]).isdigit() and len(parts) >= 7:
                    return {
                        'pid': int(parts[0]),
                        'process_name': str(parts[1]),
                        'base_address': str(parts[2]),
                        'size': str(parts[3]),
                        'name': str(parts[4]),
                        'path': str(parts[5]),
                        'load_time': str(parts[6]) if len(parts) > 6 else ''
                    }
                # 否则是 --pid 过滤后的格式 (Base Size Name Path...)
                elif not str(parts[0]).isdigit():
                    return {
                        'pid': 0,  # 会在调用处设置
                        'process_name': '',
                        'base_address': str(parts[0]),
                        'size': str(parts[1]),
                        'name': str(parts[2]),
                        'path': str(parts[3]),
                        'load_time': str(parts[4]) if len(parts) > 4 else ''
                    }

        # 句柄列表插件 - PID Process Offset HandleValue Type GrantedAccess Name
        elif 'handles' in plugin_name:
            if len(parts) >= 7:
                return {
                    'pid': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'process_name': str(parts[1]),
                    'offset': str(parts[2]),
                    'handle_value': str(parts[3]),
                    'type': str(parts[4]),
                    'granted_access': str(parts[5]),
                    'name': str(parts[6]) if len(parts) > 6 else ''
                }

        # 环境变量插件（非 Linux）
        elif 'envars' in plugin_name and 'linux' not in plugin_name:
            if len(parts) >= 3:
                return {
                    'pid': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'process_name': str(parts[1]),
                    'variable': str(parts[2]) if len(parts) > 2 else '',
                    'value': ' '.join(parts[3:]) if len(parts) > 3 else ''
                }

        # 服务扫描插件 - Offset Order PID Start State Type Name Display Binary Binary (Registry) Dll
        elif 'svcscan' in plugin_name:
            if len(parts) >= 8:
                return {
                    'offset': str(parts[0]),
                    'order': int(parts[1]) if len(parts) > 1 and str(parts[1]).isdigit() else 0,
                    'pid': int(parts[2]) if len(parts) > 2 and str(parts[2]).isdigit() else 0,
                    'start': str(parts[3]),
                    'state': str(parts[4]),
                    'type': str(parts[5]),
                    'name': str(parts[6]),
                    'display': str(parts[7]),
                    'binary': str(parts[8]) if len(parts) > 8 else '',
                    'binary_registry': str(parts[9]) if len(parts) > 9 else '',
                    'dll': str(parts[10]) if len(parts) > 10 else ''
                }

        # 获取SIDs插件
        elif 'getsids' in plugin_name:
            if len(parts) >= 3:
                return {
                    'pid': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'process_name': str(parts[1]),
                    'sid': str(parts[2]) if len(parts) > 2 else '',
                    'attributes': ' '.join(parts[3:]) if len(parts) > 3 else ''
                }

        # 哈希转储插件
        elif 'hashdump' in plugin_name:
            if len(parts) >= 4:
                return {
                    'username': str(parts[0]),
                    'rid': int(parts[1]) if len(parts) > 1 and str(parts[1]).isdigit() else 0,
                    'hash_lm': str(parts[2]) if len(parts) > 2 else '',
                    'hash_ntlm': str(parts[3]) if len(parts) > 3 else ''
                }

        # LSA密钥转储插件
        elif 'lsadump' in plugin_name:
            if len(parts) >= 2:
                # 第一行是 Key 名称，第二行开始是数据
                key_name = str(parts[0]) if parts[0] else ''
                # 将其他列合并为值
                value = '\t'.join(parts[1:]) if len(parts) > 1 else ''
                return {
                    'key': key_name,
                    'value': value[:100],  # 限制长度
                    'full_data': value
                }

        # 域缓存凭据转储插件 (mimikatz)
        elif 'cachedump' in plugin_name:
            if len(parts) >= 4:
                # cachedump 输出格式: Username Domain Domain_name Hash
                return {
                    'username': str(parts[0]) if parts[0] else '',
                    'domain': str(parts[1]) if len(parts) > 1 else '',
                    'domain_name': str(parts[2]) if len(parts) > 2 else '',
                    'hash_ntlm': str(parts[3]) if len(parts) > 3 else ''
                }

        # 注册表键值插件
        elif 'printkey' in plugin_name:
            # printkey 输出格式可能有多变，需要更灵活的解析
            # 至少需要 6 列: Last Write Time, Hive Offset, Type, Key, Name, Data, [Volatile]
            if len(parts) >= 6:
                # 列: Last Write Time, Hive Offset, Type, Key, Name, Data, [Volatile]
                type_value = str(parts[2]) if len(parts) > 2 else ''
                # 标准化type值，确保"Key"类型可以被前端识别
                logger.debug(f"printkey 解析: type={type_value}, key={parts[3] if len(parts) > 3 else 'N/A'}, name={parts[4] if len(parts) > 4 else 'N/A'}")
                return {
                    'last_write_time': str(parts[0]) if parts[0] else '',
                    'hive_offset': str(parts[1]) if len(parts) > 1 else '',
                    'type': type_value,
                    'key': str(parts[3]) if len(parts) > 3 else '',
                    'name': str(parts[4]) if len(parts) > 4 else '',
                    'data': str(parts[5]) if len(parts) > 5 else '',
                    'volatile': str(parts[6]) if len(parts) > 6 else 'False',
                    '_is_key': type_value == 'Key'  # 添加辅助字段
                }
            else:
                # 格式不匹配，记录详细信息
                logger.warning(f"printkey 格式不匹配: 期望至少6列，实际{len(parts)}列")
                logger.debug(f"printkey 原始数据 parts: {parts[:10]}")  # 只显示前10列避免太长

                # 尝试使用较少列的格式（某些情况下可能只有 5 列）
                if len(parts) >= 5:
                    type_value = str(parts[2]) if len(parts) > 2 else ''
                    return {
                        'last_write_time': str(parts[0]) if parts[0] else '',
                        'hive_offset': str(parts[1]) if len(parts) > 1 else '',
                        'type': type_value,
                        'key': str(parts[3]) if len(parts) > 3 else '',
                        'name': str(parts[4]) if len(parts) > 4 else '',
                        'data': '',
                        'volatile': 'False',
                        '_is_key': type_value == 'Key'
                    }

        # ==================== Linux 插件 ====================

        # Linux 进程列表 - OFFSET PID TID PPID COMM UID GID EUID EGID CREATION TIME File output
        elif 'pslist' in plugin_name and 'linux' in plugin_name:
            if len(parts) >= 10:
                # 前面的列是固定的，最后一列可能包含空格，需要合并
                file_output = ' '.join(parts[10:]) if len(parts) > 10 else ''
                return {
                    'offset': str(parts[0]),
                    'pid': int(parts[1]) if str(parts[1]).isdigit() else 0,
                    'tid': int(parts[2]) if len(parts) > 2 and str(parts[2]).isdigit() else 0,
                    'ppid': int(parts[3]) if len(parts) > 3 and str(parts[3]).isdigit() else 0,
                    'name': str(parts[4]) if len(parts) > 4 else '',
                    'uid': int(parts[5]) if len(parts) > 5 and str(parts[5]).isdigit() else 0,
                    'gid': int(parts[6]) if len(parts) > 6 and str(parts[6]).isdigit() else 0,
                    'euid': int(parts[7]) if len(parts) > 7 and str(parts[7]).isdigit() else 0,
                    'egid': int(parts[8]) if len(parts) > 8 and str(parts[8]).isdigit() else 0,
                    'start_time': str(parts[9]) if len(parts) > 9 else '',
                    'file_output': file_output
                }

        # Linux 进程树 - OFFSET (P) PID TID PPID COMM EXIT_STATE
        elif 'pstree' in plugin_name and 'linux' in plugin_name:
            if len(parts) >= 5:
                return {
                    'offset': str(parts[0]),
                    'pid': int(parts[1]) if str(parts[1]).isdigit() else 0,
                    'tid': int(parts[2]) if len(parts) > 2 and str(parts[2]).isdigit() else 0,
                    'ppid': int(parts[3]) if len(parts) > 3 and str(parts[3]).isdigit() else 0,
                    'name': str(parts[4]) if len(parts) > 4 else ''
                }

        # Linux Bash 历史 - PID Process CommandTime Command
        elif 'bash' in plugin_name and 'mac.' not in plugin_name:
            if len(parts) >= 4:
                # Command 可能包含空格，需要合并
                command = ' '.join(parts[3:]) if len(parts) > 3 else ''
                return {
                    'pid': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'time': str(parts[2]) if len(parts) > 2 else '',
                    'command': command
                }

        # Linux 环境变量 - PID PPID COMM KEY VALUE
        elif 'envars' in plugin_name and 'linux' in plugin_name:
            if len(parts) >= 5:
                return {
                    'pid': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'ppid': int(parts[1]) if len(parts) > 1 and str(parts[1]).isdigit() else 0,
                    'comm': str(parts[2]) if len(parts) > 2 else '',
                    'key': str(parts[3]) if len(parts) > 3 else '',
                    'value': str(parts[4]) if len(parts) > 4 else ''
                }

        # Linux ELF 文件 - PID Process Start End File Path File Output
        elif 'elfs' in plugin_name:
            if len(parts) >= 6:
                return {
                    'pid': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'start': str(parts[2]) if len(parts) > 2 else '',
                    'end': str(parts[3]) if len(parts) > 3 else '',
                    'file_path': str(parts[4]) if len(parts) > 4 else '',
                    'file_output': str(parts[5]) if len(parts) > 5 else ''
                }

        # Linux pagecache.Files - 列出缓存的文件
        # Volatility 3 InodeUser 格式: superblock_addr mountpoint device inode_num inode_addr type inode_pages cached_pages file_mode access_time modification_time change_time path inode_size
        elif 'pagecache' in plugin_name and 'files' in plugin_name.lower():
            # 至少需要 14 列，但如果 path 为空可能列数会少
            if len(parts) >= 13:
                # path 字段是 parts[12]，inode_size 是 parts[13]
                path_value = str(parts[12]) if len(parts) > 12 else ''
                inode_size_val = 0
                if len(parts) > 13:
                    size_str = str(parts[13]).replace(',', '').strip()
                    try:
                        inode_size_val = int(float(size_str))
                    except:
                        inode_size_val = 0

                return {
                    'superblock_addr': str(parts[0]),
                    'mountpoint': str(parts[1]) if len(parts) > 1 else '',
                    'device': str(parts[2]) if len(parts) > 2 else '',
                    'inode_num': int(parts[3]) if len(parts) > 3 and str(parts[3]).replace(',', '').isdigit() else 0,
                    'inode_addr': str(parts[4]) if len(parts) > 4 else '',
                    'file_type': str(parts[5]) if len(parts) > 5 else '',
                    'inode_pages': int(parts[6]) if len(parts) > 6 and str(parts[6]).replace(',', '').isdigit() else 0,
                    'cached_pages': int(parts[7]) if len(parts) > 7 and str(parts[7]).replace(',', '').isdigit() else 0,
                    'file_mode': str(parts[8]) if len(parts) > 8 else '',
                    'access_time': str(parts[9]) if len(parts) > 9 else '',
                    'modification_time': str(parts[10]) if len(parts) > 10 else '',
                    'change_time': str(parts[11]) if len(parts) > 11 else '',
                    'file_path': path_value,  # 兼容前端
                    'path': path_value,       # Volatility 3 原始字段名
                    'inode_size': inode_size_val,
                    '_can_download': True  # 标记可以下载
                }
            else:
                # 列数不对，记录警告
                logger.debug(f"pagecache.Files 列数不匹配: 期望14列，实际{len(parts)}列")

        # Linux DumpFiles - File Path | Inode | Size | Result
        elif 'dumpfiles' in plugin_name and 'linux' in plugin_name:
            if len(parts) >= 4:
                return {
                    'file_path': str(parts[0]) if parts[0] else '',
                    'inode': str(parts[1]) if len(parts) > 1 else '',
                    'size': int(parts[2]) if len(parts) > 2 and str(parts[2]).isdigit() else 0,
                    'result': str(parts[3]) if len(parts) > 3 else ''
                }

        # Linux 打开文件 - PID TID Process FD Path Device Inode Type Mode Changed Modified Accessed Size
        elif 'lsof' in plugin_name and 'mac.' not in plugin_name:
            if len(parts) >= 12:
                return {
                    'pid': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'tid': int(parts[1]) if len(parts) > 1 and str(parts[1]).isdigit() else 0,
                    'process': str(parts[2]) if len(parts) > 2 else '',
                    'fd': int(parts[3]) if len(parts) > 3 and (str(parts[3]).isdigit() or str(parts[3]) == '0') else str(parts[3]),
                    'path': str(parts[4]) if len(parts) > 4 else '',
                    'device': str(parts[5]) if len(parts) > 5 else '',
                    'inode': int(parts[6]) if len(parts) > 6 and str(parts[6]).isdigit() else 0,
                    'file_type': str(parts[7]) if len(parts) > 7 else '',
                    'mode': str(parts[8]) if len(parts) > 8 else '',
                    'changed': str(parts[9]) if len(parts) > 9 else '',
                    'modified': str(parts[10]) if len(parts) > 10 else '',
                    'accessed': str(parts[11]) if len(parts) > 11 else '',
                    'size': int(parts[12]) if len(parts) > 12 and str(parts[12]).isdigit() else 0
                }
            # Fallback for older format with fewer columns
            elif len(parts) >= 4:
                return {
                    'pid': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'fd': str(parts[1]) if len(parts) > 1 else '',
                    'file_path': str(parts[2]) if len(parts) > 2 else '',
                    'offset': str(parts[3]) if len(parts) > 3 else ''
                }

        # Linux Malfind - PID Start End Protection Permissions Constant Mapping
        # Volatility 3 输出格式: PID Start End Protection Permissions Constant Mapping
        elif 'malfind' in plugin_name and 'linux' in plugin_name:
            if len(parts) >= 7:
                return {
                    'pid': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'start': str(parts[1]),
                    'end': str(parts[2]),
                    'protection': str(parts[3]),
                    'permissions': str(parts[4]),
                    'constant': str(parts[5]) if len(parts) > 5 else '',
                    'mapping': str(parts[6]) if len(parts) > 6 else ''
                }

        # Linux Capabilities - PID Capabilities
        elif 'capabilities' in plugin_name and 'linux' in plugin_name:
            if len(parts) >= 3:
                return {
                    'pid': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'name': str(parts[1]) if len(parts) > 1 else '',
                    'capabilities': str(parts[2]) if len(parts) > 2 else ''
                }

        # Linux Check_afinfo - Address Family Info
        elif 'check_afinfo' in plugin_name:
            if len(parts) >= 3:
                return {
                    'offset': str(parts[0]),
                    'family': str(parts[1]) if len(parts) > 1 else '',
                    'status': str(parts[2]) if len(parts) > 2 else 'OK'
                }

        # Linux Check_creds - Credentials Check
        elif 'check_creds' in plugin_name:
            if len(parts) >= 4:
                return {
                    'offset': str(parts[0]),
                    'pid': int(parts[1]) if len(parts) > 1 and str(parts[1]).isdigit() else 0,
                    'process': str(parts[2]) if len(parts) > 2 else '',
                    'issue': str(parts[3]) if len(parts) > 3 else ''
                }

        # Linux Check_idt - Interrupt Descriptor Table
        elif 'check_idt' in plugin_name:
            if len(parts) >= 4:
                return {
                    'index': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'address': str(parts[1]) if len(parts) > 1 else '',
                    'expected': str(parts[2]) if len(parts) > 2 else '',
                    'status': str(parts[3]) if len(parts) > 3 else 'OK'
                }

        # Linux Check_modules - Kernel Module Check
        elif 'check_modules' in plugin_name:
            if len(parts) >= 3:
                return {
                    'name': str(parts[0]),
                    'offset': str(parts[1]) if len(parts) > 1 else '',
                    'status': str(parts[2]) if len(parts) > 2 else 'OK'
                }

        # Linux Check_syscall - System Call Table Check
        elif 'check_syscall' in plugin_name and 'mac.' not in plugin_name:
            if len(parts) >= 4:
                return {
                    'index': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'name': str(parts[1]) if len(parts) > 1 else '',
                    'address': str(parts[2]) if len(parts) > 2 else '',
                    'status': str(parts[3]) if len(parts) > 3 else 'OK'
                }

        # Linux IOMem - I/O Memory Ranges
        elif 'iomem' in plugin_name:
            if len(parts) >= 3:
                return {
                    'start': str(parts[0]),
                    'end': str(parts[1]) if len(parts) > 1 else '',
                    'description': str(parts[2]) if len(parts) > 2 else ''
                }

        # Linux Keyboard_notifiers - Keyboard Notifiers
        elif 'keyboard_notifiers' in plugin_name:
            if len(parts) >= 3:
                return {
                    'offset': str(parts[0]),
                    'address': str(parts[1]) if len(parts) > 1 else '',
                    'callback': str(parts[2]) if len(parts) > 2 else ''
                }

        # Linux Modxview - Module Extended View (综合模块视图)
        # 输出格式: Name Address In procfs In sysfs In scan Taints
        elif 'modxview' in plugin_name:
            if len(parts) >= 6:
                return {
                    'name': str(parts[0]),
                    'address': str(parts[1]) if len(parts) > 1 else '',
                    'in_procfs': str(parts[2]) if len(parts) > 2 else '',
                    'in_sysfs': str(parts[3]) if len(parts) > 3 else '',
                    'in_scan': str(parts[4]) if len(parts) > 4 else '',
                    'taints': str(parts[5]) if len(parts) > 5 else ''
                }

        # Linux Kmsg - Kernel Messages
        elif 'kmsg' in plugin_name:
            if len(parts) >= 2:
                return {
                    'timestamp': str(parts[0]),
                    'message': ' '.join(parts[1:]) if len(parts) > 1 else ''
                }

        # Linux Lsmod - List Kernel Modules
        # 输出格式: Offset Module Name Code Size Taints Load Arguments File Output
        elif 'lsmod' in plugin_name and 'mac.' not in plugin_name:
            if len(parts) >= 5:
                # 解析 Code Size (如 0x6000)
                code_size = 0
                size_str = str(parts[2]).strip()
                if size_str.startswith('0x') or size_str.startswith('0X'):
                    try:
                        code_size = int(size_str, 16)
                    except ValueError:
                        code_size = 0
                elif size_str.isdigit():
                    code_size = int(size_str)

                # Load Arguments 可能在 parts[4] 或更后，用空格连接
                load_args = ''
                file_output = ''
                if len(parts) > 5:
                    # 最后一个是 File Output，倒数第二个及之前是 Load Arguments
                    # 但实际输出中 Load Arguments 可能包含多个空格分隔的部分
                    # 所以我们取从 parts[4] 到倒数第二个作为 load_args
                    if len(parts) >= 6:
                        file_output = str(parts[-1]).strip()
                        load_args = ' '.join(parts[4:-1]).strip()
                    else:
                        load_args = str(parts[4]).strip()

                return {
                    'offset': str(parts[0]).strip(),
                    'name': str(parts[1]).strip() if len(parts) > 1 else '',
                    'code_size': code_size,
                    'taints': str(parts[3]).strip() if len(parts) > 3 else '',
                    'load_arguments': load_args,
                    'file_output': file_output
                }

        # Linux Mountinfo - Mount Information
        elif 'mountinfo' in plugin_name:
            # Linux MountInfo - 挂载信息
            # 尝试灵活解析不同数量的字段
            if len(parts) >= 5:
                result = {
                    'mount_id': int(parts[0]) if str(parts[0]).strip().isdigit() else 0,
                    'parent_id': int(parts[1]) if len(parts) > 1 and str(parts[1]).strip().isdigit() else 0,
                    'device': str(parts[2]).strip() if len(parts) > 2 else '',  # 保留 device 字段兼容性
                    'major_minor': str(parts[2]).strip() if len(parts) > 2 else '',
                    'root': str(parts[3]).strip() if len(parts) > 3 else '',
                    'mount_point': str(parts[4]).strip() if len(parts) > 4 else '',
                    'options': str(parts[5]).strip() if len(parts) > 5 else '',
                    # 只有当字段确实存在且不为空时才添加
                }

                # 尝试解析更多字段（仅当存在且非空）
                if len(parts) > 6:
                    val = str(parts[6]).strip()
                    if val and val != '-':
                        result['optional_fields'] = val
                if len(parts) > 7:
                    val = str(parts[7]).strip()
                    if val and val != '-':
                        result['separator'] = val
                if len(parts) > 8:
                    val = str(parts[8]).strip()
                    if val and val != '-':
                        result['filesystem_type'] = val
                if len(parts) > 9:
                    val = str(parts[9]).strip()
                    if val and val != '-':
                        result['mount_source'] = val
                if len(parts) > 10:
                    val = str(parts[10]).strip()
                    if val and val != '-':
                        result['super_options'] = val

                return result

        # Linux Maps (proc.Maps) - Process Memory Maps
        # Volatility 3 输出格式: PID Process Start End Permissions Offset Major Minor Inode File Path File Output
        elif ('maps' in plugin_name or 'proc.Maps' in plugin_name) and 'linux' in plugin_name.lower():
            if len(parts) >= 11:
                path_value = str(parts[9]) if len(parts) > 9 else ''
                return {
                    'pid': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'start': str(parts[2]) if len(parts) > 2 else '',
                    'end': str(parts[3]) if len(parts) > 3 else '',
                    'permissions': str(parts[4]) if len(parts) > 4 else '',
                    'offset': str(parts[5]) if len(parts) > 5 else '',
                    'major': int(parts[6]) if len(parts) > 6 and str(parts[6]).isdigit() else 0,
                    'minor': int(parts[7]) if len(parts) > 7 and str(parts[7]).isdigit() else 0,
                    'inode': int(parts[8]) if len(parts) > 8 and str(parts[8]).isdigit() else 0,
                    'path': path_value,
                    'name': path_value,  # 兼容前端
                    'file_output': str(parts[10]) if len(parts) > 10 else ''
                }
            # 更少的列（某些情况下没有 file_output）
            elif len(parts) >= 10:
                path_value = str(parts[9]) if len(parts) > 9 else ''
                return {
                    'pid': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'start': str(parts[2]) if len(parts) > 2 else '',
                    'end': str(parts[3]) if len(parts) > 3 else '',
                    'permissions': str(parts[4]) if len(parts) > 4 else '',
                    'offset': str(parts[5]) if len(parts) > 5 else '',
                    'major': int(parts[6]) if len(parts) > 6 and str(parts[6]).isdigit() else 0,
                    'minor': int(parts[7]) if len(parts) > 7 and str(parts[7]).isdigit() else 0,
                    'inode': int(parts[8]) if len(parts) > 8 and str(parts[8]).isdigit() else 0,
                    'path': path_value,
                    'name': path_value,  # 兼容前端
                    'file_output': ''
                }

        # Linux PsAux - Process Information (ps aux style)
        # Volatility 3 输出格式: PID	PPID	COMM	ARGS
        elif 'psaux' in plugin_name and 'mac.' not in plugin_name:
            if len(parts) >= 4:
                # args 可能包含空格，需要合并后面所有部分
                args = ' '.join(parts[3:]) if len(parts) > 3 else ''
                return {
                    'pid': int(parts[0]) if str(parts[0]).strip().isdigit() else 0,
                    'ppid': int(parts[1]) if len(parts) > 1 and str(parts[1]).strip().isdigit() else 0,
                    'comm': str(parts[2]) if len(parts) > 2 else '',
                    'args': args
                }

        # Linux Psscan - Process Scan
        # OFFSET (P) PID TID PPID COMM EXIT_STATE
        elif 'psscan' in plugin_name and 'linux' in plugin_name:
            if len(parts) >= 6:
                return {
                    'offset': str(parts[0]),
                    'pid': int(parts[1]) if str(parts[1]).isdigit() else 0,
                    'tid': int(parts[2]) if len(parts) > 2 and str(parts[2]).isdigit() else 0,
                    'ppid': int(parts[3]) if len(parts) > 3 and str(parts[3]).isdigit() else 0,
                    'name': str(parts[4]) if len(parts) > 4 else '',
                    'exit_state': str(parts[5]) if len(parts) > 5 else ''
                }

        # Linux Sockstat - Socket Statistics
        # Note: sockstat returns the same format as netstat in Volatility 3
        elif 'sockstat' in plugin_name and 'linux' in plugin_name:
            # Sockstat uses the same format as netstat
            if len(parts) >= 15:
                return {
                    'netns': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'process_name': str(parts[1]) if len(parts) > 1 else '',
                    'pid': int(parts[2]) if len(parts) > 2 and str(parts[2]).isdigit() else 0,
                    'tid': int(parts[3]) if len(parts) > 3 and str(parts[3]).isdigit() else 0,
                    'fd': int(parts[4]) if len(parts) > 4 and str(parts[4]).isdigit() else 0,
                    'sock_offset': str(parts[5]) if len(parts) > 5 else '',
                    'family': str(parts[6]) if len(parts) > 6 else '',
                    'type': str(parts[7]) if len(parts) > 7 else '',
                    'proto': str(parts[8]) if len(parts) > 8 else '',
                    'source_addr': str(parts[9]) if len(parts) > 9 else '',
                    'source_port': str(parts[10]) if len(parts) > 10 else '',
                    'dest_addr': str(parts[11]) if len(parts) > 11 else '',
                    'dest_port': str(parts[12]) if len(parts) > 12 else '',
                    'state': str(parts[13]) if len(parts) > 13 else '',
                    'filter': str(parts[14]) if len(parts) > 14 else ''
                }

        # Linux TTY_check - TTY Check
        elif 'tty_check' in plugin_name:
            if len(parts) >= 4:
                return {
                    'offset': str(parts[0]),
                    'address': str(parts[1]) if len(parts) > 1 else '',
                    'tty': str(parts[2]) if len(parts) > 2 else '',
                    'status': str(parts[3]) if len(parts) > 3 else 'OK'
                }

        # Linux VmaYaraScan - Yara Scan on VMA
        elif 'vmayarascan' in plugin_name:
            if len(parts) >= 5:
                return {
                    'pid': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'offset': str(parts[2]) if len(parts) > 2 else '',
                    'rule': str(parts[3]) if len(parts) > 3 else '',
                    'matches': int(parts[4]) if len(parts) > 4 and str(parts[4]).isdigit() else 0
                }

        # Windows Netstat - Proto LocalAddr LocalPort ForeignAddr ForeignPort State PID
        elif 'netstat' in plugin_name and 'windows' in plugin_name:
            if len(parts) >= 8:
                return {
                    'protocol': str(parts[0]),
                    'local_address': str(parts[1]),
                    'local_port': str(parts[2]),
                    'foreign_address': str(parts[3]),
                    'foreign_port': str(parts[4]),
                    'state': str(parts[5]),
                    'pid': int(parts[6]) if len(parts) > 6 and str(parts[6]).isdigit() else 0,
                    'process_name': str(parts[7]) if len(parts) > 7 else ''
                }

        # Linux Netfilter - Proto SrcAddr SrcPort DstAddr DstPort State
        elif 'netfilter' in plugin_name:
            if len(parts) >= 6:
                return {
                    'protocol': str(parts[0]),
                    'local_address': str(parts[1]),
                    'local_port': str(parts[2]),
                    'remote_address': str(parts[3]),
                    'remote_port': str(parts[4]),
                    'state': str(parts[5]) if len(parts) > 5 else ''
                }

        # Linux Netstat - NetNS Process Name PID TID FD Sock Offset Family Type Proto Source Addr Source Port Destination Addr Destination Port State Filter
        elif 'netstat' in plugin_name and 'linux' in plugin_name:
            if len(parts) >= 15:
                return {
                    'netns': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'process_name': str(parts[1]) if len(parts) > 1 else '',
                    'pid': int(parts[2]) if len(parts) > 2 and str(parts[2]).isdigit() else 0,
                    'tid': int(parts[3]) if len(parts) > 3 and str(parts[3]).isdigit() else 0,
                    'fd': int(parts[4]) if len(parts) > 4 and str(parts[4]).isdigit() else 0,
                    'sock_offset': str(parts[5]) if len(parts) > 5 else '',
                    'family': str(parts[6]) if len(parts) > 6 else '',
                    'type': str(parts[7]) if len(parts) > 7 else '',
                    'proto': str(parts[8]) if len(parts) > 8 else '',
                    'source_addr': str(parts[9]) if len(parts) > 9 else '',
                    'source_port': str(parts[10]) if len(parts) > 10 else '',
                    'dest_addr': str(parts[11]) if len(parts) > 11 else '',
                    'dest_port': str(parts[12]) if len(parts) > 12 else '',
                    'state': str(parts[13]) if len(parts) > 13 else '',
                    'filter': str(parts[14]) if len(parts) > 14 else ''
                }
            # Fallback for older/different format with fewer columns
            elif len(parts) >= 6:
                return {
                    'protocol': str(parts[0]),
                    'local_address': str(parts[1]),
                    'local_port': str(parts[2]),
                    'remote_address': str(parts[3]),
                    'remote_port': str(parts[4]),
                    'state': str(parts[5]) if len(parts) > 5 else ''
                }

        # Linux ip.Addr - 网络接口地址信息
        # NetNS Index Interface MAC Promiscuous IP Prefix Scope Type State
        elif 'ip.addr' in plugin_name.lower() or 'linux_ip_addr' in plugin_name.lower():
            # 灵活处理字段数量，某些行可能字段较少
            if len(parts) >= 8:
                # 解析各个字段，提供默认值
                netns = int(parts[0]) if str(parts[0]).strip().isdigit() else 0
                index = int(parts[1]) if len(parts) > 1 and str(parts[1]).strip().isdigit() else 0
                interface = str(parts[2]).strip() if len(parts) > 2 else ''
                mac = str(parts[3]).strip() if len(parts) > 3 else ''
                promiscuous = str(parts[4]).strip() if len(parts) > 4 else ''
                ip = str(parts[5]).strip() if len(parts) > 5 else ''
                prefix = int(parts[6]) if len(parts) > 6 and str(parts[6]).strip().isdigit() else 0

                # 从 parts[7] 开始可能是 Scope, Type, State
                # 某些行可能缺少最后的字段
                scope_type = str(parts[7]).strip() if len(parts) > 7 else ''

                # Type 可能在 parts[8]
                type_value = str(parts[8]).strip() if len(parts) > 8 else '-'
                if not type_value:
                    type_value = '-'

                # State 可能在 parts[9]
                state = str(parts[9]).strip() if len(parts) > 9 else ''

                return {
                    'netns': netns,
                    'index': index,
                    'interface': interface,
                    'mac': mac,
                    'promiscuous': promiscuous,
                    'ip': ip,
                    'prefix': prefix,
                    'scope_type': scope_type,
                    'type': type_value,
                    'state': state
                }

        # Linux ip.Link - 网络接口信息
        # NetNS Index Interface MAC Promiscuous State MTU Qdisc
        elif 'ip.link' in plugin_name.lower() or 'linux_ip_link' in plugin_name.lower():
            if len(parts) >= 8:
                return {
                    'netns': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'index': int(parts[1]) if len(parts) > 1 and str(parts[1]).isdigit() else 0,
                    'interface': str(parts[2]) if len(parts) > 2 else '',
                    'mac': str(parts[3]) if len(parts) > 3 else '',
                    'promiscuous': str(parts[4]) if len(parts) > 4 else '',
                    'state': str(parts[5]) if len(parts) > 5 else '',
                    'mtu': int(parts[6]) if len(parts) > 6 and str(parts[6]).isdigit() else 0,
                    'qdisc': str(parts[7]) if len(parts) > 7 else ''
                }

        # ==================== macOS 插件 ====================

        # macOS 进程列表 - OFFSET NAME PID UID GID Start Time PPID
        elif 'pslist' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 7:
                return {
                    'offset': str(parts[0]),
                    'name': str(parts[1]),
                    'pid': int(parts[2]) if str(parts[2]).strip().isdigit() else 0,
                    'uid': int(parts[3]) if len(parts) > 3 and str(parts[3]).strip().isdigit() else 0,
                    'gid': int(parts[4]) if len(parts) > 4 and str(parts[4]).strip().isdigit() else 0,
                    'start_time': str(parts[5]) if len(parts) > 5 else '',
                    'ppid': int(parts[6]) if len(parts) > 6 and str(parts[6]).strip().isdigit() else 0
                }

        # macOS 进程树 - (PID PPID COMM)
        elif 'pstree' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 3:
                return {
                    'pid': int(parts[0]) if str(parts[0]).strip().isdigit() else 0,
                    'ppid': int(parts[1]) if len(parts) > 1 and str(parts[1]).strip().isdigit() else 0,
                    'name': str(parts[2]) if len(parts) > 2 else ''
                }

        # macOS 环境变量 - PID Variable Value
        elif 'envars' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 3:
                return {
                    'pid': int(parts[0]) if str(parts[0]).isdigit() else 0,
                    'variable': str(parts[1]) if len(parts) > 1 else '',
                    'value': ' '.join(parts[2:]) if len(parts) > 2 else ''
                }

        # macOS Netstat - Offset Proto LAddr LPort RAddr RPort State Process
        elif 'netstat' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 7:
                return {
                    'offset': str(parts[0]),
                    'protocol': str(parts[1]) if len(parts) > 1 else '',
                    'local_address': str(parts[2]) if len(parts) > 2 else '',
                    'local_port': str(parts[3]) if len(parts) > 3 else '',
                    'remote_address': str(parts[4]) if len(parts) > 4 else '',
                    'remote_port': str(parts[5]) if len(parts) > 5 else '',
                    'state': str(parts[6]) if len(parts) > 6 else '',
                    'process': ' '.join(parts[7:]) if len(parts) > 7 else ''
                }

        # macOS Dmesg - Kernel Messages
        # 实际格式: line (single column with message)
        elif 'dmesg' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 1:
                return {
                    'line': ' '.join(parts)
                }

        # macOS Ifconfig - Network Interface Configuration
        # 实际格式: Interface IP Address Mac Address Promiscuous
        # 注意：当 IP 为空时，MAC 可能会出现在 IP 的位置
        elif 'ifconfig' in plugin_name:
            if len(parts) >= 4:
                interface = str(parts[0])
                # parts[1] 可能是 IP 或 MAC（当 IP 为空时）
                # parts[2] 可能是 MAC 或空
                potential_ip_or_mac = str(parts[1]) if len(parts) > 1 else ''
                potential_mac = str(parts[2]) if len(parts) > 2 else ''
                promiscuous_value = str(parts[3]) if len(parts) > 3 else ''

                # 检查 parts[1] 是否像 MAC 地址（包含冒号）
                if ':' in potential_ip_or_mac and potential_ip_or_mac.count(':') >= 5:
                    # parts[1] 是 MAC 地址，IP 为空
                    mac_address = potential_ip_or_mac
                    ip_address = ''
                else:
                    # parts[1] 是 IP 地址
                    ip_address = potential_ip_or_mac
                    mac_address = potential_mac

                return {
                    'interface': interface,
                    'ip_address': ip_address,
                    'mac_address': mac_address,
                    'promiscuous': promiscuous_value,
                    'status': promiscuous_value  # 兼容前端
                }

        # macOS Kauth_listeners - Kauth Listeners
        # 实际格式: Name IData Callback Address Module Symbol
        elif 'kauth_listeners' in plugin_name:
            if len(parts) >= 4:
                return {
                    'name': str(parts[0]),
                    'idata': str(parts[1]) if len(parts) > 1 else '',
                    'callback_address': str(parts[2]) if len(parts) > 2 else '',
                    'module': str(parts[3]) if len(parts) > 3 else '',
                    'symbol': ' '.join(parts[4:]) if len(parts) > 4 else ''
                }

        # macOS Kauth_scopes - Kauth Scopes
        # 实际格式: Name IData Listeners Callback Address Module Symbol
        elif 'kauth_scopes' in plugin_name:
            if len(parts) >= 5:
                return {
                    'name': str(parts[0]),
                    'idata': str(parts[1]) if len(parts) > 1 else '',
                    'listeners': str(parts[2]) if len(parts) > 2 else '',
                    'callback_address': str(parts[3]) if len(parts) > 3 else '',
                    'module': str(parts[4]) if len(parts) > 4 else '',
                    'symbol': ' '.join(parts[5:]) if len(parts) > 5 else ''
                }

        # macOS Kevents - Kernel Events
        # 实际格式: PID Process Ident Filter Context
        elif 'kevents' in plugin_name:
            if len(parts) >= 4:
                return {
                    'pid': int(parts[0]) if str(parts[0]).strip().isdigit() else 0,
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'ident': str(parts[2]) if len(parts) > 2 else '',
                    'filter': str(parts[3]) if len(parts) > 3 else '',
                    'context': ' '.join(parts[4:]) if len(parts) > 4 else ''
                }

        # macOS List_files - List Files
        # 实际格式: Address File Path (只有 2 列)
        elif 'list_files' in plugin_name:
            if len(parts) >= 2:
                return {
                    'offset': str(parts[0]),
                    'path': str(parts[1]) if len(parts) > 1 else '',
                    'name': str(parts[1]) if len(parts) > 1 else ''  # 兼容前端
                }

        # macOS Lsmod - List Kernel Modules
        # 实际格式: Offset Name Size (只有 3 列)
        elif 'lsmod' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 3:
                return {
                    'offset': str(parts[0]),
                    'name': str(parts[1]) if len(parts) > 1 else '',
                    'size': int(parts[2]) if len(parts) > 2 and str(parts[2]).strip().isdigit() else 0
                }

        # macOS Lsof - List Open Files
        # 实际格式: PID File Descriptor File Path
        elif 'lsof' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 3:
                fd_value = str(parts[1]) if len(parts) > 1 else ''
                return {
                    'pid': int(parts[0]) if str(parts[0]).strip().isdigit() else 0,
                    'file_descriptor': fd_value,
                    'fd': fd_value,  # 兼容前端
                    'file_path': str(parts[2]) if len(parts) > 2 else ''
                }

        # macOS Mount - Mount Information
        # 实际格式: Device Mount Point Type (只有 3 列)
        elif 'mount' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 3:
                return {
                    'device': str(parts[0]),
                    'mount_point': str(parts[1]) if len(parts) > 1 else '',
                    'type': str(parts[2]) if len(parts) > 2 else ''
                }

        # macOS Maps (proc_maps) - Process Memory Maps
        # 实际格式: PID Process Start End Protection Map Name File output
        elif ('maps' in plugin_name or 'proc.Maps' in plugin_name or 'proc_maps' in plugin_name) and 'mac' in plugin_name.lower():
            if len(parts) >= 7:
                protection_value = str(parts[4]) if len(parts) > 4 else ''
                map_name_value = str(parts[5]) if len(parts) > 5 else ''
                return {
                    'pid': int(parts[0]) if str(parts[0]).strip().isdigit() else 0,
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'start': str(parts[2]) if len(parts) > 2 else '',
                    'end': str(parts[3]) if len(parts) > 3 else '',
                    'protection': protection_value,
                    'permissions': protection_value,  # 兼容前端
                    'map_name': map_name_value,
                    'name': map_name_value,  # 兼容前端
                    'file_output': str(parts[6]) if len(parts) > 6 else ''
                }
            elif len(parts) >= 6:
                protection_value = str(parts[4]) if len(parts) > 4 else ''
                map_name_value = str(parts[5]) if len(parts) > 5 else ''
                return {
                    'pid': int(parts[0]) if str(parts[0]).strip().isdigit() else 0,
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'start': str(parts[2]) if len(parts) > 2 else '',
                    'end': str(parts[3]) if len(parts) > 3 else '',
                    'protection': protection_value,
                    'permissions': protection_value,  # 兼容前端
                    'map_name': map_name_value,
                    'name': map_name_value,  # 兼容前端
                    'file_output': ''
                }

        # macOS PsAux - Process Information (ps aux style)
        # 实际格式: PID Process Argc Arguments
        elif 'psaux' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 3:
                process = str(parts[1]) if len(parts) > 1 else ''
                arguments = ' '.join(parts[3:]) if len(parts) > 3 else ''
                command = f"{process} {arguments}".strip()
                return {
                    'pid': int(parts[0]) if str(parts[0]).strip().isdigit() else 0,
                    'process': process,
                    'argc': int(parts[2]) if len(parts) > 2 and str(parts[2]).strip().isdigit() else 0,
                    'arguments': arguments,
                    # 兼容前端字段
                    'user': '',
                    'cpu': '',
                    'mem': '',
                    'vsz': '',
                    'rss': '',
                    'tty': '',
                    'command': command
                }

        # macOS Socket_filters - Socket Filters
        # 实际格式: Filter Name Member Socket Handler Module Symbol
        elif 'socket_filters' in plugin_name:
            if len(parts) >= 7:
                return {
                    'filter': str(parts[0]),
                    'name': str(parts[1]) if len(parts) > 1 else '',
                    'member': str(parts[2]) if len(parts) > 2 else '',
                    'socket': str(parts[3]) if len(parts) > 3 else '',
                    'handler': str(parts[4]) if len(parts) > 4 else '',
                    'module': str(parts[5]) if len(parts) > 5 else '',
                    'symbol': str(parts[6]) if len(parts) > 6 else ''
                }
            elif len(parts) >= 4:
                return {
                    'filter': str(parts[0]),
                    'name': str(parts[1]) if len(parts) > 1 else '',
                    'member': str(parts[2]) if len(parts) > 2 else '',
                    'socket': str(parts[3]) if len(parts) > 3 else '',
                    'handler': '',
                    'module': '',
                    'symbol': ''
                }

        # macOS Timers - Kernel Timers
        # 实际格式: Function Param 0 Param 1 Deadline Entry Time Module Symbol
        elif 'timers' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 6:
                return {
                    'function': str(parts[0]),
                    'param_0': str(parts[1]) if len(parts) > 1 else '',
                    'param_1': str(parts[2]) if len(parts) > 2 else '',
                    'deadline': str(parts[3]) if len(parts) > 3 else '',
                    'entry_time': str(parts[4]) if len(parts) > 4 else '',
                    'module': str(parts[5]) if len(parts) > 5 else '',
                    'symbol': ' '.join(parts[6:]) if len(parts) > 6 else ''
                }

        # macOS Trustedbsd - TrustedBSD
        # 实际格式: Member Policy Name Handler Address Handler Module Handler Symbol
        elif 'trustedbsd' in plugin_name:
            if len(parts) >= 5:
                return {
                    'member': str(parts[0]),
                    'policy_name': str(parts[1]) if len(parts) > 1 else '',
                    'handler_address': str(parts[2]) if len(parts) > 2 else '',
                    'handler_module': str(parts[3]) if len(parts) > 3 else '',
                    'handler_symbol': str(parts[4]) if len(parts) > 4 else ''
                }

        # macOS VFSevents - VFS Events
        # 实际格式: Name PID Events
        elif 'vfsevents' in plugin_name:
            if len(parts) >= 3:
                return {
                    'name': str(parts[0]),
                    'pid': int(parts[1]) if len(parts) > 1 and str(parts[1]).strip().isdigit() else 0,
                    'events': ' '.join(parts[2:]) if len(parts) > 2 else ''
                }

        # macOS Check_syscall - Check System Call Table
        # 实际格式: Table Address Table Name Index Handler Address Handler Module Handler Symbol
        elif 'check_syscall' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 6:
                return {
                    'table_address': str(parts[0]),
                    'table_name': str(parts[1]) if len(parts) > 1 else '',
                    'index': int(parts[2]) if len(parts) > 2 and str(parts[2]).strip().isdigit() else 0,
                    'handler_address': str(parts[3]) if len(parts) > 3 else '',
                    'handler_module': str(parts[4]) if len(parts) > 4 else '',
                    'handler_symbol': str(parts[5]) if len(parts) > 5 else ''
                }

        # macOS Check_sysctl - Check Sysctl
        # 实际格式: Name Number Perms Handler Address Value Handler Module Handler Symbol
        elif 'check_sysctl' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 7:
                return {
                    'name': str(parts[0]),
                    'number': str(parts[1]) if len(parts) > 1 else '',
                    'perms': str(parts[2]) if len(parts) > 2 else '',
                    'handler_address': str(parts[3]) if len(parts) > 3 else '',
                    'value': str(parts[4]) if len(parts) > 4 else '',
                    'handler_module': str(parts[5]) if len(parts) > 5 else '',
                    'handler_symbol': str(parts[6]) if len(parts) > 6 else ''
                }

        # macOS Check_trap_table - Check Trap Table
        # 实际格式: Table Address Table Name Index Handler Address Handler Module Handler Symbol
        elif 'check_trap_table' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 6:
                return {
                    'table_address': str(parts[0]),
                    'table_name': str(parts[1]) if len(parts) > 1 else '',
                    'index': int(parts[2]) if len(parts) > 2 and str(parts[2]).strip().isdigit() else 0,
                    'handler_address': str(parts[3]) if len(parts) > 3 else '',
                    'handler_module': str(parts[4]) if len(parts) > 4 else '',
                    'handler_symbol': str(parts[5]) if len(parts) > 5 else ''
                }

        # macOS Malfind - Find Malicious Code
        # 实际格式: PID Process Start End Protection Hexdump Disasm
        elif 'malfind' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 6:
                return {
                    'pid': int(parts[0]) if str(parts[0]).strip().isdigit() else 0,
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'start': str(parts[2]) if len(parts) > 2 else '',
                    'end': str(parts[3]) if len(parts) > 3 else '',
                    'protection': str(parts[4]) if len(parts) > 4 else '',
                    'hexdump': str(parts[5]) if len(parts) > 5 else '',
                    'disasm': ' '.join(parts[6:]) if len(parts) > 6 else ''
                }

        # macOS Bash - Bash History
        # 实际格式: PID Process CommandTime Command
        elif 'bash' in plugin_name and 'mac' in plugin_name:
            if len(parts) >= 4:
                return {
                    'pid': int(parts[0]) if str(parts[0]).strip().isdigit() else 0,
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'command_time': str(parts[2]) if len(parts) > 2 else '',
                    'command': str(parts[3]) if len(parts) > 3 else ''
                }

        # Windows CmdScan - 命令历史记录
        # 实际格式: PID Process ConsoleInfo Property Address Data
        elif 'cmdscan' in plugin_name and 'windows' in plugin_name:
            if len(parts) >= 6:
                return {
                    'pid': int(parts[0]) if str(parts[0]).strip().isdigit() else 0,
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'console_info': str(parts[2]) if len(parts) > 2 else '',
                    'property': str(parts[3]) if len(parts) > 3 else '',
                    'address': str(parts[4]) if len(parts) > 4 else '',
                    'data': str(parts[5]) if len(parts) > 5 else ''
                }

        # Windows Consoles - 控制台历史
        # 实际格式: PID Process ConsoleInfo Property Address Data
        elif 'consoles' in plugin_name and 'windows' in plugin_name:
            if len(parts) >= 6:
                return {
                    'pid': int(parts[0]) if str(parts[0]).strip().isdigit() else 0,
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'console_info': str(parts[2]) if len(parts) > 2 else '',
                    'property': str(parts[3]) if len(parts) > 3 else '',
                    'address': str(parts[4]) if len(parts) > 4 else '',
                    'data': str(parts[5]) if len(parts) > 5 else ''
                }

        # Windows PsXview - 进程隐藏检测
        # 实际格式: Offset Name PID pslist psscan thrdscan csrss ExitTime
        elif 'psxview' in plugin_name:
            if len(parts) >= 8:
                return {
                    'offset': str(parts[0]),
                    'name': str(parts[1]) if len(parts) > 1 else '',
                    'pid': int(parts[2]) if len(parts) > 2 and str(parts[2]).strip().isdigit() else 0,
                    'pslist': str(parts[3]) if len(parts) > 3 else '',
                    'psscan': str(parts[4]) if len(parts) > 4 else '',
                    'thrdscan': str(parts[5]) if len(parts) > 5 else '',
                    'csrss': str(parts[6]) if len(parts) > 6 else '',
                    'exit_time': str(parts[7]) if len(parts) > 7 else ''
                }

        # Windows Callbacks - 回调函数
        # 实际格式: Type Callback Module Symbol Detail
        elif 'callbacks' in plugin_name:
            if len(parts) >= 5:
                return {
                    'type': str(parts[0]),
                    'callback': str(parts[1]) if len(parts) > 1 else '',
                    'module': str(parts[2]) if len(parts) > 2 else '',
                    'symbol': str(parts[3]) if len(parts) > 3 else '',
                    'detail': str(parts[4]) if len(parts) > 4 else ''
                }

        # Windows Privileges - 进程权限
        # 实际格式: PID Process Value Privilege Attributes Description
        elif 'privileges' in plugin_name or 'privs' in plugin_name:
            if len(parts) >= 6:
                return {
                    'pid': int(parts[0]) if str(parts[0]).strip().isdigit() else 0,
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'value': str(parts[2]) if len(parts) > 2 else '',
                    'privilege': str(parts[3]) if len(parts) > 3 else '',
                    'attributes': str(parts[4]) if len(parts) > 4 else '',
                    'description': str(parts[5]) if len(parts) > 5 else ''
                }

        # Windows Sessions - 会话信息
        # 实际格式: SessionID SessionType PID Process UserName CreateTime
        elif 'sessions' in plugin_name:
            if len(parts) >= 6:
                return {
                    'session_id': str(parts[0]),
                    'session_type': str(parts[1]),
                    'pid': int(parts[2]) if len(parts) > 2 and str(parts[2]).strip().isdigit() else 0,
                    'process': str(parts[3]) if len(parts) > 3 else '',
                    'user_name': str(parts[4]) if len(parts) > 4 else '',
                    'create_time': str(parts[5]) if len(parts) > 5 else ''
                }

        # Windows Suspicious Threads - 必须在 threads 之前检查
        # 实际格式: Process PID TID Context Address VADPath Note
        # 注意: VADPath 可能包含空格（如 "<Non-File Backed Region>"），会被拆分成多列
        elif 'suspicious_threads' in plugin_name:
            if len(parts) >= 7:
                # VAD Path 可能被拆分成多列，从 parts[5] 开始到 parts[6] 之前
                # Note 从 parts[6] 开始，可能包含多个词
                vad_path_parts = []
                note_parts = []
                in_vad_path = True

                # 从 parts[5] 开始处理
                for i in range(5, len(parts)):
                    part = parts[i]
                    # 检测 Note 字段的开始（通常以 "This" 或其他大写字母开头的句子开始）
                    # 但要跳过 VAD Path 中的单词
                    if in_vad_path and part in ['This', 'Thread', 'A', 'The', 'Possible']:
                        in_vad_path = False
                        note_parts.append(part)
                    elif in_vad_path:
                        vad_path_parts.append(part)
                    else:
                        note_parts.append(part)

                vad_path = ' '.join(vad_path_parts) if vad_path_parts else (str(parts[5]) if len(parts) > 5 else '')
                note = ' '.join(note_parts) if note_parts else (str(parts[6]) if len(parts) > 6 else '')

                return {
                    'process': str(parts[0]),
                    'pid': int(parts[1]) if len(parts) > 1 and str(parts[1]).strip().isdigit() else 0,
                    'tid': int(parts[2]) if len(parts) > 2 and str(parts[2]).strip().isdigit() else 0,
                    'context': str(parts[3]) if len(parts) > 3 else '',
                    'address': str(parts[4]) if len(parts) > 4 else '',
                    'vad_path': vad_path,
                    'note': note
                }

        # Windows Threads - 线程信息
        # 实际格式: Offset PID TID StartAddress StartPath Win32StartAddress Win32StartPath CreateTime ExitTime
        elif 'threads' in plugin_name:
            if len(parts) >= 9:
                return {
                    'offset': str(parts[0]),
                    'pid': int(parts[1]) if len(parts) > 1 and str(parts[1]).strip().isdigit() else 0,
                    'tid': int(parts[2]) if len(parts) > 2 and str(parts[2]).strip().isdigit() else 0,
                    'start_address': str(parts[3]) if len(parts) > 3 else '',
                    'start_path': str(parts[4]) if len(parts) > 4 else '',
                    'win32_start_address': str(parts[5]) if len(parts) > 5 else '',
                    'win32_start_path': str(parts[6]) if len(parts) > 6 else '',
                    'create_time': str(parts[7]) if len(parts) > 7 else '',
                    'exit_time': str(parts[8]) if len(parts) > 8 else ''
                }

        # Windows VadInfo - 虚拟地址描述符信息
        # 实际格式: PID Process Offset StartVPN EndVPN Tag Protection CommitCharge PrivateMemory Parent File FileOutput
        elif 'vadinfo' in plugin_name:
            if len(parts) >= 12:
                result = {
                    'pid': int(parts[0]) if str(parts[0]).strip().isdigit() else 0,
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'offset': str(parts[2]) if len(parts) > 2 else '',
                    'start_vpn': str(parts[3]) if len(parts) > 3 else '',
                    'end_vpn': str(parts[4]) if len(parts) > 4 else '',
                    'tag': str(parts[5]) if len(parts) > 5 else '',
                    'protection': str(parts[6]) if len(parts) > 6 else '',
                    'commit_charge': int(parts[7]) if len(parts) > 7 and str(parts[7]).strip().isdigit() else 0,
                    'private_memory': int(parts[8]) if len(parts) > 8 and str(parts[8]).strip().isdigit() else 0,
                    'parent': str(parts[9]) if len(parts) > 9 else '',
                    'file': str(parts[10]) if len(parts) > 10 else '',
                    'file_output': str(parts[11]) if len(parts) > 11 else ''
                }
                # 调试日志
                logger.debug(f"vadinfo 解析: file={result['file']}, parts[10]={parts[10] if len(parts) > 10 else 'N/A'}")
                return result

        # Windows MutantScan - 互斥体扫描
        # 实际格式: Offset Mutant Name
        elif 'mutantscan' in plugin_name:
            if len(parts) >= 2:
                return {
                    'offset': str(parts[0]),
                    'name': ' '.join(parts[1:]) if len(parts) > 1 else ''
                }

        # Windows ModScan - 模块扫描
        # 实际格式: Offset Base Size Name Path FileOutput
        elif 'modscan' in plugin_name:
            if len(parts) >= 6:
                return {
                    'offset': str(parts[0]),
                    'base': str(parts[1]) if len(parts) > 1 else '',
                    'size': str(parts[2]) if len(parts) > 2 else '',
                    'name': str(parts[3]) if len(parts) > 3 else '',
                    'path': str(parts[4]) if len(parts) > 4 else '',
                    'file_output': str(parts[5]) if len(parts) > 5 else ''
                }

        # Windows SSDT - 系统服务描述符表
        # 实际格式: Index Address Service Symbol
        elif 'ssdt' in plugin_name:
            if len(parts) >= 4:
                return {
                    'index': int(parts[0]) if str(parts[0]).strip().isdigit() else 0,
                    'address': str(parts[1]) if len(parts) > 1 else '',
                    'service': str(parts[2]) if len(parts) > 2 else '',
                    'symbol': str(parts[3]) if len(parts) > 3 else ''
                }

        # Windows DriverScan - 驱动扫描
        # 实际格式: Offset Start Size Service_Key Driver_Name Name
        elif 'driverscan' in plugin_name:
            if len(parts) >= 6:
                return {
                    'offset': str(parts[0]),
                    'start': str(parts[1]) if len(parts) > 1 else '',
                    'size': str(parts[2]) if len(parts) > 2 else '',
                    'service_key': str(parts[3]) if len(parts) > 3 else '',
                    'driver_name': str(parts[4]) if len(parts) > 4 else '',
                    'name': str(parts[5]) if len(parts) > 5 else ''
                }

        # Windows DriverModule - 驱动模块检测（隐藏驱动）
        # 实际格式: Offset Known_Exception Driver_Name Service_Key Alternative_Name
        elif 'drivermodule' in plugin_name:
            if len(parts) >= 5:
                return {
                    'offset': str(parts[0]),
                    'known_exception': str(parts[1]) if len(parts) > 1 else '',
                    'driver_name': str(parts[2]) if len(parts) > 2 else '',
                    'service_key': str(parts[3]) if len(parts) > 3 else '',
                    'alternative_name': str(parts[4]) if len(parts) > 4 else ''
                }

        # Windows DriverIrp - 驱动IRP列表
        # 实际格式: Offset Driver_Name IRP Address Module Symbol
        elif 'driverirp' in plugin_name:
            if len(parts) >= 6:
                return {
                    'offset': str(parts[0]),
                    'driver_name': str(parts[1]) if len(parts) > 1 else '',
                    'irp': str(parts[2]) if len(parts) > 2 else '',
                    'address': str(parts[3]) if len(parts) > 3 else '',
                    'module': str(parts[4]) if len(parts) > 4 else '',
                    'symbol': str(parts[5]) if len(parts) > 5 else ''
                }

        # Windows ShimCacheMem - Shim 缓存
        # 实际格式: Order LastModified LastUpdate ExecFlag FileSize FilePath
        elif 'shimcachemem' in plugin_name:
            if len(parts) >= 6:
                return {
                    'order': int(parts[0]) if str(parts[0]).strip().isdigit() else 0,
                    'last_modified': str(parts[1]) if len(parts) > 1 else '',
                    'last_update': str(parts[2]) if len(parts) > 2 else '',
                    'exec_flag': str(parts[3]) if len(parts) > 3 else '',
                    'file_size': str(parts[4]) if len(parts) > 4 else '',
                    'file_path': str(parts[5]) if len(parts) > 5 else ''
                }

        # Windows MftScan - MFT 扫描
        # 实际格式: Offset RecordType RecordNumber LinkCount MFTType Permissions AttributeType Created Modified Updated Accessed Filename
        elif 'mftscan' in plugin_name:
            if len(parts) >= 12:
                return {
                    'offset': str(parts[0]),
                    'record_type': str(parts[1]) if len(parts) > 1 else '',
                    'record_number': int(parts[2]) if len(parts) > 2 and str(parts[2]).strip().isdigit() else 0,
                    'link_count': int(parts[3]) if len(parts) > 3 and str(parts[3]).strip().isdigit() else 0,
                    'mft_type': str(parts[4]) if len(parts) > 4 else '',
                    'permissions': str(parts[5]) if len(parts) > 5 else '',
                    'attribute_type': str(parts[6]) if len(parts) > 6 else '',
                    'created': str(parts[7]) if len(parts) > 7 else '',
                    'modified': str(parts[8]) if len(parts) > 8 else '',
                    'updated': str(parts[9]) if len(parts) > 9 else '',
                    'accessed': str(parts[10]) if len(parts) > 10 else '',
                    'filename': str(parts[11]) if len(parts) > 11 else ''
                }

        # Windows MbrScan - MBR 扫描
        # 实际格式: Offset DiskSignature BootcodeMD5 FullMBRMD5 PartitionIndex Bootable PartitionType SectorInSize Disasm
        elif 'mbrscan' in plugin_name:
            if len(parts) >= 9:
                return {
                    'offset': str(parts[0]),
                    'disk_signature': str(parts[1]) if len(parts) > 1 else '',
                    'bootcode_md5': str(parts[2]) if len(parts) > 2 else '',
                    'full_mbr_md5': str(parts[3]) if len(parts) > 3 else '',
                    'partition_index': int(parts[4]) if len(parts) > 4 and str(parts[4]).strip().isdigit() else 0,
                    'bootable': str(parts[5]) if len(parts) > 5 else '',
                    'partition_type': str(parts[6]) if len(parts) > 6 else '',
                    'sector_size': str(parts[7]) if len(parts) > 7 else '',
                    'disasm': str(parts[8]) if len(parts) > 8 else ''
                }

        # Windows CrashInfo - 崩溃信息
        # 实际格式: Signature MajorVersion MinorVersion DirectoryTableBase PfnDataBase PsLoadedModuleList PsActiveProcessHead
        elif 'crashinfo' in plugin_name:
            if len(parts) >= 7:
                return {
                    'signature': str(parts[0]),
                    'major_version': int(parts[1]) if len(parts) > 1 and str(parts[1]).strip().isdigit() else 0,
                    'minor_version': int(parts[2]) if len(parts) > 2 and str(parts[2]).strip().isdigit() else 0,
                    'directory_table_base': str(parts[3]) if len(parts) > 3 else '',
                    'pfn_data_base': str(parts[4]) if len(parts) > 4 else '',
                    'ps_loaded_module_list': str(parts[5]) if len(parts) > 5 else '',
                    'ps_active_process_head': str(parts[6]) if len(parts) > 6 else ''
                }

        # Windows DeskScan / Desktops - 桌面扫描
        # 实际格式: Offset WindowStation Session Desktop Process PID
        elif 'deskscan' in plugin_name or 'desktops' in plugin_name:
            if len(parts) >= 6:
                return {
                    'offset': str(parts[0]),
                    'window_station': str(parts[1]) if len(parts) > 1 else '',
                    'session': int(parts[2]) if len(parts) > 2 and str(parts[2]).strip().isdigit() else 0,
                    'desktop': str(parts[3]) if len(parts) > 3 else '',
                    'process': str(parts[4]) if len(parts) > 4 else '',
                    'pid': int(parts[5]) if len(parts) > 5 and str(parts[5]).strip().isdigit() else 0
                }

        # Windows DeviceTree - 设备树
        # 实际格式: Offset Type DriverName DeviceName DriverNameOfAttDevice DeviceType
        elif 'devicetree' in plugin_name:
            if len(parts) >= 6:
                return {
                    'offset': str(parts[0]),
                    'type': str(parts[1]) if len(parts) > 1 else '',
                    'driver_name': str(parts[2]) if len(parts) > 2 else '',
                    'device_name': str(parts[3]) if len(parts) > 3 else '',
                    'driver_name_of_att_device': str(parts[4]) if len(parts) > 4 else '',
                    'device_type': str(parts[5]) if len(parts) > 5 else ''
                }

        # Windows BigPools - 大内存池
        # 实际格式: Allocation Tag PoolType NumberOfBytes Status
        elif 'bigpools' in plugin_name:
            if len(parts) >= 5:
                return {
                    'allocation': str(parts[0]),
                    'tag': str(parts[1]) if len(parts) > 1 else '',
                    'pool_type': str(parts[2]) if len(parts) > 2 else '',
                    'number_of_bytes': str(parts[3]) if len(parts) > 3 else '',
                    'status': str(parts[4]) if len(parts) > 4 else ''
                }

        # Windows Skeleton Key Check
        # 实际格式: Status Message
        elif 'skeleton_key_check' in plugin_name:
            if len(parts) >= 1:
                return {
                    'status': str(parts[0]),
                    'message': ' '.join(parts[1:]) if len(parts) > 1 else ''
                }

        # Windows TrueCrypt
        # 实际格式: Type Password
        elif 'truecrypt' in plugin_name:
            if len(parts) >= 2:
                return {
                    'type': str(parts[0]),
                    'password': ' '.join(parts[1:]) if len(parts) > 1 else ''
                }

        # Windows UserAssist - 注册表
        # 实际格式: HiveOffset HiveName Path LastWriteTime Type Name ID Count FocusCount TimeFocused LastUpdated RawData
        elif 'userassist' in plugin_name:
            if len(parts) >= 12:
                return {
                    'hive_offset': str(parts[0]),
                    'hive_name': str(parts[1]),
                    'path': str(parts[2]),
                    'last_write_time': str(parts[3]),
                    'type': str(parts[4]),
                    'name': str(parts[5]),
                    'id': str(parts[6]),
                    'count': int(parts[7]) if len(parts) > 7 and str(parts[7]).strip().isdigit() else 0,
                    'focus_count': int(parts[8]) if len(parts) > 8 and str(parts[8]).strip().isdigit() else 0,
                    'time_focused': str(parts[9]) if len(parts) > 9 else '',
                    'last_updated': str(parts[10]) if len(parts) > 10 else '',
                    'raw_data': str(parts[11]) if len(parts) > 11 else ''
                }

        # Windows Scheduled Tasks - 计划任务
        # 实际格式: TaskName PrincipalID DisplayName Enabled CreationTime LastRunTime LastSuccessfulRunTime TriggerType TriggerDescription ActionType Action ActionArguments ActionContext WorkingDirectory KeyName
        elif 'scheduled_tasks' in plugin_name:
            if len(parts) >= 15:
                return {
                    'task_name': str(parts[0]),
                    'principal_id': str(parts[1]) if len(parts) > 1 else '',
                    'display_name': str(parts[2]) if len(parts) > 2 else '',
                    'enabled': str(parts[3]) if len(parts) > 3 else '',
                    'creation_time': str(parts[4]) if len(parts) > 4 else '',
                    'last_run_time': str(parts[5]) if len(parts) > 5 else '',
                    'last_successful_run_time': str(parts[6]) if len(parts) > 6 else '',
                    'trigger_type': str(parts[7]) if len(parts) > 7 else '',
                    'trigger_description': str(parts[8]) if len(parts) > 8 else '',
                    'action_type': str(parts[9]) if len(parts) > 9 else '',
                    'action': str(parts[10]) if len(parts) > 10 else '',
                    'action_arguments': str(parts[11]) if len(parts) > 11 else '',
                    'action_context': str(parts[12]) if len(parts) > 12 else '',
                    'working_directory': str(parts[13]) if len(parts) > 13 else '',
                    'key_name': str(parts[14]) if len(parts) > 14 else ''
                }

        # Windows AmCache - 已执行应用程序信息
        # 实际格式: EntryType Path Company LastModifyTime LastModifyTime2 InstallTime CompileTime SHA1 Service ProductName ProductVersion
        elif 'amcache' in plugin_name:
            if len(parts) >= 11:
                return {
                    'entry_type': str(parts[0]),
                    'path': str(parts[1]) if len(parts) > 1 else '',
                    'company': str(parts[2]) if len(parts) > 2 else '',
                    'last_modify_time': str(parts[3]) if len(parts) > 3 else '',
                    'last_modify_time2': str(parts[4]) if len(parts) > 4 else '',
                    'install_time': str(parts[5]) if len(parts) > 5 else '',
                    'compile_time': str(parts[6]) if len(parts) > 6 else '',
                    'sha1': str(parts[7]) if len(parts) > 7 else '',
                    'service': str(parts[8]) if len(parts) > 8 else '',
                    'product_name': str(parts[9]) if len(parts) > 9 else '',
                    'product_version': str(parts[10]) if len(parts) > 10 else ''
                }

        # Windows LdrModules - DLL 隐藏检测
        # 实际格式: Pid Process Base InLoad InInit InMem MappedPath
        elif 'ldrmodules' in plugin_name:
            if len(parts) >= 7:
                return {
                    'pid': int(parts[0]) if str(parts[0]).strip().isdigit() else 0,
                    'process': str(parts[1]) if len(parts) > 1 else '',
                    'base': str(parts[2]) if len(parts) > 2 else '',
                    'inload': str(parts[3]) if len(parts) > 3 else '',
                    'ininit': str(parts[4]) if len(parts) > 4 else '',
                    'inmem': str(parts[5]) if len(parts) > 5 else '',
                    'mappedpath': str(parts[6]) if len(parts) > 6 else ''
                }

        return None

    def run_plugin(self, plugin_id: str, params: Dict = None, symbol_file_path: str = None) -> Dict[str, Any]:
        """
        运行指定的Volatility插件

        Args:
            plugin_id: 插件ID
            params: 插件参数
            symbol_file_path: 直接指定符号表文件路径（可选，优先级高于目录扫描）

        Returns:
            分析结果字典
        """
        logger.info(f"执行插件: {plugin_id}")

        # 插件ID到Volatility 3插件名的映射
        plugin_map = {
            # ==================== Windows 插件 ====================
            'pslist': 'windows.pslist.PsList',
            'pstree': 'windows.pstree.PsTree',
            'psscan': 'windows.psscan.PsScan',
            'dlllist': 'windows.dlllist.DllList',
            'handles': 'windows.handles.Handles',
            'netscan': 'windows.netscan.NetScan',
            'netstat': 'windows.netstat.NetStat',
            'cmdline': 'windows.cmdline.CmdLine',
            'filescan': 'windows.filescan.FileScan',
            'eventlog': 'windows.filescan.FileScan',
            'hivelist': 'windows.registry.hivelist.HiveList',
            'printkey': 'windows.registry.printkey.PrintKey',
            'certificates': 'windows.registry.certificates.Certificates',
            'malfind': 'windows.malware.malfind.Malfind',
            'getsids': 'windows.getsids.GetSIDs',
            'envars': 'windows.envars.Envars',
            'svcscan': 'windows.svcscan.SvcScan',
            'svcscan_reg': 'windows.registry.printkey.PrintKey',
            'hashdump': 'windows.registry.hashdump.Hashdump',
            'lsadump': 'windows.registry.lsadump.Lsadump',
            'cachedump': 'windows.registry.cachedump.Cachedump',
            # 命令历史
            'cmdscan': 'windows.cmdscan.CmdScan',
            'consoles': 'windows.consoles.Consoles',
            # 进程隐藏/DLL检测
            'psxview': 'windows.malware.psxview.PsXView',
            'ldrmodules': 'windows.malware.ldrmodules.LdrModules',
            # 恶意软件检测（新版本）
            'hollowprocesses': 'windows.malware.hollowprocesses.HollowProcesses',
            'svcdiff': 'windows.malware.svcdiff.SvcDiff',
            'unhooked_system_calls': 'windows.malware.unhooked_system_calls.UnhookedSystemCalls',
            'processghosting': 'windows.malware.processghosting.ProcessGhosting',
            'malware_psxview': 'windows.malware.psxview.PsXView',
            'pebmasquerade': 'windows.malware.pebmasquerade.PebMasquerade',
            # 恶意软件检测
            'callbacks': 'windows.callbacks.Callbacks',
            'skeleton_key_check': 'windows.malware.skeleton_key_check.Skeleton_Key_Check',
            'mutantscan': 'windows.mutantscan.MutantScan',
            'suspicious_threads': 'windows.malware.suspicious_threads.SuspiciousThreads',
            # 系统信息
            'privileges': 'windows.privileges.Privs',
            'sessions': 'windows.sessions.Sessions',
            'threads': 'windows.threads.Threads',
            'vadinfo': 'windows.vadinfo.VadInfo',
            # 注册表相关
            'userassist': 'windows.registry.userassist.UserAssist',
            'scheduled_tasks': 'windows.registry.scheduled_tasks.ScheduledTasks',
            'amcache': 'windows.registry.amcache.Amcache',
            # 加密相关
            'truecrypt': 'windows.truecrypt.Passphrase',
            # 系统扫描
            'modscan': 'windows.modscan.ModScan',
            'ssdt': 'windows.ssdt.SSDT',
            # 驱动扫描
            'driverscan': 'windows.driverscan.DriverScan',
            'drivermodule': 'windows.malware.drivermodule.DriverModule',
            'driverirp': 'windows.driverirp.DriverIrp',
            # 系统深入分析
            'shimcachemem': 'windows.shimcachemem.ShimCacheMem',
            'mftscan': 'windows.mftscan.MftScan',
            'mbrscan': 'windows.mbrscan.MbrScan',
            'crashinfo': 'windows.crashinfo.CrashInfo',
            'deskscan': 'windows.deskscan.DeskScan',
            'desktops': 'windows.desktops.Desktops',
            'devicetree': 'windows.devicetree.DeviceTree',
            'bigpools': 'windows.bigpools.BigPools',

            # ==================== Linux 插件 ====================
            # 进程相关
            'linux_pslist': 'linux.pslist.PsList',
            'linux_pstree': 'linux.pstree.PsTree',
            'linux_psscan': 'linux.psscan.PsScan',
            'linux_psaux': 'linux.psaux.PsAux',
            # 网络相关
            'linux_netstat': 'linux.sockstat.Sockstat',  # 列出所有进程的所有网络连接
            'linux_sockstat': 'linux.sockstat.Sockstat',  # 进程网络连接
            'linux_ip_addr': 'linux.ip.Addr',  # 列出所有设备的网络接口信息
            'linux_ip_link': 'linux.ip.Link',  # 列出网络接口信息，类似 ip link show
            # 文件系统
            'linux_lsof': 'linux.lsof.Lsof',
            'linux_elfs': 'linux.elfs.Elfs',
            'linux_mountinfo': 'linux.mountinfo.MountInfo',
            'linux_pagecache_files': 'linux.pagecache.Files',  # 官方插件 - 列出/搜索缓存文件
            'linux_pagecache_inodepages': 'linux.pagecache.InodePages',  # 官方插件 - 导出单个文件
            'linux_pagecache_recoverfs': 'linux.pagecache.RecoverFS',  # 官方插件 - 恢复文件系统为 tar 包
            # Shell/环境
            'linux_bash': 'linux.bash.Bash',
            'linux_bash_history': 'linux.bash.Bash',  # 使用官方 bash 插件（自定义插件未正确加载）
            'linux_envars': 'linux.envars.Envars',
            # 密码哈希 - 使用 pagecache.Files 插件查找 /etc/passwd 和 /etc/shadow
            'linux_passwd_hashes': 'linux.pagecache.Files',  # 官方插件 - 查找/提取页缓存中的文件
            # 内存/恶意代码
            'linux_malfind': 'linux.malfind.Malfind',
            'linux_vmayarascan': 'linux.vmayarascan.VmaYaraScan',
            # 内核模块
            'linux_lsmod': 'linux.lsmod.Lsmod',
            'linux_check_modules': 'linux.check_modules.Check_modules',
            # 系统检查
            'linux_capabilities': 'linux.capabilities.Capabilities',
            # Linux 恶意软件检测 - 使用新的 linux.malware.* 命名空间
            'linux_malware_malfind': 'linux.malware.malfind.Malfind',
            'linux_malware_check_afinfo': 'linux.malware.check_afinfo.Check_afinfo',
            'linux_malware_check_creds': 'linux.malware.check_creds.Check_creds',
            'linux_malware_check_idt': 'linux.malware.check_idt.Check_idt',
            'linux_malware_check_modules': 'linux.malware.check_modules.Check_modules',
            'linux_malware_check_syscall': 'linux.malware.check_syscall.Check_syscall',
            'linux_malware_hidden_modules': 'linux.malware.hidden_modules.Hidden_modules',
            'linux_malware_keyboard_notifiers': 'linux.malware.keyboard_notifiers.Keyboard_notifiers',
            'linux_malware_netfilter': 'linux.malware.netfilter.Netfilter',
            'linux_malware_tty_check': 'linux.malware.tty_check.Tty_Check',
            'linux_malware_modxview': 'linux.malware.modxview.Modxview',
            # 内核信息
            'linux_iomem': 'linux.iomem.IOMem',
            'linux_kmsg': 'linux.kmsg.Kmsg',
            # 内存映射
            'linux_maps': 'linux.proc.Maps',

            # ==================== macOS 插件 ====================
            # 进程相关（官方格式 + 别名）
            'mac.pslist.PsList': 'mac.pslist.PsList',
            'mac_pslist': 'mac.pslist.PsList',
            'mac.pstree.PsTree': 'mac.pstree.PsTree',
            'mac_pstree': 'mac.pstree.PsTree',
            'mac.psaux.Psaux': 'mac.psaux.Psaux',
            'mac_psaux': 'mac.psaux.Psaux',
            # 网络相关
            'mac.netstat.Netstat': 'mac.netstat.Netstat',
            'mac_netstat': 'mac.netstat.Netstat',
            'mac.ifconfig.Ifconfig': 'mac.ifconfig.Ifconfig',
            'mac_ifconfig': 'mac.ifconfig.Ifconfig',
            'mac.socket_filters.Socket_filters': 'mac.socket_filters.Socket_filters',
            'mac_socket_filters': 'mac.socket_filters.Socket_filters',
            # 文件系统
            'mac.lsof.Lsof': 'mac.lsof.Lsof',
            'mac_lsof': 'mac.lsof.Lsof',
            'mac.list_files.List_Files': 'mac.list_files.List_Files',
            'mac_list_files': 'mac.list_files.List_Files',
            'mac.mount.Mount': 'mac.mount.Mount',
            'mac_mount': 'mac.mount.Mount',
            # Shell/环境
            'mac.bash.Bash': 'mac.bash.Bash',
            'mac_bash': 'mac.bash.Bash',
            # 内存/恶意代码
            'mac.malfind.Malfind': 'mac.malfind.Malfind',
            'mac_malfind': 'mac.malfind.Malfind',
            # 内核模块
            'mac.lsmod.Lsmod': 'mac.lsmod.Lsmod',
            'mac_lsmod': 'mac.lsmod.Lsmod',
            # 系统检查
            'mac.check_syscall.Check_syscall': 'mac.check_syscall.Check_syscall',
            'mac_check_syscall': 'mac.check_syscall.Check_syscall',
            'mac.check_sysctl.Check_sysctl': 'mac.check_sysctl.Check_sysctl',
            'mac_check_sysctl': 'mac.check_sysctl.Check_sysctl',
            'mac.check_trap_table.Check_trap_table': 'mac.check_trap_table.Check_trap_table',
            'mac_check_trap_table': 'mac.check_trap_table.Check_trap_table',
            # 内核信息
            'mac.dmesg.Dmesg': 'mac.dmesg.Dmesg',
            'mac_dmesg': 'mac.dmesg.Dmesg',
            'mac.kevents.Kevents': 'mac.kevents.Kevents',
            'mac_kevents': 'mac.kevents.Kevents',
            'mac.timers.Timers': 'mac.timers.Timers',
            'mac_timers': 'mac.timers.Timers',
            # 权限/安全
            'mac.kauth_listeners.Kauth_listeners': 'mac.kauth_listeners.Kauth_listeners',
            'mac_kauth_listeners': 'mac.kauth_listeners.Kauth_listeners',
            'mac.kauth_scopes.Kauth_scopes': 'mac.kauth_scopes.Kauth_scopes',
            'mac_kauth_scopes': 'mac.kauth_scopes.Kauth_scopes',
            'mac.trustedbsd.Trustedbsd': 'mac.trustedbsd.Trustedbsd',
            'mac_trustedbsd': 'mac.trustedbsd.Trustedbsd',
            # 内存映射
            'mac.proc_maps.Maps': 'mac.proc_maps.Maps',
            'mac_maps': 'mac.proc_maps.Maps',
            # 文件系统事件
            'mac.vfsevents.VFSevents': 'mac.vfsevents.VFSevents',
            'mac_vfsevents': 'mac.vfsevents.VFSevents',
        }

        volatility_plugin = plugin_map.get(plugin_id)
        if not volatility_plugin:
            logger.warning(f"未知插件: {plugin_id}")
            return {
                'plugin': plugin_id,
                'timestamp': datetime.now().isoformat(),
                'image': self.image_name,
                'results': [],
                'error': f'插件 {plugin_id} 未实现'
            }

        # 构建额外参数
        extra_args = []
        if params:
            for key, value in params.items():
                extra_args.extend([f'--{key}', str(value)])

        # 事件日志插件自动添加过滤参数
        if plugin_id == 'eventlog' and not any('--pattern' in str(arg) for arg in extra_args):
            extra_args.extend(['--pattern', r'\.(evt|evtx)$'])

        # 执行插件
        results = self._run_volatility(volatility_plugin, extra_args, symbol_file_path=symbol_file_path)

        return {
            'plugin': plugin_id,
            'timestamp': datetime.now().isoformat(),
            'image': self.image_name,
            'results': results
        }

    def search_strings(self, patterns: List[str]) -> List[Dict]:
        """
        搜索内存中的字符串

        Args:
            patterns: 正则表达式模式列表

        Returns:
            匹配结果列表
        """
        results = []
        import platform
        import re
        import shutil

        # 根据操作系统选择不同的搜索方法
        if platform.system() == 'Windows':
            # Windows 上检查是否有 strings 命令（包括用户数据目录中的 strings.exe）
            strings_exe = None

            # 优先级：用户数据目录 -> 当前目录 -> PATH
            possible_paths = [
                self._symbols_dir.parent / 'strings.exe',  # 用户数据目录
                Path(os.path.dirname(sys.executable)) / 'strings.exe',  # 当前目录
            ]

            # 检查可能的路径
            for path in possible_paths:
                if path.exists():
                    strings_exe = str(path)
                    break

            # 如果没找到，检查 PATH 中的 strings 命令
            if not strings_exe:
                has_strings = shutil.which('strings') is not None
                if has_strings:
                    strings_exe = shutil.which('strings')

            if strings_exe:
                # Windows 上有 strings 命令（用户数据目录、当前目录或 PATH）
                logger.info(f"使用 strings 命令搜索内存（Windows + strings: {strings_exe}）")
                try:
                    import subprocess
                    result = subprocess.run(
                        [strings_exe, '-n', '4', self.image_path],
                        capture_output=True,
                        text=True,
                        timeout=120
                    )

                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        for i, line in enumerate(lines):
                            line = line.strip()
                            if not line:
                                continue
                            for pattern in patterns:
                                try:
                                    regex = re.compile(pattern, re.IGNORECASE)
                                    if regex.search(line):
                                        results.append({
                                            'offset': f'line_{i}',
                                            'matched_string': line,
                                            'context': line[:100]
                                        })
                                        break
                                except re.error:
                                    logger.warning(f"无效的正则表达式: {pattern}")
                        logger.info(f"搜索完成: 检查了 {len(lines)} 行，找到 {len(results)} 个匹配")
                except Exception as e:
                    logger.error(f"strings 命令执行失败: {str(e)}")
            else:
                # Windows 上没有 strings 命令，使用 Python 直接读取
                logger.info("使用 Python 读取内存文件（Windows，无 strings 命令）")
                try:
                    # 读取文件并搜索 ASCII 字符串（至少4个字符）
                    with open(self.image_path, 'rb') as f:
                        data = f.read()
                        # 查找所有连续的可打印 ASCII 字符（至少4个字符）
                        strings_list = re.findall(b'[\\x20-\\x7e]{4,}', data)

                    logger.info(f"找到 {len(strings_list)} 个字符串，开始匹配模式...")

                    for i, s in enumerate(strings_list):
                        try:
                            line = s.decode('ascii', errors='ignore')
                        except:
                            continue

                        # 检查是否匹配任何模式
                        for pattern in patterns:
                            try:
                                regex = re.compile(pattern, re.IGNORECASE)
                                if regex.search(line):
                                    results.append({
                                        'offset': f'found_{i}',
                                        'matched_string': line,
                                        'context': line[:100]
                                    })
                                    break
                            except re.error:
                                logger.warning(f"无效的正则表达式: {pattern}")

                    logger.info(f"搜索完成: 检查了 {len(strings_list)} 个字符串，找到 {len(results)} 个匹配")

                except Exception as e:
                    logger.error(f"读取内存文件失败: {str(e)}")
        else:
            # Linux/macOS 使用 strings 命令（快速）
            logger.info("使用 strings 命令搜索内存（Linux/macOS）")
            try:
                import subprocess

                # 搜索至少4个字符的ASCII字符串
                result = subprocess.run(
                    ['strings', '-n', '4', self.image_path],
                    capture_output=True,
                    text=True,
                    timeout=120  # 2分钟超时
                )

                if result.returncode == 0:
                    lines = result.stdout.split('\n')
                    total_lines = len(lines)

                    for i, line in enumerate(lines):
                        line = line.strip()
                        if not line:
                            continue

                        # 检查是否匹配任何模式
                        for pattern in patterns:
                            try:
                                regex = re.compile(pattern, re.IGNORECASE)
                                if regex.search(line):
                                    results.append({
                                        'offset': f'line_{i}',
                                        'matched_string': line,
                                        'context': line[:100]
                                    })
                                    break  # 找到匹配后就不需要继续检查其他模式
                            except re.error:
                                logger.warning(f"无效的正则表达式: {pattern}")

                    logger.info(f"搜索完成: 检查了 {total_lines} 行，找到 {len(results)} 个匹配")
                else:
                    logger.error(f"strings 命令失败: {result.stderr}")

            except subprocess.TimeoutExpired:
                logger.error("字符串搜索超时")
            except Exception as e:
                logger.error(f"字符串搜索失败: {str(e)}")

        return results

    def dump_process(self, pid: int, output_dir: str) -> Dict:
        """
        转储进程内存

        支持的操作系统：
        - Windows: windows.memmap.Memmap
        - macOS: mac.proc_maps.Maps (需要 --dump 参数)
        - Linux: linux.proc.Maps (需要 --dump 参数)

        注意：Volatility 3 会转储进程的虚拟内存区域(VMA)，
        包括共享库、映射文件等，因此可能生成多个文件。

        Args:
            pid: 进程ID
            output_dir: 输出目录

        Returns:
            转储结果
        """
        try:
            logger.info(f"开始转储进程 {pid}")

            # 检测操作系统类型
            os_type = self._detect_os_for_dump()

            old_cwd = os.getcwd()
            os.chdir(output_dir)

            try:
                if os_type == 'macOS':
                    # macOS 使用 mac.proc_maps.Maps
                    plugin_name = 'mac.proc_maps.Maps'
                    extra_args = ['--pid', str(pid), '--dump']
                    logger.info(f"使用 macOS 插件: {plugin_name}")
                elif os_type == 'Linux':
                    # Linux 使用 linux.proc.Maps
                    plugin_name = 'linux.proc.Maps'
                    extra_args = ['--pid', str(pid), '--dump']
                    logger.info(f"使用 Linux 插件: {plugin_name}")
                else:
                    # Windows 使用 windows.memmap.Memmap
                    plugin_name = 'windows.memmap.Memmap'
                    extra_args = ['--pid', str(pid), '--dump']
                    logger.info(f"使用 Windows 插件: {plugin_name}")

                self._run_volatility(plugin_name, extra_args)
            finally:
                os.chdir(old_cwd)

            # 检查文件是否生成
            # macOS/Linux 生成格式: pid.{pid}.vma.{start}-{end}.dmp (多个文件)
            # Windows 生成格式: pid.{pid}.dmp
            # Linux ELF 格式: pid.{pid}.{comm}.{start:#x}.dmp
            output_files = []

            # 查找生成的文件
            for filename in os.listdir(output_dir):
                if filename.startswith(f'pid.{pid}.'):
                    file_path = os.path.join(output_dir, filename)
                    if os.path.isfile(file_path):
                        output_files.append(file_path)

            if output_files:
                total_size = sum(os.path.getsize(f) for f in output_files)
                logger.info(f"进程 {pid} 转储成功，生成 {len(output_files)} 个文件，总大小: {total_size / 1024 / 1024:.2f} MB")

                return {
                    'pid': pid,
                    'os_type': os_type,
                    'output_files': output_files,
                    'count': len(output_files),
                    'total_size': total_size,
                    'status': 'success'
                }
            else:
                return {
                    'pid': pid,
                    'os_type': os_type,
                    'status': 'failed',
                    'error': '转储文件未生成'
                }

        except Exception as e:
            logger.error(f"进程转储失败: {str(e)}")
            return {
                'pid': pid,
                'status': 'error',
                'error': str(e)
            }

    def _detect_os_from_banner(self, banner_output: str) -> str:
        """
        从 banner 输出中检测操作系统类型

        Args:
            banner_output: banners.Banners 插件的输出

        Returns:
            'Windows', 'Linux', 'Mac', 或 'Unknown'
        """
        try:
            for line in banner_output.split('\n'):
                if 'Volatility 3' in line or 'Progress' in line:
                    continue
                line_lower = line.lower()
                if 'darwin' in line_lower or 'macos' in line_lower:
                    return 'Mac'
                elif 'linux' in line_lower:
                    return 'Linux'
                elif 'windows' in line_lower or 'microsoft' in line_lower:
                    return 'Windows'
            return 'Unknown'
        except Exception as e:
            logger.warning(f"从 banner 检测 OS 失败: {str(e)}")
            return 'Unknown'

    def _detect_os_for_dump(self) -> str:
        """
        检测内存镜像的操作系统类型（用于进程导出）

        Returns:
            'Windows', 'macOS', 'Linux', 或 'Unknown'
        """
        try:
            # 使用 banners 插件检测系统类型
            result = self._run_volatility_raw('banners.Banners')
            for line in result.split('\n'):
                if 'Volatility 3' in line:
                    continue
                if 'Darwin' in line or 'macOS' in line:
                    return 'macOS'
                elif 'Windows' in line or 'Microsoft' in line:
                    return 'Windows'
                elif 'Linux' in line:
                    return 'Linux'
            return 'Unknown'
        except Exception as e:
            logger.warning(f"OS 检测失败: {str(e)}")
            return 'Unknown'


    def extract_file(self, offset: str, output_dir: str) -> Dict:
        """
        从文件扫描结果中提取文件

        支持的操作系统：
        - Windows: windows.dumpfiles.DumpFiles (可提取任意类型文件)
        - Linux: 不支持单个文件提取，请使用 extract_elf_files() 提取 ELF 二进制文件
        - macOS: 不支持

        Args:
            offset: 文件对象的偏移地址
            output_dir: 输出目录

        Returns:
            提取结果
        """
        try:
            # 检测操作系统类型
            os_type = self._detect_os_for_dump()

            if os_type == 'macOS':
                return {
                    'status': 'unsupported',
                    'error': 'macOS 不支持文件提取（只能列出文件）'
                }

            if os_type == 'Linux':
                return {
                    'status': 'unsupported',
                    'error': 'Linux 不支持单个文件提取\n请使用 linux.elfs.Elfs 插件批量提取 ELF 二进制文件'
                }

            logger.info(f"开始提取文件 @ {offset}")

            old_cwd = os.getcwd()
            os.chdir(output_dir)

            try:
                # Windows 使用 dumpfiles
                extra_args = ['--physaddr', offset]
                self._run_volatility('windows.dumpfiles.DumpFiles', extra_args)
            finally:
                os.chdir(old_cwd)

            # 查找生成的文件
            # Windows dumpfiles 生成格式: file.<offset>.<pid>.<name>.dat
            extracted_files = []
            for filename in os.listdir(output_dir):
                if filename.startswith('file.'):
                    try:
                        file_path = os.path.join(output_dir, filename)
                        file_size = os.path.getsize(file_path)

                        extracted_files.append({
                            'file': filename,
                            'path': file_path,
                            'size': file_size
                        })

                        logger.info(f"提取成功: {filename} ({file_size} 字节)")
                        break  # 只取第一个

                    except Exception as e:
                        logger.warning(f"处理文件失败: {str(e)}")

            if not extracted_files:
                return {
                    'status': 'failed',
                    'error': '文件提取失败'
                }

            return {
                'status': 'success',
                'file': extracted_files[0]['file'],
                'size': extracted_files[0]['size']
            }

        except Exception as e:
            logger.error(f"提取文件失败: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }

    def extract_dll(self, pid: int, base: str, output_dir: str) -> Dict:
        """
        提取单个DLL文件（使用 pedump）

        Args:
            pid: 进程ID
            base: DLL的基址
            output_dir: 输出目录

        Returns:
            提取结果
        """
        try:
            logger.info(f"开始提取 DLL - PID: {pid}, Base: {base}")

            # 使用 pedump 提取DLL
            old_cwd = os.getcwd()
            os.chdir(output_dir)

            try:
                extra_args = ['--pid', str(pid), '--base', base]
                self._run_volatility('windows.pedump.PEDump', extra_args)
            finally:
                os.chdir(old_cwd)

            # 查找并重命名生成的文件
            # pedump 生成格式: PE.0x<offset>.<pid>.<base>.dmp
            for filename in os.listdir(output_dir):
                if filename.startswith('PE.') and f'.{pid}.' in filename:
                    try:
                        old_path = os.path.join(output_dir, filename)

                        # 提取基址作为文件名的一部分
                        safe_base = base.replace('0x', '').lower()
                        new_name = f'dll.{pid}.{safe_base}.dmp'
                        new_path = os.path.join(output_dir, new_name)

                        os.rename(old_path, new_path)

                        file_size = os.path.getsize(new_path)
                        logger.info(f"DLL提取成功: {new_name} ({file_size} 字节)")

                        return {
                            'status': 'success',
                            'file': new_name,
                            'size': file_size
                        }

                    except Exception as e:
                        logger.warning(f"重命名文件失败: {str(e)}")

            return {
                'status': 'failed',
                'error': 'DLL提取失败'
            }

        except Exception as e:
            logger.error(f"提取DLL失败: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }

    def extract_pagecache_file(self, file_path: str, save_path: str) -> Dict:
        """
        从页缓存提取单个文件

        使用 linux.pagecache.InodePages 插件提取文件
        注意：InodePages 默认输出到当前工作目录
        """
        try:
            logger.info(f"开始提取页缓存文件: {file_path} -> {save_path}")

            # 确保保存目录存在
            save_dir = os.path.dirname(save_path)
            if save_dir:
                os.makedirs(save_dir, exist_ok=True)

            # 记录当前工作目录
            cwd = os.getcwd()
            logger.debug(f"当前工作目录: {cwd}")

            # 构建 InodePages 插件命令
            extra_args = ['--find', file_path, '--dump']

            logger.info(f"运行命令: linux.pagecache.InodePages --find {file_path} --dump")

            # 运行插件提取文件（Linux 插件需要符号表）
            output = self._run_volatility_raw('linux.pagecache.InodePages', extra_args, use_symbols=True)

            logger.debug(f"插件输出:\n{output[:1000] if output else '无输出'}...")

            # InodePages 会生成 inode_xxx.dmp 文件在当前工作目录
            import glob
            import shutil

            # 在当前工作目录查找生成的 .dmp 文件
            possible_files = glob.glob(os.path.join(cwd, 'inode_*.dmp'))

            if possible_files:
                # 找到了生成的文件，移动到用户指定的位置
                extracted_file = possible_files[0]
                final_path = save_path

                # 移动文件到目标位置
                shutil.move(extracted_file, final_path)

                file_size = os.path.getsize(final_path)
                logger.info(f"页缓存文件提取成功: {file_path} -> {final_path} ({file_size} 字节)")
                return {
                    'status': 'success',
                    'file': final_path,
                    'size': file_size
                }
            else:
                logger.warning(f"文件提取失败，当前目录中没有找到 .dmp 文件: {cwd}")
                logger.warning(f"插件输出: {output}")
                return {
                    'status': 'failed',
                    'error': '文件提取失败，未找到输出文件（可能文件不在页缓存中）'
                }

        except Exception as e:
            logger.error(f"提取页缓存文件失败: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'error': str(e)
            }

    def extract_elf_files(self, pid: int = None, output_dir: str = None) -> Dict:
        """
        提取 Linux ELF 文件（可执行文件和库文件）

        注意：Linux ELF 提取是批量操作，不是基于单个偏移提取

        Args:
            pid: 可选，指定进程ID。如果为None，则提取所有进程的ELF文件
            output_dir: 输出目录

        Returns:
            提取结果
        """
        try:
            if output_dir is None:
                output_dir = os.getcwd()

            logger.info(f"开始提取 ELF 文件" + (f" (PID: {pid})" if pid else ""))

            # 检测操作系统
            os_type = self._detect_os_for_dump()
            if os_type != 'Linux':
                return {
                    'status': 'unsupported',
                    'error': f'ELF 文件提取仅支持 Linux 系统（当前: {os_type}）'
                }

            old_cwd = os.getcwd()
            os.chdir(output_dir)

            try:
                # 使用 linux.elfs.Elfs 插件提取 ELF 文件
                extra_args = ['--dump']
                if pid is not None:
                    extra_args.extend(['--pid', str(pid)])

                self._run_volatility('linux.elfs.Elfs', extra_args)
            finally:
                os.chdir(old_cwd)

            # 查找生成的文件
            # ELF 文件命名格式: pid.{pid}.{comm}.{start:#x}.dmp
            extracted_files = []
            pattern = f'pid.{pid}.' if pid else 'pid.'

            for filename in os.listdir(output_dir):
                if filename.startswith(pattern) and filename.endswith('.dmp'):
                    try:
                        file_path = os.path.join(output_dir, filename)
                        file_size = os.path.getsize(file_path)

                        # 解析文件名
                        parts = filename.replace('.dmp', '').split('.')
                        file_pid = parts[1] if len(parts) > 1 else 'unknown'
                        file_comm = parts[2] if len(parts) > 2 else 'unknown'
                        file_addr = parts[3] if len(parts) > 3 else 'unknown'

                        extracted_files.append({
                            'file': filename,
                            'path': file_path,
                            'size': file_size,
                            'pid': file_pid,
                            'name': file_comm,
                            'address': file_addr
                        })

                        logger.info(f"ELF文件提取成功: {filename} ({file_size} 字节)")

                    except Exception as e:
                        logger.warning(f"处理文件失败 {filename}: {str(e)}")

            if not extracted_files:
                return {
                    'status': 'failed',
                    'error': '未找到 ELF 文件'
                }

            total_size = sum(f['size'] for f in extracted_files)
            return {
                'status': 'success',
                'count': len(extracted_files),
                'total_size': total_size,
                'files': extracted_files[:10]  # 返回前10个文件信息
            }

        except Exception as e:
            logger.error(f"提取 ELF 文件失败: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }

    def extract_elf_file(self, pid: int, start: str, file_name: str, output_dir: str) -> Dict:
        """
        提取单个 ELF 文件

        Args:
            pid: 进程ID
            start: ELF 文件的起始地址
            file_name: 文件名
            output_dir: 输出目录

        Returns:
            提取结果
        """
        try:
            logger.info(f"开始提取单个 ELF 文件 - PID: {pid}, Start: {start}, Name: {file_name}")

            old_cwd = os.getcwd()
            os.chdir(output_dir)

            try:
                # 使用 linux.elfs.Elfs 插件提取指定 ELF 文件
                extra_args = ['--dump', '--pid', str(pid)]
                self._run_volatility('linux.elfs.Elfs', extra_args)
            finally:
                os.chdir(old_cwd)

            # 查找生成的文件
            # ELF 文件命名格式: pid.{pid}.{comm}.{start:#x}.dmp
            safe_name = file_name.replace('/', '_').replace('\\', '_')
            safe_start = start.lower().replace('0x', '')

            for filename in os.listdir(output_dir):
                if filename.startswith(f'pid.{pid}.') and filename.endswith('.dmp'):
                    try:
                        old_path = os.path.join(output_dir, filename)
                        new_name = f'elf.{pid}.{safe_name}.{safe_start}.dmp'
                        new_path = os.path.join(output_dir, new_name)

                        os.rename(old_path, new_path)

                        file_size = os.path.getsize(new_path)
                        logger.info(f"单个 ELF 文件提取成功: {new_name} ({file_size} 字节)")

                        return {
                            'status': 'success',
                            'output_path': new_path,
                            'file': new_name,
                            'size': file_size
                        }

                    except Exception as e:
                        logger.warning(f"处理文件失败 {filename}: {str(e)}")

            return {
                'status': 'failed',
                'error': f'未找到匹配的 ELF 文件 (PID: {pid}, Start: {start})'
            }

        except Exception as e:
            logger.error(f"提取单个 ELF 文件失败: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }

    def extract_lsof_file(self, file_path: str, plugin_id: str, output_dir: str) -> Dict:
        """
        提取打开文件列表中的单个文件

        Args:
            file_path: 文件路径
            plugin_id: 插件ID (linux_lsof 或 mac_lsof)
            output_dir: 输出目录

        Returns:
            提取结果
        """
        try:
            logger.info(f"开始提取 lsof 文件: {file_path}")

            # 提取文件名
            file_name = os.path.basename(file_path) if file_path else 'unknown'
            safe_name = file_name.replace('/', '_').replace('\\', '_')
            save_path = os.path.join(output_dir, f'lsof_{safe_name}')

            # 使用 InodePages 插件提取文件
            result = self.extract_pagecache_file(file_path, save_path)

            if result['status'] == 'success':
                return {
                    'status': 'success',
                    'output_path': result['file'],
                    'file': os.path.basename(result['file']),
                    'size': result['size']
                }
            else:
                return result

        except Exception as e:
            logger.error(f"提取 lsof 文件失败: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }

    def extract_lsof_files(self, plugin_id: str, output_dir: str) -> Dict:
        """
        批量提取打开文件列表中的所有文件

        注意：这只是个占位实现，实际上 lsof 列表中的文件
        很多可能不在页缓存中，需要逐个尝试

        Args:
            plugin_id: 插件ID
            output_dir: 输出目录

        Returns:
            提取结果统计
        """
        # 这个方法需要从前端传入完整的文件列表
        # 暂时返回不支持
        return {
            'status': 'unsupported',
            'error': '批量提取 lsof 文件暂不支持，请使用单个文件下载'
        }

    def dump_files(
        self,
        filter_pattern: str = None,
        ignore_case: bool = False,
        pid: int = None,
        output_dir: str = None
    ) -> Dict:
        """
        提取 Linux 页缓存中的文件

        注意：此功能仅支持 Linux 系统

        Args:
            filter_pattern: 可选，过滤文件路径的正则表达式
            ignore_case: 是否忽略大小写
            pid: 可选，指定进程ID（用于确定文件系统根路径）
            output_dir: 输出目录

        Returns:
            提取结果
        """
        try:
            if output_dir is None:
                output_dir = os.getcwd()

            logger.info(f"开始提取页缓存文件")

            # 检测操作系统
            os_type = self._detect_os_for_dump()
            if os_type != 'Linux':
                return {
                    'status': 'unsupported',
                    'error': f'文件提取仅支持 Linux 系统（当前: {os_type}）'
                }

            old_cwd = os.getcwd()
            os.chdir(output_dir)

            try:
                # 使用自定义 linux.dumpfiles.DumpFiles 插件
                extra_args = ['--dump']  # 默认启用文件导出
                if filter_pattern:
                    extra_args.extend(['--filter', filter_pattern])
                if ignore_case:
                    extra_args.append('--ignore-case')
                if pid is not None:
                    extra_args.extend(['--pid', str(pid)])

                # 运行插件并获取结果
                results = self._run_volatility('linux.dumpfiles.DumpFiles', extra_args)

                # 查找生成的文件
                extracted_files = []
                for result in results:
                    result_file = result.get('result', '')
                    if result_file and result_file != 'Not in cache':
                        # 文件可能在输出目录中
                        file_name = os.path.basename(result_file)
                        file_path = os.path.join(output_dir, file_name)

                        if os.path.exists(file_path):
                            file_size = os.path.getsize(file_path)
                            extracted_files.append({
                                'file': file_name,
                                'path': file_path,
                                'size': file_size,
                                'original_path': result.get('file_path', ''),
                                'inode': result.get('inode', '')
                            })
                            logger.info(f"文件提取成功: {file_name} ({file_size} 字节)")

                total_size = sum(f['size'] for f in extracted_files)
                return {
                    'status': 'success',
                    'count': len(extracted_files),
                    'total_size': total_size,
                    'files': extracted_files
                }

            finally:
                os.chdir(old_cwd)

        except Exception as e:
            logger.error(f"提取文件失败: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }

    def dump_certificates(self, output_dir: str) -> Dict:
        """
        导出Windows注册表中的证书

        使用 windows.registry.certificates.Certificates 插件的 --dump 参数
        导出的证书文件将保存为 .cer 格式

        Args:
            output_dir: 输出目录

        Returns:
            导出结果
        """
        try:
            logger.info("===== 开始导出 Windows 注册表证书 =====")

            old_cwd = os.getcwd()

            try:
                os.makedirs(output_dir, exist_ok=True)
                os.chdir(output_dir)

                logger.info(f"当前工作目录: {os.getcwd()}")
                logger.info(f"输出目录: {output_dir}")

                # 列出执行前的文件
                logger.info(f"执行前目录内容: {os.listdir('.')}")

                # Windows证书导出插件
                plugin_name = 'windows.registry.certificates.Certificates'
                extra_args = ['--dump']

                logger.info(f"使用插件: {plugin_name} with --dump")

                # 运行插件（--dump 会将证书导出到当前目录）
                self._run_volatility(plugin_name, extra_args)

                # 列出执行后的文件
                logger.info(f"执行后目录内容: {os.listdir('.')}")

                # 直接扫描输出目录中的证书文件
                # Volatility 证书导出文件格式通常是: certificate.<serial>.cer 或类似
                extracted_files = []
                try:
                    for filename in os.listdir('.'):
                        file_path = os.path.join('.', filename)
                        if os.path.isfile(file_path):
                            file_size = os.path.getsize(file_path)
                            logger.info(f"  文件: {filename}, 大小: {file_size}")
                            # 匹配证书文件（.crt 或 .cer 或包含 certificate 关键字）
                            if filename.endswith('.crt') or filename.endswith('.cer') or filename.startswith('certificate'):
                                extracted_files.append({
                                    'file': filename,
                                    'path': os.path.join(output_dir, filename),
                                    'size': file_size
                                })
                                logger.info(f"✓ 发现证书文件: {filename} ({file_size} 字节)")
                except Exception as scan_error:
                    logger.warning(f"扫描证书文件时出错: {scan_error}")

                total_size = sum(f['size'] for f in extracted_files)
                logger.info(f"证书导出完成，共 {len(extracted_files)} 个文件，总大小 {total_size} 字节")

                return {
                    'status': 'success',
                    'count': len(extracted_files),
                    'total_size': total_size,
                    'output_dir': output_dir,
                    'files': extracted_files
                }

            finally:
                os.chdir(old_cwd)

        except Exception as e:
            logger.error(f"导出证书失败: {str(e)}")
            return {
                'status': 'error',
                'error': str(e)
            }

    def detect_image_info(self) -> Dict:
        """检测镜像信息"""
        try:
            # 使用 windows.info.Info 插件获取镜像信息
            result = self._run_volatility('windows.info.Info')

            if result and len(result) > 0:
                info = result[0]
                return {
                    'format': 'raw',
                    'os': info.get('os', 'Unknown'),
                    'os_version': info.get('version', 'Unknown'),
                    'architecture': info.get('architecture', 'Unknown'),
                    'kernel_version': info.get('kernel_version', 'Unknown'),
                    'system_time': info.get('system_time', datetime.now().isoformat())
                }

        except Exception as e:
            logger.error(f"镜像信息检测失败: {str(e)}")

        return {
            'format': 'raw',
            'os': 'Unknown',
            'os_version': 'Unknown',
            'architecture': 'Unknown',
            'kernel_version': 'Unknown',
            'system_time': datetime.now().isoformat()
        }
