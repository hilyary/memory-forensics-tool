"""
API Handlers - 处理前端请求
"""

import os
import sys
import logging
import hashlib
import json
import uuid
from pathlib import Path
from typing import Optional, Dict, Any, List
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

logger = logging.getLogger(__name__)


class APIHandler:
    """API处理器类 - 桥接前端和后端功能"""

    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=4)
        self.current_image = None
        self._cached_banner = None  # 缓存 banner 内容，避免重复调用

        # 获取用户数据目录（支持打包后的应用）
        # 以下划线开头避免 pywebview 尝试序列化 Path 对象
        self._user_data_dir = self._get_user_data_dir()
        self._user_data_dir.mkdir(exist_ok=True)

        # 缓存目录
        self._cache_dir = self._user_data_dir / 'cache'
        self._cache_dir.mkdir(exist_ok=True)

        # 符号表目录
        self._symbols_dir = self._user_data_dir / 'symbols'
        self._symbols_dir.mkdir(exist_ok=True)

        # 配置文件路径
        self._config_file = self._user_data_dir / 'config.json'

        # 状态管理
        self.analysis_tasks = {}
        self.task_counter = 0

        # Flag搜索缓存: 当前镜像的搜索记录 {'default': {...}, 'custom:pattern': {...}}
        self._flag_search_cache = {}

        # 加载配置（包括代理设置）
        self._proxy_config = self._load_config().get('proxy', {})

    def _get_user_data_dir(self) -> Path:
        """获取用户数据目录"""
        import platform

        system = platform.system()

        if system == 'Darwin':  # macOS
            # macOS: ~/Library/Application Support/LensAnalysis
            app_data = Path.home() / 'Library' / 'Application Support' / 'LensAnalysis'
        elif system == 'Windows':  # Windows
            # Windows: %APPDATA%/LensAnalysis
            app_data = Path(os.environ.get('APPDATA', Path.home() / 'AppData' / 'Roaming')) / 'LensAnalysis'
        else:  # Linux 和其他
            # Linux: ~/.local/share/LensAnalysis (遵循 XDG 规范)
            app_data = Path(os.environ.get('XDG_DATA_HOME', Path.home() / '.local' / 'share')) / 'LensAnalysis'

        return app_data

    def _get_subprocess_kwargs(self, **kwargs) -> Dict[str, Any]:
        """
        获取 subprocess.run 的关键字参数
        在 Windows 上添加 CREATE_NO_WINDOW 标志来隐藏 CMD 窗口
        """
        import platform
        import subprocess

        if platform.system() == 'Windows':
            # Windows 上隐藏 CMD 窗口
            kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
        return kwargs

    # ==================== 配置管理 ====================

    def _load_config(self) -> Dict[str, Any]:
        """加载配置文件"""
        try:
            if self._config_file.exists():
                with open(self._config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            logger.warning(f"加载配置文件失败: {e}")
        return {}

    def _save_config(self, config: Dict[str, Any]):
        """保存配置文件"""
        try:
            self._config_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            logger.info(f"配置已保存到: {self._config_file}")
        except Exception as e:
            logger.error(f"保存配置文件失败: {e}")

    def get_proxy_config(self) -> Dict[str, Any]:
        """获取代理配置"""
        return {
            'status': 'success',
            'data': self._proxy_config
        }

    def test_proxy(self) -> Dict[str, Any]:
        """测试代理连接是否正常"""
        import urllib.request
        import urllib.error
        import time
        import socket as socket_module

        try:
            proxy_url = self._build_proxy_url()
            if not proxy_url:
                return {
                    'status': 'error',
                    'message': '未配置代理'
                }

            # 测试连接到几个常用的网站
            test_urls = [
                ('GitHub API', 'https://api.github.com'),
                ('Google', 'https://www.google.com'),
                ('百度', 'https://www.baidu.com')
            ]

            results = []
            proxy_type = self._proxy_config.get('type', 'http')

            # 保存原始 socket
            original_socket = socket_module.socket

            for name, url in test_urls:
                try:
                    start_time = time.time()

                    if proxy_url.startswith('socks'):
                        # SOCKS 代理
                        try:
                            import socks

                            sock_type = socks.PROXY_TYPE_SOCKS5 if 'socks5' in proxy_url else socks.PROXY_TYPE_SOCKS4
                            proxy_host = self._proxy_config.get('host')
                            proxy_port = self._proxy_config.get('port')

                            socks.set_default_proxy(sock_type, proxy_host, proxy_port)
                            socket_module.socket = socks.socksocket

                            req = urllib.request.Request(url, method='HEAD')
                            req.add_header('User-Agent', 'Mozilla/5.0')
                            urllib.request.urlopen(req, timeout=10)

                            elapsed = time.time() - start_time
                            results.append({'name': name, 'status': 'success', 'time': f'{elapsed:.2f}s'})

                        except ImportError:
                            results.append({'name': name, 'status': 'error', 'message': '需要安装 PySocks'})
                        finally:
                            # 恢复原始 socket
                            socket_module.socket = original_socket
                    else:
                        # HTTP/HTTPS 代理
                        proxy_handler = urllib.request.ProxyHandler({'https': proxy_url, 'http': proxy_url})
                        opener = urllib.request.build_opener(proxy_handler)

                        req = urllib.request.Request(url, method='HEAD')
                        req.add_header('User-Agent', 'Mozilla/5.0')
                        opener.open(req, timeout=10)

                        elapsed = time.time() - start_time
                        results.append({'name': name, 'status': 'success', 'time': f'{elapsed:.2f}s'})

                except urllib.error.HTTPError as e:
                    results.append({'name': name, 'status': 'http_error', 'code': e.code})
                except urllib.error.URLError as e:
                    results.append({'name': name, 'status': 'error', 'message': str(e.reason)})
                except Exception as e:
                    results.append({'name': name, 'status': 'error', 'message': str(e)})

            # 统计结果
            success_count = sum(1 for r in results if r['status'] == 'success')

            return {
                'status': 'success',
                'message': f'代理测试完成：{success_count}/{len(results)} 个连接成功',
                'data': {
                    'proxy_type': proxy_type,
                    'proxy_address': f"{self._proxy_config.get('host')}:{self._proxy_config.get('port')}",
                    'results': results
                }
            }

        except Exception as e:
            logger.error(f"测试代理失败: {str(e)}")
            return {
                'status': 'error',
                'message': f'测试代理失败: {str(e)}'
            }

    def set_proxy_config(self, proxy_type: str, proxy_host: str, proxy_port: int,
                         proxy_username: str = None, proxy_password: str = None) -> Dict[str, Any]:
        """设置代理配置

        Args:
            proxy_type: 代理类型 ('http', 'https', 'socks5')
            proxy_host: 代理主机地址
            proxy_port: 代理端口
            proxy_username: 代理用户名（可选）
            proxy_password: 代理密码（可选）
        """
        try:
            # 验证参数
            if not proxy_host:
                return {
                    'status': 'error',
                    'message': '代理地址不能为空'
                }

            if not proxy_port or proxy_port <= 0 or proxy_port > 65535:
                return {
                    'status': 'error',
                    'message': '代理端口无效（范围: 1-65535）'
                }

            if proxy_type not in ['http', 'https', 'socks5']:
                return {
                    'status': 'error',
                    'message': '不支持的代理类型，请选择 http、https 或 socks5'
                }

            # 构建代理配置
            proxy_config = {
                'type': proxy_type,
                'host': proxy_host,
                'port': proxy_port
            }

            # 添加认证信息（如果有）
            if proxy_username and proxy_password:
                proxy_config['username'] = proxy_username
                proxy_config['password'] = proxy_password

            # 更新内存中的配置
            self._proxy_config = proxy_config

            # 加载完整配置并更新代理部分
            config = self._load_config()
            config['proxy'] = proxy_config
            self._save_config(config)

            # 构建代理 URL（用于日志）
            auth_part = f"{proxy_username}@"
            proxy_url = f"{proxy_type}://{proxy_host}:{proxy_port}"

            logger.info(f"代理配置已更新: {proxy_type}://{proxy_host}:{proxy_port}")

            return {
                'status': 'success',
                'message': f'代理配置已保存：{proxy_type}://{proxy_host}:{proxy_port}',
                'data': {
                    'type': proxy_type,
                    'host': proxy_host,
                    'port': proxy_port,
                    'has_auth': bool(proxy_username and proxy_password)
                }
            }

        except Exception as e:
            logger.error(f"设置代理配置失败: {str(e)}")
            return {
                'status': 'error',
                'message': f'设置代理配置失败: {str(e)}'
            }

    def delete_proxy_config(self) -> Dict[str, Any]:
        """删除代理配置"""
        try:
            self._proxy_config = {}

            # 加载完整配置并删除代理部分
            config = self._load_config()
            if 'proxy' in config:
                del config['proxy']
                self._save_config(config)

            logger.info("代理配置已删除")

            return {
                'status': 'success',
                'message': '代理配置已删除'
            }

        except Exception as e:
            logger.error(f"删除代理配置失败: {str(e)}")
            return {
                'status': 'error',
                'message': f'删除代理配置失败: {str(e)}'
            }

    def _build_proxy_url(self) -> Optional[str]:
        """构建代理 URL（用于 urllib）

        Returns:
            代理 URL 字符串，如果未配置代理则返回 None
        """
        if not self._proxy_config:
            return None

        proxy_type = self._proxy_config.get('type', 'http')
        host = self._proxy_config.get('host')
        port = self._proxy_config.get('port')
        username = self._proxy_config.get('username')
        password = self._proxy_config.get('password')

        if not host or not port:
            return None

        # 构建认证部分
        if username and password:
            auth = f"{username}:{password}@"
        else:
            auth = ""

        # 构建 URL
        if proxy_type == 'socks5':
            # urllib 需要 socks 代理支持，需要安装 PySocks
            # 这里返回 socks5:// 格式，调用方需要处理
            return f"socks5://{auth}{host}:{port}"
        else:
            return f"{proxy_type}://{auth}{host}:{port}"

    # ==================== 前端UI控制 ====================

    def _show_loading(self, text: str = '加载中...', hint: str = None):
        """显示加载动画"""
        import webview
        try:
            # 转义单引号
            text_escaped = text.replace("'", "\\'").replace("\n", "\\n")
            if hint:
                hint_escaped = hint.replace("'", "\\'").replace("\n", "\\n")
                hint_js = f"'{hint_escaped}'"
            else:
                hint_js = 'null'

            js_code = f"""
                if (document.getElementById('loadingText')) document.getElementById('loadingText').textContent = '{text_escaped}';
                if (document.getElementById('loadingHint')) {{
                    const hint = {hint_js};
                    document.getElementById('loadingHint').textContent = hint ? hint : '请稍候，正在处理...';
                }}
                if (document.getElementById('loadingOverlay')) document.getElementById('loadingOverlay').classList.remove('hidden');
            """
            webview.windows[0].evaluate_js(js_code)
        except Exception as e:
            logger.warning(f"无法显示加载动画: {e}")

    def _hide_loading(self):
        """隐藏加载动画"""
        import webview
        try:
            js_code = """
                if (document.getElementById('loadingOverlay')) document.getElementById('loadingOverlay').classList.add('hidden');
            """
            webview.windows[0].evaluate_js(js_code)
        except Exception as e:
            logger.warning(f"无法隐藏加载动画: {e}")

    # ==================== 文件选择对话框 ====================

    def load_memory_image_dialog(self, os_type: str = None) -> Dict[str, Any]:
        """打开文件选择对话框加载内存镜像

        Args:
            os_type: 用户指定的操作系统类型 ('Windows', 'Linux', 'macOS')，如果为None则自动检测
        """
        try:
            import webview
            from webview import FileDialog
            logger.info(f"打开文件选择对话框 (用户指定OS类型: {os_type or '自动检测'})")

            # macOS 文件过滤器格式（默认显示所有文件）
            file_types = (
                '所有文件 (*.*)',
                '内存镜像文件 (*.raw;*.vmem;*.dmp;*.mem;*.lime)'
            )

            result = webview.windows[0].create_file_dialog(
                FileDialog.OPEN,
                file_types=file_types
            )

            if result and len(result) > 0:
                file_path = result[0]
                # 显示加载动画
                self._show_loading(
                    '正在加载内存镜像...',
                    '正在读取文件并计算哈希值，大文件可能需要较长时间...'
                )
                try:
                    result = self.load_memory_image(file_path, user_specified_os=os_type)
                    return result
                finally:
                    # 确保加载动画被隐藏
                    self._hide_loading()
            else:
                return {
                    'status': 'cancelled',
                    'message': '用户取消了文件选择'
                }

        except Exception as e:
            self._hide_loading()
            logger.error(f"文件选择对话框失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def select_directory_dialog(self) -> Dict[str, Any]:
        """打开目录选择对话框"""
        try:
            import webview
            logger.info("打开目录选择对话框")

            result = webview.windows[0].create_file_dialog(webview.FOLDER_DIALOG)

            if result and len(result) > 0:
                selected_dir = result[0]
                logger.info(f"用户选择目录: {selected_dir}")
                return {
                    'status': 'success',
                    'data': {
                        'path': selected_dir
                    }
                }
            else:
                return {
                    'status': 'cancelled',
                    'message': '用户取消了目录选择'
                }

        except Exception as e:
            logger.error(f"目录选择对话框失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def create_directory(self, path: str) -> Dict[str, Any]:
        """创建目录"""
        try:
            os.makedirs(path, exist_ok=True)
            logger.info(f"目录已创建: {path}")
            return {
                'status': 'success',
                'message': f'目录已创建: {path}'
            }
        except Exception as e:
            logger.error(f"创建目录失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    # ==================== 系统信息 ====================

    def get_system_info(self) -> Dict[str, Any]:
        """获取系统信息"""
        import platform
        import volatility3
        from volatility3.framework import constants

        try:
            vol_version = volatility3.__version__
        except AttributeError:
            import pkg_resources
            try:
                vol_version = pkg_resources.get_distribution('volatility3').version
            except:
                vol_version = 'unknown'

        return {
            'status': 'success',
            'data': {
                'system': platform.system(),
                'python_version': platform.python_version(),
                'volatility_version': vol_version,
                'os_release': platform.release(),
                'machine': platform.machine(),
                'cache_dir': str(self._cache_dir)
            }
        }

    def quit_app(self) -> Dict[str, Any]:
        """退出应用程序"""
        import sys
        import os

        logger.info('用户拒绝使用条款，退出应用')

        # 延迟执行退出，给前端时间响应
        def delayed_exit():
            logger.info('正在退出应用...')
            # 先尝试关闭窗口
            if hasattr(self, '_window') and self._window:
                try:
                    self._window.destroy()
                except:
                    pass
            # 再退出进程
            os._exit(0)

        import threading
        threading.Timer(0.5, delayed_exit).start()

        return {'status': 'success', 'message': '应用即将退出'}

    def set_window(self, window):
        """设置窗口引用"""
        self._window = window

    def resize_window(self, width: int, height: int) -> Dict[str, Any]:
        """调整窗口大小"""
        if hasattr(self, '_window') and self._window:
            try:
                self._window.resize(width, height)
                logger.info(f'窗口大小已调整为: {width}x{height}')
                return {'status': 'success', 'message': f'窗口已调整为 {width}x{height}'}
            except Exception as e:
                logger.error(f'调整窗口大小失败: {e}')
                return {'status': 'error', 'message': f'调整窗口大小失败: {str(e)}'}
        return {'status': 'error', 'message': '窗口引用不存在'}

    def set_license_manager(self, license_manager):
        """设置许可证管理器"""
        self._license_manager = license_manager

    def set_app(self, app):
        """设置应用引用"""
        self._app = app

    def activate_license(self, license_key: str) -> Dict[str, Any]:
        """激活许可证"""
        if hasattr(self, '_license_manager') and self._license_manager:
            success, message = self._license_manager.activate_license(license_key)
            if success:
                # 激活成功，需要重启应用
                return {
                    'status': 'success',
                    'message': message,
                    'require_restart': True
                }
            return {
                'status': 'error',
                'message': message
            }
        return {
            'status': 'error',
            'message': '许可证管理器未初始化'
        }

    def get_license_status(self) -> Dict[str, Any]:
        """获取许可证状态"""
        logger.info("=========== get_license_status 被调用 ===========")
        if hasattr(self, '_app') and self._app:
            status = self._app.get_license_status()
            logger.info(f"许可证状态: {status}")
            return {
                'status': 'success',
                'data': status
            }
        logger.warning("app 未初始化")
        return {
            'status': 'success',
            'data': {'valid': False}
        }

    def test_api(self) -> Dict[str, Any]:
        """测试API是否工作"""
        logger.info("=========== test_api 被调用 ===========")
        return {
            'status': 'success',
            'message': 'API工作正常',
            'timestamp': int(time.time())
        }

    def get_machine_code(self) -> Dict[str, Any]:
        """获取当前机器的机器码"""
        logger.info("get_machine_code 被调用")
        if hasattr(self, '_license_manager') and self._license_manager:
            machine_code = self._license_manager.get_machine_code()
            logger.info(f"机器码获取成功: {machine_code}")
            return {
                'status': 'success',
                'data': {
                    'machine_code': machine_code
                }
            }
        logger.error("license_manager 未初始化")
        return {
            'status': 'error',
            'message': '无法获取机器码'
        }

    def save_terms_accepted(self) -> Dict[str, Any]:
        """保存用户已同意条款"""
        try:
            terms_file = self._user_data_dir / 'terms_accepted.json'
            terms_file.write_text(json.dumps({
                'accepted': True,
                'date': datetime.now().isoformat()
            }), encoding='utf-8')
            logger.info(f"已保存用户同意条款状态到 {terms_file}")
            return {'status': 'success'}
        except Exception as e:
            logger.error(f"保存条款同意状态失败: {e}")
            return {'status': 'error', 'message': str(e)}

    def check_terms_accepted(self) -> Dict[str, Any]:
        """检查用户是否已同意条款"""
        try:
            terms_file = self._user_data_dir / 'terms_accepted.json'
            if terms_file.exists():
                data = json.loads(terms_file.read_text(encoding='utf-8'))
                logger.info(f"用户已同意条款，日期: {data.get('date')}")
                return {'status': 'success', 'accepted': True, 'date': data.get('date')}
            else:
                logger.info("用户未同意条款")
                return {'status': 'success', 'accepted': False}
        except Exception as e:
            logger.error(f"检查条款同意状态失败: {e}")
            return {'status': 'error', 'message': str(e)}

    def get_available_plugins(self) -> Dict[str, Any]:
        """获取可用的Volatility插件列表"""
        plugins = {
            # ==================== Windows 插件 ====================
            'Windows': {
                'process': [
                    {'id': 'pslist', 'name': '进程列表', 'description': '列出所有正在运行的进程'},
                    {'id': 'pstree', 'name': '进程树', 'description': '以树形结构显示进程关系'},
                    {'id': 'psscan', 'name': '进程扫描', 'description': '扫描隐藏/终止的进程'},
                    {'id': 'dlllist', 'name': 'DLL列表', 'description': '列出进程加载的DLL'},
                    {'id': 'handles', 'name': '句柄列表', 'description': '列出进程打开的句柄'}
                ],
                'network': [
                    {'id': 'netscan', 'name': '网络连接', 'description': '扫描网络连接'},
                    {'id': 'netstat', 'name': '网络状态', 'description': '显示网络统计信息'}
                ],
                'registry': [
                    {'id': 'hivelist', 'name': '注册表配置单元', 'description': '列出注册表配置单元'},
                    {'id': 'printkey', 'name': '打印注册表键', 'description': '显示注册表键值'}
                ],
                'filesystem': [
                    {'id': 'filescan', 'name': '文件扫描', 'description': '扫描文件对象'},
                    {'id': 'files', 'name': '文件列表', 'description': '列出文件系统文件'}
                ],
                'malware': [
                    {'id': 'malfind', 'name': '恶意代码查找', 'description': '查找注入的代码'},
                    {'id': 'ldrmodules', 'name': '加载模块', 'description': '检测未加载的DLL'}
                ],
                'cmdline': [
                    {'id': 'cmdline', 'name': '命令行参数', 'description': '显示进程命令行'},
                    {'id': 'consoles', 'name': '控制台历史', 'description': '提取控制台命令历史'}
                ],
                'crypto': [
                    {'id': 'hashdump', 'name': '哈希转储', 'description': '提取Windows密码哈希'},
                    {'id': 'lsadump', 'name': 'LSA密钥', 'description': '提取LSA密钥'},
                    {'id': 'cachedump', 'name': '域缓存', 'description': '提取域缓存凭据(mimikatz)'}
                ],
                'system': [
                    {'id': 'getsids', 'name': '获取SIDs', 'description': '获取进程安全标识符'},
                    {'id': 'envars', 'name': '环境变量', 'description': '显示进程环境变量'},
                    {'id': 'svcscan', 'name': '服务扫描', 'description': '扫描Windows服务'},
                    {'id': 'ssdt', 'name': 'SSDT', 'description': '显示系统服务描述符表'},
                    {'id': 'timers', 'name': '定时器', 'description': '显示内核定时器'},
                    {'id': 'callbacks', 'name': '回调', 'description': '显示内核回调'},
                    {'id': 'verinfo', 'name': '版本信息', 'description': '显示版本信息'},
                    {'id': 'clipboard', 'name': '剪贴板', 'description': '提取剪贴板内容'},
                    {'id': 'console', 'name': '控制台', 'description': '提取控制台历史命令'},
                    {'id': 'deskscan', 'name': '桌面扫描', 'description': '扫描桌面线程'},
                    {'id': 'dbgprint', 'name': '调试打印', 'description': '提取调试输出'},
                ]
            },

            # ==================== Linux 插件 ====================
            'Linux': {
                'process': [
                    {'id': 'linux_pslist', 'name': '进程列表', 'description': '列出所有正在运行的进程'},
                    {'id': 'linux_pstree', 'name': '进程树', 'description': '以树形结构显示进程关系'},
                    {'id': 'linux_psscan', 'name': '进程扫描', 'description': '扫描隐藏/终止的进程'},
                    {'id': 'linux_psaux', 'name': '进程参数', 'description': '显示进程命令行参数'},
                ],
                'network': [
                    {'id': 'linux_netstat', 'name': '网络状态', 'description': '显示网络统计信息'},
                    {'id': 'linux_sockstat', 'name': '进程网络连接', 'description': '显示网络连接信息'},
                    {'id': 'linux_ip_addr', 'name': '网络地址', 'description': '显示网络接口地址信息'},
                    {'id': 'linux_ip_link', 'name': '网络接口', 'description': '显示网络接口信息'},
                ],
                'filesystem': [
                    {'id': 'linux_elfs', 'name': 'ELF文件列表', 'description': '列出所有进程的所有内存映射 ELF 文件'},
                    {'id': 'linux_lsof', 'name': '打开文件列表', 'description': '列出每个进程的打开文件'},
                    {'id': 'linux_mountinfo', 'name': '挂载信息', 'description': '显示文件系统挂载信息'},
                    {'id': 'linux_pagecache_files', 'name': '页缓存文件', 'description': '列出页缓存中的文件'},
                    {'id': 'linux_pagecache_recoverfs', 'name': '恢复文件系统', 'description': '将缓存的文件系统恢复为压缩的 tar 包'},
                ],
                'malware': [
                    {'id': 'linux_malfind', 'name': '恶意代码查找', 'description': '查找注入的代码'},
                    {'id': 'linux_vmayarascan', 'name': 'VMARA扫描', 'description': '扫描VMARA结构'},
                ],
                'cmdline': [
                    {'id': 'linux_bash', 'name': 'Bash历史', 'description': '提取Bash命令历史'},
                    {'id': 'linux_envars', 'name': '环境变量', 'description': '显示进程环境变量'},
                ],
                'kernel': [
                    {'id': 'linux_lsmod', 'name': '内核模块', 'description': '列出已加载的内核模块'},
                    {'id': 'linux_check_modules', 'name': '模块检查', 'description': '检查内核模块完整性'},
                    {'id': 'linux_iomem', 'name': 'IO内存', 'description': '显示IO内存映射'},
                    {'id': 'linux_kmsg', 'name': '内核消息', 'description': '提取内核日志消息'},
                ],
                'system': [
                    {'id': 'linux_capabilities', 'name': '权限检查', 'description': '检查进程权限'},
                    {'id': 'linux_check_afinfo', 'name': 'AFINFO检查', 'description': '检查地址族信息'},
                    {'id': 'linux_check_creds', 'name': '凭据检查', 'description': '检查凭据结构'},
                    {'id': 'linux_check_idt', 'name': 'IDT检查', 'description': '检查中断描述符表'},
                    {'id': 'linux_check_syscall', 'name': '系统调用检查', 'description': '检查系统调用表'},
                    {'id': 'linux_tty_check', 'name': 'TTY检查', 'description': '检查TTY设备'},
                    {'id': 'linux_keyboard_notifiers', 'name': '键盘监听器', 'description': '检查键盘通知器'},
                    {'id': 'linux_maps', 'name': '内存映射', 'description': '显示进程内存映射'},
                ]
            },

            # ==================== macOS 插件 ====================
            'macOS': {
                'process': [
                    {'id': 'mac.pslist.PsList', 'name': '进程列表', 'description': '列出所有正在运行的进程'},
                    {'id': 'mac_pstree', 'name': '进程树', 'description': '以树形结构显示进程关系'},
                    {'id': 'mac_psaux', 'name': '进程参数', 'description': '显示进程命令行参数'},
                ],
                'network': [
                    {'id': 'mac.netstat.Netstat', 'name': '网络状态', 'description': '显示网络统计信息'},
                    {'id': 'mac.ifconfig.Ifconfig', 'name': '网络接口', 'description': '显示网络接口配置'},
                    {'id': 'mac.socket_filters.Socket_filters', 'name': '套接字过滤器', 'description': '显示套接字过滤器'},
                ],
                'filesystem': [
                    {'id': 'mac.lsof.Lsof', 'name': '打开文件', 'description': '列出进程打开的文件'},
                    {'id': 'mac.list_files.List_Files', 'name': '文件列表', 'description': '列出文件系统文件'},
                    {'id': 'mac.mount.Mount', 'name': '挂载信息', 'description': '显示文件系统挂载信息'},
                ],
                'malware': [
                    {'id': 'mac.malfind.Malfind', 'name': '恶意代码查找', 'description': '查找注入的代码'},
                ],
                'cmdline': [
                    {'id': 'mac.bash.Bash', 'name': 'Bash历史', 'description': '提取Bash命令历史'},
                ],
                'kernel': [
                    {'id': 'mac.lsmod.Lsmod', 'name': '内核扩展', 'description': '列出已加载的内核扩展(Kext)'},
                ],
                'system': [
                    {'id': 'mac.check_syscall.Check_syscall', 'name': '系统调用检查', 'description': '检查系统调用表'},
                    {'id': 'mac.check_sysctl.Check_sysctl', 'name': 'Sysctl检查', 'description': '检查sysctl表'},
                    {'id': 'mac.check_trap_table.Check_trap_table', 'name': '陷阱表检查', 'description': '检查陷阱表'},
                    {'id': 'mac.dmesg.Dmesg', 'name': '内核消息', 'description': '提取内核日志消息'},
                    {'id': 'mac.kevents.Kevents', 'name': '内核事件', 'description': '显示内核事件'},
                    {'id': 'mac.timers.Timers', 'name': '定时器', 'description': '显示内核定时器'},
                    {'id': 'mac.kauth_listeners.Kauth_listeners', 'name': 'Kauth监听器', 'description': '显示Kauth授权监听器'},
                    {'id': 'mac.kauth_scopes.Kauth_scopes', 'name': 'Kauth范围', 'description': '显示Kauth授权范围'},
                    {'id': 'mac.trustedbsd.Trustedbsd', 'name': 'TrustedBSD', 'description': '显示TrustedBSD信息'},
                    {'id': 'mac.proc_maps.Maps', 'name': '内存映射', 'description': '显示进程内存映射'},
                    {'id': 'mac.vfsevents.VFSevents', 'name': '文件系统事件', 'description': '显示文件系统事件'},
                ],
                'flags': [
                    {'id': 'search_flag', 'name': 'Flag搜索', 'description': '搜索CTF Flag字符串'},
                ]
            }
        }

        # 扁平化为 {plugin_id: {display_name, description}} 格式
        flat_plugins = {}
        for os_type, os_plugins in plugins.items():
            # 统一使用小写的键名
            os_key = os_type.lower()
            flat_plugins[os_key] = {}
            for category, plugin_list in os_plugins.items():
                for plugin in plugin_list:
                    flat_plugins[os_key][plugin['id']] = {
                        'display_name': plugin['name'],
                        'description': plugin['description']
                    }

        return {
            'status': 'success',
            'data': flat_plugins
        }

    # ==================== 符号表管理 ====================

    def get_symbol_status(self) -> Dict[str, Any]:
        """获取符号表安装状态（包含当前镜像所需的符号表信息）"""
        try:
            symbols_dir = self._symbols_dir

            # 确保符号表目录存在
            if not symbols_dir.exists():
                symbols_dir.mkdir(parents=True, exist_ok=True)

            # 检查各个操作系统的符号表
            symbol_status = {
                'windows': {'installed': False, 'count': 0, 'path': str(symbols_dir / 'windows'), 'pdb_info': None},
                'linux': {'installed': False, 'count': 0, 'path': str(symbols_dir / 'linux'), 'kernel_version': None},
                'mac': {'installed': False, 'count': 0, 'path': str(symbols_dir / 'mac'), 'kernel_version': None},
            }

            for os_name in symbol_status:
                os_dir = symbols_dir / os_name
                if os_dir.exists():
                    # 递归统计符号表文件数量（.json.xz 或 .json 文件）
                    count = len(list(os_dir.rglob('*.json.xz'))) + len(list(os_dir.rglob('*.json')))
                    symbol_status[os_name]['installed'] = count > 0
                    symbol_status[os_name]['count'] = count
                    logger.info(f"符号表状态 {os_name}: installed={symbol_status[os_name]['installed']}, count={count}")

            # 如果有当前加载的镜像，检查其所需的具体符号表
            if self.current_image:
                os_type = self.current_image.get('os_type', '').lower()

                # 统一 macOS 的类型名称
                if os_type == 'macos':
                    os_type = 'mac'

                if os_type == 'windows':
                    # 获取Windows镜像的PDB信息 - 直接使用Volatility3框架
                    try:
                        from volatility3.framework.symbols.windows import pdbutil
                        from volatility3.framework import contexts
                        from volatility3.framework.layers import physical

                        # 构建context并加载镜像
                        context = contexts.Context()
                        file_path = self.current_image['path']

                        # FileLayer需要URL格式的路径
                        import urllib.request
                        import urllib.parse
                        file_url = 'file://' + urllib.request.pathname2url(file_path)

                        # 设置配置
                        context.config['FileLayer.location'] = file_url

                        # 加载物理层
                        layer = physical.FileLayer(context, 'FileLayer', name="FileLayer")
                        context.add_layer(layer)

                        # 获取层名称
                        layer_name = layer.name
                        page_size = 0x1000  # 默认页面大小

                        # 扫描常见的Windows内核PDB名称
                        pdb_names = [b'ntkrnlmp.pdb', b'ntoskrnl.pdb', b'krnl.pdb', b'ntkrpamp.pdb']

                        # 使用pdbname_scan扫描PDB签名
                        found = False
                        for result in pdbutil.PDBUtility.pdbname_scan(
                            context, layer_name, page_size, pdb_names
                        ):
                            guid = result.get('GUID', '')
                            age = result.get('age', 0)
                            pdb_name = result.get('pdb_name', '')

                            if guid and pdb_name:
                                # 检查符号表文件是否存在
                                symbol_path = self._symbols_dir / 'windows' / pdb_name / f"{guid}-{age}.json.xz"
                                is_match = symbol_path.exists()

                                symbol_status['windows']['pdb_info'] = {
                                    'name': pdb_name,
                                    'guid': guid,
                                    'age': age,
                                    'symbol_exists': is_match,
                                    'symbol_path': str(symbol_path) if is_match else None
                                }

                                logger.info(f"Windows镜像PDB信息: {pdb_name} - {guid}-{age}, 符号表匹配: {is_match}")
                                found = True
                                break

                        if not found:
                            logger.info("未找到Windows内核PDB信息（打包后无法使用volatility3模块，但功能正常）")
                    except ImportError as e:
                        # 打包后无法导入 volatility3 模块，这是正常的
                        logger.info(f"打包后无法使用 volatility3 模块获取 PDB 信息（功能正常）: {e}")

                        # 尝试从之前保存的文件读取 PDB 信息
                        try:
                            pdb_info_path = self._symbols_dir / 'windows' / 'pdb_info.json'
                            if pdb_info_path.exists():
                                import json
                                saved_pdb_info = json.loads(pdb_info_path.read_text())
                                # 检查是否是当前镜像的 PDB 信息
                                if saved_pdb_info.get('image_path') == self.current_image.get('path'):
                                    pdb_name = saved_pdb_info.get('name')
                                    guid = saved_pdb_info.get('guid')
                                    age = saved_pdb_info.get('age')

                                    # 检查符号表文件是否存在
                                    symbol_path = self._symbols_dir / 'windows' / pdb_name / f"{guid}-{age}.json.xz"
                                    is_match = symbol_path.exists()

                                    symbol_status['windows']['pdb_info'] = {
                                        'name': pdb_name,
                                        'guid': guid,
                                        'age': age,
                                        'symbol_exists': is_match,
                                        'symbol_path': str(symbol_path) if is_match else None
                                    }
                                    logger.info(f"从文件读取 PDB 信息: {pdb_name} - {guid}-{age}, 符号表匹配: {is_match}")
                                else:
                                    logger.info(f"保存的 PDB 信息不匹配当前镜像")
                        except Exception as e2:
                            logger.warning(f"从文件读取 PDB 信息失败: {e2}")
                    except Exception as e:
                        logger.warning(f"获取Windows PDB信息失败: {e}")

                elif os_type in ['linux', 'mac']:
                    # Linux/macOS使用banner中的内核版本
                    banner = self.current_image.get('banner', '')
                    logger.info(f"{os_type} 镜像 banner 内容: {banner[:200] if banner else '(空)'}")
                    if banner:
                        kernel_version = self._extract_kernel_version(banner, os_type)
                        logger.info(f"{os_type} 从 banner 提取的内核版本: '{kernel_version}'")
                        if kernel_version:
                            symbol_status[os_type]['kernel_version'] = kernel_version
                            # 检查对应的符号表是否存在
                            symbol_exists = self._check_symbol_exists(os_type, kernel_version)
                            symbol_status[os_type]['kernel_symbol_exists'] = symbol_exists
                            logger.info(f"{os_type}镜像内核版本: {kernel_version}, 符号表匹配: {symbol_exists}")
                        else:
                            logger.warning(f"{os_type} 无法从 banner 提取内核版本")
                    else:
                        logger.warning(f"{os_type} 镜像没有 banner 信息")

            logger.info(f"返回符号表状态: current_os={self.current_image.get('os_type') if self.current_image else None}, os_types keys={list(symbol_status.keys())}")
            for os_name, os_info in symbol_status.items():
                logger.info(f"  {os_name}: installed={os_info.get('installed')}, kernel_symbol_exists={os_info.get('kernel_symbol_exists')}, kernel_version={os_info.get('kernel_version')}")

            return {
                'status': 'success',
                'data': {
                    'symbols_dir': str(symbols_dir),
                    'current_os': self.current_image.get('os_type') if self.current_image else None,
                    'os_types': symbol_status
                }
            }

        except Exception as e:
            logger.error(f"获取符号表状态失败: {str(e)}")
            return {
                'status': 'error',
                'message': f'获取符号表状态失败: {str(e)}'
            }

    def upload_symbol_file(self) -> Dict[str, Any]:
        """打开文件选择对话框上传符号表文件"""
        try:
            import webview
            from webview import FileDialog
            logger.info("打开符号表文件选择对话框")

            file_types = (
                '符号表压缩包 (*.zip)',
                '所有文件 (*.*)'
            )

            result = webview.windows[0].create_file_dialog(
                FileDialog.OPEN,
                file_types=file_types
            )

            if result and len(result) > 0:
                file_path = result[0]

                # 检查文件
                if not file_path.endswith('.zip'):
                    return {
                        'status': 'error',
                        'message': '请选择 .zip 格式的符号表文件'
                    }

                self._show_loading(
                    '正在安装符号表...',
                    '正在解压并安装符号表文件，请稍候...'
                )

                try:
                    install_result = self.install_symbols(file_path)
                    return install_result
                finally:
                    self._hide_loading()
            else:
                return {
                    'status': 'cancelled',
                    'message': '用户取消了文件选择'
                }

        except Exception as e:
            self._hide_loading()
            logger.error(f"符号表上传失败: {str(e)}")
            return {
                'status': 'error',
                'message': f'符号表上传失败: {str(e)}'
            }

    def install_symbols(self, zip_file_path: str) -> Dict[str, Any]:
        """安装符号表文件"""
        try:
            import zipfile

            symbols_dir = self._symbols_dir
            symbols_dir.mkdir(parents=True, exist_ok=True)

            logger.info(f"开始安装符号表: {zip_file_path}")

            # 检测 ZIP 文件内容，判断是哪个 OS 的符号表
            detected_os = None

            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                file_list = zip_ref.namelist()

                # 根据文件名判断操作系统
                for filename in file_list:
                    filename_lower = filename.lower()

                    # macOS 符号表特征
                    if ('kerneldebugkit' in filename_lower or 'debugkit' in filename_lower) and ('10.' in filename or 'build' in filename):
                        detected_os = 'mac'
                        break
                    # Windows 符号表特征
                    elif 'ntkrnl' in filename_lower or filename_lower.startswith('windows-'):
                        detected_os = 'windows'
                        break
                    # Linux 符号表特征
                    elif filename_lower.startswith('linux/') or filename_lower.startswith('linux\\') or 'linux' in filename_lower:
                        detected_os = 'linux'
                        break

            # 如果无法自动检测，默认为 mac
            if not detected_os:
                logger.warning("无法自动检测操作系统类型，默认安装到 mac 目录")
                detected_os = 'mac'

            # 目标目录
            target_dir = symbols_dir / detected_os
            target_dir.mkdir(parents=True, exist_ok=True)

            # 解压文件
            with zipfile.ZipFile(zip_file_path, 'r') as zip_ref:
                for member in zip_ref.infolist():
                    # 获取文件名
                    filename = member.filename

                    # 处理带目录前缀的情况（如 linux/xxx.json.xz）
                    # 如果文件名包含子目录（如 linux/），提取实际的文件名部分
                    parts = filename.replace('\\', '/').split('/')
                    if len(parts) > 1:
                        # 如果第一层是操作系统名称，使用后面的部分
                        if parts[0].lower() in ['linux', 'windows', 'mac']:
                            actual_filename = '/'.join(parts[1:]) if len(parts) > 2 else parts[1]
                        else:
                            actual_filename = parts[-1]  # 使用最后一部分作为文件名
                    else:
                        actual_filename = filename

                    # 跳过目录和空文件名
                    if not actual_filename or actual_filename.endswith('/'):
                        continue

                    # 只提取 .json 和 .json.xz 文件
                    if not (actual_filename.endswith('.json') or actual_filename.endswith('.json.xz')):
                        continue

                    # 解压到目标目录
                    target_path = target_dir / actual_filename

                    # 确保目标目录存在
                    target_path.parent.mkdir(parents=True, exist_ok=True)

                    with open(target_path, 'wb') as f:
                        f.write(zip_ref.read(member))

                    logger.info(f"已提取: {actual_filename}")

            # 统计安装的文件数量
            installed_count = len(list(target_dir.glob('*.json.xz'))) + len(list(target_dir.glob('*.json')))

            # 对于 macOS，创建符号链接以支持 Volatility 3 识别
            if detected_os == 'mac':
                try:
                    self._fix_macos_symbol_files(target_dir)
                except Exception as e:
                    logger.warning(f"创建 macOS 符号链接失败: {e}")

            logger.info(f"符号表安装成功: {detected_os} -> {target_dir}, 共 {installed_count} 个文件")

            return {
                'status': 'success',
                'message': f'符号表安装成功！已安装到 {detected_os.upper()} 目录，共 {installed_count} 个符号表文件。',
                'data': {
                    'os_type': detected_os,
                    'target_dir': str(target_dir),
                    'file_count': installed_count
                }
            }

        except zipfile.BadZipFile:
            logger.error("无效的 ZIP 文件")
            return {
                'status': 'error',
                'message': '无效的 ZIP 文件，请检查文件是否损坏'
            }
        except Exception as e:
            logger.error(f"符号表安装失败: {str(e)}")
            return {
                'status': 'error',
                'message': f'符号表安装失败: {str(e)}'
            }

    def open_symbol_directory(self, os_type: str) -> Dict[str, Any]:
        """打开符号表目录"""
        try:
            import platform
            import subprocess

            symbols_dir = self._symbols_dir / os_type

            if not symbols_dir.exists():
                # 如果目录不存在，创建它
                symbols_dir.mkdir(parents=True, exist_ok=True)

            # 根据操作系统使用不同的命令打开目录
            current_os = platform.system()

            if current_os == 'Windows':
                # Windows: 使用 explorer
                subprocess.run(['explorer', str(symbols_dir)])
            elif current_os == 'Darwin':
                # macOS: 使用 open
                subprocess.run(['open', str(symbols_dir)])
            elif current_os == 'Linux':
                # Linux: 使用 xdg-open
                subprocess.run(['xdg-open', str(symbols_dir)])
            else:
                return {
                    'status': 'error',
                    'message': f'不支持的操作系统: {current_os}'
                }

            return {
                'status': 'success',
                'message': f'已打开 {os_type.upper()} 符号表目录'
            }

        except Exception as e:
            logger.error(f"打开符号表目录失败: {str(e)}")
            return {
                'status': 'error',
                'message': f'打开目录失败: {str(e)}'
            }

    def download_symbols_from_github(self, os_type: str, kernel_version: str = None) -> Dict[str, Any]:
        """从 GitHub 自动下载符号表（适配新仓库结构）

        仓库结构:
        - Linux: Ubuntu/amd64/{major_version}/{abi}/{flavor}/Ubuntu_{full_version}.json.xz
        - macOS: mac/{darwin_version}/macOS_{darwin_version}.json.xz

        Args:
            os_type: 操作系统类型 ('linux' 或 'mac')
            kernel_version: 可选的内核版本，如果不提供则尝试自动检测

        Returns:
            下载结果
        """
        import urllib.request
        import urllib.error
        import json as json_lib
        import os
        import re

        try:
            logger.info(f"开始从 GitHub 下载 {os_type} 符号表...")

            # 如果没有提供内核版本，尝试从当前镜像获取
            if not kernel_version and self.current_image:
                kernel_version = self._extract_kernel_version_from_banner()
                if not kernel_version:
                    return {
                        'status': 'error',
                        'message': '无法从镜像中提取内核版本信息，请手动指定内核版本'
                    }

            # macOS 符号表下载
            if os_type.lower() == 'mac':
                return self._download_macos_symbols(kernel_version)

            # Linux 符号表下载（原有逻辑）
            # 从 banner 中检测发行版类型
            distro = self._detect_linux_distro_from_banner()
            if not distro:
                return {
                    'status': 'error',
                    'message': '无法从 banner 中检测 Linux 发行版类型（仅支持 Ubuntu/Debian 等）'
                }

            logger.info(f"检测到发行版: {distro}")

            # 解析内核版本，例如: 5.15.0-151-generic -> (5.15.0, 151, generic)
            parsed = self._parse_linux_kernel_version(kernel_version)
            if not parsed:
                return {
                    'status': 'error',
                    'message': f'无法解析内核版本格式: {kernel_version}'
                }

            major_version, abi, flavor = parsed['major'], parsed['abi'], parsed['flavor']
            logger.info(f"解析内核版本: major={major_version}, abi={abi}, flavor={flavor}")

            # 构建路径（假设 amd64 架构）
            # Ubuntu/amd64/5.15.0/151/generic/
            symbol_path = f"{distro}/amd64/{major_version}/{abi}/{flavor}"

            # 构建 GitHub API URL
            api_url = f"https://api.github.com/repos/Abyss-W4tcher/volatility3-symbols/contents/{symbol_path}"

            logger.info(f"获取符号表列表: {api_url}")

            # 检查是否配置了代理
            proxy_url = self._build_proxy_url()
            if proxy_url:
                logger.info(f"使用代理下载: {proxy_url.split('@')[0] if '@' in proxy_url else proxy_url}")

            # 请求 GitHub API - 使用更真实的 User-Agent
            req = urllib.request.Request(api_url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')
            req.add_header('Accept', 'application/vnd.github.v3+json')

            try:
                # 如果配置了代理，使用代理
                if proxy_url:
                    # 根据代理类型设置不同的处理器
                    if proxy_url.startswith('socks'):
                        # SOCKS 代理需要 PySocks 库
                        try:
                            import socks
                            import socket as socket_module
                            import ssl

                            # 保存原始函数并设置新的 SSL 上下文创建函数
                            _original_create_context = ssl._create_default_https_context

                            def _create_unverified_context():
                                ctx = ssl.create_default_context()
                                ctx.check_hostname = False
                                ctx.verify_mode = ssl.CERT_NONE
                                return ctx

                            ssl._create_default_https_context = _create_unverified_context

                            sock_type = socks.PROXY_TYPE_SOCKS5 if 'socks5' in proxy_url else socks.PROXY_TYPE_SOCKS4
                            # 解析代理地址
                            proxy_host = self._proxy_config.get('host')
                            proxy_port = self._proxy_config.get('port')
                            proxy_user = self._proxy_config.get('username')
                            proxy_pass = self._proxy_config.get('password')

                            # 创建 SOCKS 代理 opener
                            socks.set_default_proxy(sock_type, proxy_host, proxy_port, proxy_user, proxy_pass)
                            socket_module.socket = socks.socksocket

                            # 打开 URL（会使用我们设置的 SSL 上下文创建函数）
                            response = urllib.request.urlopen(req, timeout=30)

                            # 恢复原始函数
                            ssl._create_default_https_context = _original_create_context
                        except ImportError:
                            logger.warning("未安装 PySocks 库，SOCKS 代理不可用。请运行: pip install PySocks")
                            return {
                                'status': 'error',
                                'message': 'SOCKS 代理需要安装 PySocks 库。\n\n请运行: pip install PySocks\n\n或者使用 HTTP 代理（端口 7890）'
                            }
                        finally:
                            # 恢复原始 socket
                            try:
                                import socket as socket_module
                                socket_module.socket = socket_module._socket.socket
                            except:
                                pass
                    else:
                        # HTTP/HTTPS 代理 - 尝试使用更宽松的 SSL 设置
                        import ssl
                        ssl_context = ssl.create_default_context()
                        ssl_context.check_hostname = False
                        ssl_context.verify_mode = ssl.CERT_NONE

                        proxy_handler = urllib.request.ProxyHandler({'https': proxy_url, 'http': proxy_url})
                        https_handler = urllib.request.HTTPSHandler(context=ssl_context)
                        opener = urllib.request.build_opener(proxy_handler, https_handler)
                        response = opener.open(req, timeout=30)
                else:
                    response = urllib.request.urlopen(req, timeout=30)

                data = json_lib.loads(response.read().decode('utf-8'))
            except urllib.error.HTTPError as e:
                logger.error(f"GitHub API 请求失败: {e.code} - {e.reason}")
                # 读取响应内容获取更多信息
                error_msg = str(e)
                try:
                    error_body = e.read().decode('utf-8')
                    logger.error(f"GitHub API 错误详情: {error_body}")
                except:
                    pass

                # 根据错误码提供具体提示
                if e.code == 403:
                    # 速率限制或认证问题
                    proxy_hint = f"\n\n提示: GitHub API 请求被限制 (403)。\n\n可能的解决方案：\n1. 检查代理是否正常工作\n2. 尝试更换代理类型（如 SOCKS5）\n3. 稍后重试（GitHub 对未认证请求有限制）\n4. 手动下载符号表文件后使用【安装符号表】功能"
                    if proxy_url:
                        proxy_hint += f"\n\n当前代理: {proxy_url.split('@')[0] if '@' in proxy_url else proxy_url}"
                    return {
                        'status': 'error',
                        'message': f'GitHub API 访问被限制 (403)。\n\n这可能是由于：\n- GitHub API 速率限制\n- 代理配置问题\n- 网络连接问题{proxy_hint}'
                    }
                elif e.code == 404:
                    return {
                        'status': 'error',
                        'message': f'未找到匹配的符号表。\n\n路径: {symbol_path}\n\n该内核版本的符号表可能尚未收录到仓库中。\n\n请访问 https://github.com/Abyss-W4tcher/volatility3-symbols 查看可用版本'
                    }
                else:
                    return {
                        'status': 'error',
                        'message': f'GitHub API 请求失败 (HTTP {e.code})\n\n{error_msg}'
                    }
            except urllib.error.URLError as e:
                logger.error(f"网络请求失败: {str(e)}")
                proxy_hint = f"\n\n提示: 当前{'使用' if proxy_url else '未使用'}代理。"
                if proxy_url:
                    proxy_hint += f"\n代理地址: {proxy_url.split('@')[0] if '@' in proxy_url else proxy_url}\n\n请检查：\n1. 代理服务是否正常运行\n2. 代理地址和端口是否正确\n3. 尝试更换代理类型（HTTP/HTTPS/SOCKS5）"
                else:
                    proxy_hint += "\n如果访问 GitHub 较慢，可以在符号表管理中设置代理。"
                return {
                    'status': 'error',
                    'message': f'网络请求失败，请检查网络连接或代理设置。\n\n错误详情: {str(e)}{proxy_hint}'
                }
            except Exception as e:
                logger.error(f"获取符号表列表失败: {str(e)}")
                proxy_hint = f"\n\n提示: 当前{'使用' if proxy_url else '未使用'}代理。如果下载慢，可以在符号表管理中设置代理。"
                return {
                    'status': 'error',
                    'message': f'获取符号表列表失败: {str(e)}{proxy_hint}'
                }

            # 查找 .json.xz 文件
            matching_files = []
            for item in data:
                if item.get('type') == 'file' and item.get('name', '').endswith('.json.xz'):
                    matching_files.append({
                        'name': item.get('name'),
                        'download_url': item.get('download_url'),
                        'size': item.get('size', 0)
                    })

            if not matching_files:
                return {
                    'status': 'error',
                    'message': f'该目录下没有找到符号表文件。\n路径: {symbol_path}'
                }

            # 选择第一个文件
            target_file = matching_files[0]
            file_name = target_file['name']
            download_url = target_file['download_url']

            logger.info(f"找到匹配的符号表: {file_name}")
            logger.info(f"下载地址: {download_url}")

            # 创建目标目录并直接下载到目标位置
            target_dir = self._symbols_dir / os_type
            target_dir.mkdir(parents=True, exist_ok=True)
            target_path = target_dir / file_name

            # 检查文件是否已存在
            if target_path.exists():
                # 文件已存在，检查是否匹配当前镜像
                current_kernel = self._extract_kernel_version_from_banner()
                if current_kernel:
                    # 检查文件名是否包含当前内核版本
                    if current_kernel in file_name:
                        return {
                            'status': 'success',
                            'message': f'当前镜像已有匹配的符号表，可以正常使用需要符号表的插件。\n\n内核版本: {current_kernel}\n已安装匹配的符号表: {file_name}',
                            'file_name': file_name,
                            'already_exists': True
                        }
                    else:
                        return {
                            'status': 'error',
                            'message': f'符号表文件已存在，但版本可能不匹配。\n\n当前内核: {current_kernel}\n已安装: {file_name}\n\n如需重新下载，请先删除现有文件。'
                        }
                else:
                    return {
                        'status': 'error',
                        'message': f'符号表文件已存在：\n{file_name}\n\n如需重新下载，请先删除现有文件。'
                    }

            # 显示进度
            proxy_hint_text = f'\n(使用代理: {proxy_url.split("@")[0] if proxy_url and "@" in proxy_url else proxy_url})' if proxy_url else ''
            self._show_loading('正在下载符号表...', f'从 GitHub 下载 {file_name}...{proxy_hint_text}\n\n文件较大时可能需要几分钟，请耐心等待。')

            # 直接下载到目标文件
            try:
                if proxy_url:
                    # 使用代理下载
                    # 创建 SSL 上下文以避免证书验证失败（代理可能中断 SSL 连接）
                    import ssl
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE

                    proxy_handler = urllib.request.ProxyHandler({'https': proxy_url, 'http': proxy_url})
                    opener = urllib.request.build_opener(proxy_handler, urllib.request.HTTPSHandler(context=ssl_context))

                    # 创建请求并添加 User-Agent
                    file_req = urllib.request.Request(download_url)
                    file_req.add_header('User-Agent', 'LensAnalysis-Forensics-Tool')

                    # 下载文件
                    with opener.open(file_req, timeout=120) as response:
                        with open(target_path, 'wb') as f:
                            # 分块下载，显示进度
                            block_size = 8192
                            downloaded = 0
                            total_size = response.getheader('Content-Length')
                            if total_size:
                                total_size = int(total_size)

                            while True:
                                block = response.read(block_size)
                                if not block:
                                    break
                                f.write(block)
                                downloaded += len(block)
                else:
                    # 直接下载
                    urllib.request.urlretrieve(download_url, str(target_path))
            except Exception as e:
                logger.error(f"下载失败: {str(e)}")
                # 清理可能残留的不完整文件
                if target_path.exists():
                    try:
                        target_path.unlink()
                    except:
                        pass
                self._hide_loading()
                proxy_hint = f"\n\n提示: 当前{'使用' if proxy_url else '未使用'}代理。如果下载慢，可以在符号表管理中设置代理。"
                return {
                    'status': 'error',
                    'message': f'下载符号表失败: {str(e)}{proxy_hint}'
                }

            logger.info(f"下载完成，文件大小: {target_path.stat().st_size} bytes")
            logger.info(f"符号表已安装到: {target_path}")

            self._hide_loading()

            return {
                'status': 'success',
                'message': f'符号表下载成功！\n文件: {file_name}\n已安装到: {target_dir}',
                'file_name': file_name,
                'os_type': os_type,
                'kernel_version': kernel_version,
                'update_ui': True  # 标记需要更新 UI
            }

        except Exception as e:
            self._hide_loading()
            logger.error(f"下载符号表失败: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'message': f'下载符号表失败: {str(e)}'
            }

    def _download_macos_symbols(self, darwin_version: str) -> Dict[str, Any]:
        """下载 macOS 符号表

        GitHub 路径: macOS/{macos_version}/
        例如: macOS/10.12/, macOS/11.0/

        Darwin -> macOS 版本映射:
        - Darwin 16.x -> macOS 10.12
        - Darwin 17.x -> macOS 10.13
        - Darwin 18.x -> macOS 10.14
        - Darwin 19.x -> macOS 10.15
        - Darwin 20.x -> macOS 11.0
        - Darwin 21.x -> macOS 12.0
        - Darwin 22.x -> macOS 13.0
        - Darwin 23.x -> macOS 14.0
        """
        import urllib.request
        import urllib.error
        import json as json_lib

        # Darwin 版本转 macOS 版本
        darwin_to_macos = {
            '16.': '10.12',
            '17.': '10.13',
            '18.': '10.14',
            '19.': '10.15',
            '20.': '11.0',
            '21.': '12.0',
            '22.': '13.0',
            '23.': '14.0',
        }

        macos_version = None
        for darwin_prefix, macos in darwin_to_macos.items():
            if darwin_version.startswith(darwin_prefix):
                macos_version = macos
                break

        if not macos_version:
            return {
                'status': 'error',
                'message': f'不支持的 Darwin 版本: {darwin_version}\n\n请确保是 macOS 10.12 (Sierra) 或更高版本'
            }

        # 构建路径
        symbol_path = f"macOS/{macos_version}"

        # 构建 GitHub API URL
        api_url = f"https://api.github.com/repos/Abyss-W4tcher/volatility3-symbols/contents/{symbol_path}"

        logger.info(f"Darwin {darwin_version} -> macOS {macos_version}")
        logger.info(f"获取 macOS 符号表列表: {api_url}")

        # 检查是否配置了代理
        proxy_url = self._build_proxy_url()
        if proxy_url:
            logger.info(f"使用代理下载: {proxy_url.split('@')[0] if '@' in proxy_url else proxy_url}")

        # 请求 GitHub API
        req = urllib.request.Request(api_url)
        req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        req.add_header('Accept', 'application/vnd.github.v3+json')

        try:
            # 处理代理
            if proxy_url:
                if proxy_url.startswith('socks'):
                    try:
                        import socks
                        import socket as socket_module
                        import ssl

                        # 保存原始函数并设置新的 SSL 上下文创建函数
                        _original_create_context = ssl._create_default_https_context

                        def _create_unverified_context():
                            ctx = ssl.create_default_context()
                            ctx.check_hostname = False
                            ctx.verify_mode = ssl.CERT_NONE
                            return ctx

                        ssl._create_default_https_context = _create_unverified_context

                        sock_type = socks.PROXY_TYPE_SOCKS5 if 'socks5' in proxy_url else socks.PROXY_TYPE_SOCKS4
                        proxy_host = self._proxy_config.get('host')
                        proxy_port = self._proxy_config.get('port')
                        proxy_user = self._proxy_config.get('username')
                        proxy_pass = self._proxy_config.get('password')
                        socks.set_default_proxy(sock_type, proxy_host, proxy_port, proxy_user, proxy_pass)
                        socket_module.socket = socks.socksocket

                        # 打开 URL（会使用我们设置的 SSL 上下文创建函数）
                        response = urllib.request.urlopen(req, timeout=30)

                        # 恢复原始函数
                        ssl._create_default_https_context = _original_create_context
                    except ImportError:
                        return {
                            'status': 'error',
                            'message': 'SOCKS 代理需要安装 PySocks 库。请运行: pip install PySocks'
                        }
                    finally:
                        try:
                            import socket as socket_module
                            socket_module.socket = socket_module._socket.socket
                        except:
                            pass
                else:
                    import ssl
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    proxy_handler = urllib.request.ProxyHandler({'https': proxy_url, 'http': proxy_url})
                    https_handler = urllib.request.HTTPSHandler(context=ssl_context)
                    opener = urllib.request.build_opener(proxy_handler, https_handler)
                    response = opener.open(req, timeout=30)
            else:
                response = urllib.request.urlopen(req, timeout=30)

            data = json_lib.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            logger.error(f"GitHub API 请求失败: {e.code} - {e.reason}")
            if e.code == 404:
                return {
                    'status': 'error',
                    'message': f'未找到 macOS {macos_version} (Darwin {darwin_version}) 的符号表。\n\n请访问 https://github.com/Abyss-W4tcher/volatility3-symbols/tree/main/macOS 查看可用版本'
                }
            else:
                return {
                    'status': 'error',
                    'message': f'GitHub API 请求失败 (HTTP {e.code})'
                }
        except urllib.error.URLError as e:
            return {
                'status': 'error',
                'message': f'网络请求失败: {str(e)}'
            }
        except Exception as e:
            logger.error(f"获取符号表列表失败: {str(e)}")
            return {
                'status': 'error',
                'message': f'获取符号表列表失败: {str(e)}'
            }

        # 查找 .json.xz 文件
        matching_files = []
        for item in data:
            if item.get('type') == 'file' and item.get('name', '').endswith('.json.xz'):
                matching_files.append({
                    'name': item.get('name'),
                    'download_url': item.get('download_url'),
                    'size': item.get('size', 0)
                })

        if not matching_files:
            return {
                'status': 'error',
                'message': f'该目录下没有找到符号表文件。\n路径: {symbol_path}'
            }

        # 按文件名排序，选择几个常见的版本进行下载
        # macOS 10.12.x 有很多 build 版本，下载前几个和几个主要的版本
        matching_files.sort(key=lambda x: x['name'])

        # 对于 10.12.x，选择几个主要的 build 版本
        # 优先选择早期的 build (如 16G29) 和一些常见的版本
        priority_builds = []
        for f in matching_files:
            name = f['name']
            # 优先选择 build 16G29 (通常是 10.12.6 的早期版本)
            if '16G29' in name or '16G1408' in name or '16G1618' in name:
                if name not in priority_builds:
                    priority_builds.append(f)

        # 如果没有优先版本，使用前几个文件
        if priority_builds:
            files_to_download = priority_builds[:3]  # 下载最多3个优先版本
        else:
            files_to_download = matching_files[:5]  # 下载前5个版本

        logger.info(f"准备下载 {len(files_to_download)} 个 macOS 符号表文件")

        # 创建目标目录
        target_dir = self._symbols_dir / 'mac'
        target_dir.mkdir(parents=True, exist_ok=True)

        downloaded_files = []
        skipped_files = []

        # 下载每个文件
        for target_file in files_to_download:
            file_name = target_file['name']
            download_url = target_file['download_url']
            target_path = target_dir / file_name

            # 检查文件是否已存在
            if target_path.exists():
                logger.info(f"符号表已存在，跳过: {file_name}")
                skipped_files.append(file_name)
                continue

            # 下载文件
            logger.info(f"开始下载: {file_name}")

            req = urllib.request.Request(download_url)
            req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')

            try:
                if proxy_url:
                    if proxy_url.startswith('socks'):
                        try:
                            import socks
                            import socket as socket_module
                            import ssl

                            # 保存原始函数并设置新的 SSL 上下文创建函数
                            _original_create_context = ssl._create_default_https_context

                            def _create_unverified_context():
                                ctx = ssl.create_default_context()
                                ctx.check_hostname = False
                                ctx.verify_mode = ssl.CERT_NONE
                                return ctx

                            ssl._create_default_https_context = _create_unverified_context

                            sock_type = socks.PROXY_TYPE_SOCKS5 if 'socks5' in proxy_url else socks.PROXY_TYPE_SOCKS4
                            proxy_host = self._proxy_config.get('host')
                            proxy_port = self._proxy_config.get('port')
                            proxy_user = self._proxy_config.get('username')
                            proxy_pass = self._proxy_config.get('password')
                            socks.set_default_proxy(sock_type, proxy_host, proxy_port, proxy_user, proxy_pass)
                            socket_module.socket = socks.socksocket

                            # 打开 URL（会使用我们设置的 SSL 上下文创建函数）
                            response = urllib.request.urlopen(req, timeout=60)

                            # 恢复原始函数
                            ssl._create_default_https_context = _original_create_context
                        except ImportError:
                            return {
                                'status': 'error',
                                'message': 'SOCKS 代理需要安装 PySocks 库'
                            }
                        finally:
                            try:
                                import socket as socket_module
                                socket_module.socket = socket_module._socket.socket
                            except:
                                pass
                    else:
                        import ssl
                        ssl_context = ssl.create_default_context()
                        ssl_context.check_hostname = False
                        ssl_context.verify_mode = ssl.CERT_NONE
                        proxy_handler = urllib.request.ProxyHandler({'https': proxy_url, 'http': proxy_url})
                        https_handler = urllib.request.HTTPSHandler(context=ssl_context)
                        opener = urllib.request.build_opener(proxy_handler, https_handler)
                        response = opener.open(req, timeout=60)
                else:
                    response = urllib.request.urlopen(req, timeout=60)

                # 写入文件
                with open(target_path, 'wb') as f:
                    f.write(response.read())

                logger.info(f"macOS 符号表下载完成: {file_name}")
                downloaded_files.append(file_name)

            except Exception as e:
                logger.error(f"下载文件失败 {file_name}: {str(e)}")
                # 继续下载下一个文件

        # 所有下载完成后，创建符号链接
        if downloaded_files:
            try:
                self._fix_macos_symbol_files(target_dir)
            except Exception as e:
                logger.warning(f"创建符号链接失败: {e}")

        # 构建返回消息
        message_parts = []
        if downloaded_files:
            message_parts.append(f"已下载 {len(downloaded_files)} 个符号表文件:")
            for f in downloaded_files:
                message_parts.append(f"  • {f}")
        if skipped_files:
            message_parts.append(f"\n已存在 {len(skipped_files)} 个文件（跳过）:")
            for f in skipped_files:
                message_parts.append(f"  • {f}")

        message = '\n'.join(message_parts) if message_parts else '没有下载新文件'

        return {
            'status': 'success',
            'message': message,
            'downloaded_count': len(downloaded_files),
            'skipped_count': len(skipped_files)
        }

    def _detect_linux_distro_from_banner(self) -> str:
        """从 banner 中检测 Linux 发行版类型"""
        if not self.current_image:
            return None

        banner = self.current_image.get('banner', '')
        if not banner:
            return None

        banner_lower = banner.lower()

        # 检测发行版
        if 'ubuntu' in banner_lower:
            return 'Ubuntu'
        elif 'debian' in banner_lower:
            return 'Debian'
        elif 'kali' in banner_lower:
            return 'KaliLinux'
        elif 'almalinux' in banner_lower or 'alma' in banner_lower:
            return 'AlmaLinux'
        elif 'rocky' in banner_lower:
            return 'RockyLinux'

        return None

    def _parse_linux_kernel_version(self, kernel_version: str):
        """解析 Linux 内核版本

        例如: 5.15.0-151-generic -> (major=5.15.0, abi=151, flavor=generic)
        """
        import re

        # 匹配格式: 5.15.0-151-generic 或 5.4.0-84-generic
        match = re.match(r'^(\d+\.\d+\.\d+)-(\d+)-(\w+)', kernel_version)
        if match:
            return {
                'major': match.group(1),  # 5.15.0
                'abi': match.group(2),     # 151
                'flavor': match.group(3)  # generic
            }

        # 尝试其他格式
        match = re.match(r'^(\d+\.\d+\.\d+)-(\d+)', kernel_version)
        if match:
            return {
                'major': match.group(1),
                'abi': match.group(2),
                'flavor': 'generic'  # 默认
            }

        return None

    def _install_single_symbol(self, file_path: str, os_type: str) -> Dict[str, Any]:
        """安装单个符号表文件"""
        try:
            import lzma
            import shutil

            symbols_dir = self._symbols_dir / os_type
            symbols_dir.mkdir(parents=True, exist_ok=True)

            # 解压文件
            if file_path.endswith('.xz'):
                # 解压 .xz 文件
                json_xz_path = Path(file_path)
                json_filename = json_xz_path.stem  # 去掉 .xz 后缀
                output_path = symbols_dir / json_filename

                with lzma.open(file_path, 'rb') as f_in:
                    with open(output_path, 'wb') as f_out:
                        f_out.write(f_in.read())

                logger.info(f"符号表已安装到: {output_path}")

                # 对于 macOS，复制原始 .json.xz 文件并创建符号链接
                if os_type == 'mac':
                    original_xz_path = symbols_dir / Path(file_path).name
                    shutil.copy(file_path, original_xz_path)
                    self._fix_macos_symbol_files(symbols_dir)

                return {
                    'status': 'success',
                    'message': f'符号表安装成功',
                    'data': {
                        'path': str(output_path),
                        'os_type': os_type
                    }
                }
            else:
                # 直接复制文件
                output_path = symbols_dir / Path(file_path).name
                shutil.copy(file_path, output_path)

                # 对于 macOS，创建符号链接
                if os_type == 'mac':
                    self._fix_macos_symbol_files(symbols_dir)

                return {
                    'status': 'success',
                    'message': f'符号表安装成功',
                    'data': {
                        'path': str(output_path),
                        'os_type': os_type
                    }
                }

        except Exception as e:
            logger.error(f"安装符号表失败: {str(e)}")
            return {
                'status': 'error',
                'message': f'安装失败: {str(e)}'
            }

    # ==================== 镜像管理 ====================

    def _detect_os_type(self, file_path: str) -> str:
        """检测内存镜像的操作系统类型

        简化策略：只使用 banners 检测
        - banners 有结果：根据banner内容判断
        - banners 为空：默认为 Windows
        """
        from backend.volatility_wrapper import VolatilityWrapper
        wrapper = VolatilityWrapper(file_path)
        logger.info(f"开始检测镜像文件: {file_path}")

        # 清空之前的缓存
        self._cached_banner = None

        # 使用 banners 插件检测
        try:
            logger.info("使用 banners 插件检测操作系统...")
            result = wrapper._run_volatility('banners.Banners', [], use_symbols=False)

            if result and isinstance(result, list) and len(result) > 0:
                # 检查第一个 banner 的内容
                first_banner = str(result[0].get('banner', ''))
                logger.info(f"Banner 内容: {first_banner[:200]}")

                # 缓存 banner 内容，供后续使用
                self._cached_banner = first_banner

                # 根据关键字判断操作系统
                first_banner_lower = first_banner.lower()

                # 注意：如果banner中出现了Windows关键字，仍然是Windows
                if 'windows' in first_banner_lower or 'microsoft' in first_banner_lower:
                    logger.info("✅ 通过 Banner 检测到 Windows 内存镜像")
                    return 'Windows'
                elif 'darwin kernel' in first_banner_lower or 'mac os x' in first_banner_lower:
                    logger.info("✅ 通过 Banner 检测到 macOS 内存镜像")
                    return 'macOS'
                elif 'linux' in first_banner_lower and 'version' in first_banner_lower:
                    logger.info("✅ 通过 Banner 检测到 Linux 内存镜像")
                    return 'Linux'
                else:
                    logger.warning(f"Banner 无法识别系统类型: {first_banner[:100]}")
            else:
                logger.info("Banners 插件未返回结果（空）")
        except Exception as e:
            logger.warning(f"Banners 检测失败: {str(e)}")

        # banners 为空或失败，默认为 Windows
        logger.info("✅ Banners 为空，默认识别为 Windows 内存镜像")
        return 'Windows'

    def _check_plugin_compatibility(self, plugin_id: str, os_type: str) -> tuple[bool, str]:
        """检查插件是否与当前操作系统兼容"""
        # 定义每个插件支持的操作系统
        plugin_os_support = {
            # ==================== Windows 专用插件 ====================
            'pslist': ['Windows'],
            'pstree': ['Windows'],
            'psscan': ['Windows'],
            'dlllist': ['Windows'],
            'handles': ['Windows'],
            'cmdline': ['Windows'],
            'envars': ['Windows'],
            'getsids': ['Windows'],
            'netscan': ['Windows'],
            'netstat': ['Windows'],
            'svcscan': ['Windows'],
            'filescan': ['Windows'],
            'hivelist': ['Windows'],
            'printkey': ['Windows'],
            'malfind': ['Windows'],
            'hashdump': ['Windows'],
            'lsadump': ['Windows'],
            'cachedump': ['Windows'],
            'svcscan_reg': ['Windows'],
            'certificates': ['Windows'],
            # 恶意软件检测（新版本）
            'drivermodule': ['Windows'],
            'hollowprocesses': ['Windows'],
            'ldrmodules': ['Windows'],
            'svcdiff': ['Windows'],
            'unhooked_system_calls': ['Windows'],
            'processghosting': ['Windows'],
            'malware_psxview': ['Windows'],
            'pebmasquerade': ['Windows'],

            # ==================== Linux 专用插件 ====================
            # 进程相关
            'linux_pslist': ['Linux'],
            'linux_pstree': ['Linux'],
            'linux_psscan': ['Linux'],
            'linux_psaux': ['Linux'],
            # 网络相关
            'linux_netstat': ['Linux'],
            'linux_sockstat': ['Linux'],
            'linux_ip_addr': ['Linux'],
            'linux_ip_link': ['Linux'],
            # 文件系统
            'linux_lsof': ['Linux'],
            'linux_elfs': ['Linux'],
            'linux_mountinfo': ['Linux'],
            'linux_pagecache_files': ['Linux'],
            # Shell/环境
            'linux_bash': ['Linux'],
            'linux_envars': ['Linux'],
            # 内存/恶意代码
            'linux_malfind': ['Linux'],
            'linux_vmayarascan': ['Linux'],
            # 内核模块
            'linux_lsmod': ['Linux'],
            'linux_check_modules': ['Linux'],
            # 系统检查
            'linux_capabilities': ['Linux'],
            'linux_check_afinfo': ['Linux'],
            'linux_check_creds': ['Linux'],
            'linux_check_idt': ['Linux'],
            'linux_check_syscall': ['Linux'],
            'linux_tty_check': ['Linux'],
            # 内核信息
            'linux_iomem': ['Linux'],
            'linux_keyboard_notifiers': ['Linux'],
            'linux_kmsg': ['Linux'],
            # 内存映射
            'linux_maps': ['Linux'],

            # ==================== macOS 专用插件 ====================
            # 进程相关
            'mac.pslist.PsList': ['macOS', 'mac'],
            'mac.pstree.PsTree': ['macOS', 'mac'],
            'mac.psaux.Psaux': ['macOS', 'mac'],
            # 网络相关
            'mac.netstat.Netstat': ['macOS', 'mac'],
            'mac.ifconfig.Ifconfig': ['macOS', 'mac'],
            'mac.socket_filters.Socket_filters': ['macOS', 'mac'],
            # 文件系统
            'mac.lsof.Lsof': ['macOS', 'mac'],
            'mac.list_files.List_Files': ['macOS', 'mac'],
            'mac.mount.Mount': ['macOS', 'mac'],
            # Shell/环境
            'mac.bash.Bash': ['macOS', 'mac'],
            # 内存/恶意代码
            'mac.malfind.Malfind': ['macOS', 'mac'],
            # 内核模块
            'mac.lsmod.Lsmod': ['macOS', 'mac'],
            # 系统检查
            'mac.check_syscall.Check_syscall': ['macOS', 'mac'],
            'mac.check_sysctl.Check_sysctl': ['macOS', 'mac'],
            'mac.check_trap_table.Check_trap_table': ['macOS', 'mac'],
            # 内核信息
            'mac.dmesg.Dmesg': ['macOS', 'mac'],
            'mac.kevents.Kevents': ['macOS', 'mac'],
            'mac.timers.Timers': ['macOS', 'mac'],
            # 权限/安全
            'mac.kauth_listeners.Kauth_listeners': ['macOS', 'mac'],
            'mac.kauth_scopes.Kauth_scopes': ['macOS', 'mac'],
            'mac.trustedbsd.Trustedbsd': ['macOS', 'mac'],
            # 内存映射
            'mac.proc_maps.Maps': ['macOS', 'mac'],
            # 文件系统事件
            'mac.vfsevents.VFSevents': ['macOS', 'mac'],

            # macOS 插件别名（保持向后兼容）
            'mac_pslist': ['macOS', 'mac'],
            'mac_pstree': ['macOS', 'mac'],
            'mac_psaux': ['macOS', 'mac'],
            'mac_netstat': ['macOS', 'mac'],
            'mac_ifconfig': ['macOS', 'mac'],
            'mac_socket_filters': ['macOS', 'mac'],
            'mac_lsof': ['macOS', 'mac'],
            'mac_list_files': ['macOS', 'mac'],
            'mac_mount': ['macOS', 'mac'],
            'mac_bash': ['macOS', 'mac'],
            'mac_malfind': ['macOS', 'mac'],
            'mac_lsmod': ['macOS', 'mac'],
            'mac_check_syscall': ['macOS', 'mac'],
            'mac_check_sysctl': ['macOS', 'mac'],
            'mac_check_trap_table': ['macOS', 'mac'],
            'mac_dmesg': ['macOS', 'mac'],
            'mac_kevents': ['macOS', 'mac'],
            'mac_timers': ['macOS', 'mac'],
            'mac_kauth_listeners': ['macOS', 'mac'],
            'mac_kauth_scopes': ['macOS', 'mac'],
            'mac_trustedbsd': ['macOS', 'mac'],
            'mac_maps': ['macOS', 'mac'],
            'mac_vfsevents': ['macOS', 'mac'],
            'mac_envars': ['macOS', 'mac'],

            # ==================== 通用插件（所有系统） ====================
            'search_flag': ['Windows', 'Linux', 'macOS', 'mac'],
            'mac_search_flag': ['macOS', 'mac'],
        }

        supported_os = plugin_os_support.get(plugin_id, ['Windows', 'Linux', 'macOS', 'mac'])

        if os_type in supported_os or os_type == 'Unknown':
            return True, ''
        else:
            return False, f'此插件仅支持 {", ".join(supported_os)} 系统，当前镜像为 {os_type} 系统'

    def load_memory_image(self, file_path: str, user_specified_os: str = None) -> Dict[str, Any]:
        """加载内存镜像文件

        Args:
            file_path: 镜像文件路径
            user_specified_os: 用户指定的操作系统类型 ('Windows', 'Linux', 'macOS')，如果为None则自动检测
        """
        try:
            if not os.path.exists(file_path):
                return {
                    'status': 'error',
                    'message': f'文件不存在: {file_path}'
                }

            # 计算文件哈希
            file_hash = self._calculate_file_hash(file_path)
            file_size = os.path.getsize(file_path)

            # 检查缓存是否存在
            project_cache_dir = self._cache_dir / file_hash
            project_info_file = project_cache_dir / 'project_info.json'

            os_type = None
            banner = None
            from_cache = False

            # 优先尝试从缓存读取
            if project_info_file.exists():
                try:
                    with open(project_info_file, 'r', encoding='utf-8') as f:
                        cached_info = json.load(f)
                    # 验证哈希是否匹配
                    if cached_info.get('hash') == file_hash:
                        os_type = cached_info.get('os_type')
                        banner = cached_info.get('banner')
                        from_cache = True
                        logger.info(f"从缓存加载镜像信息: {cached_info.get('name')}, os_type={os_type}, banner={'有' if banner else '无'}")

                        # 如果缓存中没有 banner，且OS类型是Linux/macOS，需要重新获取
                        # Windows不需要banner（通过PDB GUID获取符号表）
                        if not banner and os_type and ('linux' in os_type.lower() or 'mac' in os_type.lower()):
                            logger.info(f"缓存中没有 banner，且OS类型为 {os_type}，需要重新获取...")
                            banner = self._get_image_banner(file_path, os_type)
                            # 更新缓存中的 banner
                            if banner:
                                cached_info['banner'] = banner
                                try:
                                    with open(project_info_file, 'w', encoding='utf-8') as f:
                                        json.dump(cached_info, f, indent=2, ensure_ascii=False)
                                    logger.info("已更新缓存中的 banner")
                                except Exception as e:
                                    logger.warning(f"更新缓存 banner 失败: {e}")

                        # 缓存 banner 供后续使用
                        if banner:
                            self._cached_banner = banner
                except Exception as e:
                    logger.warning(f"读取缓存失败: {e}")

            # 如果缓存命中，直接使用缓存（镜像哈希唯一确定类型，忽略用户手动选择）
            if from_cache:
                logger.info(f"缓存命中，跳过检测和 banner 执行")
                # 如果用户手动指定了不同的OS类型，记录提示但仍使用缓存
                if user_specified_os and user_specified_os.lower() != os_type.lower():
                    logger.info(f"用户指定 {user_specified_os}，但缓存记录为 {os_type}，使用缓存的OS类型")

                # 检查是否需要符号表
                needs_symbol = False
                symbol_info = None
                os_type_lower = os_type.lower() if os_type else 'unknown'

                # Linux/macOS 需要banner来提取内核版本，Windows则检查符号表目录
                if ('linux' in os_type_lower or 'mac' in os_type_lower) and banner:
                    kernel_version = self._extract_kernel_version(banner, os_type_lower)
                    if kernel_version:
                        symbol_exists = self._check_symbol_exists(os_type_lower, kernel_version)
                        if not symbol_exists:
                            needs_symbol = True
                            symbol_info = {
                                'os_type': os_type_lower,
                                'kernel_version': kernel_version
                            }
                elif os_type_lower == 'windows':
                    has_windows_symbols = self._check_windows_symbols()
                    if not has_windows_symbols:
                        needs_symbol = True
                        symbol_info = {
                            'os_type': 'windows',
                            'kernel_version': None
                        }

                # 检查本地符号表状态
                has_symbols = False
                symbol_count = 0
                if 'linux' in os_type_lower or 'mac' in os_type_lower:
                    # 确定符号表目录名（macos -> mac）
                    symbol_dir_name = 'mac' if 'mac' in os_type_lower else 'linux'
                    symbol_dir = self._symbols_dir / symbol_dir_name
                    if symbol_dir.exists():
                        symbol_count = len(list(symbol_dir.glob('*.json.xz'))) + len(list(symbol_dir.glob('*.json')))
                        has_symbols = symbol_count > 0
                elif 'windows' in os_type_lower:
                    symbol_dir = self._symbols_dir / 'windows'
                    if symbol_dir.exists():
                        symbol_count = len(list(symbol_dir.rglob('*.json.xz'))) + len(list(symbol_dir.rglob('*.json')))
                        has_symbols = symbol_count > 0

                # 保存当前镜像信息（重要：后续操作依赖这个）
                self.current_image = {
                    'path': file_path,
                    'name': cached_info.get('name'),
                    'hash': file_hash,
                    'size': file_size,
                    'os_type': os_type,
                    'banner': banner,
                    'loaded_at': cached_info.get('loaded_at', datetime.now().isoformat())
                }

                # 获取符号表文件名
                symbol_file = self._get_symbol_file_name()
                if symbol_file:
                    self.current_image['symbol_file'] = symbol_file
                else:
                    self.current_image['symbol_file'] = '未安装'

                # 加载当前镜像的Flag搜索缓存
                self._load_flag_search_cache_from_file()

                # 更新缓存访问时间
                cached_info['last_accessed'] = datetime.now().isoformat()
                with open(project_info_file, 'w', encoding='utf-8') as f:
                    json.dump(cached_info, f, ensure_ascii=False, indent=2)

                logger.info(f"成功从缓存加载镜像: {self.current_image['name']}")

                # 构建 os_types 结构（前端期望）
                os_types = {}
                if os_type_lower in ['linux', 'mac', 'windows']:
                    os_types[os_type_lower] = {
                        'installed': has_symbols,
                        'count': symbol_count
                    }

                # 返回缓存的结果
                response_data = {
                    'name': self.current_image['name'],
                    'size': self._format_size(file_size),
                    'hash': file_hash,
                    'path': file_path,
                    'os_type': os_type,
                    'banner': banner,
                    'has_symbols': has_symbols,
                    'symbol_count': symbol_count,
                    'from_cache': True,
                    'os_types': os_types
                }

                # 如果需要符号表，添加提示信息
                if needs_symbol and symbol_info:
                    response_data['needs_symbol'] = True
                    response_data['symbol_info'] = symbol_info

                return {
                    'status': 'success',
                    'data': response_data
                }

            # 缓存未命中，需要执行检测
            if user_specified_os:
                logger.info(f"用户指定系统类型: {user_specified_os}，使用指定类型（跳过OS自动检测）")
                os_type = user_specified_os
                # 统一 OS 类型名称（macOS -> mac）
                os_type_lower = os_type.lower()
                if os_type_lower == 'macos':
                    os_type = 'mac'
                    os_type_lower = 'mac'
                    logger.info(f"统一 OS 类型名称: macOS -> mac")
                # 用户手动指定类型时，Linux/macOS仍需获取banner用于符号表匹配，Windows不需要
                logger.info(f"os_type_lower = {os_type_lower}, 检查是否需要获取 banner")
                # 使用 'in' 检查，这样 'macos' 也能匹配 'mac'
                if 'linux' in os_type_lower or 'mac' in os_type_lower:
                    logger.info(f"进入 Linux/macOS banner 获取分支，准备调用 _get_image_banner")
                    banner = self._get_image_banner(file_path, os_type)
                    logger.info(f"_get_image_banner 返回，banner={'有' if banner else '无'}")
                    if banner:
                        self._cached_banner = banner
                        logger.info(f"获取到 banner: {banner[:100]}...")
                    else:
                        logger.warning(f"未能获取 {os_type} 的 banner")
                elif 'windows' in os_type_lower:
                    logger.info(f"进入 Windows 分支，banner 设为 None")
                    banner = None
                else:
                    logger.warning(f"未知的 os_type_lower: {os_type_lower}")
            elif not os_type:
                logger.info("缓存未命中，执行检测...")
                os_type = self._detect_os_type(file_path)

                # 检测后获取banner
                if os_type and os_type.lower() not in ['windows']:
                    banner = self._get_image_banner(file_path, os_type)
                    if banner:
                        self._cached_banner = banner
                elif os_type and os_type.lower() == 'windows':
                    banner = None

            # 检查是否需要符号表
            needs_symbol = False
            symbol_info = None

            # 统一 OS 类型为小写用于符号表检查
            os_type_lower = os_type.lower() if os_type else 'unknown'

            # Linux/macOS 需要banner来提取内核版本，Windows则检查符号表目录
            if ('linux' in os_type_lower or 'mac' in os_type_lower) and banner:
                # 从 banner 中提取内核版本
                kernel_version = self._extract_kernel_version(banner, os_type_lower)

                if kernel_version:
                    # 检查是否已有对应的符号表
                    symbol_exists = self._check_symbol_exists(os_type_lower, kernel_version)

                    if not symbol_exists:
                        needs_symbol = True
                        symbol_info = {
                            'os_type': os_type_lower,
                            'kernel_version': kernel_version
                        }
                        logger.info(f"检测到需要符号表: {os_type_lower} {kernel_version}")
            elif 'windows' in os_type_lower:
                # Windows 检查符号表目录是否有文件
                symbol_dir = self._symbols_dir / 'windows'
                has_windows_symbols = False
                if symbol_dir.exists():
                    symbol_files = list(symbol_dir.rglob('*.json.xz')) + list(symbol_dir.rglob('*.json'))
                    has_windows_symbols = len(symbol_files) > 0
                    logger.info(f"Windows符号表检查: 找到 {len(symbol_files)} 个文件")

                if not has_windows_symbols:
                    needs_symbol = True
                    symbol_info = {
                        'os_type': 'windows',
                        'kernel_version': None  # Windows不需要版本号
                    }
                    logger.info(f"检测到Windows镜像，但符号表目录为空")

            # 保存当前镜像信息
            self.current_image = {
                'path': file_path,
                'name': os.path.basename(file_path),
                'hash': file_hash,
                'size': file_size,
                'os_type': os_type,
                'banner': banner,
                'loaded_at': datetime.now().isoformat()
            }

            # 获取符号表文件名
            symbol_file = self._get_symbol_file_name()
            if symbol_file:
                self.current_image['symbol_file'] = symbol_file
            else:
                self.current_image['symbol_file'] = '未安装'

            # 加载当前镜像的Flag搜索缓存
            self._load_flag_search_cache_from_file()

            # 创建项目缓存目录并保存项目信息
            project_cache_dir = self._get_image_cache_dir()
            project_info_file = project_cache_dir / 'project_info.json'
            project_info = {
                'name': self.current_image['name'],
                'path': file_path,
                'hash': file_hash,
                'size': self._format_size(file_size),
                'os_type': os_type,
                'banner': banner,
                'loaded_at': self.current_image['loaded_at'],
                'last_accessed': datetime.now().isoformat()
            }
            with open(project_info_file, 'w', encoding='utf-8') as f:
                json.dump(project_info, f, ensure_ascii=False, indent=2)

            logger.info(f"成功加载镜像: {self.current_image['name']} ({file_size} bytes), from_cache={from_cache}")

            # 检查本地符号表状态
            has_symbols = False
            symbol_count = 0
            if 'linux' in os_type_lower or 'mac' in os_type_lower or 'windows' in os_type_lower:
                # 确定符号表目录名（macos -> mac）
                if 'mac' in os_type_lower:
                    symbol_dir_name = 'mac'
                elif 'windows' in os_type_lower:
                    symbol_dir_name = 'windows'
                else:
                    symbol_dir_name = 'linux'
                symbol_dir = self._symbols_dir / symbol_dir_name
                if symbol_dir.exists():
                    # 统计符号表文件数量
                    symbol_files = list(symbol_dir.rglob('*.json.xz')) + list(symbol_dir.rglob('*.json'))
                    symbol_count = len(symbol_files)
                    has_symbols = symbol_count > 0
                logger.info(f"符号表检查: OS={os_type_lower}, has_symbols={has_symbols}, count={symbol_count}")

            # 构建响应数据（包含前端期望的 os_types 结构）
            os_types = {}
            if 'linux' in os_type_lower or 'mac' in os_type_lower or 'windows' in os_type_lower:
                # 确定os_types的键名（macos -> mac）
                os_types_key = symbol_dir_name  # 使用上面确定的目录名
                os_types[os_types_key] = {
                    'installed': has_symbols,
                    'count': symbol_count
                }

            response_data = {
                'name': self.current_image['name'],
                'size': self._format_size(file_size),
                'hash': file_hash,
                'path': file_path,
                'os_type': os_type,
                'banner': banner,
                'has_symbols': has_symbols,
                'symbol_count': symbol_count,
                'from_cache': from_cache,  # 标识是否来自缓存
                'os_types': os_types  # 前端期望的数据结构
            }

            # 如果需要符号表，添加提示信息
            if needs_symbol and symbol_info:
                response_data['needs_symbol'] = True
                response_data['symbol_info'] = symbol_info

            return {
                'status': 'success',
                'data': response_data
            }

        except Exception as e:
            logger.error(f"加载镜像失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def get_current_image(self) -> Dict[str, Any]:
        """获取当前加载的镜像信息"""
        if self.current_image:
            return {
                'status': 'success',
                'data': self.current_image
            }
        return {
            'status': 'error',
            'message': '未加载镜像'
        }

    def _get_image_banner(self, file_path: str, os_type: str) -> str:
        """获取镜像的 banner 信息（优先使用缓存）"""
        logger.info(f"_get_image_banner 被调用: file_path={file_path}, os_type={os_type}")

        # 验证缓存是否有效（不能是表头或无效值）
        if self._cached_banner:
            # 检查缓存是否有效
            is_valid = (
                self._cached_banner and
                self._cached_banner not in ['Banner', 'banner', '有'] and
                len(self._cached_banner) > 20 and  # 正常 banner 应该更长
                ('Linux' in self._cached_banner or 'Darwin' in self._cached_banner or 'Windows' in self._cached_banner)
            )
            if is_valid:
                logger.info(f"使用缓存的 banner: {self._cached_banner[:100]}...")
                return self._cached_banner
            else:
                logger.warning(f"缓存的 banner 无效，重新获取: {self._cached_banner}")
                self._cached_banner = None  # 清除无效缓存

        # 如果没有缓存，调用 banners 插件获取
        try:
            from backend.volatility_wrapper import VolatilityWrapper

            logger.info(f"创建 VolatilityWrapper 实例，准备执行 banners.Banners 插件")
            wrapper = VolatilityWrapper(file_path)

            # 运行 banners 插件获取 banner
            logger.info(f"调用 wrapper._run_volatility('banners.Banners', use_symbols=False)")
            results = wrapper._run_volatility('banners.Banners', use_symbols=False)
            logger.info(f"banners.Banners 返回结果类型: {type(results)}, 数量: {len(results) if results else 0}")

            if results and len(results) > 1:
                logger.info(f"results[0] 内容（表头）: {results[0]}")
                logger.info(f"results[1] 内容（数据）: {results[1]}")
                # 跳过第一行（表头），使用第二行（实际数据）
                banner = results[1].get('banner', '')
                if banner and banner != 'Banner':  # 确保不是表头
                    logger.info(f"获取到 banner: {banner[:100]}...")
                    # 缓存起来
                    self._cached_banner = banner
                    return banner
                else:
                    logger.warning(f"results[1] 中的 banner 无效或为表头")
            elif results and len(results) == 1:
                logger.warning(f"banners.Banners 只返回了表头，没有实际数据")
            else:
                logger.warning(f"banners.Banners 返回了空结果或None")

            return ''
        except Exception as e:
            logger.warning(f"获取 banner 失败: {str(e)}", exc_info=True)
            return ''

    def _extract_kernel_version(self, banner: str, os_type: str) -> str:
        """从 banner 中提取内核版本"""
        import re

        # 统一处理 os_type（支持 macos -> mac）
        os_type_lower = os_type.lower()
        if 'mac' in os_type_lower:
            os_type_for_check = 'mac'
        elif 'linux' in os_type_lower:
            os_type_for_check = 'linux'
        elif 'windows' in os_type_lower:
            os_type_for_check = 'windows'
        else:
            os_type_for_check = os_type_lower

        if os_type_for_check == 'linux':
            # Linux banner 格式: "Linux version 5.15.0-151-generic (buildd@lcy02) (gcc version 11.4.0) #161-Ubuntu SMP Tue Jul 22 14:25:40 UTC 2025"
            match = re.search(r'Linux version\s+(\S+)', banner)
            if match:
                return match.group(1)

        elif os_type_for_check == 'windows':
            # Windows banner 格式: "Windows Version 17763 (Server 2019)"
            match = re.search(r'Windows Version\s+(\d+)', banner)
            if match:
                return match.group(1)

        elif os_type_for_check == 'mac':
            # macOS banner 格式: "Darwin Kernel Version 16.7.0: Tue Jan 10 20:36:05 PST 2017; root:xnu-3789.60.24~6/RELEASE_X86_64"
            match = re.search(r'Darwin Kernel Version\s+([\d.]+)', banner)
            if match:
                return match.group(1)

        return ''

    def _extract_kernel_version_from_banner(self) -> str:
        """从当前镜像的 Banner 中提取内核版本（优先使用缓存）"""
        try:
            import re

            if not self.current_image:
                return None

            # 优先使用 _cached_banner
            banner = self._cached_banner or self.current_image.get('banner', '')

            # 如果没有缓存的 banner，才执行 banners 获取
            if not banner:
                from backend.volatility_wrapper import VolatilityWrapper
                logger.info("缓存中无 banner，执行 banners 获取...")
                wrapper = VolatilityWrapper(self.current_image['path'])
                result = wrapper._run_volatility('banners.Banners', [], use_custom_plugins=False, use_symbols=False)

                if result and len(result) > 0:
                    banner = result[0].get('banner', '')
                    logger.info(f"提取内核版本，Banner: {banner[:200]}...")
                    # 缓存起来
                    if banner:
                        self._cached_banner = banner
                else:
                    return None
            else:
                logger.info(f"使用缓存的 banner 提取内核版本")

            # Linux Banner 格式: "Linux version 5.4.0-84-generic ..."
            if 'Linux version' in banner:
                match = re.search(r'Linux version\s+(\S+)', banner)
                if match:
                    version = match.group(1)
                    logger.info(f"提取到 Linux 内核版本: {version}")
                    return version

            # macOS Banner 格式: "Darwin Kernel Version 19.6.0 ..."
            elif 'Darwin Kernel Version' in banner:
                match = re.search(r'Darwin Kernel Version\s+([\d.]+)', banner)
                if match:
                    version = match.group(1)
                    logger.info(f"提取到 macOS 内核版本: {version}")
                    return version

            return None
        except Exception as e:
            logger.warning(f"提取内核版本失败: {str(e)}")
            return None

    def _check_windows_symbols(self) -> bool:
        """检查是否有任何 Windows 符号表"""
        try:
            symbol_dir = self._symbols_dir / 'windows'
            if not symbol_dir.exists():
                return False

            # 递归检查是否有任何符号文件
            symbol_files = list(symbol_dir.rglob('*.json.xz')) + list(symbol_dir.rglob('*.json'))
            has_symbols = len(symbol_files) > 0

            if has_symbols:
                logger.info(f"找到 {len(symbol_files)} 个 Windows 符号表文件")

            return has_symbols
        except Exception as e:
            logger.warning(f"检查 Windows 符号表失败: {str(e)}")
            return False

    def _check_symbol_exists(self, os_type: str, kernel_version: str) -> bool:
        """检查符号表是否已存在"""
        try:
            symbol_dir = self._symbols_dir / os_type
            if not symbol_dir.exists():
                return False

            # 对于 macOS，需要将 Darwin 版本转换为 macOS 版本进行匹配
            # 文件名格式可能是: macOS_KDK_10.12.1_build-16B2657.json.xz (旧格式)
            # 或: mac-10.12.1.json.xz (新格式)
            search_versions = [kernel_version]
            if os_type == 'mac':
                # 先检查并修复旧格式文件
                self._fix_macos_symbol_files(symbol_dir)

                # Darwin 版本转 macOS 版本
                darwin_to_macos = {
                    '16.': '10.12', '17.': '10.13', '18.': '10.14',
                    '19.': '10.15', '20.': '11.0', '21.': '12.0',
                    '22.': '13.0', '23.': '14.0'
                }
                for darwin_prefix, macos in darwin_to_macos.items():
                    if kernel_version.startswith(darwin_prefix):
                        search_versions.append(macos)
                        break

            # 直接在对应操作系统目录下搜索（不递归），提升速度
            # 符号表文件命名格式: Ubuntu_5.15.0-151-generic_5.15.0-151.161_amd64.json.xz
            # 或者: linux-5.15.0-151-generic.json.xz
            # macOS: macOS_KDK_10.12.1_build-16B2657.json.xz
            kernel_version_normalized = kernel_version.replace('_', '-').replace(' ', '-')

            # 先检查 .json.xz 文件
            for file_path in symbol_dir.glob('*.json.xz'):
                file_name = file_path.name
                # 检查文件名中是否包含内核版本
                for version in search_versions:
                    if version in file_name or kernel_version_normalized in file_name:
                        logger.info(f"找到匹配的符号表: {file_path.name}")
                        return True

            # 也检查 .json 文件（解压后的）
            for file_path in symbol_dir.glob('*.json'):
                file_name = file_path.name
                for version in search_versions:
                    if version in file_name or kernel_version_normalized in file_name:
                        logger.info(f"找到匹配的符号表: {file_path.name}")
                        return True

            logger.info(f"未找到匹配内核版本 {kernel_version} 的符号表")
            return False

        except Exception as e:
            logger.warning(f"检查符号表失败: {str(e)}")
            return False

    # ==================== 分析功能 ====================

    def run_analysis(self, plugin_id: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """运行分析插件 - 支持文件缓存"""
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            # 检查插件兼容性
            os_type = self.current_image.get('os_type', 'Unknown')
            is_compatible, error_msg = self._check_plugin_compatibility(plugin_id, os_type)

            if not is_compatible:
                logger.warning(f"插件 {plugin_id} 与 {os_type} 系统不兼容")
                return {
                    'status': 'error',
                    'message': error_msg,
                    'code': 'INCOMPATIBLE_PLUGIN'
                }

            logger.info(f"开始执行分析: {plugin_id} (系统: {os_type})")

            # 创建任务
            self.task_counter += 1
            task_id = f"task_{self.task_counter}"

            self.analysis_tasks[task_id] = {
                'id': task_id,
                'plugin': plugin_id,
                'params': params or {},
                'status': 'running',
                'started_at': datetime.now().isoformat()
            }

            # 生成缓存键
            cache_key = self._get_cache_key(plugin_id, params)

            # 尝试从缓存加载
            cached_result = self._load_from_cache_file(cache_key)
            if cached_result:
                logger.info(f"从缓存加载结果: {plugin_id}")
                self.analysis_tasks[task_id]['status'] = 'completed'
                self.analysis_tasks[task_id]['from_cache'] = True
                self.analysis_tasks[task_id]['completed_at'] = datetime.now().isoformat()

                return {
                    'status': 'success',
                    'task_id': task_id,
                    'data': cached_result,
                    'cached': True
                }

            # 没有缓存，执行分析
            result = self._execute_plugin(plugin_id, params)

            # 检查结果中是否有错误
            results = result.get('results', [])
            if results and results[0].get('_error'):
                error_type = results[0].get('_error')
                error_msg = results[0].get('_message', '未知错误')
                logger.warning(f"插件执行失败: {plugin_id}, 错误类型: {error_type}")
                self.analysis_tasks[task_id]['status'] = 'failed'
                self.analysis_tasks[task_id]['completed_at'] = datetime.now().isoformat()
                return {
                    'status': 'error',
                    'task_id': task_id,
                    'message': error_msg,
                    'error_type': error_type
                }

            logger.info(f"分析完成: {plugin_id}, 结果数量: {len(results)}")

            # svcscan 特殊处理：如果返回空结果，使用注册表方式作为后备
            if plugin_id == 'svcscan' and len(results) == 0:
                logger.warning("svcscan 返回空结果，尝试使用注册表方式获取服务列表")
                registry_result = self._get_services_from_registry()
                if registry_result:
                    result = registry_result
                    result['_info'] = '通过注册表获取服务列表'

            # 保存到缓存文件（仅保存成功的结果）
            self._save_to_cache_file(cache_key, result)

            self.analysis_tasks[task_id]['status'] = 'completed'
            self.analysis_tasks[task_id]['from_cache'] = False
            self.analysis_tasks[task_id]['completed_at'] = datetime.now().isoformat()

            return {
                'status': 'success',
                'task_id': task_id,
                'data': result,
                'cached': False
            }

        except Exception as e:
            logger.error(f"分析失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def run_analysis_with_params(self, plugin_id: str, params: Dict) -> Dict[str, Any]:
        """运行分析插件（带参数）- run_analysis的别名方法"""
        return self.run_analysis(plugin_id, params)

    def _execute_plugin(self, plugin_id: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """执行Volatility插件

        策略：
        1. 优先使用本地符号表（适用于打包后的用户，可能无网络）
        2. 如果本地没有符号表，Volatility 会尝试自动下载（需要网络）
        """
        from backend.volatility_wrapper import VolatilityWrapper

        wrapper = VolatilityWrapper(self.current_image['path'])

        # 优先查找本地符号表（所有系统都支持）
        symbol_file_path = None
        os_type = self.current_image.get('os_type', '').lower()

        # 确定符号表目录名
        if 'mac' in os_type:
            symbol_dir_name = 'mac'
        elif 'linux' in os_type:
            symbol_dir_name = 'linux'
        elif 'windows' in os_type:
            symbol_dir_name = 'windows'
        else:
            # 未知系统，不使用符号表
            symbol_dir_name = None

        # 如果确定了符号表目录，查找本地符号表文件
        if symbol_dir_name:
            symbol_dir = self._symbols_dir / symbol_dir_name

            # 对于macOS，检查并创建符号链接
            if 'mac' in os_type and symbol_dir.exists():
                self._fix_macos_symbol_files(symbol_dir)

            # 查找符号表文件（优先使用本地符号表）
            if symbol_dir.exists():
                # Windows 符号表在子目录中，需要递归查找
                # Linux/macOS 符号表直接在目录根下
                if 'windows' in os_type:
                    symbol_files = list(symbol_dir.rglob('*.json.xz'))
                    if not symbol_files:
                        symbol_files = list(symbol_dir.rglob('*.json'))
                else:
                    # Linux/macOS 使用 glob（非递归）
                    symbol_files = list(symbol_dir.glob('*.json.xz'))
                    if not symbol_files:
                        symbol_files = list(symbol_dir.glob('*.json'))

                if symbol_files:
                    # 使用第一个找到的符号表文件
                    symbol_file_path = str(symbol_files[0])
                    logger.info(f"[{os_type.upper()}] 使用本地符号表: {symbol_files[0].name}")
                else:
                    logger.info(f"[{os_type.upper()}] 本地无符号表，将尝试Volatility自动下载")
            else:
                logger.info(f"[{os_type.upper()}] 符号表目录不存在: {symbol_dir}，将尝试自动下载")

        result = wrapper.run_plugin(plugin_id, params or {}, symbol_file_path=symbol_file_path)
        return result

    def _fix_macos_symbol_files(self, symbol_dir: Path) -> None:
        """检查并创建符号链接，使 Volatility 3 能识别 macOS 符号表

        支持的原始文件格式:
        - macOS_KDK_*.json.xz (GitHub 下载格式)
        - Kernel_Debug_Kit_*.json.xz 或 kernel_debug_kit_*.json.xz (官方格式)
        - KernelDebugKit_*.json.xz (变体格式)

        ISF (Intermediate Symbol Format) 通过 JSON 元数据中的 hash 值匹配内核，
        文件名本身不影响 Volatility 3 的符号匹配，但为了统一管理和查找，
        我们创建标准格式的符号链接。
        """
        try:
            import re

            # 定义需要处理的文件模式
            file_patterns = [
                'macOS_KDK_*.json.xz',           # GitHub 格式
                'Kernel_Debug_Kit_*.json.xz',    # 官方格式 (大写K)
                'kernel_debug_kit_*.json.xz',    # 官方格式 (小写k)
                'KernelDebugKit_*.json.xz',      # 变体格式
                'macOS10*.json.xz',              # 其他变体
            ]

            processed_files = set()

            for pattern in file_patterns:
                for symbol_file in symbol_dir.glob(pattern):
                    # 跳过符号链接本身，只处理实际文件
                    if symbol_file.is_symlink():
                        continue

                    # 避免重复处理同一个文件（通过符号链接）
                    real_path = symbol_file.resolve()
                    if str(real_path) in processed_files:
                        continue
                    processed_files.add(str(real_path))

                    logger.info(f"处理 macOS 符号表文件: {symbol_file.name}")

                    # 从文件名中提取版本信息和构建号
                    # 支持多种格式:
                    # - macOS_KDK_10.12.6_build-16G1618.json.xz
                    # - Kernel_Debug_Kit_10.12.6_build_16G1618.dmg.json.xz
                    # - kernel_debug_kit_10.6.4_10f569.dmg.json.xz

                    # 提取 macOS 版本 (10.12.6 格式)
                    version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', symbol_file.name)
                    if not version_match:
                        logger.debug(f"无法从文件名提取版本: {symbol_file.name}")
                        continue

                    macos_version = version_match.group(1)
                    logger.info(f"提取的 macOS 版本: {macos_version}")

                    # 提取构建号 (16G1618 格式)
                    build_match = re.search(r'build[-_]([A-Z]?\d+[A-Z]?\d*)', symbol_file.name, re.IGNORECASE)
                    if build_match:
                        build_number = build_match.group(1)
                        logger.info(f"提取的构建号: {build_number}")
                    else:
                        # 尝试另一种格式: 10f569
                        build_match = re.search(r'(\d+[a-z]+\d+)', symbol_file.name, re.IGNORECASE)
                        build_number = build_match.group(1) if build_match else None
                        logger.info(f"提取的构建号 (备用格式): {build_number}")

                    # 创建符号链接 - 使用多个可能的名称
                    # 这些链接名都是为了便于查找和管理，不影响 Volatility 3 的实际匹配
                    link_names = []

                    # 标准格式链接
                    link_names.append(f"mac-{macos_version}.json.xz")
                    link_names.append(f"macOS-{macos_version}.json.xz")

                    # 如果有构建号，也创建包含构建号的链接
                    if build_number:
                        link_names.append(f"mac-{macos_version}-{build_number}.json.xz")
                        link_names.append(f"macOS_KDK_{macos_version}_build-{build_number}.json.xz")

                    for link_name in link_names:
                        link_path = symbol_dir / link_name
                        if not link_path.exists():
                            try:
                                # 使用绝对路径创建符号链接，避免路径问题
                                link_path.symlink_to(symbol_file)
                                logger.info(f"创建符号链接: {link_name} -> {symbol_file.name}")
                            except FileExistsError:
                                pass  # 链接已存在
                            except Exception as e:
                                logger.debug(f"创建链接失败 {link_name}: {e}")

        except Exception as e:
            logger.warning(f"修复macOS符号表文件名失败: {e}")

    def get_analysis_status(self, task_id: str) -> Dict[str, Any]:
        """获取分析任务状态"""
        if task_id in self.analysis_tasks:
            return {
                'status': 'success',
                'data': self.analysis_tasks[task_id]
            }
        return {
            'status': 'error',
            'message': '任务不存在'
        }

    # ==================== CTF功能 ====================

    def check_strings_tool(self) -> Dict[str, Any]:
        """检测系统是否有 strings 工具"""
        try:
            import platform
            import shutil

            system = platform.system()
            has_strings = False
            strings_path = None

            if system == 'Windows':
                # Windows 上检查 strings.exe
                # 优先级：用户数据目录 -> 当前目录 -> PATH
                possible_paths = [
                    self._user_data_dir / 'strings.exe',
                    Path(os.path.dirname(sys.executable)) / 'strings.exe',
                    'strings.exe'
                ]
                for path in possible_paths:
                    if isinstance(path, str):
                        if shutil.which(path):
                            has_strings = True
                            strings_path = shutil.which(path)
                            break
                    else:
                        if path.exists():
                            has_strings = True
                            strings_path = str(path)
                            break
            else:
                # macOS/Linux 上检查 strings 命令
                has_strings = shutil.which('strings') is not None
                if has_strings:
                    strings_path = shutil.which('strings')

            return {
                'status': 'success',
                'has_strings': has_strings,
                'platform': system,
                'strings_path': strings_path if has_strings else None
            }
        except Exception as e:
            logger.error(f"检测 strings 工具失败: {e}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def download_strings_tool(self) -> Dict[str, Any]:
        """下载 Windows strings 工具"""
        import platform
        import zipfile

        try:
            if platform.system() != 'Windows':
                return {
                    'status': 'error',
                    'message': '此功能仅支持 Windows 系统'
                }

            self._show_loading('正在下载 strings 工具', '正在从微软官方下载...\n\n文件较小，请稍候。')

            # 目标路径
            exe_path = self._user_data_dir / 'strings.exe'

            # 如果已存在，直接返回
            if exe_path.exists():
                self._hide_loading()
                return {
                    'status': 'success',
                    'message': 'strings 工具已存在',
                    'already_exists': True
                }

            # 下载 zip 文件
            zip_path = self._user_data_dir / 'Strings.zip'
            url = 'https://download.sysinternals.com/files/Strings.zip'

            logger.info(f"开始下载 strings 工具: {url}")

            # 下载（支持代理）
            try:
                import urllib.request

                proxy_url = self._build_proxy_url()
                if proxy_url:
                    # 设置代理
                    if proxy_url.startswith('socks'):
                        # SOCKS 代理需要特殊处理
                        try:
                            import socks
                            import socket as socket_module
                            import ssl

                            # 保存原始函数并设置新的 SSL 上下文创建函数
                            _original_create_context = ssl._create_default_https_context

                            def _create_unverified_context():
                                ctx = ssl.create_default_context()
                                ctx.check_hostname = False
                                ctx.verify_mode = ssl.CERT_NONE
                                return ctx

                            ssl._create_default_https_context = _create_unverified_context

                            sock_type = socks.PROXY_TYPE_SOCKS5 if 'socks5' in proxy_url else socks.PROXY_TYPE_SOCKS4
                            proxy_host = self._proxy_config.get('host')
                            proxy_port = self._proxy_config.get('port')
                            proxy_user = self._proxy_config.get('username')
                            proxy_pass = self._proxy_config.get('password')

                            socks.set_default_proxy(sock_type, proxy_host, proxy_port, proxy_user, proxy_pass)
                            socket_module.socket = socks.socksocket

                            urllib.request.urlretrieve(url, zip_path)

                            # 恢复原始函数和 socket
                            ssl._create_default_https_context = _original_create_context
                            try:
                                import socket as socket_module2
                                socket_module2.socket = socket_module2._socket.socket
                            except:
                                pass
                        except ImportError:
                            logger.warning("未安装 PySocks 库，尝试直接下载")
                            urllib.request.urlretrieve(url, zip_path)
                    else:
                        # HTTP/HTTPS 代理
                        proxy_handler = urllib.request.ProxyHandler({'https': proxy_url, 'http': proxy_url})
                        opener = urllib.request.build_opener(proxy_handler)
                        urllib.request.urlretrieve(url, zip_path)
                else:
                    urllib.request.urlretrieve(url, zip_path)

                logger.info(f"下载完成: {zip_path}")

            except Exception as download_error:
                self._hide_loading()
                logger.error(f"下载失败: {download_error}")
                return {
                    'status': 'error',
                    'message': f'下载失败: {str(download_error)}'
                }

            # 解压 zip 文件
            logger.info(f"开始解压: {zip_path}")
            try:
                with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                    zip_ref.extractall(self._user_data_dir)
                logger.info("解压完成")
            except Exception as extract_error:
                self._hide_loading()
                # 清理失败的 zip 文件
                if zip_path.exists():
                    zip_path.unlink()
                logger.error(f"解压失败: {extract_error}")
                return {
                    'status': 'error',
                    'message': f'解压失败: {str(extract_error)}'
                }

            # 清理 zip 文件
            try:
                zip_path.unlink()
                logger.info(f"已清理临时文件: {zip_path}")
            except:
                pass

            # 验证 strings.exe 是否存在
            if exe_path.exists():
                self._hide_loading()
                logger.info(f"strings 工具安装成功: {exe_path}")
                return {
                    'status': 'success',
                    'message': 'strings 工具下载成功',
                    'already_exists': False
                }
            else:
                self._hide_loading()
                return {
                    'status': 'error',
                    'message': '下载完成但未找到 strings.exe'
                }

        except Exception as e:
            self._hide_loading()
            logger.error(f"下载 strings 工具失败: {e}", exc_info=True)
            return {
                'status': 'error',
                'message': f'下载失败: {str(e)}'
            }

    def search_flag(self, patterns: List[str] = None, force: bool = False) -> Dict[str, Any]:
        """搜索可能的Flag - 支持自定义格式和缓存

        Args:
            patterns: 自定义正则表达式列表
            force: 强制重新搜索（忽略缓存）
        """
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            # 确定缓存键
            if patterns:
                # 自定义搜索：将模式列表转换为字符串作为键
                cache_key = 'custom:' + ':'.join(patterns)
                is_custom = True
            else:
                # 默认搜索
                cache_key = 'default'
                is_custom = False

            # 检查是否正在搜索
            if cache_key in self._flag_search_cache:
                cache_entry = self._flag_search_cache[cache_key]
                if cache_entry.get('searching', False):
                    return {
                        'status': 'searching',
                        'message': '正在搜索中，请稍候...'
                    }

                # 如果有缓存且不强制重新搜索，直接返回缓存结果
                if not force and 'results' in cache_entry:
                    logger.info(f"使用缓存的Flag搜索结果: {cache_key}, {len(cache_entry['results'])} 条")
                    return {
                        'status': 'success',
                        'data': {
                            'flags': cache_entry['results'],
                            'count': len(cache_entry['results']),
                            'cached': True,
                            'timestamp': cache_entry.get('timestamp', ''),
                            'pattern': cache_entry.get('pattern', ''),
                            'is_custom': is_custom
                        }
                    }

            # 标记为正在搜索
            self._flag_search_cache[cache_key] = {
                'searching': True,
                'results': [],
                'timestamp': None,
                'pattern': ':'.join(patterns) if patterns else ''
            }

            # 默认CTF flag格式（更全面的模式）
            if not patterns:
                patterns = [
                    r'flag\{[^}]+\}',      # flag{xxx}
                    r'FLAG\{[^}]+\}',      # FLAG{xxx}
                    r'ctf\{[^}]+\}',       # ctf{xxx}
                    r'CTF\{[^}]+\}',       # CTF{xxx}
                    r'key\{[^}]+\}',       # key{xxx}
                    r'KEY\{[^}]+\}',       # KEY{xxx}
                ]

            # 检测strings命令是否可用
            import shutil
            import platform
            has_strings = shutil.which('strings') is not None

            # Windows上可能没有strings命令
            if platform.system() == 'Windows' and not has_strings:
                logger.warning("Windows系统未找到strings命令，搜索功能可能受限")

            from backend.volatility_wrapper import VolatilityWrapper
            wrapper = VolatilityWrapper(self.current_image['path'])

            results = wrapper.search_strings(patterns)

            # 更新缓存
            self._flag_search_cache[cache_key] = {
                'searching': False,
                'results': results,
                'timestamp': datetime.now().isoformat(),
                'pattern': ':'.join(patterns) if patterns else ''
            }

            # 保存到文件
            self._save_flag_search_cache_to_file()

            logger.info(f"Flag搜索完成: {cache_key}, 找到 {len(results)} 条结果")

            return {
                'status': 'success',
                'data': {
                    'flags': results,
                    'count': len(results),
                    'cached': False,
                    'timestamp': self._flag_search_cache[cache_key]['timestamp'],
                    'pattern': self._flag_search_cache[cache_key]['pattern'],
                    'is_custom': is_custom,
                    'cache_key': cache_key
                }

            }
        except Exception as e:
            logger.error(f"搜索Flag失败: {str(e)}")
            # 清除搜索状态
            if 'cache_key' in locals() and cache_key in self._flag_search_cache:
                self._flag_search_cache[cache_key]['searching'] = False
            return {
                'status': 'error',
                'message': str(e)
            }

    def get_flag_search_history(self) -> Dict[str, Any]:
        """获取当前镜像的Flag搜索历史"""
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            logger.info(f"获取Flag搜索历史，当前镜像有 {len(self._flag_search_cache)} 条记录")

            history = []

            for cache_key, entry in self._flag_search_cache.items():
                if entry.get('searching', False):
                    continue  # 跳过正在搜索的

                if cache_key == 'default':
                    history.append({
                        'cache_key': cache_key,
                        'pattern': '默认搜索 (flag{xxx}, FLAG{xxx}, ctf{xxx}, CTF{xxx})',
                        'display_name': '默认搜索',
                        'count': len(entry.get('results', [])),
                        'timestamp': entry.get('timestamp', ''),
                        'is_default': True
                    })
                elif cache_key.startswith('custom:'):
                    pattern = entry.get('pattern', cache_key[7:])
                    history.append({
                        'cache_key': cache_key,
                        'pattern': pattern,
                        'display_name': pattern if len(pattern) <= 50 else pattern[:50] + '...',
                        'count': len(entry.get('results', [])),
                        'timestamp': entry.get('timestamp', ''),
                        'is_default': False
                    })

            # 按时间倒序排序
            history.sort(key=lambda x: x['timestamp'], reverse=True)

            return {
                'status': 'success',
                'data': {'history': history}
            }

        except Exception as e:
            logger.error(f"获取搜索历史失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def delete_flag_search_result(self, cache_key: str) -> Dict[str, Any]:
        """删除指定的Flag搜索结果"""
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if cache_key in self._flag_search_cache:
                del self._flag_search_cache[cache_key]
                # 保存到文件
                self._save_flag_search_cache_to_file()
                logger.info(f"已删除搜索结果: {cache_key}")
                return {
                    'status': 'success',
                    'message': '已删除搜索结果'
                }

            return {
                'status': 'error',
                'message': '搜索结果不存在'
            }

        except Exception as e:
            logger.error(f"删除搜索结果失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def get_cached_flag_result(self, cache_key: str) -> Dict[str, Any]:
        """获取指定缓存键的Flag搜索结果"""
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if cache_key not in self._flag_search_cache:
                return {
                    'status': 'error',
                    'message': f'缓存键不存在: {cache_key}'
                }

            entry = self._flag_search_cache[cache_key]
            if entry.get('searching', False):
                return {
                    'status': 'searching',
                    'message': '正在搜索中...'
                }

            return {
                'status': 'success',
                'data': {
                    'flags': entry.get('results', []),
                    'count': len(entry.get('results', [])),
                    'cached': True,
                    'timestamp': entry.get('timestamp', ''),
                    'pattern': entry.get('pattern', ''),
                    'cache_key': cache_key
                }
            }

        except Exception as e:
            logger.error(f"获取缓存结果失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def get_flag_search_status(self) -> Dict[str, Any]:
        """获取当前镜像的Flag搜索状态"""
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            image_hash = self.current_image.get('hash', '')
            if not image_hash:
                return {
                    'status': 'not_searched',
                    'message': '尚未进行过搜索'
                }

            if image_hash not in self._flag_search_cache:
                return {
                    'status': 'not_searched',
                    'message': '尚未进行过搜索'
                }

            cache_entry = self._flag_search_cache[image_hash]

            if cache_entry.get('searching', False):
                return {
                    'status': 'searching',
                    'message': '正在搜索中...'
                }

            return {
                'status': 'completed',
                'data': {
                    'count': len(cache_entry.get('results', [])),
                    'timestamp': cache_entry.get('timestamp', '')
                }
            }

        except Exception as e:
            logger.error(f"获取搜索状态失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def clear_flag_search_cache(self) -> Dict[str, Any]:
        """清除当前镜像的Flag搜索缓存"""
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if self._flag_search_cache:
                self._flag_search_cache.clear()
                self._save_flag_search_cache_to_file()
                return {
                    'status': 'success',
                    'message': '缓存已清除'
                }

            return {
                'status': 'success',
                'message': '无需清除（无缓存）'
            }

        except Exception as e:
            logger.error(f"清除缓存失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def _load_flag_search_cache_from_file(self):
        """从当前镜像的缓存目录加载Flag搜索缓存"""
        try:
            cache_file = self._get_image_cache_dir() / 'flag_search_cache.json'
            if cache_file.exists():
                with open(cache_file, 'r', encoding='utf-8') as f:
                    self._flag_search_cache = json.load(f)
                logger.info(f"已加载当前镜像的Flag搜索缓存: {len(self._flag_search_cache)} 条记录")
            else:
                logger.info("当前镜像的Flag搜索缓存文件不存在")
                self._flag_search_cache = {}
        except Exception as e:
            logger.warning(f"加载Flag搜索缓存失败: {e}")
            self._flag_search_cache = {}

    def _save_flag_search_cache_to_file(self):
        """保存Flag搜索缓存到当前镜像的缓存目录"""
        try:
            cache_dir = self._get_image_cache_dir()
            cache_file = cache_dir / 'flag_search_cache.json'
            cache_dir.mkdir(parents=True, exist_ok=True)
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(self._flag_search_cache, f, ensure_ascii=False, indent=2)
            logger.info(f"Flag搜索缓存已保存到: {cache_file}")
        except Exception as e:
            logger.warning(f"保存Flag搜索缓存失败: {e}")

    def dump_process_memory(self, pid: int, output_dir: str = None) -> Dict[str, Any]:
        """转储进程内存"""
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if not output_dir:
                output_dir = str(Path.cwd() / 'dumps')

            os.makedirs(output_dir, exist_ok=True)

            from backend.volatility_wrapper import VolatilityWrapper
            wrapper = VolatilityWrapper(self.current_image['path'])

            result = wrapper.dump_process(pid, output_dir)

            return {
                'status': 'success',
                'data': result
            }

        except Exception as e:
            logger.error(f"转储进程内存失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def extract_file(self, offset: str, output_dir: str = None) -> Dict[str, Any]:
        """从文件扫描结果中提取文件"""
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if not output_dir:
                output_dir = str(Path.cwd() / 'extracted')

            os.makedirs(output_dir, exist_ok=True)

            from backend.volatility_wrapper import VolatilityWrapper
            wrapper = VolatilityWrapper(self.current_image['path'])

            result = wrapper.extract_file(offset, output_dir)

            return {
                'status': 'success',
                'data': result
            }

        except Exception as e:
            logger.error(f"提取文件失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def extract_pagecache_file(self, file_path: str, output_dir: str = None) -> Dict[str, Any]:
        """从Linux页缓存中提取文件"""
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if not output_dir:
                output_dir = str(Path.cwd() / 'extracted')

            os.makedirs(output_dir, exist_ok=True)

            # 构建保存路径
            file_name = os.path.basename(file_path)
            save_path = os.path.join(output_dir, file_name)

            from backend.volatility_wrapper import VolatilityWrapper
            wrapper = VolatilityWrapper(self.current_image['path'])

            result = wrapper.extract_pagecache_file(file_path, save_path)

            return {
                'status': 'success',
                'data': result
            }

        except Exception as e:
            logger.error(f"提取页缓存文件失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def extract_dll(self, pid: str, base: str, output_dir: str = None) -> Dict[str, Any]:
        """提取单个DLL文件"""
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if not output_dir:
                output_dir = str(Path.cwd() / 'extracted')

            os.makedirs(output_dir, exist_ok=True)

            from backend.volatility_wrapper import VolatilityWrapper
            wrapper = VolatilityWrapper(self.current_image['path'])

            result = wrapper.extract_dll(int(pid), base, output_dir)

            return {
                'status': 'success',
                'data': result
            }

        except Exception as e:
            logger.error(f"提取DLL失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def extract_elf_file(self, pid: str, start: str, file_name: str, output_dir: str = None) -> Dict[str, Any]:
        """提取单个 ELF 文件"""
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if not output_dir:
                output_dir = str(Path.cwd() / 'extracted')

            os.makedirs(output_dir, exist_ok=True)

            from backend.volatility_wrapper import VolatilityWrapper
            wrapper = VolatilityWrapper(self.current_image['path'])

            result = wrapper.extract_elf_file(int(pid), start, file_name, output_dir)

            return {
                'status': 'success',
                'data': result
            }

        except Exception as e:
            logger.error(f"提取 ELF 文件失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def extract_lsof_file(self, file_path: str, plugin_id: str, output_dir: str = None) -> Dict[str, Any]:
        """提取打开文件列表中的单个文件"""
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if not output_dir:
                output_dir = str(Path.cwd() / 'extracted')

            os.makedirs(output_dir, exist_ok=True)

            from backend.volatility_wrapper import VolatilityWrapper
            wrapper = VolatilityWrapper(self.current_image['path'])

            result = wrapper.extract_lsof_file(file_path, plugin_id, output_dir)

            return {
                'status': 'success',
                'data': result
            }

        except Exception as e:
            logger.error(f"提取文件失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def extract_lsof_files(self, plugin_id: str, output_dir: str = None) -> Dict[str, Any]:
        """批量提取打开文件列表中的所有文件"""
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if not output_dir:
                output_dir = str(Path.cwd() / 'extracted')

            os.makedirs(output_dir, exist_ok=True)

            from backend.volatility_wrapper import VolatilityWrapper
            wrapper = VolatilityWrapper(self.current_image['path'])

            result = wrapper.extract_lsof_files(plugin_id, output_dir)

            return {
                'status': 'success',
                'data': result
            }

        except Exception as e:
            logger.error(f"批量提取文件失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def extract_elf_files(self, pid: str = None, output_dir: str = None) -> Dict[str, Any]:
        """
        提取 Linux ELF 文件（可执行文件和库文件）

        Args:
            pid: 可选，指定进程ID
            output_dir: 输出目录
        """
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if not output_dir:
                output_dir = str(Path.cwd() / 'extracted')

            os.makedirs(output_dir, exist_ok=True)

            from backend.volatility_wrapper import VolatilityWrapper
            wrapper = VolatilityWrapper(self.current_image['path'])

            pid_int = int(pid) if pid else None
            result = wrapper.extract_elf_files(pid_int, output_dir)

            return {
                'status': 'success',
                'data': result
            }

        except Exception as e:
            logger.error(f"提取 ELF 文件失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def dump_file(
        self,
        offset: str,
        output_dir: str,
        file_name: str = None
    ) -> Dict[str, Any]:
        """
        从文件扫描结果中提取单个文件（Windows）

        Args:
            offset: 文件对象的物理偏移地址
            output_dir: 输出目录
            file_name: 可选，重命名提取的文件

        Returns:
            提取结果
        """
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            os.makedirs(output_dir, exist_ok=True)

            from backend.volatility_wrapper import VolatilityWrapper
            wrapper = VolatilityWrapper(self.current_image['path'])

            result = wrapper.extract_file(offset, output_dir)

            if result['status'] == 'success':
                # 如果指定了文件名，重命名提取的文件
                if file_name:
                    old_path = os.path.join(output_dir, result['file'])
                    new_path = os.path.join(output_dir, file_name)

                    try:
                        os.rename(old_path, new_path)
                        result['file'] = file_name
                        result['path'] = new_path
                        logger.info(f"文件已重命名为: {file_name}")
                    except Exception as rename_error:
                        logger.warning(f"重命名文件失败: {rename_error}")
                        result['path'] = old_path

                return {
                    'status': 'success',
                    'data': result
                }
            else:
                return {
                    'status': 'error',
                    'message': result.get('error', '文件提取失败')
                }

        except Exception as e:
            logger.error(f"提取文件失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def dump_files(
        self,
        filter_pattern: str = None,
        ignore_case: bool = False,
        pid: str = None,
        output_dir: str = None
    ) -> Dict[str, Any]:
        """
        提取 Linux 页缓存中的文件

        Args:
            filter_pattern: 可选，过滤文件路径的正则表达式
            ignore_case: 是否忽略大小写
            pid: 可选，指定进程ID
            output_dir: 输出目录
        """
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if not output_dir:
                output_dir = str(Path.cwd() / 'dumped_files')

            os.makedirs(output_dir, exist_ok=True)

            from backend.volatility_wrapper import VolatilityWrapper
            wrapper = VolatilityWrapper(self.current_image['path'])

            pid_int = int(pid) if pid else None
            result = wrapper.dump_files(filter_pattern, ignore_case, pid_int, output_dir)

            return {
                'status': 'success',
                'data': result
            }

        except Exception as e:
            logger.error(f"提取文件失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def export_certificates(self, output_dir: str = None) -> Dict[str, Any]:
        """
        导出Windows注册表证书

        使用 windows.registry.certificates.Certificates 插件的 --dump 参数
        导出的证书将保存为 .cer 格式文件

        Args:
            output_dir: 输出目录，默认为当前工作目录下的 certificates 目录

        Returns:
            导出结果
        """
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            if not output_dir:
                output_dir = str(Path.cwd() / 'certificates')

            os.makedirs(output_dir, exist_ok=True)

            from backend.volatility_wrapper import VolatilityWrapper
            wrapper = VolatilityWrapper(self.current_image['path'])

            result = wrapper.dump_certificates(output_dir)

            if result['status'] == 'success':
                return {
                    'status': 'success',
                    'data': {
                        'count': result['count'],
                        'total_size': result['total_size'],
                        'output_dir': result['output_dir'],
                        'files': result['files']
                    },
                    'message': f"成功导出 {result['count']} 个证书到 {output_dir}"
                }
            else:
                return {
                    'status': 'error',
                    'message': result.get('error', '证书导出失败')
                }

        except Exception as e:
            logger.error(f"导出证书失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    # ==================== 报告生成 ====================

    def generate_report(self, format_type: str = 'markdown') -> Dict[str, Any]:
        """生成取证报告"""
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像并执行分析'
                }

            from backend.report_generator import ReportGenerator
            generator = ReportGenerator(self.current_image)

            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            if format_type == 'markdown':
                report_path = generator.generate_markdown(timestamp)
            elif format_type == 'html':
                report_path = generator.generate_html(timestamp)
            elif format_type == 'docx':
                report_path = generator.generate_docx(timestamp)
            else:
                return {
                    'status': 'error',
                    'message': f'不支持的报告格式: {format_type}'
                }

            return {
                'status': 'success',
                'data': {
                    'path': report_path,
                    'format': format_type
                }
            }

        except Exception as e:
            logger.error(f"生成报告失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def generate_report_with_data(self, report_data: Dict[str, Any]) -> Dict[str, Any]:
        """使用提供的插件数据生成取证报告

        Args:
            report_data: 包含以下键的字典
                - image_info: 镜像信息
                - plugins: 插件结果列表
                - format: 报告格式 (markdown, html, docx)
                - generated_at: 生成时间
        """
        try:
            if not report_data or 'plugins' not in report_data:
                return {
                    'status': 'error',
                    'message': '无效的报告数据'
                }

            from backend.report_generator import ReportGenerator

            # 使用提供的镜像信息或当前镜像信息
            image_info = report_data.get('image_info') or self.current_image
            if not image_info:
                return {
                    'status': 'error',
                    'message': '缺少镜像信息'
                }

            generator = ReportGenerator(image_info)

            # 提取插件数据
            plugins_data = report_data.get('plugins', [])
            format_type = report_data.get('format', 'markdown')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

            # 根据格式生成报告
            if format_type == 'markdown':
                report_path = generator.generate_markdown_from_data(plugins_data, timestamp)
            elif format_type == 'html':
                report_path = generator.generate_html_from_data(plugins_data, timestamp)
            elif format_type == 'docx':
                report_path = generator.generate_docx_from_data(plugins_data, timestamp)
            else:
                return {
                    'status': 'error',
                    'message': f'不支持的报告格式: {format_type}'
                }

            return {
                'status': 'success',
                'data': {
                    'path': report_path,
                    'format': format_type,
                    'plugins_count': len(plugins_data)
                }
            }

        except Exception as e:
            logger.error(f"生成报告失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def get_cached_plugins(self) -> Dict[str, Any]:
        """获取当前镜像的缓存插件列表"""
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            cache_dir = self._get_image_cache_dir()
            plugins = []

            # 扫描缓存目录中的所有JSON文件
            for cache_file in cache_dir.glob('*.json'):
                # 跳过项目信息文件
                if cache_file.name == 'project_info.json':
                    continue

                # 处理Flag搜索缓存文件
                if cache_file.name == 'flag_search_cache.json':
                    try:
                        with open(cache_file, 'r', encoding='utf-8') as f:
                            flag_cache = json.load(f)

                        # 遍历所有Flag搜索项
                        for search_key, search_data in flag_cache.items():
                            results = search_data.get('results', [])
                            pattern = search_data.get('pattern')

                            # 确定插件ID和显示名称
                            if pattern is None:
                                plugin_id = 'flag_search_default'
                                display_name = 'Flag搜索（默认）'
                            else:
                                plugin_id = f'flag_search_custom:{pattern}'
                                display_name = f'Flag搜索: {pattern}'

                            plugin_info = {
                                'pluginId': plugin_id,
                                'displayName': display_name,
                                'count': search_data.get('count', len(results)),
                                'results': results,
                                'executionTime': 0,
                                'timestamp': search_data.get('timestamp', ''),
                                'cached': True,
                                'isFlagSearch': True
                            }

                            plugins.append(plugin_info)

                    except Exception as e:
                        logger.warning(f"读取Flag搜索缓存失败 {cache_file}: {e}")
                    continue

                # 处理常规插件缓存文件
                try:
                    with open(cache_file, 'r', encoding='utf-8') as f:
                        cache_data = json.load(f)

                    # 提取插件信息
                    plugin_id = cache_file.stem  # 文件名去掉.json后缀
                    results = cache_data.get('results', [])
                    metadata = cache_data.get('metadata', {})

                    # 获取插件显示名称
                    display_name = self._get_plugin_display_name(plugin_id)

                    plugin_info = {
                        'pluginId': plugin_id,
                        'displayName': display_name,
                        'count': len(results),
                        'results': results,
                        'executionTime': metadata.get('execution_time', 0),
                        'timestamp': metadata.get('timestamp', cache_data.get('timestamp', '')),
                        'cached': True
                    }

                    plugins.append(plugin_info)

                except Exception as e:
                    logger.warning(f"读取缓存文件失败 {cache_file}: {e}")
                    continue

            # 按时间倒序排序
            plugins.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

            return {
                'status': 'success',
                'data': {
                    'plugins': plugins,
                    'count': len(plugins)
                }
            }

        except Exception as e:
            logger.error(f"获取缓存插件列表失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def _get_plugin_display_name(self, plugin_id: str) -> str:
        """获取插件的显示名称"""
        # 特殊处理Flag搜索
        if plugin_id.startswith('flag_search_'):
            if plugin_id == 'flag_search_default':
                return 'Flag搜索（默认）'
            elif plugin_id.startswith('flag_search_custom:'):
                pattern = plugin_id.split(':', 1)[1] if ':' in plugin_id else plugin_id
                return f'Flag搜索: {pattern}'

        # 完整的插件中文名称映射
        plugin_name_map = {
            # Linux 插件
            'linux.bash.Bash': 'Bash命令历史',
            'linux.check_afinfo.CheckAffinity': '进程亲和性检查',
            'linux.check_creds.CheckCreds': '凭据检查',
            'linux.check_idt.CheckIdt': 'IDT检查',
            'linux.check_modules.CheckModules': '内核模块检查',
            'linux.check_syscall.SyscallChecker': '系统调用检查',
            'linux.chk_creds.CheckCreds': '凭据检查',
            'linux.elfs.Elfs': 'ELF文件信息',
            'linux.heap.HEAP': '堆信息',
            'linux.keyboard_notifiers.KeyboardNotifiers': '键盘通知器',
            'linux.kmsg.Kmsg': '内核消息',
            'linux.librarylist.LibraryList': '加载的库列表',
            'linux.lsof.Lsof': '打开的文件',
            'linux.malfind.Malfind': '恶意代码查找',
            'linux-mount.Mount': '挂载点信息',
            'linuxmount.Mount': '挂载点信息',
            'linux.proc.Maps': '进程内存映射',
            'linuxpslist.PsList': '进程列表',
            'linux.pstree.PsTree': '进程树',
            'linux.sockstat.Sockstat': '网络连接统计',
            'linux.strings.Strings': '字符串扫描',
            'linux.banner.Banner': '内核Banner',
            'linux.linux banners.Banners': 'Linux Banner',

            # Linux 网络相关
            'linux.ip.IpFilters': 'IP过滤器',
            'linux.ip.NetFilters': '网络过滤器',
            'linux.ip.Addr': 'IP地址',
            'linux.ip.Filters': 'IP过滤器',
            'linux.ip.Interface': '网络接口',
            'linux.ip.Link': '网络链接',
            'linux.ip.Route': '路由表',
            'linux.ip.Sockets': '网络套接字',
            'linux.netfilter.Netfilter': 'Netfilter网络过滤',
            'linux.netstat.Netstat': '网络状态',
            'linux.arpscan.ArpScan': 'ARP扫描',
            'linux.tty_check.tty_check': 'TTY检查',

            # Linux 进程/内存相关
            'linux.pslist.PsList': '进程列表',
            'linux.psscan.PsScan': '进程扫描',
            'linux.pstree.PsTree': '进程树',
            'linux.proc.Maps': '内存映射',
            'linux.taskstats.TaskStats': '任务统计',
            'linux.environ.Environ': '环境变量',
            'linux.linuxmodels.LinuxModels': 'Linux模型',

            # Linux 文件系统相关
            'linux.lsof.Lsof': '打开的文件',
            'linux.filescan.FileScan': '文件扫描',
            'linux.mft.MFT': '主文件表',
            'linux.link_count.LinkCount': '链接计数',
            'linux.pagecache.Pagecache': '页缓存',
            'linux.pagecache.PageCache': '页缓存',

            # Linux 其他
            'linux.banner.Banner': '内核Banner',
            'linux.kernel_modules.KernelModules': '内核模块',
            'linux.loadables_kernels.KernelLoadables': '可加载内核模块',
            'linux.malfind.Malfind': '恶意代码查找',
            'linux.bigpools.BigPools': '大内存池',
            'linux.pidhashtable.PidHashTable': 'PID哈希表',
            'linux.kallsyms.Kallsyms': '内核符号表',

            # Windows 插件
            'windows.bigpools.BigPools': '大内存池',
            'windows.cmdline.CmdLine': '命令行参数',
            'windows.devicetree.DeviceTree': '设备树',
            'windows.dlllist.DllList': 'DLL列表',
            'windows.driverirp.DriverIrp': '驱动IRP',
            'windows.driverscan.DriverScan': '驱动扫描',
            'windows.filescan.FileScan': '文件扫描',
            'windows.getsids.GetSIDs': '安全ID',
            'windows.handles.Handles': '句柄列表',
            'windows.hashdump.HashDump': '密码哈希',
            'windows.info.Info': '系统信息',
            'windows.malware.malfind.Malfind': '恶意代码查找',
            'windows.mbrscan.MBRScan': 'MBR扫描',
            'windows.memmap.Memmap': '内存映射',
            'windows.modscan.ModScan': '内核模块扫描',
            'windows.modules.Modules': '内核模块',
            'windows.mutantscan.MutantScan': '互斥体扫描',
            'windows.poolscanner.PoolScanner': '池扫描',
            'windows.privileges.Privileges': '进程权限',
            'windows.pslist.PsList': '进程列表',
            'windows.psscan.PsScan': '进程扫描',
            'windows.pstree.PsTree': '进程树',
            'windows.services.Services': '服务列表',
            'windows.svcscan.SvcScan': '服务扫描',
            'windows.vadtree.VadTree': 'VAD树',
            'windows.vadyarascan.VadYaraScan': 'VAD Yara扫描',
            'windows.verinfo.VerInfo': '版本信息',
            'windows.volshell.Volshell': 'Volshell控制台',

            # macOS 插件（使用官方Volatility 3插件ID格式）
            'mac.bash.Bash': 'Bash命令历史',
            'mac.check_sysctl.Check_sysctl': 'Sysctl检查',
            'mac.check_syscall.Check_syscall': '系统调用检查',
            'mac.check_trap_table.Check_trap_table': '陷阱表检查',
            'mac.dmesg.Dmesg': '内核消息',
            'mac.ifconfig.Ifconfig': '网络配置',
            'mac.kauth_listeners.Kauth_listeners': 'Kauth监听器',
            'mac.kauth_scopes.Kauth_scopes': 'Kauth范围',
            'mac.kevents.Kevents': '内核事件',
            'mac.list_files.List_Files': '文件列表',
            'mac.lsof.Lsof': '打开的文件',
            'mac.lsmod.Lsmod': '内核扩展',
            'mac.malfind.Malfind': '恶意代码查找',
            'mac.mount.Mount': '挂载点信息',
            'mac.netstat.Netstat': '网络状态',
            'mac.proc_maps.Maps': '进程内存映射',
            'mac.psaux.Psaux': '进程参数',
            'mac.pslist.PsList': '进程列表',
            'mac.pstree.PsTree': '进程树',
            'mac.socket_filters.Socket_filters': '套接字过滤器',
            'mac.timers.Timers': '定时器',
            'mac.trustedbsd.Trustedbsd': 'TrustedBSD',
            'mac.vfsevents.VFSevents': '文件系统事件',

            # 常见别名（缓存文件名格式）
            'banner': 'Banner信息',
            # Linux 别名
            'linux_pslist': '进程列表',
            'linux_psscan': '进程扫描',
            'linux_pstree': '进程树',
            'linux_bash': 'Bash历史',
            'linux_lsof': '打开文件',
            'linux_envars': '环境变量',
            'linux_environ': '环境变量',
            'linux_mount': '挂载信息',
            'linux_sockstat': '网络连接',
            'linux_ip_addr': 'IP地址',
            'linux_ip_link': '网络链接',
            'linux_ip_route': '路由表',
            'linux_ip_interface': '网络接口',
            'linux_ip_filters': 'IP过滤器',
            'linux_netstat': '网络状态',
            'linux_maps': '内存映射',
            'linux_malfind': '恶意代码查找',
            'linux_pstree': '进程树',
            'linux_pslist': '进程列表',
            'linux_sockstat': '网络连接',
            'linux_kmsg': '内核消息',
            'linux_elfs': 'ELF文件',
            'linux_librarylist': '加载的库',
            'linux_keyboard_notifiers': '键盘通知器',
            'linux_check_modules': '内核模块检查',
            'linux_check_syscall': '系统调用检查',
            'linux_check_creds': '凭据检查',
            'linux_check_afinfo': '进程亲和性',
            'linux_taskstats': '任务统计',
            'linux_pidhashtable': 'PID哈希表',
            'linux_bigpools': '大内存池',
            'linux_kallsyms': '内核符号表',
            # macOS 别名
            'mac_pslist': '进程列表',
            'mac_pstree': '进程树',
            'mac_psaux': '进程参数',
            'mac_netstat': '网络状态',
            'mac_ifconfig': '网络配置',
            'mac_socket_filters': '套接字过滤器',
            'mac_lsof': '打开的文件',
            'mac_list_files': '文件列表',
            'mac_mount': '挂载点信息',
            'mac_bash': 'Bash命令历史',
            'mac_malfind': '恶意代码查找',
            'mac_lsmod': '内核扩展',
            'mac_check_syscall': '系统调用检查',
            'mac_check_sysctl': 'Sysctl检查',
            'mac_check_trap_table': '陷阱表检查',
            'mac_dmesg': '内核消息',
            'mac_kevents': '内核事件',
            'mac_timers': '定时器',
            'mac_kauth_listeners': 'Kauth监听器',
            'mac_kauth_scopes': 'Kauth范围',
            'mac_trustedbsd': 'TrustedBSD',
            'mac_maps': '进程内存映射',
            'mac_vfsevents': '文件系统事件',
        }

        # 先检查完整匹配
        if plugin_id in plugin_name_map:
            return plugin_name_map[plugin_id]

        # 尝试从插件列表中查找
        plugins_dict = self.get_available_plugins()
        for os_type, categories in plugins_dict.items():
            if not isinstance(categories, dict):
                continue
            for category, plugin_list in categories.items():
                if not isinstance(plugin_list, list):
                    continue
                for plugin in plugin_list:
                    if isinstance(plugin, dict) and plugin.get('id') == plugin_id:
                        return plugin.get('name', plugin_id)

        # 尝试部分匹配（处理 linux_bash 这种格式）
        for key, name in plugin_name_map.items():
            if key.endswith(plugin_id) or plugin_id.endswith(key.split('.')[-1]):
                return name

        # 最后尝试格式化
        if '_' in plugin_id:
            parts = plugin_id.replace('linux_', '').replace('windows_', '').replace('mac_', '').split('_')
            formatted = ' '.join([p.capitalize() for p in parts])
            return formatted

        return plugin_id

    # ==================== 辅助方法 ====================

    def _get_symbol_file_name(self) -> str:
        """获取当前镜像的符号表文件名"""
        if not self.current_image:
            return None

        os_type = self.current_image.get('os_type', '').lower()

        try:
            if os_type == 'windows':
                # Windows: 获取PDB符号表文件名
                from volatility3.framework.symbols.windows import pdbutil
                from volatility3.framework import contexts
                from volatility3.framework.layers import physical

                context = contexts.Context()
                file_path = self.current_image['path']

                import urllib.request
                file_url = 'file://' + urllib.request.pathname2url(file_path)
                context.config['FileLayer.location'] = file_url

                layer = physical.FileLayer(context, 'FileLayer', name="FileLayer")
                context.add_layer(layer)

                layer_name = layer.name
                page_size = 0x1000

                pdb_names = [b'ntkrnlmp.pdb', b'ntoskrnl.pdb', b'krnl.pdb', b'ntkrpamp.pdb']

                for result in pdbutil.PDBUtility.pdbname_scan(
                    context, layer_name, page_size, pdb_names
                ):
                    guid = result.get('GUID', '')
                    age = result.get('age', 0)
                    pdb_name = result.get('pdb_name', '')

                    if guid and pdb_name:
                        # 检查符号表文件是否存在
                        symbol_path = self._symbols_dir / 'windows' / pdb_name / f"{guid}-{age}.json.xz"
                        if symbol_path.exists():
                            # 返回格式: ntkrnlmp.pdb (GUID-age)
                            return f"{pdb_name} ({guid}-{age})"
                        else:
                            return None

                return None

            elif 'linux' in os_type or 'mac' in os_type:
                # Linux/macOS: 从banner提取内核版本并查找符号表文件
                banner = self.current_image.get('banner', '')
                if not banner:
                    return None

                kernel_version = self._extract_kernel_version(banner, os_type)
                if not kernel_version:
                    return None

                # 确定符号表目录名（macos -> mac）
                if 'mac' in os_type:
                    symbol_dir_name = 'mac'
                else:
                    symbol_dir_name = os_type

                # 查找符号表目录中匹配的文件
                symbol_dir = self._symbols_dir / symbol_dir_name
                if not symbol_dir.exists():
                    return None

                # 查找包含内核版本的符号表文件
                for symbol_file in symbol_dir.glob('*.json.xz'):
                    if kernel_version in symbol_file.stem:
                        return symbol_file.name

                for symbol_file in symbol_dir.glob('*.json'):
                    if kernel_version in symbol_file.stem:
                        return symbol_file.name

                return None

        except ImportError as e:
            # 打包后无法导入 volatility3 模块，这是正常的
            logger.info(f"打包后无法使用 volatility3 模块获取符号表文件名（功能正常）")
            return None
        except Exception as e:
            logger.warning(f"获取符号表文件名失败: {e}")
            return None

    def _calculate_file_hash(self, file_path: str) -> str:
        """计算文件SHA256哈希（完整计算）"""
        sha256_hash = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()

    def _get_cache_key(self, plugin_id: str, params: Optional[Dict] = None) -> str:
        """生成缓存键（包含插件ID和参数）"""
        if params:
            # 将参数排序并转换为字符串，生成稳定的键
            sorted_params = sorted(params.items())
            params_str = '&'.join(f"{k}={v}" for k, v in sorted_params)
            return f"{plugin_id}?{params_str}"
        return plugin_id

    def _get_image_cache_dir(self) -> Path:
        """获取当前镜像的缓存目录"""
        if not self.current_image:
            return self._cache_dir
        image_cache_dir = self._cache_dir / self.current_image['hash']
        image_cache_dir.mkdir(parents=True, exist_ok=True)
        return image_cache_dir

    def _load_from_cache(self, cache_key: str) -> Optional[Dict]:
        """从缓存加载数据"""
        cache_dir = self._get_image_cache_dir()
        cache_file = cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                pass
        return None

    def _save_to_cache(self, cache_key: str, data: Dict):
        """保存数据到缓存"""
        cache_dir = self._get_image_cache_dir()
        cache_file = cache_dir / f"{cache_key}.json"
        try:
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.warning(f"缓存保存失败: {str(e)}")

    def _load_from_cache_file(self, cache_key: str) -> Optional[Dict]:
        """从缓存文件加载数据"""
        cache_dir = self._get_image_cache_dir()
        cache_file = cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            try:
                with open(cache_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"缓存读取失败: {str(e)}")
        return None

    def _save_to_cache_file(self, cache_key: str, data: Dict):
        """保存数据到缓存文件"""
        cache_dir = self._get_image_cache_dir()
        cache_file = cache_dir / f"{cache_key}.json"
        try:
            cache_dir.mkdir(parents=True, exist_ok=True)
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            logger.info(f"结果已缓存到: {cache_file}")
        except Exception as e:
            logger.warning(f"缓存保存失败: {str(e)}")

    def _format_size(self, size_bytes: int) -> str:
        """格式化文件大小"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024.0
        return f"{size_bytes:.2f} PB"

    def _get_services_from_registry(self) -> Optional[Dict]:
        """从注册表获取服务列表（当 svcscan 失败时的后备方案）"""
        try:
            from backend.volatility_wrapper import VolatilityWrapper

            wrapper = VolatilityWrapper(self.current_image['path'])

            # 1. 获取 SYSTEM 注册表偏移
            hivelist_result = wrapper.run_plugin('hivelist')
            system_offset = None
            for hive in hivelist_result.get('results', []):
                if 'SYSTEM' in hive.get('path', ''):
                    system_offset = hive['offset']
                    break

            if not system_offset:
                logger.error("未找到 SYSTEM 注册表")
                return None

            logger.info(f"找到 SYSTEM 注册表偏移: {system_offset}")

            # 2. 获取所有服务键（使用原始文本输出）
            services_result = wrapper._run_volatility_raw(
                'windows.registry.printkey.PrintKey',
                ['--offset', system_offset, '--key', 'ControlSet001\\services']
            )

            if not services_result:
                logger.error("无法读取服务列表")
                return None

            # 解析服务列表
            services = []
            for line in services_result.strip().split('\n'):
                if not line.strip() or line.startswith('Volatility') or line.startswith('Last Write') or line.startswith('-') or 'Hive Offset' in line:
                    continue

                parts = line.split('\t')
                # 格式: 时间 | 偏移 | Type | Key | 服务名 | Data | Volatile
                # Type 在 parts[2]，服务名在 parts[4]
                if len(parts) >= 5 and parts[2] == 'Key':
                    service_name = parts[4]
                    services.append(service_name)

            logger.info(f"找到 {len(services)} 个服务")

            # 3. 为每个服务获取详细信息（限制数量以提高速度）
            service_details = []
            start_type_map = {
                '0': 'Boot',
                '1': 'System',
                '2': 'Auto',
                '3': 'Manual',
                '4': 'Disabled'
            }

            # 限制只读取前 50 个服务的详细信息以提高速度
            for i, service in enumerate(services[:50]):
                try:
                    detail_result = wrapper._run_volatility_raw(
                        'windows.registry.printkey.PrintKey',
                        ['--offset', system_offset, '--key', f'ControlSet001\\services\\{service}']
                    )

                    service_info = {
                        'order': i + 1,
                        'name': service,
                        'pid': 0,
                        'start': 'Unknown',
                        'state': 'Unknown',
                        'type': 'Unknown',
                        'display': service,
                        'binary': 'Unknown'
                    }

                    # 解析详细信息
                    for line in detail_result.strip().split('\n'):
                        if not line.strip() or line.startswith('Volatility') or line.startswith('Last Write') or line.startswith('-') or 'Hive Offset' in line:
                            continue

                        parts = line.split('\t')
                        # 格式: 时间 | 偏移 | Type | Key | Name | Data | Volatile
                        # Type 在 parts[2]，Name 在 parts[4]，Data 在 parts[5]
                        if len(parts) >= 6 and parts[2] != 'Key':
                            key_name = parts[4]
                            data = parts[5]

                            if key_name == 'Start':
                                service_info['start'] = start_type_map.get(data, data)
                            elif key_name == 'DisplayName':
                                service_info['display'] = data
                            elif key_name == 'ImagePath':
                                service_info['binary'] = data
                            elif key_name == 'Type':
                                service_info['type'] = data
                            elif key_name == 'ObjectName':
                                # 可能包含进程 ID
                                try:
                                    service_info['pid'] = int(data)
                                except:
                                    pass

                    service_details.append(service_info)

                except Exception as e:
                    logger.warning(f"读取服务 {service} 失败: {str(e)}")
                    continue

            # 剩余的服务只添加名称
            for i, service in enumerate(services[50:], start=51):
                service_details.append({
                    'order': i,
                    'name': service,
                    'pid': 0,
                    'start': 'Unknown',
                    'state': 'Unknown',
                    'type': 'Unknown',
                    'display': service,
                    'binary': 'Unknown'
                })

            return {
                'plugin': 'svcscan',
                'timestamp': datetime.now().isoformat(),
                'image': self.current_image['name'],
                'results': service_details
            }

        except Exception as e:
            logger.error(f"从注册表获取服务失败: {str(e)}")
            return None

    def clear_cache(self) -> Dict[str, Any]:
        """清除缓存

        - 如果有加载的镜像：清除当前镜像的缓存
        - 如果没有加载镜像：清除所有缓存
        """
        try:
            import shutil
            cache_dir = self._get_image_cache_dir()

            if self.current_image:
                # 有加载的镜像，只清除当前镜像的缓存
                if cache_dir.exists() and cache_dir != self._cache_dir:
                    shutil.rmtree(cache_dir)
                    logger.info(f"当前镜像缓存已清除: {cache_dir}")
                    message = f'当前镜像缓存已清除'
                else:
                    message = '当前镜像没有缓存'
            else:
                # 没有加载镜像，清除所有缓存
                if self._cache_dir.exists():
                    # 先统计项目数量
                    project_dirs = [d for d in self._cache_dir.iterdir() if d.is_dir()]
                    count = len(project_dirs)

                    if count > 0:
                        # 删除所有项目缓存目录
                        for project_dir in project_dirs:
                            shutil.rmtree(project_dir)
                            logger.info(f"清除项目缓存: {project_dir.name}")
                        message = f'所有缓存已清除（共清除 {count} 个项目）'
                    else:
                        message = '没有缓存需要清除'
                else:
                    message = '没有缓存需要清除'

            return {
                'status': 'success',
                'message': message
            }
        except Exception as e:
            logger.error(f"清除缓存失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def get_project_list(self) -> Dict[str, Any]:
        """获取项目列表（历史加载的镜像）"""
        try:
            projects = []
            if not self._cache_dir.exists():
                return {'status': 'success', 'data': []}

            for project_dir in self._cache_dir.iterdir():
                if project_dir.is_dir():
                    # 读取项目信息
                    info_file = project_dir / 'project_info.json'
                    if info_file.exists():
                        try:
                            with open(info_file, 'r', encoding='utf-8') as f:
                                info = json.load(f)
                        except:
                            info = {}
                    else:
                        info = {}

                    # 统计分析结果数量
                    analysis_count = len(list(project_dir.glob('*.json')))
                    if info_file.exists():
                        analysis_count -= 1

                    # 获取最后修改时间
                    last_modified = datetime.fromtimestamp(project_dir.stat().st_mtime)

                    projects.append({
                        'hash': project_dir.name,
                        'name': info.get('name', '未知'),
                        'path': info.get('path', ''),
                        'size': info.get('size', ''),
                        'last_modified': last_modified.strftime('%Y-%m-%d %H:%M:%S'),
                        'analysis_count': analysis_count,
                        'is_current': self.current_image and self.current_image.get('hash', '')[:16] == project_dir.name
                    })

            # 按最后修改时间排序
            projects.sort(key=lambda x: x['last_modified'], reverse=True)

            return {
                'status': 'success',
                'data': projects
            }
        except Exception as e:
            logger.error(f"获取项目列表失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def load_project(self, project_hash: str) -> Dict[str, Any]:
        """加载历史项目"""
        try:
            project_dir = self._cache_dir / project_hash
            if not project_dir.exists():
                return {
                    'status': 'error',
                    'message': '项目不存在'
                }

            info_file = project_dir / 'project_info.json'
            if not info_file.exists():
                return {
                    'status': 'error',
                    'message': '项目信息丢失'
                }

            with open(info_file, 'r', encoding='utf-8') as f:
                info = json.load(f)

            # 重新加载镜像
            if not Path(info['path']).exists():
                return {
                    'status': 'error',
                    'message': '镜像文件不存在，可能已被移动或删除'
                }

            load_result = self.load_image(info['path'])
            if load_result['status'] == 'success':
                return {
                    'status': 'success',
                    'message': f'已加载项目: {info.get("name", "未知")}',
                    'data': load_result.get('data', {})
                }
            else:
                return load_result

        except Exception as e:
            logger.error(f"加载项目失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def delete_project(self, project_hash: str) -> Dict[str, Any]:
        """删除项目及其缓存"""
        try:
            project_dir = self._cache_dir / project_hash
            if not project_dir.exists():
                return {
                    'status': 'error',
                    'message': '项目不存在'
                }

            # 删除整个项目目录
            import shutil
            shutil.rmtree(project_dir)

            return {
                'status': 'success',
                'message': '项目已删除'
            }
        except Exception as e:
            logger.error(f"删除项目失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def export_results(self, data: List[Dict], format_type: str = 'csv') -> Dict[str, Any]:
        """导出分析结果"""
        try:
            from datetime import datetime
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            export_dir = self._user_data_dir / 'exports'
            export_dir.mkdir(exist_ok=True)

            if format_type == 'csv':
                import csv
                file_path = export_dir / f"results_{timestamp}.csv"
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    if data:
                        writer = csv.DictWriter(f, fieldnames=data[0].keys())
                        writer.writeheader()
                        writer.writerows(data)
            elif format_type == 'json':
                file_path = export_dir / f"results_{timestamp}.json"
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(data, f, ensure_ascii=False, indent=2)
            else:
                return {
                    'status': 'error',
                    'message': f'不支持的导出格式: {format_type}'
                }

            return {
                'status': 'success',
                'data': {
                    'path': str(file_path),
                    'count': len(data)
                }
            }

        except Exception as e:
            logger.error(f"导出失败: {str(e)}")
            return {
                'status': 'error',
                'message': str(e)
            }

    def download_windows_symbols(self) -> Dict[str, Any]:
        """从微软官方符号服务器自动下载Windows符号表

        优先策略：
        1. 首先尝试运行 Volatility 不带 -s 参数，让官方自动下载符号表
        2. 如果失败，再使用自定义 PDB 扫描和下载逻辑作为备用
        """
        import os
        try:
            if not self.current_image:
                return {
                    'status': 'error',
                    'message': '请先加载内存镜像'
                }

            # 检查是否是Windows镜像
            os_type = self.current_image.get('os_type', '').lower()
            if os_type != 'windows':
                return {
                    'status': 'error',
                    'message': f'当前镜像不是Windows系统 (检测到: {os_type})'
                }

            logger.info("开始下载Windows符号表...")
            logger.info("使用独立脚本下载符号表...")
            self._show_loading('正在下载Windows符号表...', '正在从微软官方符号服务器下载...\n\n这可能需要几分钟，请耐心等待。')

            # 生成临时下载脚本（不依赖打包时的目录结构）
            import subprocess
            import sys
            import platform
            import tempfile
            import os

            script_content = '''#!/usr/bin/env python3
"""
Windows 符号表下载脚本
"""
import sys
import os
from pathlib import Path

try:
    from volatility3.framework.symbols.windows import pdbutil
    from volatility3.framework import contexts
    from volatility3.framework.layers import physical
    import urllib.request
    import urllib.parse
    import tempfile
    import lzma
    import json
    import uuid
except ImportError as e:
    print(f"错误: 缺少依赖 {e}")
    print("请安装: pip install volatility3")
    sys.exit(1)

def download_symbols(image_path, symbols_dir):
    """下载 Windows 符号表"""
    if not os.path.exists(image_path):
        print(f"错误: 镜像文件不存在: {image_path}")
        return False

    symbols_dir = Path(symbols_dir)
    symbols_dir.mkdir(parents=True, exist_ok=True)

    print(f"正在扫描镜像: {image_path}")

    try:
        # 构建context并加载镜像
        context = contexts.Context()
        file_url = 'file://' + urllib.request.pathname2url(image_path)
        context.config['FileLayer.location'] = file_url

        # 加载物理层
        layer = physical.FileLayer(context, 'FileLayer', name="FileLayer")
        context.add_layer(layer)

        layer_name = layer.name
        page_size = 0x1000

        # 扫描常见的Windows内核PDB名称
        pdb_names = [b'ntkrnlmp.pdb', b'ntoskrnl.pdb', b'krnl.pdb', b'ntkrpamp.pdb']

        print("正在扫描 PDB 签名...")

        # 使用pdbname_scan扫描PDB签名
        pdb_results = list(pdbutil.PDBUtility.pdbname_scan(
            context, layer_name, page_size, pdb_names
        ))

        if not pdb_results:
            print("错误: 未在内存镜像中找到 PDB 信息")
            return False

        # 使用第一个找到的内核PDB
        result = pdb_results[0]
        guid = result.get('GUID', '')
        age = result.get('age', 0)
        pdb_name = result.get('pdb_name', 'ntkrnlmp.pdb')

        print(f"找到 PDB 信息: {pdb_name}")
        print(f"  GUID: {guid}")
        print(f"  Age: {age}")

        # 检查符号表是否已存在
        symbol_path = symbols_dir / 'windows' / pdb_name / f"{guid}-{age}.json.xz"
        if symbol_path.exists():
            print(f"符号表已存在: {symbol_path}")
            return True

        # 创建临时目录
        temp_dir = Path(tempfile.gettempdir())
        temp_pdb_path = temp_dir / f"temp_pdb_{os.getpid()}_{uuid.uuid4().hex[:8]}.pdb"

        try:
            # 下载 PDB 文件（支持代理和进度显示）
            pdb_url = f"https://msdl.microsoft.com/download/symbols/{pdb_name}/{guid}{age:01X}/{pdb_name}"
            print(f"正在下载 PDB 文件...")
            print(f"  URL: {pdb_url}")

            # 使用 urllib 下载（最快）
            import urllib.request as req2

            # 检测系统代理
            proxies = None
            try:
                http_proxy = os.environ.get('http_proxy') or os.environ.get('HTTP_PROXY')
                https_proxy = os.environ.get('https_proxy') or os.environ.get('HTTPS_PROXY')
                if http_proxy or https_proxy:
                    # 创建代理处理器
                    proxy_handler = req2.ProxyHandler({
                        'http': http_proxy or '',
                        'https': https_proxy or ''
                    })
                    opener = req2.build_opener(proxy_handler)
                    req2.install_opener(opener)
                    print(f"检测到代理配置")
            except:
                pass

            # 进度回调函数（避免重复打印）
            last_shown = [0]  # 用列表跟踪上次显示的百分比
            def show_progress(block_num, block_size, total_size):
                downloaded = block_num * block_size
                if total_size > 0:
                    percent = min(int(downloaded * 100 / total_size), 100)
                    # 每下载 25% 显示一次进度，避免重复
                    if percent % 25 == 0 and percent > 0 and percent != last_shown[0]:
                        filled = percent // 5
                        bar = '=' * filled + ' ' * (20 - filled)
                        print(f"  下载进度: [{bar}] {percent}%")
                        last_shown[0] = percent

            req2.urlretrieve(pdb_url, str(temp_pdb_path), reporthook=show_progress)
            pdb_size = temp_pdb_path.stat().st_size

            # 转换 PDB 为 ISF 格式
            temp_pdb_url = temp_pdb_path.as_uri()

            # 创建context并加载PDB文件
            pdb_context = contexts.Context()
            pdb_context.config['pdbreader.FileLayer.location'] = temp_pdb_url

            pdb_layer = physical.FileLayer(pdb_context, 'pdbreader.FileLayer', 'FileLayer')
            pdb_context.add_layer(pdb_layer)

            # 使用PdbReader转换
            msf_layer_name, new_context = pdbutil.pdbconv.PdbReader.load_pdb_layer(pdb_context, temp_pdb_url)
            reader = pdbutil.pdbconv.PdbReader(new_context, temp_pdb_url, pdb_name)
            json_output = reader.get_json()

            # 将字典转换为 JSON 字符串
            json_str = json.dumps(json_output, indent=2, sort_keys=True)
            print(f"符号表转换成功，JSON 大小: {len(json_str)} bytes")

            # 确保目录存在
            os.makedirs(os.path.dirname(symbol_path), exist_ok=True)

            # 保存为JSON.xz文件
            with lzma.open(symbol_path, 'w') as f:
                f.write(bytes(json_str, 'utf-8'))

            print(f"符号表已保存: {symbol_path}")
            print(f"符号表大小: {symbol_path.stat().st_size} bytes")
            return True

        finally:
            # 清理临时文件
            try:
                if temp_pdb_path.exists():
                    temp_pdb_path.unlink()
            except:
                pass

    except Exception as e:
        print(f"错误: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("用法: script.py <镜像文件> <符号表目录>")
        sys.exit(1)

    image_path = sys.argv[1]
    symbols_dir = sys.argv[2]

    success = download_symbols(image_path, symbols_dir)
    sys.exit(0 if success else 1)
'''

            # 创建固定位置的脚本文件
            scripts_dir = self._user_data_dir / 'scripts'
            scripts_dir.mkdir(parents=True, exist_ok=True)
            script_path = scripts_dir / 'download_symbols.py'

            try:
                # 写入脚本内容（明确使用 UTF-8 编码）
                script_path.write_text(script_content, encoding='utf-8')

                # 构建命令
                if platform.system() == 'Windows':
                    python_cmd = 'python'
                else:
                    python_cmd = 'python3'

                cmd = [python_cmd, str(script_path), self.current_image['path'], str(self._symbols_dir)]

                # 传递用户配置的代理给子进程
                import os as os_module
                env = os_module.environ.copy()

                # 如果用户配置了代理，设置到环境变量
                proxy_url = self._build_proxy_url()
                if proxy_url:
                    # 将代理 URL 转换为 urllib 格式
                    env['http_proxy'] = proxy_url
                    env['https_proxy'] = proxy_url
                    logger.info(f"下载脚本使用代理: {proxy_url.split('@')[0] if '@' in proxy_url else proxy_url}")

                logger.info(f"执行下载命令: {' '.join(cmd)}")

                # 执行下载脚本（Windows 上隐藏 CMD 窗口）
                subprocess_kwargs = self._get_subprocess_kwargs(
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=300  # 5分钟超时
                )
                result = subprocess.run(cmd, **subprocess_kwargs)

                # 检查执行结果
                if result.returncode == 0:
                    self._hide_loading()
                    output = result.stdout + result.stderr
                    logger.info(f"符号表下载成功:\n{output}")

                    # 解析 PDB 信息并保存
                    pdb_info = None
                    try:
                        import re
                        pdb_match = re.search(r'找到 PDB 信息:\s*(\S+)', output)
                        guid_match = re.search(r'GUID:\s*([0-9A-Fa-f]+)', output)
                        age_match = re.search(r'Age:\s*(\d+)', output)

                        if pdb_match and guid_match and age_match:
                            pdb_name = pdb_match.group(1)
                            guid = guid_match.group(1)
                            age = int(age_match.group(1))

                            # 保存 PDB 信息到文件
                            pdb_info_path = self._symbols_dir / 'windows' / 'pdb_info.json'
                            pdb_info_path.parent.mkdir(parents=True, exist_ok=True)

                            import json
                            pdb_info = {
                                'name': pdb_name,
                                'guid': guid,
                                'age': age,
                                'image_path': self.current_image['path']
                            }
                            pdb_info_path.write_text(json.dumps(pdb_info, indent=2), encoding='utf-8')
                            logger.info(f"已保存 PDB 信息到: {pdb_info_path}")
                    except Exception as e:
                        logger.warning(f"解析或保存 PDB 信息失败: {e}")

                    return {
                        'status': 'success',
                        'message': 'Windows符号表下载成功！',
                        'pdb_info': pdb_info
                    }
                else:
                    self._hide_loading()
                    error_output = result.stderr or result.stdout
                    logger.error(f"符号表下载失败:\n{error_output}")

                    # 检查是否是缺少 volatility3
                    if 'No module named' in error_output or '缺少依赖' in error_output:
                        return {
                            'status': 'error',
                            'message': f'缺少 Volatility 3 依赖\n\n'
                                      f'请安装: pip install volatility3'
                        }
                    else:
                        return {
                            'status': 'error',
                            'message': f'下载失败:\n\n{error_output}'
                        }

            except subprocess.TimeoutExpired:
                self._hide_loading()
                return {
                    'status': 'error',
                    'message': '下载超时（超过5分钟）\n\n请检查网络连接或手动下载'
                }
            except Exception as e:
                self._hide_loading()
                logger.error(f"执行下载脚本失败: {e}", exc_info=True)
                return {
                    'status': 'error',
                    'message': f'执行下载脚本失败: {str(e)}'
                }
            finally:
                # 脚本保留在固定位置，方便调试
                pass

        except Exception as e:
            self._hide_loading()
            logger.error(f"下载Windows符号表失败: {str(e)}", exc_info=True)
            return {
                'status': 'error',
                'message': f'下载Windows符号表失败: {str(e)}'
            }

    # ==================== Volatility 3 检测和安装 ====================

    def check_volatility3(self) -> Dict[str, Any]:
        """检测 Volatility 3 是否已安装（跨平台）"""
        try:
            import subprocess
            import shutil
            import platform
            import sys

            system = platform.system()
            logger.info(f"检测 Volatility 3，平台: {system}")

            # 清除可能的模块缓存，确保检测最新状态
            if 'volatility3' in sys.modules:
                del sys.modules['volatility3']
            # 同时清除可能的子模块缓存
            modules_to_remove = [k for k in sys.modules.keys() if k.startswith('volatility3.')]
            for module in modules_to_remove:
                del sys.modules[module]

            # 检测是否在打包环境中运行
            is_frozen = getattr(sys, 'frozen', False)
            is_packaged = is_frozen or '.app' in sys.executable or '.exe' in sys.executable

            # 检查是否能导入 volatility3 模块
            can_import = False
            try:
                import volatility3
                can_import = True
                logger.info("Volatility 3 模块可导入")
            except ImportError as e:
                logger.info(f"Volatility 3 模块不可导入: {e}")

            # 检查 vol 命令是否可用（根据平台）
            # 打包环境下，系统的 vol 命令不可用，必须检查模块导入
            if is_packaged:
                logger.info(f"打包环境检测: can_import={can_import}")
                vol_works = False
                vol_path = None
            else:
                vol_path = None
                vol_works = False

            if system == 'Windows':
                # Windows: 检查 vol.exe
                possible_commands = ['vol', 'vol.exe']
                for cmd in possible_commands:
                    path = shutil.which(cmd)
                    if path:
                        vol_path = path
                        break

                # 检查用户级安装路径
                if not vol_path:
                    home_paths = [
                        Path.home() / 'AppData' / 'Local' / 'Programs' / 'Python' / 'Scripts' / 'vol.exe',
                        Path.home() / 'AppData' / 'Roaming' / 'Python' / 'Scripts' / 'vol.exe',
                    ]
                    for path in home_paths:
                        if path.exists():
                            vol_path = str(path)
                            break

            elif system == 'Darwin':  # macOS
                # macOS: 检查 vol
                vol_path = shutil.which('vol')

                # 检查用户级安装路径
                if not vol_path:
                    home_paths = [
                        Path.home() / 'Library' / 'Python' / '3.9' / 'bin' / 'vol',
                        Path.home() / 'Library' / 'Python' / '3.10' / 'bin' / 'vol',
                        Path.home() / 'Library' / 'Python' / '3.11' / 'bin' / 'vol',
                        Path.home() / 'Library' / 'Python' / '3.12' / 'bin' / 'vol',
                        Path.home() / '.local' / 'bin' / 'vol',
                    ]
                    for path in home_paths:
                        if path.exists():
                            vol_path = str(path)
                            break

            else:  # Linux
                # Linux: 检查 vol
                vol_path = shutil.which('vol')

                # 检查用户级和系统级路径
                if not vol_path:
                    possible_paths = [
                        Path.home() / '.local' / 'bin' / 'vol',
                        Path('/usr/local/bin/vol'),
                        Path('/usr/bin/vol'),
                    ]
                    for path in possible_paths:
                        if path.exists() and os.access(path, os.X_OK):
                            vol_path = str(path)
                            break

            # 验证 vol 命令是否真的可用
            if vol_path:
                try:
                    result = subprocess.run(
                        [vol_path, '--help'],
                        capture_output=True,
                        timeout=5
                    )
                    # 检查输出是否包含 Volatility 3 标识
                    output = result.stdout.decode('utf-8', errors='ignore') + result.stderr.decode('utf-8', errors='ignore')
                    vol_works = result.returncode == 0 or 'Volatility 3' in output or 'volatility' in output.lower()
                    if vol_works:
                        logger.info(f"Vol 命令可用: {vol_path}")
                    else:
                        logger.warning(f"Vol 命令存在但不可用: {vol_path}")
                except Exception as e:
                    logger.warning(f"验证 vol 命令失败: {e}")
                    vol_works = False

            installed = vol_works or can_import

            # 获取版本号
            version = None
            if can_import:
                try:
                    import volatility3
                    version = getattr(volatility3, '__version__', None)
                except Exception:
                    pass

            return {
                'status': 'success',
                'data': {
                    'installed': installed,
                    'platform': system,
                    'vol_command': bool(vol_path),
                    'can_import': can_import,
                    'vol_works': vol_works,
                    'vol_path': vol_path,
                    'version': version,
                    'install_command': self._get_install_command(system)
                }
            }
        except Exception as e:
            logger.error(f"检测 Volatility 3 失败: {e}", exc_info=True)
            return {
                'status': 'error',
                'message': f'检测失败: {str(e)}'
            }

    def _get_install_command(self, platform: str) -> str:
        """获取平台特定的安装命令"""
        # 使用清华镜像加速（国内用户）
        mirror = ' -i https://pypi.tuna.tsinghua.edu.cn/simple'

        if platform == 'Windows':
            return f'pip install{mirror} volatility3'
        elif platform == 'Darwin':
            return f'pip3 install{mirror} volatility3'
        else:  # Linux
            return f'pip3 install{mirror} volatility3 --user'

    def install_volatility3(self) -> Dict[str, Any]:
        """安装 Volatility 3（使用 pip，跨平台）"""
        try:
            import subprocess
            import sys
            import platform

            system = platform.system()
            logger.info(f"安装 Volatility 3，平台: {system}")

            # 先检测是否在打包环境中运行（必须在 Python 检测之前）
            is_frozen = getattr(sys, 'frozen', False)
            is_packaged = is_frozen or '.app' in sys.executable or '.exe' in sys.executable
            logger.info(f"检测到打包环境: {is_packaged}, is_frozen={is_frozen}, executable={sys.executable}")

            # 选择 Python：打包环境用系统 Python，否则用当前 Python
            if is_packaged and system == 'Darwin':
                python_cmd = 'python3'  # macOS 打包环境使用系统 python3
            elif is_packaged and system == 'Windows':
                python_cmd = 'python'  # Windows 打包环境使用系统 python
            elif is_packaged and system == 'Linux':
                python_cmd = 'python3'  # Linux 打包环境使用系统 python3
            else:
                python_cmd = sys.executable  # 开发环境使用当前 Python

            logger.info(f"使用 Python 命令: {python_cmd}")

            # 检查 Python 是否可用
            python_available = False
            try:
                logger.info(f"检测 Python 可用性: {python_cmd} --version")
                subprocess_kwargs = self._get_subprocess_kwargs(
                    capture_output=True,
                    timeout=10
                )
                result = subprocess.run([python_cmd, '--version'], **subprocess_kwargs)
                python_available = result.returncode == 0
                logger.info(f"Python 可用性检测: {'成功' if python_available else '失败'}, stdout={result.stdout.decode('utf-8', errors='ignore').strip()}")
            except Exception as e:
                logger.error(f"Python 可用性检测异常: {e}")

            if not python_available:
                logger.error(f"Python 不可用: {python_cmd}")
                return {
                    'status': 'error',
                    'message': self._get_manual_install_message(system)
                }

            # 显示加载提示
            self._show_loading('正在安装 Volatility 3，请稍候...')

            try:
                # 继续使用之前选择的 python_cmd

                # 构建安装命令（使用清华镜像加速）
                if system == 'Windows':
                    cmd = [python_cmd, '-m', 'pip', 'install', '-i', 'https://pypi.tuna.tsinghua.edu.cn/simple', 'volatility3']
                else:
                    # macOS/Linux 使用 pip3
                    cmd = [python_cmd, '-m', 'pip', 'install', '-i', 'https://pypi.tuna.tsinghua.edu.cn/simple', 'volatility3']
                    if system == 'Linux':
                        cmd.append('--user')  # Linux 默认用户级安装
                    elif is_packaged and system == 'Darwin':
                        cmd.append('--user')  # macOS 打包环境也使用 --user

                logger.info(f"执行安装命令: {' '.join(cmd)}")
                logger.info(f"打包环境: {is_packaged}, 使用 Python: {python_cmd}")

                # 准备环境变量：清除可能干扰的 Python 环境变量
                import os
                clean_env = os.environ.copy()
                # 移除可能导致路径问题的环境变量
                clean_env.pop('PYTHONPATH', None)
                clean_env.pop('PYTHONHOME', None)
                # 移除 PYTHONIOENCODING 以避免编码问题
                clean_env.pop('PYTHONIOENCODING', None)

                # 设置工作目录为用户主目录（避免从 AppTranslocation 运行时的路径问题）
                cwd = str(Path.home())

                subprocess_kwargs = self._get_subprocess_kwargs(
                    capture_output=True,
                    text=True,
                    timeout=300,  # 5 分钟超时
                    env=clean_env,
                    cwd=cwd
                )
                result = subprocess.run(cmd, **subprocess_kwargs)

                if result.returncode == 0:
                    self._hide_loading()
                    logger.info("Volatility 3 安装成功")

                    # 获取安装的版本号（使用相同的 Python 命令）
                    version = None
                    try:
                        # 尝试读取版本（使用安装时相同的 Python）
                        subprocess_kwargs2 = self._get_subprocess_kwargs(
                            capture_output=True,
                            text=True,
                            timeout=5,
                            env=clean_env,
                            cwd=cwd
                        )
                        result2 = subprocess.run([python_cmd, '-c', 'import volatility3; print(volatility3.__version__)'], **subprocess_kwargs2)
                        if result2.returncode == 0:
                            version = result2.stdout.strip()
                            logger.info(f"Volatility3 版本: {version}")
                    except Exception as e:
                        logger.warning(f"无法获取 volatility3 版本: {e}")

                    # 检查是否需要更新 PATH
                    version_info = f' (版本 {version})' if version else ''
                    if system in ['Darwin', 'Linux']:
                        message = f'Volatility 3 安装成功{version_info}！\n\n使用清华镜像加速下载。\n\n如果 vol 命令不可用，请将以下路径添加到 PATH:\n~/Library/Python/3.9/bin (macOS)\n~/.local/bin (Linux)'
                    else:
                        message = f'Volatility 3 安装成功{version_info}！\n\n使用清华镜像加速下载。\n\n现在可以使用内存分析功能了。'

                    return {
                        'status': 'success',
                        'message': message,
                        'version': version
                    }
                else:
                    self._hide_loading()
                    error_msg = result.stderr or result.stdout or '未知错误'
                    logger.error(f"Volatility 3 安装失败: {error_msg}")

                    # 提供手动安装方案
                    return {
                        'status': 'error',
                        'message': f'自动安装失败：\n{error_msg}\n\n{self._get_manual_install_message(system)}'
                    }
            except subprocess.TimeoutExpired:
                self._hide_loading()
                return {
                    'status': 'error',
                    'message': f'安装超时，请检查网络连接。\n\n{self._get_manual_install_message(system)}'
                }
            except FileNotFoundError:
                self._hide_loading()
                return {
                    'status': 'error',
                    'message': f'未找到 pip 命令。\n\n{self._get_manual_install_message(system)}'
                }
            except Exception as e:
                self._hide_loading()
                logger.error(f"安装 Volatility 3 异常: {e}", exc_info=True)
                return {
                    'status': 'error',
                    'message': f'安装异常：{str(e)}\n\n{self._get_manual_install_message(system)}'
                }
        except Exception as e:
            self._hide_loading()
            logger.error(f"安装 Volatility 3 失败: {e}")
            return {
                'status': 'error',
                'message': f'安装失败: {str(e)}'
            }


    def _get_manual_install_message(self, platform: str) -> str:
        """获取手动安装指引"""
        if platform == 'Windows':
            return """手动安装步骤：

1. 打开命令提示符（CMD）或 PowerShell
2. 运行命令（使用清华镜像加速）：
   pip install -i https://pypi.tuna.tsinghua.edu.cn/simple volatility3
   或使用官方源：
   pip install volatility3
3. 如果提示 pip 不存在，请先安装 Python：
   https://www.python.org/downloads/
4. 安装时勾选 "Add Python to PATH" """
        elif platform == 'Darwin':  # macOS
            return """手动安装步骤：

1. 打开终端（Terminal）
2. 运行命令（使用清华镜像加速）：
   pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple volatility3
   或使用官方源：
   pip3 install volatility3
3. 如果提示 pip3 不存在，请先安装 Python：
   brew install python3
   或访问 https://www.python.org/downloads/
4. 安装后可能需要添加到 PATH：
   export PATH=$PATH:~/Library/Python/3.9/bin """
        else:  # Linux
            return """手动安装步骤：

1. 打开终端
2. 运行命令（使用清华镜像加速）：
   pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple volatility3 --user
   或使用官方源：
   pip3 install volatility3 --user
3. 如果提示 pip3 不存在，请先安装：
   Ubuntu/Debian: sudo apt install python3-pip
   CentOS/RHEL: sudo yum install python3-pip
   Arch: sudo pacman -S python-pip
4. 添加到 PATH（如果需要）：
   export PATH=$PATH:~/.local/bin """
