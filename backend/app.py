"""
析镜 LensAnalysis - Main Application
基于Volatility 3的图形化内存取证工具
"""

import sys
import os
import logging
from pathlib import Path
from threading import Thread
import json
import platform

# ===== 重要：在导入 webview 之前设置 backend =====
# Nuitka/PyInstaller 需要明确指定 PyWebView backend
# Qt backend 跨平台兼容性最好
if platform.system() == 'Darwin':
    # macOS: 优先使用 Cocoa，失败则使用 Qt
    os.environ.setdefault('PYWEBVIEW_BACKEND', 'cocoa')
elif platform.system() == 'Windows':
    # Windows: 使用 MSHTML 或 Edge
    os.environ.setdefault('PYWEBVIEW_BACKEND', 'edge')
else:
    # Linux: 使用 Qt
    os.environ.setdefault('PYWEBVIEW_BACKEND', 'qt')

import webview

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.api.handlers import APIHandler


def get_user_data_dir() -> Path:
    """获取用户数据目录"""
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


# Configure logging
user_data_dir = get_user_data_dir()
logs_dir = user_data_dir / 'logs'
logs_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(logs_dir / 'app.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class LensAnalysisApp:
    """析镜 - 内存取证工具主应用类"""

    def __init__(self):
        self.window = None
        self.api_handler = APIHandler()

        # Ensure directories exist (已在 APIHandler 中处理)
        # 不再需要手动创建 cache 和 logs 目录

    def start(self):
        """启动应用"""
        logger.info("启动析镜 LensAnalysis...")

        # 使用 HTTP 服务器模式（pywebview 需要 HTTP 才能注入 JS API）
        # 这不是 Web 后端，只是本地桥接机制

        # 获取前端文件路径（支持打包后的应用）
        # PyInstaller/Nuitka 打包后，__file__ 指向编译后的模块
        # 我们需要相对于可执行文件的位置来查找 frontend
        if getattr(sys, 'frozen', False):
            # 打包后的应用
            if platform.system() == 'Darwin':
                # macOS .app bundle: 可执行文件在 Contents/MacOS/
                # frontend 也在 Contents/MacOS/
                executable_dir = Path(sys.executable).parent
                frontend_path = str(executable_dir / 'frontend' / 'index.html')
            else:
                # Windows/Linux: standalone 模式
                executable_dir = Path(sys.executable).parent
                frontend_path = str(executable_dir / 'frontend' / 'index.html')
        else:
            # 开发环境
            frontend_path = str(Path(__file__).parent.parent / 'frontend' / 'index.html')

        logger.info(f"前端路径: {frontend_path}")

        if not Path(frontend_path).exists():
            logger.error(f"前端文件不存在: {frontend_path}")
            raise FileNotFoundError(f"找不到前端文件: {frontend_path}")

        # 构建窗口参数
        window_args = {
            'title': '析镜 LensAnalysis - 内存取证分析工具',
            'url': frontend_path,
            'js_api': self.api_handler,
            'width': 1400,
            'height': 900,
            'min_size': (1200, 700),
            'resizable': True,
            'frameless': False,
            'background_color': '#ffffff'
        }

        # PyWebView 的 icon 参数支持情况:
        # - macOS Cocoa: 不支持
        # - Windows MSHTML/Edge: 不支持
        # - Linux GTK: 支持
        # - QT: 支持
        #
        # 注意: 打包后的应用图标由打包工具配置 (PyInstaller/Nuitka)
        # 开发模式下，只有 Linux GTK 可以设置窗口图标
        system = platform.system()
        if system != 'Darwin' and system != 'Windows':
            # 只有非 macOS/Windows 平台才尝试设置图标
            icon_path = self._get_app_icon()
            if icon_path:
                window_args['icon'] = str(icon_path)

        self.window = webview.create_window(**window_args)

        # 将窗口引用传递给 APIHandler，用于退出功能
        self.api_handler.set_window(self.window)

        # 必须使用 http_server=True 才能让 JS API 工作
        webview.start(debug=False, http_server=True)

    def _get_app_icon(self) -> Path:
        """获取应用图标文件路径（跨平台）

        Returns:
            Path: 图标文件路径，如果不存在则返回 None
        """
        system = platform.system()
        assets_dir = Path(__file__).parent.parent / 'frontend' / 'assets'

        # 根据平台选择合适的图标格式
        icon_files = []

        if system == 'Windows':
            # Windows 优先使用 .ico，其次 .png
            icon_files = ['LensAnalysis-icon.ico', 'LensAnalysis-icon.png']
        elif system == 'Darwin':
            # macOS 优先使用 .icns，其次 .png
            icon_files = ['LensAnalysis-icon.icns', 'LensAnalysis-icon.png']
        else:
            # Linux 使用 .png
            icon_files = ['LensAnalysis-icon.png']

        # 按优先级查找图标文件
        for icon_file in icon_files:
            icon_path = assets_dir / icon_file
            if icon_path.exists():
                logger.info(f"使用应用图标: {icon_path}")
                return icon_path

        logger.warning("未找到应用图标文件，将使用默认图标")
        return None

    def on_loaded(self):
        """页面加载完成回调"""
        logger.info("前端页面加载完成")


def main():
    """主函数"""
    import sys

    # 添加启动日志，帮助调试双击问题
    logger.info("=" * 60)
    logger.info("LensAnalysis 启动")
    logger.info(f"Python executable: {sys.executable}")
    logger.info(f"sys.frozen: {getattr(sys, 'frozen', False)}")
    logger.info(f"Command line args: {sys.argv}")
    logger.info("=" * 60)

    # 创建一个标记文件，表示应用已启动
    try:
        import tempfile
        marker_file = Path(tempfile.gettempdir()) / 'lensanalysis_started.txt'
        marker_file.write_text(f"Started at: {Path(__file__)}\nArgs: {sys.argv}\n")
        logger.info(f"启动标记文件已创建: {marker_file}")
    except Exception as e:
        logger.warning(f"无法创建启动标记: {e}")

    app = LensAnalysisApp()
    app.start()


if __name__ == '__main__':
    main()
