#!/usr/bin/env python3
"""
析镜 LensAnalysis - Nuitka 打包脚本

本地打包工具，与 GitHub Actions 配置一致
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def print_header(msg):
    print(f"\n{'=' * 60}")
    print(f"  {msg}")
    print(f"{'=' * 60}\n")

def print_success(msg):
    print(f"✓ {msg}")

def print_error(msg):
    print(f"✗ {msg}")

def print_info(msg):
    print(f"ℹ {msg}")

def get_project_root():
    return Path(__file__).parent

def build_with_nuitka():
    """使用 Nuitka 打包"""
    print_header("Nuitka 打包")
    print_info(f"平台: {platform.system()}")
    print_info(f"Python: {sys.version}")

    project_root = get_project_root()
    main_py = project_root / 'LensAnalysis.py'

    if not main_py.exists():
        print_error(f"未找到 {main_py}")
        return False

    system = platform.system()
    is_macos = system == 'Darwin'
    is_windows = system == 'Windows'

    # 输出目录
    output_dir = project_root / 'build' / 'nuitka'

    # ===== Nuitka 命令配置 =====
    cmd = [
        sys.executable, '-m', 'nuitka',

        # ===== 打包模式 =====
        '--standalone',              # Standalone 模式
        '--assume-yes-for-downloads', # 自动下载依赖

        # ===== 输出设置 =====
        f'--output-dir={output_dir}',
        f'--output-filename=LensAnalysis' + ('.exe' if is_windows else ''),

        # ===== 性能优化 =====
        '--jobs=4',                  # 并行编译

        # ===== 包含数据文件 =====
        f'--include-data-dir={project_root / "frontend"}=frontend',
        f'--include-data-dir={project_root / "backend" / "scripts"}=backend/scripts',

        # ===== PyWebView 相关 =====
        '--plugin-disable=pywebview',
        '--include-module=webview',
    ]

    # 添加平台特定 webview 模块
    if is_macos:
        cmd.extend([
            '--include-module=webview.platforms.cocoa',
        ])
    elif is_windows:
        cmd.extend([
            '--include-module=webview.platforms.edgechromium',
        ])

    # ===== 添加排除模块 =====
    cmd.extend([
        # 排除 Volatility 3（用户自己安装）
        '--nofollow-import-to=volatility3',

        # 排除数据科学库
        '--nofollow-import-to=matplotlib',
        '--nofollow-import-to=numpy',
        '--nofollow-import-to=pandas',
        '--nofollow-import-to=scipy',
        '--nofollow-import-to=tkinter',
    ])

    # 平台特定选项
    if is_macos:
        cmd.extend([
            '--macos-create-app-bundle',
            '--macos-app-icon=frontend/assets/LensAnalysis-icon.icns',
            '--macos-app-name=LensAnalysis',
            '--macos-app-version=1.0.0',
        ])
    elif is_windows:
        cmd.append('--windows-disable-console')

    # 添加主文件
    cmd.append(str(main_py))

    print_info(f"开始打包...")
    print_info(f"编译时间约 10-20 分钟，请耐心等待...")
    print()

    try:
        result = subprocess.run(cmd, check=True)
        print_success("Nuitka 打包完成!")
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"打包失败: {e}")
        return False
    except KeyboardInterrupt:
        print_error("\n打包已取消")
        return False

def main():
    """主函数"""
    print_header("析镜 LensAnalysis - Nuitka 打包工具")

    # 执行打包
    if build_with_nuitka():
        print_header("打包完成!")

        project_root = get_project_root()
        output_dir = project_root / 'build' / 'nuitka'

        print_success(f"打包后的文件位于 {output_dir} 目录中")

        if platform.system() == 'Darwin':
            app_path = output_dir / 'LensAnalysis.app'
            if app_path.exists():
                print_info(f"运行: open {app_path}")
        elif platform.system() == 'Windows':
            exe_path = output_dir / 'LensAnalysis.dist' / 'LensAnalysis.exe'
            if exe_path.exists():
                print_info(f"运行: {exe_path}")

if __name__ == '__main__':
    main()
