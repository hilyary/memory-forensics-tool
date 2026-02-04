#!/usr/bin/env python3
"""
析镜 LensAnalysis - PyInstaller 打包脚本

使用方法:
    python3 build.py

特点:
- 使用系统默认 Python
- 自动清理旧文件
- 直接打包，无需额外依赖
"""

import os
import sys
import shutil
import subprocess
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

def main():
    """主函数"""
    print_header("析镜 LensAnalysis - 打包工具")
    print(f"Python: {sys.version}")
    print(f"路径: {sys.executable}")

    project_root = Path(__file__).parent

    # 清理旧文件
    print_header("清理旧文件")
    for name in ['dist', 'build']:
        path = project_root / name
        if path.exists():
            shutil.rmtree(path)
            print_success(f"已清理 {name}/")

    # 运行 PyInstaller
    print_header("PyInstaller 打包")
    print_info("开始打包...")

    cmd = [sys.executable, '-m', 'PyInstaller', 'build.spec', '-y']

    try:
        result = subprocess.run(cmd, check=True)
        print_success("打包完成!")
    except subprocess.CalledProcessError as e:
        print_error(f"打包失败: {e}")
        sys.exit(1)

    # 显示结果
    print_header("打包完成")

    app_path = project_root / 'dist' / 'LensAnalysis.app'
    if app_path.exists():
        size_mb = sum(f.stat().st_size for f in app_path.rglob('*') if f.is_file()) / (1024 * 1024)
        print_success(f"App: {app_path}")
        print_success(f"大小: {size_mb:.1f} MB")
        print_info("运行: open " + str(app_path))
    else:
        print_error("未找到生成的 App")
        sys.exit(1)

if __name__ == '__main__':
    main()
