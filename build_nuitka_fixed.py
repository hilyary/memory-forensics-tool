#!/usr/bin/env python3
"""
析镜 LensAnalysis - Nuitka 打包脚本（修复版）

解决 pywebview 插件冲突：
- 不使用 --nofollow-import-to 排除平台后端
- 让 Nuitka 的 pywebview 插件自动处理
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
    main_py = project_root / 'main.py'

    if not main_py.exists():
        print_error(f"未找到 {main_py}")
        return False

    system = platform.system()
    is_macos = system == 'Darwin'
    is_windows = system == 'Windows'
    is_linux = system == 'Linux'

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
        f'--include-data-dir={project_root / "backend" / "plugins"}=backend/plugins',

        # ===== PyWebView 相关 =====
        # 关键：只包含 webview 主模块，让插件自动处理平台后端
        '--include-module=webview',
    ]

    # ===== 添加排除模块（只排除真正不需要的）=====
    cmd.extend([
        # 排除 Volatility 3（用户自己安装）
        '--nofollow-import-to=volatility3',
        '--nofollow-import-to=volatility3.cli',
        '--nofollow-import-to=volatility3.framework',
        '--nofollow-import-to=volatility3.plugins',

        # 排除数据科学库
        '--nofollow-import-to=matplotlib',
        '--nofollow-import-to=numpy',
        '--nofollow-import-to=pandas',
        '--nofollow-import-to=scipy',
        '--nofollow-import-to=IPython',
        '--nofollow-import-to=tkinter',

        # 排除其他 GUI 库
        '--nofollow-import-to=PyQt5',
        '--nofollow-import-to=PySide2',
        '--nofollow-import-to=PySide6',
        '--nofollow-import-to=PyQt6',

        # 排除测试和开发工具
        '--nofollow-import-to=test',
        '--nofollow-import-to=unittest',
    ])

    # 平台特定选项
    if is_windows:
        cmd.append('--windows-disable-console')

    # 添加主文件
    cmd.append(str(main_py))

    print_info(f"开始打包...")
    print_info(f"编译时间约 5-15 分钟，请耐心等待...")
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

def post_build():
    """打包后处理"""
    print_header("打包完成")

    project_root = get_project_root()
    system = platform.system()

    if system == 'Darwin':
        # Nuitka 创建的是 .dist 目录，需要手动创建 .app
        dist_dir = project_root / 'build' / 'nuitka' / 'LensAnalysis.dist'
        app_path = project_root / 'build' / 'nuitka' / 'LensAnalysis.app'

        if dist_dir.exists() and not app_path.exists():
            print_info("创建 macOS .app 包...")

            import shutil
            app_path.mkdir(parents=True, exist_ok=True)
            contents_dir = app_path / 'Contents'
            contents_dir.mkdir(exist_ok=True)
            macos_dir = contents_dir / 'MacOS'
            macos_dir.mkdir(exist_ok=True)
            resources_dir = contents_dir / 'Resources'
            resources_dir.mkdir(exist_ok=True)

            # 复制可执行文件
            exe_path = dist_dir / 'LensAnalysis'
            if exe_path.exists():
                shutil.copy2(exe_path, macos_dir / 'LensAnalysis')

            # 复制所有依赖文件
            for f in dist_dir.glob('*'):
                if f.is_file() and f.name != 'LensAnalysis':
                    shutil.copy2(f, macos_dir / f.name)

            # 复制数据目录
            for d in ['frontend', 'backend']:
                if (dist_dir / d).exists():
                    shutil.copytree(dist_dir / d, macos_dir / d, dirs_exist_ok=True)

            # 复制图标
            icon_src = project_root / 'frontend' / 'assets' / 'LensAnalysis-icon.icns'
            if icon_src.exists():
                shutil.copy2(icon_src, resources_dir / 'LensAnalysis-icon.icns')

            # 创建 Info.plist
            info_plist = f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>LensAnalysis</string>
    <key>CFBundleIconFile</key>
    <string>LensAnalysis-icon.icns</string>
    <key>CFBundleIdentifier</key>
    <string>com.lensanalysis.forensics</string>
    <key>CFBundleName</key>
    <string>LensAnalysis</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0.0</string>
    <key>CFBundleVersion</key>
    <string>1.0.0</string>
    <key>LSMinimumSystemVersion</key>
    <string>10.15.0</string>
</dict>
</plist>'''
            (contents_dir / 'Info.plist').write_text(info_plist)

            # 签名
            subprocess.run(['codesign', '--force', '--deep', '-s', '-', str(app_path)],
                          capture_output=True)

            # 计算总大小
            total_size = sum(f.stat().st_size for f in app_path.rglob('*') if f.is_file())
            size_mb = total_size / (1024 * 1024)
            print_success(f"macOS App: {app_path}")
            print_success(f"总大小: {size_mb:.1f} MB")
            print_info("运行: open " + str(app_path))
        elif app_path.exists():
            total_size = sum(f.stat().st_size for f in app_path.rglob('*') if f.is_file())
            size_mb = total_size / (1024 * 1024)
            print_success(f"macOS App: {app_path}")
            print_success(f"总大小: {size_mb:.1f} MB")
            print_info("运行: open " + str(app_path))

    elif system == 'Windows':
        output_dir = project_root / 'build' / 'nuitka' / 'LensAnalysis.dist'
        if output_dir.exists():
            print_success(f"输出目录: {output_dir}")
            exe_path = output_dir / 'LensAnalysis.exe'
            if exe_path.exists():
                size_mb = exe_path.stat().st_size / (1024 * 1024)
                print_success(f"可执行文件: ({size_mb:.1f} MB)")

    elif system == 'Linux':
        output_dir = project_root / 'build' / 'nuitka' / 'LensAnalysis.dist'
        if output_dir.exists():
            print_success(f"输出目录: {output_dir}")

def main():
    """主函数"""
    print_header("析镜 LensAnalysis - Nuitka 打包工具")

    # 执行打包
    if build_with_nuitka():
        post_build()

        print_header("打包完成!")
        print_success("打包后的文件位于 build/nuitka/ 目录中")

        print_info("\nNuitka 优势:")
        print("  ✓ 编译成机器码，性能更好")
        print("  ✓ 防反编译能力强（机器码极难还原）")
        print("  ✓ 体积更小")
        print("  ✓ 启动速度更快")

if __name__ == '__main__':
    main()
