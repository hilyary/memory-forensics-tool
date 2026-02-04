#!/usr/bin/env python3
"""
析镜 LensAnalysis - Python 字节码编译 + PyInstaller 打包脚本

使用流程:
1. 将 Python 代码编译成 .pyc 字节码
2. 使用 PyInstaller 打包

优点:
- 字节码比源码更难反编译
- PyInstaller 打包提供额外保护
- 完全免费，无限制
"""

import os
import sys
import shutil
import subprocess
import compileall
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
    """获取项目根目录"""
    return Path(__file__).parent

def clean_dist():
    """清理旧的输出"""
    print_header("清理旧文件")
    project_root = get_project_root()

    if (project_root / 'dist').exists():
        shutil.rmtree(project_root / 'dist')
        print_success("已清理 dist/ 目录")

    if (project_root / 'build').exists():
        shutil.rmtree(project_root / 'build')
        print_success("已清理 build/ 目录")

def compile_to_pyc():
    """将 Python 代码编译成字节码"""
    print_header("编译 Python 代码为字节码")

    project_root = get_project_root()
    output_dir = project_root / 'dist' / 'compiled'
    output_dir.mkdir(parents=True, exist_ok=True)

    # 需要编译的目录
    targets = ['backend']

    # 复制不需要编译的文件
    print_info("复制不需要编译的文件...")
    if (project_root / 'frontend').exists():
        shutil.copytree(
            project_root / 'frontend',
            output_dir / 'frontend',
            dirs_exist_ok=True
        )
    if (project_root / 'main.py').exists():
        shutil.copy2(project_root / 'main.py', output_dir / 'main.py')
    if (project_root / 'build.spec').exists():
        shutil.copy2(project_root / 'build.spec', output_dir / 'build.spec')

    # 编译 Python 代码
    for target in targets:
        target_path = project_root / target
        if not target_path.exists():
            continue

        print_info(f"编译 {target}...")

        # 复制到输出目录
        dest_path = output_dir / target
        if dest_path.exists():
            shutil.rmtree(dest_path)
        shutil.copytree(target_path, dest_path)

        # 编译为 .pyc
        compileall.compile_dir(
            dest_path,
            force=True,
            legacy=True,  # 使用旧的 .pyc 位置（与源文件同目录）
            quiet=1
        )

        # 删除源 .py 文件（保留 .pyc）
        for py_file in dest_path.rglob('*.py'):
            pyc_file = py_file.with_suffix('.pyc')
            if pyc_file.exists():
                py_file.unlink()
                print_success(f"  {py_file.name} -> .pyc")

    print_success("编译完成")
    return True

def build_with_pyinstaller():
    """使用 PyInstaller 打包"""
    print_header("PyInstaller 打包")

    project_root = get_project_root()
    output_dir = project_root / 'dist' / 'compiled'

    os.chdir(output_dir)

    cmd = [sys.executable, '-m', 'PyInstaller', 'build.spec', '-y']

    try:
        print_info("开始打包...")
        subprocess.run(cmd, check=True)
        print_success("PyInstaller 打包完成")
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"打包失败: {e}")
        return False
    finally:
        os.chdir(project_root)

def move_final_app():
    """移动最终的 app"""
    print_header("整理输出")

    project_root = get_project_root()
    obf_dist = project_root / 'dist' / 'compiled' / 'dist'

    if (obf_dist / 'LensAnalysis.app').exists():
        final_app = project_root / 'dist' / 'LensAnalysis.app'
        if final_app.exists():
            shutil.rmtree(final_app)
        shutil.copytree(obf_dist / 'LensAnalysis.app', final_app)

        # 清理临时文件
        if (project_root / 'dist' / 'compiled').exists():
            shutil.rmtree(project_root / 'dist' / 'compiled')

        size_mb = sum(f.stat().st_size for f in final_app.rglob('*') if f.is_file()) / (1024 * 1024)

        print_success(f"最终 App: {final_app}")
        print_success(f"大小: {size_mb:.1f} MB")
        print_info("运行: open " + str(final_app))
        return True
    else:
        print_error("未找到生成的 App")
        return False

def main():
    """主函数"""
    print_header("析镜 LensAnalysis - 字节码打包工具")
    print(f"Python: {sys.version}")

    clean_dist()

    if not compile_to_pyc():
        print_error("编译失败，终止打包")
        sys.exit(1)

    if not build_with_pyinstaller():
        print_error("打包失败")
        sys.exit(1)

    if not move_final_app():
        print_error("整理输出失败")
        sys.exit(1)

    print_header("打包完成!")
    print_success("Python 代码已编译为字节码 (.pyc)")
    print_success("字节码已打包为可执行文件")

    print_info("\n安全特性:")
    print("  ✓ 字节码编译 (比源码更难反编译)")
    print("  ✓ PyInstaller 打包 (防止直接查看文件)")
    print("  ✓ 删除源文件 (只保留 .pyc)")

if __name__ == '__main__':
    main()
