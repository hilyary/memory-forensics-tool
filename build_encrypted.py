#!/usr/bin/env python3
"""
析镜 LensAnalysis - PyArmor 加密 + PyInstaller 打包脚本

使用流程:
1. 使用 PyArmor 加密 Python 代码
2. 使用 PyInstaller 打包加密后的代码

优点:
- 代码加密保护，防止反编译
- 加密后打包，双重保护
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

def get_project_root():
    """获取项目根目录"""
    return Path(__file__).parent

def clean_dist():
    """清理旧的输出"""
    print_header("清理旧文件")
    project_root = get_project_root()

    # 清理 PyArmor 输出
    if (project_root / 'dist').exists():
        shutil.rmtree(project_root / 'dist')
        print_success("已清理 dist/ 目录")

    # 清理 PyInstaller 输出
    if (project_root / 'build').exists():
        shutil.rmtree(project_root / 'build')
        print_success("已清理 build/ 目录")

    # 清理 PyArmor 缓存
    if (project_root / '.pyarmor').exists():
        shutil.rmtree(project_root / '.pyarmor')
        print_success("已清理 .pyarmor/ 缓存")

def encrypt_with_pyarmor():
    """使用 PyArmor 加密代码"""
    print_header("PyArmor 代码加密")

    project_root = get_project_root()

    # 需要加密的目录和文件
    targets = [
        'backend',
        'main.py',
    ]

    # PyArmor 加密选项
    # --exact: 精确模式，不包含额外文件
    # --output: 输出目录
    # --recursive: 递归处理子目录
    output_dir = project_root / 'dist' / 'obf'
    output_dir.mkdir(parents=True, exist_ok=True)

    # 大制不需要加密的文件（frontend、配置等）
    print_info("复制不需要加密的文件...")
    if (project_root / 'frontend').exists():
        shutil.copytree(
            project_root / 'frontend',
            output_dir / 'frontend',
            dirs_exist_ok=True
        )
    if (project_root / 'build.spec').exists():
        shutil.copy2(project_root / 'build.spec', output_dir / 'build.spec')

    # 使用 PyArmor 加密
    for target in targets:
        target_path = project_root / target
        if not target_path.exists():
            print_error(f"未找到: {target_path}")
            continue

        print_info(f"加密 {target}...")

        cmd = [
            'pyarmor',
            'gen',
            '-O', str(output_dir),
            '-r',  # 递归
            str(target_path)
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            print_success(f"已加密: {target}")
        except subprocess.CalledProcessError as e:
            print_error(f"加密失败: {target}")
            print_error(e.stderr)
            return False

    # 复制 PyArmor 运行时文件
    print_info("复制 PyArmor 运行时文件...")
    pyarmor_bootstrap = project_root / '.pyarmor' / 'pyarmor_bootstrap.py'
    if pyarmor_bootstrap.exists():
        shutil.copy2(pyarmor_bootstrap, output_dir / 'pyarmor_bootstrap.py')

    print_success("PyArmor 加密完成")
    return True

def build_with_pyinstaller():
    """使用 PyInstaller 打包加密后的代码"""
    print_header("PyInstaller 打包")

    project_root = get_project_root()
    output_dir = project_root / 'dist' / 'obf'

    # 切换到加密后的目录
    os.chdir(output_dir)

    # 运行 PyInstaller
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
        # 切换回项目根目录
        os.chdir(project_root)

def move_final_app():
    """移动最终的 app 到 dist 目录"""
    print_header("整理输出")

    project_root = get_project_root()
    obf_dist = project_root / 'dist' / 'obf' / 'dist'

    if (obf_dist / 'LensAnalysis.app').exists():
        # 复制到 dist 根目录
        final_app = project_root / 'dist' / 'LensAnalysis.app'
        if final_app.exists():
            shutil.rmtree(final_app)
        shutil.copytree(obf_dist / 'LensAnalysis.app', final_app)

        # 清理临时文件
        if (project_root / 'dist' / 'obf').exists():
            shutil.rmtree(project_root / 'dist' / 'obf')

        # 计算大小
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
    print_header("析镜 LensAnalysis - 加密打包工具")
    print(f"Python: {sys.version}")

    # 1. 清理旧文件
    clean_dist()

    # 2. PyArmor 加密
    if not encrypt_with_pyarmor():
        print_error("加密失败，终止打包")
        sys.exit(1)

    # 3. PyInstaller 打包
    if not build_with_pyinstaller():
        print_error("打包失败")
        sys.exit(1)

    # 4. 整理输出
    if not move_final_app():
        print_error("整理输出失败")
        sys.exit(1)

    print_header("加密打包完成!")
    print_success("代码已使用 PyArmor 加密")
    print_success("加密后的代码已打包为可执行文件")
    print_success("双重保护: 代码加密 + 字节码打包")

    print_info("\n安全特性:")
    print("  ✓ PyArmor 代码加密 (防止静态分析)")
    print("  ✓ PyInstaller 打包 (防止直接查看源码)")
    print("  ✓ 运行时解密 (不暴露明文代码)")

if __name__ == '__main__':
    main()
