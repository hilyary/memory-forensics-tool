#!/usr/bin/env python3
"""
析镜 LensAnalysis - 代码混淆 + 打包脚本

混淆策略：
- 删除注释和空行
- 压缩代码格式
- 保留所有变量名和函数名（不影响后续开发）
- 只对打包副本操作，源代码保持不变

使用方法:
    python3 build_obfuscated.py
"""

import os
import re
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

def obfuscate_python_code(source_file):
    """
    混淆 Python 代码（只影响格式，不改变变量名）

    保留：
    - 所有变量名
    - 所有函数名
    - 所有类名
    - 代码逻辑完全不变

    移除：
    - 注释
    - 多余的空行
    - 行尾空格
    """
    with open(source_file, 'r', encoding='utf-8') as f:
        content = f.read()

    lines = content.split('\n')
    obfuscated_lines = []

    for line in lines:
        # 移除行尾空格
        line = line.rstrip()

        # 跳过注释行（但保留 shebang）
        stripped = line.strip()
        if stripped.startswith('#'):
            if lines.index(line) == 0 and stripped.startswith('#!'):
                obfuscated_lines.append(line)  # 保留 shebang
            # 跳过其他注释
            continue

        # 跳过空行
        if not stripped:
            continue

        obfuscated_lines.append(line)

    return '\n'.join(obfuscated_lines)

def obfuscate_directory(source_dir, target_dir):
    """递归混淆目录中的所有 Python 文件"""
    for item in source_dir.iterdir():
        target_path = target_dir / item.name

        if item.is_dir():
            # 递归处理子目录
            target_path.mkdir(exist_ok=True)
            obfuscate_directory(item, target_path)
        elif item.suffix == '.py':
            # 混淆 Python 文件
            print_info(f"混淆: {item.relative_to(source_dir)}")
            obfuscated_code = obfuscate_python_code(item)
            target_path.write_text(obfuscated_code, encoding='utf-8')
        else:
            # 直接复制其他文件
            shutil.copy2(item, target_path)

def main():
    """主函数"""
    print_header("析镜 LensAnalysis - 代码混淆打包工具")
    print(f"Python: {sys.version}")

    project_root = Path(__file__).parent
    temp_dir = project_root / '.temp_obfuscated'

    # 清理临时目录
    if temp_dir.exists():
        shutil.rmtree(temp_dir)
    temp_dir.mkdir()

    # 1. 混淆 backend 代码
    print_header("步骤 1: 混淆代码")
    backend_source = project_root / 'backend'
    backend_target = temp_dir / 'backend'

    if backend_source.exists():
        print_info("混淆 backend 目录...")
        backend_target.mkdir(exist_ok=True)
        obfuscate_directory(backend_source, backend_target)
        print_success("backend 混淆完成")
    else:
        print_error("未找到 backend 目录")
        sys.exit(1)

    # 2. 复制其他文件（不混淆）
    print_header("步骤 2: 复制其他文件")

    # 复制 frontend
    if (project_root / 'frontend').exists():
        shutil.copytree(project_root / 'frontend', temp_dir / 'frontend')
        print_success("已复制 frontend")

    # 复制主文件
    for file in ['main.py', 'build.spec']:
        if (project_root / file).exists():
            shutil.copy2(project_root / file, temp_dir / file)
            print_success(f"已复制 {file}")

    # 3. 切换到临时目录并打包
    print_header("步骤 3: PyInstaller 打包")

    # 清理旧的输出
    for name in ['dist', 'build']:
        path = project_root / name
        if path.exists():
            shutil.rmtree(path)

    # 切换到临时目录
    original_dir = os.getcwd()
    os.chdir(temp_dir)

    try:
        cmd = [sys.executable, '-m', 'PyInstaller', 'build.spec', '-y']
        subprocess.run(cmd, check=True)
        print_success("打包完成")
    finally:
        os.chdir(original_dir)

    # 4. 移动最终输出
    print_header("步骤 4: 整理输出")

    if (temp_dir / 'dist' / 'LensAnalysis.app').exists():
        # 复制到项目 dist 目录
        dist_dir = project_root / 'dist'
        dist_dir.mkdir(exist_ok=True)

        final_app = dist_dir / 'LensAnalysis.app'
        if final_app.exists():
            shutil.rmtree(final_app)

        shutil.copytree(temp_dir / 'dist' / 'LensAnalysis.app', final_app)

        # 清理临时目录
        shutil.rmtree(temp_dir)

        # 计算大小
        size_mb = sum(f.stat().st_size for f in final_app.rglob('*') if f.is_file()) / (1024 * 1024)

        print_success(f"最终 App: {final_app}")
        print_success(f"大小: {size_mb:.1f} MB")
        print_info("运行: open " + str(final_app))

        print_header("完成!")
        print_success("代码已混淆并打包")
        print_info("源代码保持不变，可继续开发")
    else:
        print_error("打包失败")
        shutil.rmtree(temp_dir)
        sys.exit(1)

if __name__ == '__main__':
    main()
