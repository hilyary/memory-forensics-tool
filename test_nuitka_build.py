#!/usr/bin/env python3
"""
Nuitka 打包后测试脚本

用于验证打包后的程序功能是否正常

使用方法:
    python test_nuitka_build.py
"""

import sys
import os
from pathlib import Path
import platform

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

def test_build_exists():
    """检查打包文件是否存在"""
    print_header("检查打包文件")

    project_root = Path(__file__).parent
    system = platform.system()

    if system == 'Darwin':
        build_path = project_root / 'build' / 'nuitka' / 'LensAnalysis.app'
    elif system == 'Windows':
        build_path = project_root / 'build' / 'nuitka' / 'LensAnalysis.dist'
    else:
        build_path = project_root / 'build' / 'nuitka' / 'LensAnalysis.dist'

    if build_path.exists():
        print_success(f"找到打包文件: {build_path}")
        return build_path
    else:
        print_error("未找到打包文件")
        print_info("请先运行: python build_nuitka.py")
        return None

def test_dependencies():
    """测试依赖是否安装"""
    print_header("检查依赖")

    dependencies = [
        ('volatility3', 'Volatility 3'),
        ('webview', 'PyWebView'),
        ('docx', 'python-docx'),
    ]

    missing = []
    for module_name, display_name in dependencies:
        try:
            __import__(module_name)
            print_success(f"{display_name}: 已安装")
        except ImportError:
            print_error(f"{display_name}: 未安装")
            missing.append(display_name)

    if missing:
        print_info("\n缺少以下依赖，请运行:")
        print("  pip install volatility3 pywebview python-docx")
        return False

    return True

def test_project_structure():
    """测试项目结构是否正确"""
    print_header("检查项目结构")

    project_root = Path(__file__).parent

    required_paths = [
        ('backend/plugins', '自定义插件目录'),
        ('frontend/index.html', '前端文件'),
        ('frontend/assets', '前端资源'),
    ]

    all_exist = True
    for path, description in required_paths:
        full_path = project_root / path
        if full_path.exists():
            print_success(f"{description}: 存在")
        else:
            print_error(f"{description}: 不存在")
            all_exist = False

    return all_exist

def test_imports():
    """测试关键模块导入"""
    print_header("测试模块导入")

    tests = [
        ('backend.volatility_wrapper', 'VolatilityWrapper'),
        ('backend.api.handlers', 'APIHandler'),
        ('backend.app', '主应用模块'),
    ]

    all_success = True
    for module_name, description in tests:
        try:
            __import__(module_name)
            print_success(f"{description}: 导入成功")
        except Exception as e:
            print_error(f"{description}: 导入失败 - {e}")
            all_success = False

    return all_success

def print_quick_start_guide(build_path):
    """打印快速开始指南"""
    print_header("快速开始指南")

    system = platform.system()

    print("1. 安装 Volatility 3（如果还没有）:")
    print("   pip install volatility3")
    print()

    if system == 'Darwin':
        print("2. 运行打包后的程序:")
        print(f"   open {build_path}")
        print()
    elif system == 'Windows':
        print("2. 运行打包后的程序:")
        print(f"   {build_path}\\LensAnalysis.exe")
        print()
    else:
        print("2. 运行打包后的程序:")
        print(f"   {build_path}/LensAnalysis")
        print()

    print("3. 测试功能:")
    print("   - 打开一个内存镜像文件")
    print("   - 运行 Windows.pslist 插件")
    print("   - 检查符号表管理")
    print("   - 测试导出报告功能")
    print()

    print("4. 如果遇到问题:")
    print("   - 检查日志: ~/Library/Application Support/LensAnalysis/logs/app.log")
    print("   - 确保已安装: pip install volatility3")
    print()

def main():
    """主函数"""
    print_header("析镜 LensAnalysis - Nuitka 打包测试")

    # 检查项目结构
    if not test_project_structure():
        print_error("项目结构不完整")
        return False

    # 检查依赖
    if not test_dependencies():
        print_error("依赖不完整，请先安装")
        return False

    # 测试模块导入
    if not test_imports():
        print_error("模块导入测试失败")
        return False

    # 检查打包文件
    build_path = test_build_exists()
    if not build_path:
        return False

    print_quick_start_guide(build_path)

    print_header("测试完成!")
    print_success("所有检查通过，可以开始使用打包后的程序了")

    return True

if __name__ == '__main__':
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n测试已取消")
        sys.exit(1)
    except Exception as e:
        print_error(f"测试过程中发生错误: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
