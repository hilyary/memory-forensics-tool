#!/usr/bin/env python3
"""
简单的 macOS .icns 图标生成工具

使用方法:
    python tools/generate_icns_simple.py
"""

import os
import sys
import subprocess
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("请安装 Pillow: pip install Pillow")
    sys.exit(1)


def generate_iconset(source_png, output_dir):
    """生成 macOS iconset 目录结构"""
    iconset_name = "LensAnalysis-icon.iconset"
    iconset_dir = output_dir / iconset_name
    iconset_dir.mkdir(exist_ok=True)

    img = Image.open(source_png).convert("RGBA")

    # macOS 需要的尺寸（包括 @2x Retina 版本）
    sizes = [
        (16, "16x16"),
        (32, "16x16@2x"),
        (32, "32x32"),
        (64, "32x32@2x"),
        (128, "128x128"),
        (256, "128x128@2x"),
        (256, "256x256"),
        (512, "256x256@2x"),
        (512, "512x512"),
        (1024, "512x512@2x"),
    ]

    print("生成 iconset 文件...")
    for size, name in sizes:
        resized = img.resize((size, size), Image.Resampling.LANCZOS)
        output_path = iconset_dir / f"icon_{name}.png"
        resized.save(output_path, format="PNG")
        print(f"  ✓ {output_path.name}")

    return iconset_dir


def convert_to_icns(iconset_dir, output_icns):
    """使用 iconutil 将 iconset 转换为 .icns（仅 macOS）"""
    try:
        subprocess.run(
            ["iconutil", "-c", "icns", str(iconset_dir)],
            check=True,
            capture_output=True
        )
        print(f"\n✓ 生成: {output_icns}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"\n⚠ iconutil 执行失败: {e}")
        print(f"⚠ 请确保在 macOS 上运行此脚本")
        return False
    except FileNotFoundError:
        print(f"\n⚠ 未找到 iconutil 工具")
        print(f"⚠ iconutil 仅在 macOS 上可用")
        return False


def main():
    print("=" * 60)
    print("  析镜 LensAnalysis - macOS 图标生成工具")
    print("=" * 60)

    # 获取路径
    project_root = Path(__file__).parent.parent
    assets_dir = project_root / 'frontend' / 'assets'
    source_png = assets_dir / 'LensAnalysis-icon.png'
    output_icns = assets_dir / 'LensAnalysis-icon.icns'

    if not source_png.exists():
        print(f"错误: 未找到源图标: {source_png}")
        sys.exit(1)

    # 生成 iconset
    print(f"\n源文件: {source_png}")
    iconset_dir = generate_iconset(source_png, assets_dir)

    # 转换为 .icns
    print(f"\n转换为 .icns...")
    if convert_to_icns(iconset_dir, output_icns):
        # 清理 iconset
        import shutil
        shutil.rmtree(iconset_dir)
        print(f"✓ 清理临时文件")

        print("\n" + "=" * 60)
        print("  完成！")
        print("=" * 60)
        print(f"\n生成的文件: {output_icns}")
        print(f"\n现在重启应用，应该能看到新图标了！")
    else:
        print("\n" + "=" * 60)
        print("  iconset 已生成，但无法转换为 .icns")
        print("=" * 60)
        print(f"\n你可以手动在 macOS 上运行:")
        print(f"  iconutil -c icns {iconset_dir}")


if __name__ == '__main__':
    main()
