#!/usr/bin/env python3
"""
图标生成工具

从 SVG 源文件生成各平台所需的图标格式:
- Windows: .ico
- macOS: .icns
- Linux: .png (多尺寸)

使用方法:
    python tools/generate_icons.py

依赖:
    pip install Pillow cairosvg
"""

import os
import sys
from pathlib import Path

try:
    from PIL import Image
    import cairosvg
except ImportError as e:
    print(f"缺少依赖: {e}")
    print("请运行: pip install Pillow cairosvg")
    sys.exit(1)


def svg_to_png(svg_path, png_path, size):
    """将 SVG 转换为 PNG"""
    cairosvg.svg2png(
        url=str(svg_path),
        write_to=str(png_path),
        output_width=size,
        output_height=size
    )


def generate_ico(input_png, output_ico):
    """生成 Windows .ico 文件（多尺寸）"""
    sizes = [(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    img = Image.open(input_png)

    icons = []
    for size in sizes:
        # 转换为 RGBA 模式
        icon = img.resize(size, Image.Resampling.LANCZOS).convert('RGBA')
        icons.append(icon)

    # 保存为 ICO
    icons[0].save(
        output_ico,
        format='ICO',
        sizes=[(size[0], size[1]) for size in sizes]
    )
    print(f"✓ 生成: {output_ico}")


def generate_icns(input_png, output_icns):
    """生成 macOS .icns 文件

    注意: 需要 iconutil (macOS 系统自带) 或使用 PIL 保存多尺寸 PNG
    这里我们创建一个简单的 iconset 结构
    """
    # .icns 需要多个尺寸的图片
    sizes = [16, 32, 64, 128, 256, 512, 1024]
    img = Image.open(input_png)

    # 创建临时目录
    iconset_dir = output_icns.parent / f"{output_icns.stem}.iconset"
    iconset_dir.mkdir(exist_ok=True)

    # 生成不同尺寸
    for size in sizes:
        # 1x 和 2x 尺寸
        for scale in [1, 2]:
            actual_size = size * scale
            resized = img.resize((actual_size, actual_size), Image.Resampling.LANCZOS)

            # macOS 命名格式: icon_16x16.png, icon_16x16@2x.png
            if scale == 1:
                filename = f"icon_{size}x{size}.png"
            else:
                filename = f"icon_{size}x{size}@2x.png"

            resized.save(iconset_dir / filename)

    # 尝试使用 iconutil 生成 .icns (仅 macOS)
    import subprocess
    try:
        subprocess.run(
            ['iconutil', '-c', 'icns', str(iconset_dir)],
            check=True,
            capture_output=True
        )
        print(f"✓ 生成: {output_icns}")
        # 清理临时目录
        import shutil
        shutil.rmtree(iconset_dir)
    except (subprocess.CalledProcessError, FileNotFoundError):
        # iconutil 不可用，保留 iconset 目录
        print(f"⚠ iconutil 不可用，已生成 iconset: {iconset_dir}")
        print(f"  如果你在 macOS 上，可以手动运行:")
        print(f"  iconutil -c icns {iconset_dir}")


def generate_png_sizes(input_svg, output_dir):
    """生成多尺寸 PNG 文件（用于 Linux 等）"""
    sizes = [32, 64, 128, 256, 512]
    output_dir.mkdir(exist_ok=True)

    for size in sizes:
        output_png = output_dir / f"icon_{size}x{size}.png"
        svg_to_png(input_svg, output_png, size)
        print(f"✓ 生成: {output_png}")


def main():
    """主函数"""
    print("=" * 60)
    print("  析镜 LensAnalysis - 图标生成工具")
    print("=" * 60)

    # 获取项目根目录
    project_root = Path(__file__).parent.parent
    assets_dir = project_root / 'frontend' / 'assets'
    svg_icon = assets_dir / 'LensAnalysis-icon.svg'

    if not svg_icon.exists():
        print(f"错误: 未找到源图标文件: {svg_icon}")
        sys.exit(1)

    # 生成基础 PNG (256x256)
    base_png = assets_dir / 'LensAnalysis-icon-base.png'
    print(f"\n从 SVG 生成基础 PNG (256x256)...")
    svg_to_png(svg_icon, base_png, 256)
    print(f"✓ 生成: {base_png}")

    # 生成 Windows .ico
    print(f"\n生成 Windows .ico 文件...")
    ico_output = assets_dir / 'LensAnalysis-icon.ico'
    generate_ico(base_png, ico_output)

    # 生成 macOS .icns
    print(f"\n生成 macOS .icns 文件...")
    icns_output = assets_dir / 'LensAnalysis-icon.icns'
    generate_icns(base_png, icns_output)

    # 生成多尺寸 PNG
    print(f"\n生成多尺寸 PNG 文件...")
    png_output_dir = assets_dir / 'icons'
    generate_png_sizes(svg_icon, png_output_dir)

    # 清理临时文件
    if base_png.exists():
        base_png.unlink()
        print(f"\n✓ 清理临时文件: {base_png}")

    print("\n" + "=" * 60)
    print("  图标生成完成！")
    print("=" * 60)
    print(f"\n生成的文件位于: {assets_dir}")
    print(f"  - LensAnalysis-icon.ico  (Windows)")
    print(f"  - LensAnalysis-icon.icns (macOS)")
    print(f"  - icons/                 (Linux 多尺寸)")


if __name__ == '__main__':
    main()
