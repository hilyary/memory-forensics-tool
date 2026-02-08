# -*- mode: python ; coding: utf-8 -*-
"""
析镜 LensAnalysis - PyInstaller 打包配置

使用方法:
    pyinstaller build.spec

生成的文件在 dist/ 目录下
"""

block_cipher = None
import os
import sys

# 获取项目根目录
project_root = os.path.dirname(os.path.abspath(SPEC))

# 应用基本信息
app_name = 'LensAnalysis'
app_version = '1.0.0'

# 主程序文件
main_script = os.path.join(project_root, 'backend', 'app.py')

# 数据文件
datas = [
    # 前端文件
    (os.path.join(project_root, 'frontend'), 'frontend'),
]

# 隐藏导入（PyInstaller 可能检测不到的模块）
hiddenimports = [
    'webview',
    'webview.platforms',
    'webview.platforms.cocoa',
    'webview.platforms.winforms',
    'webview.platforms.gtk',
    'Flask',
    'hmac',
    'hashlib',
    'uuid',
    'platform',
    'json',
    'pathlib',
    'typing',
    # Volatility 3 hashdump/lsadump/cachedump 插件需要
    'Cryptodome',
    'Cryptodome.Cipher',
    'Cryptodome.Cipher.AES',
    'Cryptodome.Cipher.DES',
    'Cryptodome.Cipher.DESCipher',
    'Cryptodome.Cipher._mode_ecb',
    'Cryptodome.Util',
    'Cryptodome.Util.Counter',
]

# 分析配置
a = Analysis(
    [main_script],
    pathex=[project_root],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # 排除不需要的模块，减小体积
        'tkinter',
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

# 文件收集
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name=app_name,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,  # 使用 UPX 压缩（如果可用）
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # 不显示控制台窗口
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # macOS 特定选项
    bundle_identifier='com.lensanalysis.app',
    info_plist={
        'CFBundleName': app_name,
        'CFBundleDisplayName': '析镜 LensAnalysis',
        'CFBundleVersion': app_version,
        'CFBundleShortVersionString': app_version,
        'NSHighResolutionCapable': True,
        'LSMinimumSystemVersion': '10.13.0',
    },
    # 图标（如果有）
    # icon='frontend/assets/LensAnalysis-icon.icns',
)
