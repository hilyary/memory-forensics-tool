#!/usr/bin/env python3
"""
Windows 符号表下载脚本

用法: python download_windows_symbols.py <镜像文件路径>
"""

import sys
import os
from pathlib import Path

try:
    from volatility3.framework.symbols.windows import pdbutil
    from volatility3.framework import contexts
    from volatility3.framework.layers import physical
    import urllib.request
    import urllib.parse
    import tempfile
    import lzma
    import json
    import uuid
except ImportError as e:
    print(f"错误: 缺少依赖 {e}")
    print("请安装: pip install volatility3")
    sys.exit(1)


def download_symbols(image_path: str, symbols_dir: str = None):
    """下载 Windows 符号表"""
    if not os.path.exists(image_path):
        print(f"错误: 镜像文件不存在: {image_path}")
        return False

    if symbols_dir is None:
        # 默认符号表目录
        symbols_dir = Path.home() / 'Library' / 'Application Support' / 'LensAnalysis' / 'symbols'
    else:
        symbols_dir = Path(symbols_dir)

    symbols_dir.mkdir(parents=True, exist_ok=True)

    print(f"正在扫描镜像: {image_path}")

    try:
        # 构建context并加载镜像
        context = contexts.Context()
        file_url = 'file://' + urllib.request.pathname2url(image_path)
        context.config['FileLayer.location'] = file_url

        # 加载物理层
        layer = physical.FileLayer(context, 'FileLayer', name="FileLayer")
        context.add_layer(layer)

        layer_name = layer.name
        page_size = 0x1000

        # 扫描常见的Windows内核PDB名称
        pdb_names = [b'ntkrnlmp.pdb', b'ntoskrnl.pdb', b'krnl.pdb', b'ntkrpamp.pdb']

        print("正在扫描 PDB 签名...")

        # 使用pdbname_scan扫描PDB签名
        pdb_results = list(pdbutil.PDBUtility.pdbname_scan(
            context, layer_name, page_size, pdb_names
        ))

        if not pdb_results:
            print("错误: 未在内存镜像中找到 PDB 信息")
            print("这可能不是有效的 Windows 镜像")
            return False

        # 使用第一个找到的内核PDB
        result = pdb_results[0]
        guid = result.get('GUID', '')
        age = result.get('age', 0)
        pdb_name = result.get('pdb_name', 'ntkrnlmp.pdb')

        print(f"找到 PDB 信息: {pdb_name}")
        print(f"  GUID: {guid}")
        print(f"  Age: {age}")

        # 检查符号表是否已存在
        symbol_path = symbols_dir / 'windows' / pdb_name / f"{guid}-{age}.json.xz"
        if symbol_path.exists():
            print(f"符号表已存在: {symbol_path}")
            return True

        # 创建临时目录
        temp_dir = Path(tempfile.gettempdir())
        temp_pdb_path = temp_dir / f"temp_pdb_{os.getpid()}_{uuid.uuid4().hex[:8]}.pdb"

        try:
            # 下载 PDB 文件（支持代理和进度显示）
            pdb_url = f"https://msdl.microsoft.com/download/symbols/{pdb_name}/{guid}{age:01X}/{pdb_name}"
            print(f"正在下载 PDB 文件...")
            print(f"  URL: {pdb_url}")

            # 使用 urllib 下载（最快）
            import urllib.request as req2

            # 检测系统代理
            proxies = None
            try:
                http_proxy = os.environ.get('http_proxy') or os.environ.get('HTTP_PROXY')
                https_proxy = os.environ.get('https_proxy') or os.environ.get('HTTPS_PROXY')
                if http_proxy or https_proxy:
                    # 创建代理处理器
                    proxy_handler = req2.ProxyHandler({
                        'http': http_proxy or '',
                        'https': https_proxy or ''
                    })
                    opener = req2.build_opener(proxy_handler)
                    req2.install_opener(opener)
                    print(f"检测到代理配置")
            except:
                pass

            # 进度回调函数
            def show_progress(block_num, block_size, total_size):
                downloaded = block_num * block_size
                if total_size > 0:
                    percent = min(int(downloaded * 100 / total_size), 100)
                    # 每下载 25% 显示一次进度
                    if percent % 25 == 0 and percent > 0:
                        filled = percent // 5
                        bar = '=' * filled + ' ' * (20 - filled)
                        print(f"  下载进度: [{bar}] {percent}%")
                if downloaded >= total_size and total_size > 0:
                    pass  # 下载完成

            req2.urlretrieve(pdb_url, str(temp_pdb_path), reporthook=show_progress)
            pdb_size = temp_pdb_path.stat().st_size
            print(f"PDB 下载完成: {pdb_size} bytes")

            # 转换 PDB 为 ISF 格式
            print("正在转换 PDB 为 ISF 格式...")
            temp_pdb_url = temp_pdb_path.as_uri()

            # 创建context并加载PDB文件
            from volatility3.framework import symbols as vol_symbols
            pdb_context = contexts.Context()
            pdb_context.config['pdbreader.FileLayer.location'] = temp_pdb_url

            pdb_layer = physical.FileLayer(pdb_context, 'pdbreader.FileLayer', 'FileLayer')
            pdb_context.add_layer(pdb_layer)

            # 使用PdbReader转换
            msf_layer_name, new_context = pdbutil.pdbconv.PdbReader.load_pdb_layer(pdb_context, temp_pdb_url)
            reader = pdbutil.pdbconv.PdbReader(new_context, temp_pdb_url, pdb_name)
            json_output = reader.get_json()

            print(f"符号表转换成功，JSON 大小: {len(json_output)} bytes")

            # 确保目录存在
            os.makedirs(os.path.dirname(symbol_path), exist_ok=True)

            # 保存为JSON.xz文件
            with lzma.open(symbol_path, 'w') as f:
                f.write(bytes(json.dumps(json_output, indent=2, sort_keys=True), 'utf-8'))

            print(f"符号表已保存: {symbol_path}")
            print(f"符号表大小: {symbol_path.stat().st_size} bytes")
            return True

        finally:
            # 清理临时文件
            try:
                if temp_pdb_path.exists():
                    temp_pdb_path.unlink()
            except:
                pass

    except Exception as e:
        print(f"错误: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("用法: python download_windows_symbols.py <镜像文件路径> [符号表目录]")
        sys.exit(1)

    image_path = sys.argv[1]
    symbols_dir = sys.argv[2] if len(sys.argv) > 2 else None

    success = download_symbols(image_path, symbols_dir)
    sys.exit(0 if success else 1)
