#!/usr/bin/env python3
"""
析镜 LensAnalysis - 主启动脚本
基于Volatility 3的图形化内存取证工具

使用方法:
    python main.py
"""

import sys
import os

# Add project root to path
project_root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, project_root)

from backend.app import main

if __name__ == '__main__':
    print("""
╔════════════════════════════════════════════════════════════╗
║                                                            ║
║   析镜 LensAnalysis                                       ║
║   基于 Volatility 3 的图形化内存取证工具                   ║
║   Email: hil_yary@163.com                                 ║
║                                                            ║
╚════════════════════════════════════════════════════════════╝
""")

    try:
        main()
    except KeyboardInterrupt:
        print("\n\n程序已退出")
        sys.exit(0)
    except Exception as e:
        print(f"\n错误: {e}")
        sys.exit(1)
