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
    # GUI 应用不使用 print，避免弹出控制台窗口
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception:
        sys.exit(1)
