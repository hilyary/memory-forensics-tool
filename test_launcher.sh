#!/bin/bash
# 测试启动器

# 获取脚本所在目录
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

# 记录启动
echo "=== Launcher started at $(date) ===" >> /tmp/lens_launcher.log
echo "DIR: $DIR" >> /tmp/lens_launcher.log
echo "PWD: $(pwd)" >> /tmp/lens_launcher.log

# 设置环境变量
export PYTHONPATH="$DIR:$PYTHONPATH"

# 启动 Nuitka 可执行文件
exec "./LensAnalysis.bin" "$@" 2>&1 | tee -a /tmp/lens_launcher.log
