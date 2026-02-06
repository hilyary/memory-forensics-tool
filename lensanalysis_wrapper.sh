#!/bin/bash
# LensAnalysis 启动包装器
# 确保正确的工作目录和环境

# 获取脚本所在目录
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

# 重定向输出到日志文件（避免双击时因无终端而崩溃）
LOG_FILE="$HOME/Library/Logs/LensAnalysis-launch.log"
mkdir -p "$(dirname "$LOG_FILE")"

# 记录启动信息
echo "=== LensAnalysis 启动 ===" >> "$LOG_FILE"
echo "时间: $(date)" >> "$LOG_FILE"
echo "目录: $DIR" >> "$LOG_FILE"
echo "参数: $@" >> "$LOG_FILE"

# 启动真正的可执行文件
exec "./LensAnalysis.bin" "$@" 2>&1 | tee -a "$LOG_FILE"
