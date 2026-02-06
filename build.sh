#!/bin/bash
# 析镜 LensAnalysis - 打包脚本

set -e

echo "=================================================="
echo "析镜 LensAnalysis - 应用打包"
echo "=================================================="
echo ""

# 检查 Python 版本
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "当前 Python 版本: $PYTHON_VERSION"
echo ""

# 检查是否设置了密钥
if [ -z "$LENS_SECRET_KEY" ]; then
    echo "⚠️  警告: 未设置 LENS_SECRET_KEY 环境变量"
    echo ""
    echo "请使用以下命令设置密钥："
    echo "  export LENS_SECRET_KEY=\"\$(openssl rand -hex 32)\""
    echo ""
    echo "或者直接使用（本次打包）："
    read -p "是否使用生成的密钥继续？(y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        export LENS_SECRET_KEY="$(openssl rand -hex 32)"
        echo "已设置临时密钥"
    else
        echo "打包已取消"
        exit 1
    fi
fi

echo "使用密钥: ${LENS_SECRET_KEY:0:16}..."
echo ""

# 安装依赖
echo "1. 检查并安装依赖..."
pip3 install -q pyinstaller pywebview Flask || true

# 清理旧的构建文件
echo "2. 清理旧的构建文件..."
rm -rf build dist *.spec 2>/dev/null || true

# 执行打包
echo "3. 开始打包..."
echo ""

# 使用 spec 文件打包
pyinstaller build.spec

# 检查打包结果
if [ -f "dist/LensAnalysis" ]; then
    echo ""
    echo "=================================================="
    echo "✅ 打包成功！"
    echo "=================================================="
    echo ""
    echo "生成的文件: dist/LensAnalysis"
    echo ""
    echo "测试运行:"
    echo "  cd dist"
    echo "  ./LensAnalysis"
    echo ""
    ls -lh dist/LensAnalysis
else
    echo ""
    echo "❌ 打包失败，请检查错误信息"
    exit 1
fi
