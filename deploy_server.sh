#!/bin/bash
# 析镜 LensAnalysis - 服务器部署脚本
# 用于部署激活码生成 Web 服务到服务器

set -e

echo "=================================================="
echo "析镜 LensAnalysis - Web 服务部署"
echo "=================================================="
echo ""

# 检查是否为服务器环境
if [ -z "$SERVER_DEPLOY" ] && [ -z "$LENS_SECRET_KEY" ]; then
    echo "⚠️  服务器部署必须设置密钥！"
    echo ""
    echo "请使用以下命令设置密钥："
    echo "  export LENS_SECRET_KEY=\"\$(openssl rand -hex 32)\""
    echo ""
    echo "然后重新运行此脚本"
    exit 1
fi

# 生成密钥（如果未设置）
if [ -z "$LENS_SECRET_KEY" ]; then
    echo "生成新的密钥..."
    export LENS_SECRET_KEY="$(openssl rand -hex 32)"
    echo ""
    echo "⚠️  重要：请保存以下密钥，应用打包时也需要使用！"
    echo "LENS_SECRET_KEY=$LENS_SECRET_KEY"
    echo ""
    read -p "按回车继续..." -r
fi

echo "使用密钥: ${LENS_SECRET_KEY:0:16}..."
echo ""

# 安装依赖
echo "1. 安装依赖..."
pip3 install -q flask gunicorn || true

# 创建服务目录
SERVICE_DIR="/opt/lensanalysis"
echo "2. 创建服务目录: $SERVICE_DIR"
sudo mkdir -p $SERVICE_DIR

# 复制文件
echo "3. 复制文件..."
sudo cp -r backend tools templates $SERVICE_DIR/
sudo chown -R $USER:$USER $SERVICE_DIR

# 创建 systemd 服务
echo "4. 创建 systemd 服务..."
sudo tee /etc/systemd/system/lensanalysis-web.service > /dev/null <<EOF
[Unit]
Description=LensAnalysis License Web Service
After=network.target

[Service]
Type=notify
User=$USER
Group=$USER
WorkingDirectory=$SERVICE_DIR
Environment="PATH=$SERVICE_DIR/venv/bin:/usr/local/bin:/usr/bin:/bin"
Environment="LENS_SECRET_KEY=$LENS_SECRET_KEY"
Environment="PORT=8080"
Environment="HOST=127.0.0.1"
ExecStart=$SERVICE_DIR/venv/bin/gunicorn -w 4 -b 127.0.0.1:8080 tools.license_web:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# 创建虚拟环境
echo "5. 创建虚拟环境..."
python3 -m venv $SERVICE_DIR/venv
$SERVICE_DIR/venv/bin/pip install -q flask gunicorn

# 启动服务
echo "6. 启动服务..."
sudo systemctl daemon-reload
sudo systemctl enable lensanalysis-web
sudo systemctl start lensanalysis-web

# 检查状态
echo ""
echo "=================================================="
echo "✅ 部署完成！"
echo "=================================================="
echo ""
echo "服务状态:"
sudo systemctl status lensanalysis-web --no-pager | head -10
echo ""
echo "管理日志:"
echo "  sudo journalctl -u lensanalysis-web -f"
echo ""
echo "服务管理:"
echo "  启动: sudo systemctl start lensanalysis-web"
echo "  停止: sudo systemctl stop lensanalysis-web"
echo "  重启: sudo systemctl restart lensanalysis-web"
echo ""
