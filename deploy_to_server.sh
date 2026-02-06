#!/bin/bash
# 析镜 LensAnalysis - 自动部署到服务器
# 使用保存的配置自动部署

set -e

# 加载服务器配置
if [ -f .env.server ]; then
    source .env.server
else
    echo "错误: 找不到 .env.server 配置文件"
    exit 1
fi

echo "=================================================="
echo "析镜 LensAnalysis - 自动部署到服务器"
echo "=================================================="
echo ""
echo "服务器: ${SERVER_USER}@${SERVER_HOST}"
echo "Web 端口: ${WEB_PORT}"
echo ""

# 创建远程部署脚本
REMOTE_SCRIPT="#!/bin/bash
set -e

echo '1. 安装依赖...'
apt-get update -qq
apt-get install -y python3 python3-pip python3-venv nginx > /dev/null 2>&1

echo '2. 创建服务目录...'
mkdir -p /opt/lensanalysis
cd /opt/lensanalysis

echo '3. 创建虚拟环境...'
python3 -m venv venv
venv/bin/pip install -q flask gunicorn

echo '4. 创建 systemd 服务...'
cat > /etc/systemd/system/lensanalysis-web.service <<EOF
[Unit]
Description=LensAnalysis License Web Service
After=network.target

[Service]
Type=notify
User=root
WorkingDirectory=/opt/lensanalysis
Environment=\"LENS_SECRET_KEY=${LENS_SECRET_KEY}\"
Environment=\"PORT=${WEB_PORT}\"
Environment=\"HOST=127.0.0.1\"
ExecStart=/opt/lensanalysis/venv/bin/gunicorn -w 4 -b 127.0.0.1:${WEB_PORT} tools.license_web:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

echo '5. 配置 nginx...'
cat > /etc/nginx/sites-available/lensanalysis <<'NGINX_EOF'
server {
    listen 80;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:${WEB_PORT};
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        add_header X-Frame-Options \"SAMEORIGIN\" always;
        add_header X-Content-Type-Options \"nosniff\" always;
        add_header X-XSS-Protection \"1; mode=block\" always;
    }
}
NGINX_EOF

ln -sf /etc/nginx/sites-available/lensanalysis /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx

echo '✅ 服务器配置完成！'
echo 'Web 服务端口: ${WEB_PORT}'
echo '访问地址: http://${SERVER_HOST}:${WEB_PORT}/admin'
"

# 显示部署信息
echo "准备部署到服务器..."
echo ""
echo "将执行以下操作："
echo "  1. 上传项目文件"
echo "  2. 安装依赖"
echo "  3. 配置服务"
echo "  4. 启动 Web 服务"
echo ""

read -p "确认继续？(y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "已取消"
    exit 0
fi

# 上传文件
echo "正在上传文件..."
ssh ${SERVER_USER}@${SERVER_HOST} "mkdir -p /opt/lensanalysis"

# 上传必要的文件
scp -q backend/license_manager.py ${SERVER_USER}@${SERVER_HOST}:/opt/lensanalysis/backend/
scp -q tools/license_web.py ${SERVER_USER}@${SERVER_HOST}:/opt/lensanalysis/tools/

# 在服务器上执行部署脚本
echo "正在配置服务器..."
ssh ${SERVER_USER}@${SERVER_HOST} "$REMOTE_SCRIPT"

# 重启服务
echo "正在启动服务..."
ssh ${SERVER_USER}@${SERVER_HOST} "systemctl daemon-reload && systemctl enable lensanalysis-web && systemctl restart lensanalysis-web"

echo ""
echo "=================================================="
echo "✅ 部署完成！"
echo "=================================================="
echo ""
echo "管理界面: http://${SERVER_HOST}:${WEB_PORT}/admin"
echo ""
echo "服务器管理命令:"
echo "  查看状态: ssh ${SERVER_USER}@${SERVER_HOST} 'systemctl status lensanalysis-web'"
echo "  查看日志: ssh ${SERVER_USER}@${SERVER_HOST} 'journalctl -u lensanalysis-web -f'"
echo "  重启服务: ssh ${SERVER_USER}@${SERVER_HOST} 'systemctl restart lensanalysis-web'"
echo ""
