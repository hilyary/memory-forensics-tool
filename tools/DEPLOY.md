# 析镜 LensAnalysis - 激活码生成Web服务

这是一个部署在云服务器上的Web服务，允许用户自助生成激活码。

## 功能特点

- 🌐 Web界面，用户自助操作
- 📱 响应式设计，支持移动端
- ✅ 实时验证机器码格式
- 📋 一键复制激活码
- 🔒 安全的后端验证

## 环境要求

- Python 3.7+
- Flask

## 安装依赖

```bash
pip install flask
```

或使用项目依赖：

```bash
pip install -r requirements.txt
```

## 本地测试

```bash
# 方式1：直接运行
python3 tools/license_web.py

# 方式2：使用Flask
FLASK_ENV=development python3 tools/license_web.py

# 方式3：指定端口
PORT=8080 python3 tools/license_web.py
```

访问: http://localhost:5000

## 云服务器部署

### 使用 systemd（推荐）

1. 创建服务文件 `/etc/systemd/system/lensanalysis-license.service`:

```ini
[Unit]
Description=LensAnalysis License Web Service
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/path/to/memory_forensics_tool
Environment="PORT=5000"
ExecStart=/usr/bin/python3 tools/license_web.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

2. 启动服务:

```bash
sudo systemctl daemon-reload
sudo systemctl enable lensanalysis-license
sudo systemctl start lensanalysis-license
sudo systemctl status lensanalysis-license
```

### 使用 Gunicorn（生产环境推荐）

1. 安装 Gunicorn:

```bash
pip install gunicorn
```

2. 启动服务:

```bash
# 4个worker进程
gunicorn -w 4 -b 0.0.0.0:5000 tools.license_web:app

# 或使用systemd
ExecStart=/usr/local/bin/gunicorn -w 4 -b 0.0.0.0:5000 tools.license_web:app
```

### 使用 Nginx 反向代理

Nginx 配置示例：

```nginx
server {
    listen 80;
    server_name license.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 配置 HTTPS（使用 Let's Encrypt）

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d license.yourdomain.com
```

## API 接口

### POST /api/generate

生成激活码

**请求体:**
```json
{
    "machine_code": "F068-9249-C256-87F1",
    "user_id": "user123",
    "days": 30
}
```

**响应:**
```json
{
    "success": true,
    "data": {
        "license_key": "LENS-F0689249-user123-1772973178-...",
        "machine_code": "F068-9249-C256-87F1",
        "user_id": "user123",
        "days": 30,
        "expiry": "30天"
    }
}
```

### POST /api/verify

验证机器码格式

**请求体:**
```json
{
    "machine_code": "F068-9249-C256-87F1"
}
```

**响应:**
```json
{
    "success": true,
    "valid": true,
    "error": null
}
```

## 安全建议

1. **限制访问**: 使用防火墙或Nginx限制访问IP
2. **添加认证**: 考虑添加简单的访问密码
3. **HTTPS**: 生产环境务必使用HTTPS
4. **日志监控**: 记录所有激活码生成操作
5. **速率限制**: 防止滥用，添加速率限制

## Docker 部署（可选）

创建 `Dockerfile`:

```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY . .

RUN pip install flask gunicorn

EXPOSE 5000

CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "tools.license_web:app"]
```

构建并运行:

```bash
docker build -t lensanalysis-license .
docker run -d -p 5000:5000 --name license-service lensanalysis-license
```

## 监控和日志

```bash
# 查看服务日志
sudo journalctl -u lensanalysis-license -f

# 查看最近100条日志
sudo journalctl -u lensanalysis-license -n 100
```

## 故障排查

**问题**: 服务无法启动
- 检查端口是否被占用: `netstat -tlnp | grep 5000`
- 检查Python路径: `which python3`
- 检查文件权限: `ls -la tools/`

**问题**: 无法访问网页
- 检查防火墙: `sudo ufw status`
- 检查服务状态: `sudo systemctl status lensanalysis-license`
- 检查Nginx配置: `sudo nginx -t`

**问题**: 激活码生成失败
- 检查后端日志
- 验证机器码格式是否正确
- 确认 `backend.license_manager` 模块可用

## 更新部署

```bash
# 拉取最新代码
git pull

# 重启服务
sudo systemctl restart lensanalysis-license

# 检查状态
sudo systemctl status lensanalysis-license
```
