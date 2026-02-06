# 析镜 LensAnalysis - 部署指南

## 📋 目录
1. [环境准备](#环境准备)
2. [服务器部署](#服务器部署)
3. [应用打包](#应用打包)
4. [密钥管理](#密钥管理)
5. [安全检查清单](#安全检查清单)

---

## 环境准备

### 开发/打包机器
- macOS 10.13+ / Windows 10+ / Linux
- Python 3.8+
- pip

### 服务器
- Linux (推荐 Ubuntu 20.04+)
- Python 3.8+
- root 或 sudo 权限

---

## 服务器部署

### 1. 生成并保存密钥

```bash
# 生成密钥（只执行一次，保存好这个密钥！）
export LENS_SECRET_KEY="$(openssl rand -hex 32)"

# 显示密钥（请保存到安全的地方）
echo $LENS_SECRET_KEY

# 添加到 ~/.bashrc 永久保存
echo "export LENS_SECRET_KEY=\"$LENS_SECRET_KEY\"" >> ~/.bashrc
source ~/.bashrc
```

### 2. 上传文件到服务器

```bash
# 在本地打包工具文件
tar czf lensanalysis-tools.tar.gz tools/ backend/ templates/

# 上传到服务器
scp lensanalysis-tools.tar.gz user@your-server:/tmp/

# 在服务器上解压
ssh user@your-server
cd /opt
sudo mkdir -p lensanalysis
cd lensanalysis
sudo tar xzf /tmp/lensanalysis-tools.tar.gz
```

### 3. 使用部署脚本

```bash
# 给脚本执行权限
chmod +x deploy_server.sh

# 运行部署（确保已设置 LENS_SECRET_KEY）
./deploy_server.sh
```

### 4. 配置 nginx 反向代理（推荐）

```bash
sudo apt install nginx

sudo tee /etc/nginx/sites-available/lensanalysis > /dev/null <<'EOF'
server {
    listen 80;
    server_name your-domain.com;  # 修改为你的域名

    # 基础认证（可选，增加安全性）
    auth_basic "LensAnalysis Admin";
    auth_basic_user_file /etc/nginx/.htpasswd;

    # 创建密码文件: htpasswd -c /etc/nginx/.htpasswd admin

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # 安全头
        add_header X-Frame-Options "SAMEORIGIN" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-XSS-Protection "1; mode=block" always;
    }
}
EOF

sudo ln -s /etc/nginx/sites-available/lensanalysis /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### 5. 配置 HTTPS（推荐）

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

---

## 应用打包

### 1. 设置密钥（与服务器使用相同的密钥！）

```bash
# 使用与服务器相同的密钥
export LENS_SECRET_KEY="你之前保存的密钥"
```

### 2. 安装打包工具

```bash
pip3 install pyinstaller pywebview
```

### 3. 执行打包

```bash
# 方法 1: 使用打包脚本
chmod +x build.sh
./build.sh

# 方法 2: 直接使用 PyInstaller
pyinstaller build.spec
```

### 4. 签名（macOS）

```bash
# 如果有开发者证书，可以签名
codesign --sign "Developer ID Application: Your Name" dist/LensAnalysis
```

### 5. 打包为 dmg（macOS，可选）

```bash
# 创建 dmg 镜像
hdiutil create -volname "LensAnalysis" -srcfolder dist -ov -format UDZO LensAnalysis.dmg
```

---

## 密钥管理

### ⚠️ 重要提示

1. **应用和服务器必须使用相同的密钥**
2. **密钥一旦设置不要更改**（否则已激活的软件会失效）
3. **将密钥备份到安全的地方**

### 密钥存储位置

```
本地开发:     ~/.bashrc 或 .env
服务器:       /etc/systemd/system/lensanalysis-web.service
打包时:       打包脚本中设置环境变量
```

---

## 安全检查清单

### 服务器端

- [ ] 设置了强随机密钥 (`LENS_SECRET_KEY`)
- [ ] 使用 systemd 管理服务
- [ ] 配置了 nginx 反向代理
- [ ] 启用了 HTTPS
- [ ] 配置了基础认证（可选）
- [ ] 限制了 API 访问频率（可选）
- [ ] 定期检查日志

### 应用端

- [ ] 打包时使用了正确的密钥
- [ ] 移除了调试代码
- [ ] 签名了可执行文件（macOS/Windows）
- [ ] 测试了激活/验证流程

### 密钥安全

- [ ] 密钥长度足够（32字节十六进制）
- [ ] 密钥存储在安全的位置
- [ ] 密钥没有硬编码在代码中
- [ ] 密钥有备份

---

## 测试

### 1. 测试 Web 服务

```bash
# 测试机器码验证
curl -X POST http://your-server/api/verify \
  -H "Content-Type: application/json" \
  -d '{"machine_code": "F068-9249-C256-87F1"}'

# 测试激活码生成
curl -X POST http://your-server/api/generate \
  -H "Content-Type: application/json" \
  -d '{"machine_code": "F068-9249-C256-87F1", "user_id": "test_user", "days": 365}'
```

### 2. 测试应用

```bash
# 运行打包的应用
./dist/LensAnalysis

# 检查激活状态
cat ~/Library/Application\ Support/LensAnalysis/license.json
```

---

## 故障排查

### Web 服务无法启动

```bash
# 查看服务状态
sudo systemctl status lensanalysis-web

# 查看日志
sudo journalctl -u lensanalysis-web -n 50

# 检查端口占用
sudo netstat -tlnp | grep 8080
```

### 激活失败

1. 检查密钥是否一致
2. 检查机器码格式
3. 查看应用日志：
   ```bash
   tail -f ~/Library/Application\ Support/LensAnalysis/logs/app.log
   ```

---

## 维护

### 更新服务

```bash
# 1. 停止服务
sudo systemctl stop lensanalysis-web

# 2. 更新文件
cd /opt/lensanalysis
# 上传新文件并解压

# 3. 重启服务
sudo systemctl start lensanalysis-web
```

### 备份

```bash
# 备份密钥
echo $LENS_SECRET_KEY > /backup/lens_secret_key.txt

# 备份配置
tar czf lensanalysis-backup-$(date +%Y%m%d).tar.gz /opt/lensanalysis
```

---

## 联系支持

如有问题，请提供：
1. 操作系统版本
2. Python 版本
3. 错误日志
4. 复现步骤
