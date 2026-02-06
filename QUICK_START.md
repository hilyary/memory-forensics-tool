# 析镜 LensAnalysis - 快速部署指南

## 🔑 第一步：生成密钥（最重要！）

**⚠️ 应用和服务器必须使用相同的密钥！**

```bash
# 生成密钥（只执行一次，妥善保存！）
LENS_SECRET_KEY="$(openssl rand -hex 32)"

# 保存到文件
echo "$LENS_SECRET_KEY" > /secure/path/lens_secret_key.txt

# 复制显示出来，保存到密码管理器
echo "请保存以下密钥到安全的地方："
echo "$LENS_SECRET_KEY"
```

---

## 🌐 第二步：部署 Web 服务（服务器）

### 快速部署

```bash
# 1. 设置密钥
export LENS_SECRET_KEY="你保存的密钥"

# 2. 运行部署脚本
./deploy_server.sh

# 3. 配置 nginx（推荐）
sudo apt install nginx
sudo cp nginx-config.conf /etc/nginx/sites-available/lensanalysis
sudo ln -s /etc/nginx/sites-available/lensanalysis /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# 4. 配置 HTTPS（推荐）
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

### 验证服务

访问：`https://your-domain.com/admin`

---

## 📦 第三步：打包应用（本地）

### macOS 打包

```bash
# 1. 设置相同的密钥
export LENS_SECRET_KEY="你保存的密钥"

# 2. 安装依赖
pip3 install pyinstaller pywebview

# 3. 执行打包
./build.sh

# 4. 生成的文件
# dist/LensAnalysis - 可执行文件
```

### Windows 打包

```powershell
# 1. 设置密钥
set LENS_SECRET_KEY=你保存的密钥

# 2. 安装依赖
pip install pyinstaller pywebview

# 3. 执行打包
pyinstaller build.spec

# 4. 生成的文件
# dist/LensAnalysis.exe - 可执行文件
```

---

## ✅ 验证部署

### 1. 测试 Web 服务

```bash
# 测试 API
curl -X POST https://your-domain.com/api/generate \
  -H "Content-Type: application/json" \
  -d '{"machine_code": "F068-9249-C256-87F1", "user_id": "test", "days": 365}'
```

### 2. 测试应用激活

1. 运行应用：`./dist/LensAnalysis`
2. 获取机器码
3. 在 Web 界面生成激活码
4. 在应用中激活

---

## 🔧 常用命令

### 服务器管理

```bash
# 查看服务状态
sudo systemctl status lensanalysis-web

# 重启服务
sudo systemctl restart lensanalysis-web

# 查看日志
sudo journalctl -u lensanalysis-web -f
```

### 密钥检查

```bash
# 服务器
cat /etc/systemd/system/lensanalysis-web.service | grep LENS_SECRET_KEY

# 应用（运行后查看）
echo $LENS_SECRET_KEY
```

---

## 📝 部署检查清单

- [ ] 密钥已生成并安全保存
- [ ] 服务器已部署 Web 服务
- [ ] nginx 已配置并启用 HTTPS
- [ ] 应用已使用相同密钥打包
- [ ] 激活流程测试通过
- [ ] 密钥已备份到多个安全位置

---

## 🚨 安全提醒

1. **永远不要将密钥提交到代码仓库**
2. **生产环境必须使用强密钥**（32字节随机）
3. **定期备份密钥和配置**
4. **限制 Web 服务的访问权限**
5. **启用 HTTPS 和基础认证**

---

## 📞 需要帮助？

查看完整文档：`DEPLOYMENT.md`
