# 析镜 LensAnalysis - 管理员工具

此文件夹包含管理员工具，**不应被打包到发布版本中**。

## 工具列表

### 1. 命令行激活码生成工具

`generate_license.py` - 根据用户机器码生成激活码

**使用方法：**

```bash
# 为特定机器生成永久激活码
python tools/generate_license.py ABCD1234-EFGH-5678-IJKL user123

# 为特定机器生成限时激活码（30天）
python tools/generate_license.py ABCD1234-EFGH-5678-IJKL user123 --days 30

# 批量生成
python tools/generate_license.py ABCD1234-EFGH-5678-IJKL user1 user2 user3 --days 365
```

---

### 2. Web版激活码生成服务 ⭐

`license_web.py` - Web服务，包含两个页面：

#### 📱 用户版（云服务器）
- **访问地址**: `http://yourserver.com/`
- **功能**: 固定生成 **365天** 有效期的激活码
- **用途**: 部署到云服务器，让普通用户自助生成激活码

#### 🔐 管理员版（本地运行）
- **访问地址**: `http://localhost:8080/admin`
- **功能**: 可 **自定义任意天数** 或永久激活码
- **用途**: 管理员本地使用，灵活设置有效期

**快速启动：**

```bash
# 启动Web服务
python3 tools/license_web.py

# 指定端口
PORT=8080 python3 tools/license_web.py

# 使用 gunicorn（生产环境）
gunicorn -w 4 -b 0.0.0.0:5000 tools.license_web:app
```

**页面特点：**
- 🌐 Web界面，用户自助操作
- 📱 响应式设计，支持手机访问
- ✅ 实时验证机器码格式
- 📋 点击激活码自动复制
- 🎨 现代紫色渐变UI设计

**详细部署文档：** 参见 [DEPLOY.md](./DEPLOY.md)

---

## 激活流程

### 命令行方式：
1. 用户启动软件，获取机器码（16位，格式：XXXX-XXXX-XXXX-XXXX）
2. 用户在公众号发送机器码给管理员
3. 管理员使用 `generate_license.py` 生成激活码
4. 管理员将激活码发送给用户
5. 用户在软件中输入激活码完成激活

### Web方式 - 用户版：
1. 用户启动软件，获取机器码
2. 用户访问你部署的云服务器网页
3. 输入机器码和用户ID
4. 自动获得365天有效期的激活码
5. 复制激活码，在软件中输入完成激活

### Web方式 - 管理员版：
1. 管理员启动本地Web服务
2. 访问 http://localhost:8080/admin
3. 输入机器码、用户ID和自定义天数
4. 生成激活码并发送给用户

---

## 云服务器部署示例

### 1. 安装依赖

```bash
pip install flask gunicorn
```

### 2. 启动服务

```bash
# 开发测试
python3 tools/license_web.py

# 生产环境
gunicorn -w 4 -b 0.0.0.0:5000 tools.license_web:app
```

### 3. 使用 systemd 管理

创建服务文件 `/etc/systemd/system/lensanalysis-license.service`:

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

[Install]
WantedBy=multi-user.target
```

启动服务：

```bash
sudo systemctl daemon-reload
sudo systemctl enable lensanalysis-license
sudo systemctl start lensanalysis-license
```

---

## 打包注意事项

⚠️ **重要**：在使用 PyInstaller 或 Nuitka 打包时，请确保排除此文件夹：

**Nuitka:**
```bash
nuitka --standalone --enable-plugin=pywebview \
    --exclude-module=tools \
    backend/app.py
```

**PyInstaller:**
```bash
pyinstaller --exclude-module tools backend/app.py
```

或在 .spec 文件中添加:
```python
excludes=['tools']
```

---

## 文件结构

```
tools/
├── generate_license.py     # 命令行工具
├── license_web.py          # Web服务后端
├── templates/
│   ├── user.html           # 用户版页面（固定365天）
│   └── admin.html          # 管理员版页面（可自定义天数）
├── static/                 # 静态资源（预留）
├── README.md              # 本文件
└── DEPLOY.md              # Web部署详细文档
```
