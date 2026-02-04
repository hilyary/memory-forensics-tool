# Memory Forensics Tool - 析镜 LensAnalysis

基于 Volatility 3 框架的图形化内存取证工具，专为 CTF 竞赛和安全研究设计。

## 功能特性

- 🎨 **现代界面** - 简约大气的科技风格界面设计
- 🚀 **快速分析** - 智能缓存机制，重复操作秒级响应
- 🔍 **全面检测** - 支持 Volatility 3 核心插件（Windows/Linux/macOS）
- 🎯 **CTF 优化** - 内置 Flag 自动搜索功能
- 📊 **可视化展示** - 表格化呈现分析结果
- 📄 **报告导出** - 支持 Markdown/HTML/Word 格式报告
- 🌐 **代理支持** - 支持 HTTP/HTTPS/SOCKS5 代理下载符号表
- 💾 **符号表管理** - 自动下载和管理系统符号表

## 当前版本

**v1.0.0** (2026-02-02)

- 基于 Volatility 3.27.0
- 支持 Windows、Linux、macOS 内存镜像分析
- 自动符号表下载和管理
- 跨平台支持（Windows/macOS/Linux）

## 快速开始

### 系统要求

- Python 3.9+
- 支持 Windows 10/11、macOS 12+、Linux (Ubuntu/Kali)

### 安装

```bash
# 克隆项目
git clone https://github.com/hilyary/LensAnalysis.git
cd LensAnalysis

# 安装依赖
pip install -r requirements.txt

# 启动应用
python main.py
```

### 文档

- [用户使用手册](docs/用户使用手册.md) - 完整的功能使用说明
- [更新日志](CHANGELOG.md) - 版本更新记录

## 主要功能概览

### Windows 镜像分析
- 进程分析：pslist, pstree, psscan, dlllist, handles, cmdline
- 网络分析：netscan, netstat（含时间戳）
- 注册表：hivelist, printkey
- 恶意代码：malfind, ldrmodules
- 密码提取：hashdump, lsadump, cachedump

### Linux 镜像分析
- 进程分析：pslist, pstree, psaux, lsof
- 网络分析：netstat, sockstat, ip_addr
- 内核模块：lsmod, check_modules
- Bash 历史：bash

### macOS 镜像分析
- 进程分析：pslist, pstree, psaux
- 网络分析：netstat, ifconfig
- 内核扩展：lsmod
- 文件系统：lsof, list_files

### CTF 专用功能
- **Flag 搜索** - 自动搜索常见 Flag 格式
- **正则搜索** - 自定义正则表达式搜索
- **字符串提取** - 提取可打印字符串

## 项目结构

```
memory_forensics_tool/
├── backend/                # Python 后端
│   ├── api/               # API 接口层
│   │   └── handlers.py    # 请求处理器
│   ├── plugins/           # 自定义插件
│   │   ├── linux/         # Linux 专用插件
│   │   └── mac_contacts.py # macOS 联系人插件
│   ├── volatility_wrapper.py # Volatility 3 封装
│   ├── report_generator.py # 报告生成器
│   └── app.py             # 应用入口
├── frontend/              # 前端资源
│   ├── css/              # 样式文件
│   ├── js/               # JavaScript 文件
│   └── index.html        # 主页面
├── cache/                # 缓存目录（自动创建）
├── logs/                 # 日志目录（自动创建）
├── reports/              # 报告输出目录（自动创建）
├── docs/                 # 文档目录
│   └── 用户使用手册.md
├── requirements.txt      # Python 依赖
├── CHANGELOG.md          # 更新日志
└── main.py              # 主启动脚本
```

## 开源协议

**本项目采用 GPL v3 协议开源。**

### ⚠️ 商业使用说明

虽然 GPL v3 协议允许商业使用，但本项目有额外的商业使用限制：

**未经作者书面许可，禁止商业使用。**

商业用途包括但不限于：
- 直接销售本软件或其修改版本
- 将本软件集成到商业产品中
- 利用本软件提供付费服务
- 其他任何形式的商业获利行为

### 📧 商业使用授权

如需商业使用授权，请联系作者：

- **邮箱**: hil_yary@163.com
- **GitHub**: https://github.com/hilyary/LensAnalysis
- **个人博客**: https://hilyary.github.io

### ✅ 允许的使用

- 个人使用、学习和研究
- 教育机构和学术研究
- CTF 竞赛等安全竞赛活动
- 授权的安全测试和渗透测试
- 应急响应和数字取证（需有合法授权）

### ❌ 禁止的行为

- 未经授权的商业使用
- 移除或修改软件中的版权声明
- 将修改后的版本作为原作者官方版本发布
- 利用本软件进行任何违法违规活动
- 未经授权访问他人计算机系统
- 窃取他人隐私信息

## 技术架构

- **后端框架**: Python 3 + PyWebView
- **分析引擎**: Volatility 3.27.0
- **前端技术**: HTML5 + CSS3 + JavaScript
- **异步处理**: ThreadPoolExecutor
- **缓存机制**: 文件系统缓存
- **代理支持**: urllib + PySocks

## 快捷键

- `Ctrl/Cmd + K` - 快速搜索
- `Escape` - 关闭对话框

## 贡献

欢迎提交 Issue 和 Pull Request！

## 联系方式

- **作者**: hilyary
- **邮箱**: hil_yary@163.com
- **GitHub**: https://github.com/hilyary/LensAnalysis
- **个人博客**: https://hilyary.github.io

## 致谢

- [Volatility 3](https://github.com/volatilityfoundation/volatility3) 框架
- [PyWebView](https://pywebview.flowrl.com/) 项目

---

**析镜 LensAnalysis** - 专业的内存取证分析工具

最后更新：2026年2月2日
