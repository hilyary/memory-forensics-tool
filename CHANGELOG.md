# 更新日志 (CHANGELOG)

本文档记录析镜 LensAnalysis 的所有重要变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/)，
版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

---

## [1.0.0] - 2026-02-02

### 新增
- 首次发布析镜 LensAnalysis
- 基于 Volatility 3.27.0 框架
- 支持 Windows、Linux、macOS 内存镜像分析
- 图形化用户界面（基于 PyWebView）
- 自动符号表下载和管理
- 代理支持（HTTP/HTTPS/SOCKS5）
- 智能缓存机制
- 分析结果导出（Markdown/HTML/Word）

### Windows 分析功能
- 进程分析：pslist, pstree, psscan, dlllist, handles, cmdline, consoles
- 网络分析：netscan（含时间戳）, netstat
- 注册表：hivelist, printkey
- 文件系统：filescan, files
- 恶意代码：malfind, ldrmodules
- 密码提取：hashdump, lsadump, cachedump
- 系统信息：svcscan, getsids, envars, timers, callbacks, ssdt, verinfo

### Linux 分析功能
- 进程分析：pslist, pstree, psscan, psaux
- 网络分析：netstat, sockstat, ip_addr, ip_link
- 文件系统：lsof, elfs, mountinfo
- 内核模块：lsmod, check_modules
- 命令历史：bash
- 环境变量：envars
- 内存分析：malfind, vmayarascan, maps

### macOS 分析功能
- 进程分析：pslist, pstree, psaux
- 网络分析：netstat, ifconfig, socket_filters
- 文件系统：lsof, list_files, mount
- 内核扩展：lsmod
- 系统检查：check_syscall, check_sysctl, check_trap_table
- 日志分析：dmesg, kevents, vfsevents

### CTF 专用功能
- Flag 自动搜索（支持多种常见格式）
- 正则表达式搜索
- 字符串提取
- 搜索历史记录

### 符号表管理
- Windows 符号表自动下载（绕过 Volatility3 PDB 解析 bug）
- Linux/macOS 符号表从 GitHub 自动下载
- 符号表状态查看
- 手动安装符号表

### 技术特性
- 跨平台支持（Windows/macOS/Linux）
- 代理配置和测试
- 跨平台临时文件处理
- 异步任务处理
- 结果缓存和复用
- 详细日志记录

---

## 版本说明

### 版本号格式

`主版本号.次版本号.修订号`

- **主版本号**：不兼容的 API 变更
- **次版本号**：向下兼容的功能新增
- **修订号**：向下兼容的问题修复

### 更新类型

- **新增** (Added): 新功能
- **变更** (Changed): 功能变更
- **弃用** (Deprecated): 即将移除的功能
- **移除** (Removed): 已移除的功能
- **修复** (Fixed): 问题修复
- **安全** (Security): 安全相关修复

---

## 路线图

### 计划中的功能 (Future)

- [ ] 更多自定义插件开发
- [ ] 内存镜像比对功能
- [ ] 自动化分析流程
- [ ] 云端符号表缓存
- [ ] 协作分析功能
- [ ] 插件市场

---

**析镜 LensAnalysis** - 专业的内存取证分析工具
