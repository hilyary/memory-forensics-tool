# Memory Forensics Tool - 使用说明

## 界面预览

界面采用**现代浅色主题**设计，参考了 Linear、Raycast 等现代工具的设计风格。

### 配色方案
- **主色调**: 现代蓝色 (#3b82f6)
- **辅助色**: 紫色 (#8b5cf6)
- **背景**: 白色/浅灰
- **文本**: 深灰/黑色

### 界面特点
- 简约大气
- 浅色主题，不再使用黑色背景
- 现代阴影效果
- 流畅动画过渡
- 清晰的视觉层次

## 快速测试

### 方法1: 浏览器预览（推荐）

直接在浏览器中打开 HTML 文件即可预览界面：

```bash
# 在浏览器中打开
open /Users/hilyary/knowledge/lsw/毕业设计/memory_forensics_tool/frontend/index.html
```

或者启动本地服务器：

```bash
cd /Users/hilyary/knowledge/lsw/毕业设计/memory_forensics_tool
python3 -m http.server 8888

# 然后在浏览器访问
# http://localhost:8888/frontend/index.html
```

### 方法2: 启动完整应用

```bash
cd /Users/hilyary/knowledge/lsw/毕业设计/memory_forensics_tool

# 安装依赖
pip3 install -r requirements.txt

# 启动应用
python3 main.py
```

## 功能演示

界面支持**演示模式**，无需实际运行后端即可体验界面交互：

### 演示模式功能
1. 加载模拟镜像
2. 运行各种分析插件（进程列表、网络连接、文件扫描等）
3. 搜索 Flag
4. 生成报告
5. Toast 通知反馈

### 操作步骤
1. 点击 **"加载镜像"** 按钮加载模拟镜像
2. 点击左侧功能按钮执行分析（如：进程列表、网络连接）
3. 点击 **"搜索Flag"** 查看 Flag 搜索功能
4. 查看分析结果的表格展示

## 界面说明

### 顶部导航栏
- 左侧：Logo 和应用名称
- 中间：系统状态指示器
- 右侧：清除缓存、导出报告按钮

### 左侧边栏
- 镜像管理：加载镜像按钮
- 进程分析：进程列表、进程树、进程扫描、命令行
- 网络分析：网络连接
- 注册表：注册表列表
- 文件系统：文件扫描
- 恶意软件：恶意代码查找
- CTF工具：搜索Flag（紫色高亮）

### 主内容区
- 欢迎页：应用启动时显示
- 镜像信息卡片：显示当前加载的镜像信息
- 结果面板：表格展示分析结果
- 加载动画：分析时显示加载状态

## 技术栈

- **前端**: HTML5 + CSS3 + JavaScript (ES6+)
- **后端**: Python 3 + PyWebView
- **分析引擎**: Volatility 3

## 项目文件结构

```
memory_forensics_tool/
├── frontend/
│   ├── index.html          # 主页面
│   ├── css/
│   │   ├── style.css       # 主样式（浅色主题）
│   │   └── components.css  # 组件样式
│   └── js/
│       ├── app.js          # 应用逻辑
│       └── components.js   # UI 组件库
├── backend/
│   ├── app.py             # 应用入口
│   ├── api/
│   │   └── handlers.py    # API 处理
│   ├── volatility_wrapper.py  # Volatility 封装
│   ├── task_manager.py    # 任务管理
│   └── report_generator.py # 报告生成
├── main.py                # 主启动脚本
├── requirements.txt       # Python 依赖
└── README.md             # 项目文档
```

## 下一步

1. **安装 Volatility 3**
   ```bash
   pip3 install volatility3
   ```

2. **准备测试镜像**
   - 可从 Volatility 官网获取测试镜像
   - 或使用虚拟机生成内存转储

3. **实际分析**
   - 启动应用后加载真实镜像
   - 执行各种分析功能
   - 导出分析报告

## 常见问题

**Q: 界面显示不正常？**
A: 确保使用现代浏览器（Chrome、Firefox、Safari、Edge 最新版本）

**Q: 演示模式和完整模式的区别？**
A: 演示模式使用模拟数据，无需后端即可体验界面；完整模式需要运行 Python 后端

**Q: 如何更改主题颜色？**
A: 编辑 `frontend/css/style.css` 中的 `:root` 变量

**Q: 支持哪些内存镜像格式？**
A: .raw、.vmem、.dmp、.lime 等主流格式
