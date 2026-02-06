/**
 * Memory Forensics Tool - Main Application
 * 内存取证工具主应用逻辑
 */

class ForensicsApp {
    constructor() {
        this.currentImage = null;
        this.api = window.pywebview ? window.pywebview.api : null;
        this.currentResults = null;
        this.executionStartTime = null;
        this.isDemoMode = !window.pywebview;
    }

    /**
     * 初始化应用
     */
    async init() {
        this.log('应用初始化中...');

        // 绑定事件
        this.bindEvents();

        // 检查API状态
        this.log('isDemoMode: ' + this.isDemoMode);
        this.log('window.pywebview: ' + (window.pywebview ? '存在' : '不存在'));
        this.log('this.api: ' + (this.api ? '存在' : '不存在'));
        if (this.api) {
            const apiMethods = Object.keys(this.api);
            this.log('API 方法数量: ' + apiMethods.length);
            this.log('get_license_status 存在: ' + apiMethods.includes('get_license_status'));
        }

        if (this.isDemoMode) {
            this.log('运行在演示模式 (无 pywebview)');
            this.setSystemStatus('演示模式', 'warning');
            return;
        }

        // 等待pywebview就绪
        try {
            await window.pywebview.ready;
            this.log('pywebview 已就绪');

            // 检查许可证状态
            await this.checkLicenseStatus();

        } catch (error) {
            this.log('pywebview 初始化失败: ' + error.message, 'error');
            this.setSystemStatus('初始化失败', 'error');
        }
    }

    /**
     * 绑定事件处理器
     */
    bindEvents() {
        // 加载镜像
        const loadImageBtn = document.getElementById('loadImageBtn');
        const welcomeLoadBtn = document.getElementById('welcomeLoadBtn');
        if (loadImageBtn) loadImageBtn.addEventListener('click', () => this.loadImage());
        if (welcomeLoadBtn) welcomeLoadBtn.addEventListener('click', () => this.loadImage());

        // 插件按钮
        document.querySelectorAll('.sidebar-btn[data-plugin]').forEach(btn => {
            btn.addEventListener('click', () => {
                const plugin = btn.dataset.plugin;
                if (plugin) this.runPlugin(plugin);
            });
        });

        // CTF功能
        const searchFlagBtn = document.getElementById('searchFlagBtn');
        if (searchFlagBtn) searchFlagBtn.addEventListener('click', () => this.searchFlag());

        // 导出功能
        const exportBtn = document.getElementById('exportBtn');
        const exportResults = document.getElementById('exportResults');
        if (exportBtn) exportBtn.addEventListener('click', () => this.generateReport());
        if (exportResults) exportResults.addEventListener('click', () => this.exportCurrentResults());

        // 缓存管理
        const clearCacheBtn = document.getElementById('clearCacheBtn');
        if (clearCacheBtn) clearCacheBtn.addEventListener('click', () => this.clearCache());

        // 搜索结果
        const searchInResults = document.getElementById('searchInResults');
        if (searchInResults) searchInResults.addEventListener('click', () => this.searchInResults());

        // 激活按钮
        const activateBtn = document.getElementById('activateBtn');
        if (activateBtn) {
            activateBtn.addEventListener('click', () => this.activateLicense());
        }

        // 复制机器码按钮
        const copyMachineCodeBtn = document.getElementById('copyMachineCodeBtn');
        if (copyMachineCodeBtn) {
            copyMachineCodeBtn.addEventListener('click', () => this.copyMachineCode());
        }
    }

    /**
     * 加载系统信息
     */
    async loadSystemInfo() {
        if (this.isDemoMode) return;

        try {
            const result = await this.api.get_system_info();
            if (result && result.status === 'success') {
                const data = result.data;
                this.log(`系统: ${data.system} ${data.os_release}`);
                this.log(`Python: ${data.python_version}`);
                this.log(`Volatility: ${data.volatility_version}`);
                this.setSystemStatus('系统就绪', 'active');
            }
        } catch (error) {
            this.log('获取系统信息失败: ' + error.message, 'error');
            this.setSystemStatus('系统错误', 'error');
        }
    }

    /**
     * 加载可用插件列表
     */
    async loadAvailablePlugins() {
        if (this.isDemoMode) return;

        try {
            const result = await this.api.get_available_plugins();
            if (result && result.status === 'success') {
                this.log(`已加载 ${this.countPlugins(result.data)} 个插件`);
            }
        } catch (error) {
            this.log('加载插件列表失败: ' + error.message, 'error');
        }
    }

    /**
     * 加载内存镜像
     */
    async loadImage() {
        try {
            if (this.isDemoMode) {
                // 演示模式使用模拟数据
                this.currentImage = {
                    name: 'sample_memory.raw',
                    size: '256.00 MB',
                    hash: 'a1b2c3d4e5f6...',
                    path: '/path/to/sample_memory.raw'
                };
                this.displayImageInfo(this.currentImage);
                this.hideWelcome();
                this.showImageInfo();
                this.toast('success', '镜像加载成功 (演示模式)', `已加载 ${this.currentImage.name}`);
                return;
            }

            // 调用文件选择对话框
            this.log('打开文件选择对话框...');
            const result = await this.api.load_memory_image_dialog();

            if (result && result.status === 'success') {
                this.currentImage = result.data;
                this.displayImageInfo(this.currentImage);
                this.hideWelcome();
                this.showImageInfo();
                this.toast('success', '镜像加载成功', `已加载 ${this.currentImage.name}`);
                this.log(`镜像加载成功: ${this.currentImage.name} (${this.currentImage.size})`);
            } else if (result && result.status === 'cancelled') {
                this.log('用户取消了文件选择', 'info');
            } else {
                this.toast('error', '加载失败', result?.message || '未知错误');
            }
        } catch (error) {
            this.toast('error', '加载失败', error.message);
            this.log('加载镜像失败: ' + error.message, 'error');
        }
    }

    /**
     * 运行分析插件
     */
    async runPlugin(pluginId) {
        if (!this.currentImage) {
            this.toast('warning', '未加载镜像', '请先加载内存镜像');
            return;
        }

        try {
            // 更新按钮状态
            this.setActivePlugin(pluginId);
            this.executionStartTime = Date.now();

            let result;
            if (this.isDemoMode) {
                // 演示模式使用模拟数据
                await this.delay(800);
                result = this.getMockResult(pluginId);
            } else {
                result = await this.api.run_analysis(pluginId);
            }

            if (result && result.status === 'success') {
                this.currentResults = result.data;
                this.displayResults(result.data, result.cached);

                const executionTime = this.isDemoMode ? '0.80' : ((Date.now() - this.executionStartTime) / 1000).toFixed(2);
                const cacheStatus = result.cached ? ' (来自缓存)' : '';
                this.toast('success', '分析完成', `${pluginId} 耗时 ${executionTime}秒${cacheStatus}`);
                this.log(`${pluginId} 分析完成，耗时 ${executionTime}秒${cacheStatus}`);
            } else {
                this.toast('error', '分析失败', result?.message || '未知错误');
            }
        } catch (error) {
            this.toast('error', '分析失败', error.message);
            this.log(`${pluginId} 分析失败: ${error.message}`, 'error');
        }
    }

    /**
     * 搜索Flag
     */
    async searchFlag() {
        if (!this.currentImage) {
            this.toast('warning', '未加载镜像', '请先加载内存镜像');
            return;
        }

        try {
            let result;
            if (this.isDemoMode) {
                await this.delay(600);
                result = {
                    status: 'success',
                    data: {
                        flags: [
                            { offset: '0x12345678', pattern: 'flag{test_flag_12345}', context: '...flag{test_flag_12345}...' },
                            { offset: '0x23456789', pattern: 'FLAG{another_flag}', context: '...some FLAG{another_flag} here...' }
                        ],
                        count: 2
                    }
                };
            } else {
                result = await this.api.search_flag();
            }

            if (result && result.status === 'success') {
                this.displayFlagResults(result.data);
                this.toast('success', '搜索完成', `找到 ${result.data.count} 个可能的 Flag`);
            } else {
                this.toast('error', '搜索失败', result?.message || '未知错误');
            }
        } catch (error) {
            this.toast('error', '搜索失败', error.message);
        }
    }

    /**
     * 生成报告
     */
    async generateReport() {
        if (!this.currentImage) {
            this.toast('warning', '未加载镜像', '请先加载内存镜像并执行分析');
            return;
        }

        try {
            let result;
            if (this.isDemoMode) {
                await this.delay(500);
                result = { status: 'success', data: { path: '/path/to/report.md' } };
            } else {
                result = await this.api.generate_report('markdown');
            }

            if (result && result.status === 'success') {
                this.toast('success', '报告已生成', result.data.path);
            } else {
                this.toast('error', '生成失败', result?.message || '未知错误');
            }
        } catch (error) {
            this.toast('error', '生成失败', error.message);
        }
    }

    /**
     * 导出当前结果
     */
    async exportCurrentResults() {
        if (!this.currentResults) {
            this.toast('warning', '无数据', '请先执行分析');
            return;
        }

        try {
            const results = this.extractResultsData(this.currentResults);

            if (this.isDemoMode) {
                this.toast('success', '导出成功', `已导出 ${results.length} 条记录 (演示模式)`);
                return;
            }

            const result = await this.api.export_results(results, 'csv');

            if (result && result.status === 'success') {
                this.toast('success', '导出成功', `已导出 ${result.data.count} 条记录`);
            } else {
                this.toast('error', '导出失败', result?.message || '未知错误');
            }
        } catch (error) {
            this.toast('error', '导出失败', error.message);
        }
    }

    /**
     * 清除缓存
     */
    async clearCache() {
        try {
            if (this.isDemoMode) {
                this.toast('success', '缓存已清除', '演示模式');
                return;
            }

            const result = await this.api.clear_cache();
            if (result && result.status === 'success') {
                this.toast('success', '缓存已清除', '所有缓存数据已被删除');
            }
        } catch (error) {
            this.toast('error', '清除失败', error.message);
        }
    }

    /**
     * 在结果中搜索
     */
    searchInResults() {
        this.toast('info', '搜索功能', '结果内搜索功能开发中...');
    }

    // ==================== UI 更新方法 ====================

    /**
     * 显示镜像信息
     */
    displayImageInfo(imageInfo) {
        const el = (id) => document.getElementById(id);
        if (el('imageName')) el('imageName').textContent = imageInfo.name || '-';
        if (el('imageSize')) el('imageSize').textContent = imageInfo.size || '-';
        if (el('imageHash')) el('imageHash').textContent = imageInfo.hash || '-';
        if (el('imagePath')) el('imagePath').textContent = imageInfo.path || '-';
    }

    /**
     * 显示分析结果
     */
    displayResults(data, cached = false) {
        const panel = document.getElementById('resultsPanel');
        const emptyState = document.getElementById('resultsEmpty');
        const tableContainer = document.getElementById('resultsTableContainer');
        const thead = document.getElementById('resultsTableHead');
        const tbody = document.getElementById('resultsTableBody');
        const cacheIndicator = document.getElementById('cacheIndicator');

        // 显示面板
        if (panel) panel.classList.remove('hidden');
        if (emptyState) emptyState.classList.add('hidden');
        if (tableContainer) tableContainer.classList.remove('hidden');
        if (cacheIndicator) {
            if (cached) {
                cacheIndicator.classList.remove('hidden');
            } else {
                cacheIndicator.classList.add('hidden');
            }
        }

        // 更新标题
        const titleEl = document.getElementById('resultsTitle');
        if (titleEl) titleEl.textContent = this.getPluginDisplayName(data.plugin);

        // 更新统计
        const results = data.results || [];
        const countEl = document.getElementById('resultCount');
        const timeEl = document.getElementById('executionTime');
        if (countEl) countEl.textContent = results.length;
        if (timeEl) {
            timeEl.textContent = this.executionStartTime
                ? ((Date.now() - this.executionStartTime) / 1000).toFixed(2) + 's'
                : '-';
        }

        // 构建表格
        this.buildTable(thead, tbody, results, data.plugin);
    }

    /**
     * 显示Flag搜索结果
     */
    displayFlagResults(data) {
        const panel = document.getElementById('resultsPanel');
        const emptyState = document.getElementById('resultsEmpty');
        const tableContainer = document.getElementById('resultsTableContainer');
        const thead = document.getElementById('resultsTableHead');
        const tbody = document.getElementById('resultsTableBody');
        const cacheIndicator = document.getElementById('cacheIndicator');

        if (panel) panel.classList.remove('hidden');
        if (emptyState) emptyState.classList.add('hidden');
        if (tableContainer) tableContainer.classList.remove('hidden');
        if (cacheIndicator) cacheIndicator.classList.add('hidden');

        const titleEl = document.getElementById('resultsTitle');
        if (titleEl) titleEl.textContent = 'Flag 搜索结果';

        const countEl = document.getElementById('resultCount');
        const timeEl = document.getElementById('executionTime');
        if (countEl) countEl.textContent = data.count;
        if (timeEl) timeEl.textContent = '-';

        if (thead) thead.innerHTML = `
            <tr>
                <th>偏移</th>
                <th>匹配内容</th>
                <th>上下文</th>
            </tr>
        `;

        if (tbody) tbody.innerHTML = data.flags.map(flag => `
            <tr>
                <td class="monospace">${this.escapeHtml(flag.offset)}</td>
                <td><span class="highlight">${this.escapeHtml(flag.pattern)}</span></td>
                <td class="monospace">${this.escapeHtml(flag.context)}</td>
            </tr>
        `).join('');
    }

    /**
     * 构建结果表格
     */
    buildTable(thead, tbody, results, plugin) {
        const columns = this.getTableColumns(plugin);

        if (!columns || columns.length === 0 || !results || results.length === 0) {
            if (thead) thead.innerHTML = '';
            if (tbody) tbody.innerHTML = '<tr><td colspan="100%" style="text-align:center;color:var(--text-muted);">暂无数据</td></tr>';
            return;
        }

        // 构建表头
        if (thead) {
            thead.innerHTML = `
                <tr>
                    ${columns.map(col => `<th>${col.label}</th>`).join('')}
                </tr>
            `;
        }

        // 构建表格内容
        if (tbody) {
            tbody.innerHTML = results.map(row => `
                <tr>
                    ${columns.map(col => `
                        <td class="${col.monospace ? 'monospace' : ''}">
                            ${col.format ? col.format(row[col.key]) : this.escapeHtml(String(row[col.key] ?? '-'))}
                        </td>
                    `).join('')}
                </tr>
            `).join('');
        }
    }

    /**
     * 获取表格列配置
     */
    getTableColumns(plugin) {
        const columnMap = {
            'pslist': [
                { key: 'pid', label: 'PID', monospace: true },
                { key: 'ppid', label: 'PPID', monospace: true },
                { key: 'name', label: '进程名' },
                { key: 'threads', label: '线程' },
                { key: 'handles', label: '句柄' },
                { key: 'create_time', label: '创建时间' }
            ],
            'netscan': [
                { key: 'protocol', label: '协议' },
                { key: 'local_address', label: '本地地址', monospace: true },
                { key: 'local_port', label: '本地端口', monospace: true },
                { key: 'remote_address', label: '远程地址', monospace: true },
                { key: 'remote_port', label: '远程端口', monospace: true },
                { key: 'state', label: '状态' },
                { key: 'process_name', label: '进程' }
            ],
            'filescan': [
                { key: 'offset', label: '偏移', monospace: true },
                { key: 'path', label: '文件路径' },
                { key: 'size', label: '大小', format: v => this.formatSize(v) }
            ],
            'cmdline': [
                { key: 'pid', label: 'PID', monospace: true },
                { key: 'name', label: '进程名' },
                { key: 'command_line', label: '命令行' }
            ],
            'malfind': [
                { key: 'pid', label: 'PID', monospace: true },
                { key: 'process_name', label: '进程名' },
                { key: 'address', label: '地址', monospace: true },
                { key: 'size', label: '大小', format: v => this.formatSize(v) },
                { key: 'protection', label: '保护', monospace: true },
                { key: 'suspicious', label: '可疑', format: v => v ? '<span class="tag error">是</span>' : '<span class="tag success">否</span>' }
            ]
        };

        return columnMap[plugin] || this.getDefaultColumns();
    }

    /**
     * 获取默认列配置
     */
    getDefaultColumns() {
        if (!this.currentResults || !this.currentResults.results || this.currentResults.results.length === 0) {
            return [];
        }
        return Object.keys(this.currentResults.results[0]).map(key => ({
            key,
            label: key.toUpperCase().replace(/_/g, ' '),
            monospace: false
        }));
    }

    /**
     * 提取结果数据用于导出
     */
    extractResultsData(data) {
        return data.results || [];
    }

    // ==================== UI 辅助方法 ====================

    hideWelcome() {
        const el = document.getElementById('welcomePanel');
        if (el) el.classList.add('hidden');
    }

    showImageInfo() {
        const el = document.getElementById('imageInfoPanel');
        if (el) el.classList.remove('hidden');
    }

    setActivePlugin(pluginId) {
        document.querySelectorAll('.sidebar-btn[data-plugin]').forEach(btn => {
            btn.classList.remove('active');
            if (btn.dataset.plugin === pluginId) {
                btn.classList.add('active');
            }
        });
    }

    setSystemStatus(text, type = 'normal') {
        const dot = document.getElementById('systemStatusDot');
        const statusText = document.getElementById('systemStatusText');

        if (dot) {
            dot.className = 'status-dot';
            if (type !== 'normal') dot.classList.add(type);
        }
        if (statusText) statusText.textContent = text;
    }

    showLoading(text = '加载中...', hint = null) {
        const loadingText = document.getElementById('loadingText');
        const loadingHint = document.getElementById('loadingHint');
        const loadingOverlay = document.getElementById('loadingOverlay');

        if (loadingText) loadingText.textContent = text;
        if (loadingHint) {
            loadingHint.textContent = hint || '请稍候，正在处理...';
        }
        if (loadingOverlay) loadingOverlay.classList.remove('hidden');
    }

    hideLoading() {
        const loadingOverlay = document.getElementById('loadingOverlay');
        if (loadingOverlay) loadingOverlay.classList.add('hidden');
    }

    toast(type, title, message) {
        const container = document.getElementById('toastContainer');
        if (!container) return;

        const toast = document.createElement('div');
        toast.className = 'toast';
        toast.innerHTML = `
            <div class="toast-icon ${type}">
                ${this.getToastIcon(type)}
            </div>
            <div class="toast-content">
                <div class="toast-title">${title}</div>
                <div class="toast-message">${message}</div>
            </div>
            <button class="toast-close">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="18" y1="6" x2="6" y2="18"/>
                    <line x1="6" y1="6" x2="18" y2="18"/>
                </svg>
            </button>
        `;

        container.appendChild(toast);

        // 自动关闭
        setTimeout(() => {
            toast.classList.add('removing');
            setTimeout(() => toast.remove(), 300);
        }, 3000);

        // 手动关闭
        toast.querySelector('.toast-close').addEventListener('click', () => {
            toast.classList.add('removing');
            setTimeout(() => toast.remove(), 300);
        });
    }

    getToastIcon(type) {
        const icons = {
            success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22,4 12,14.01 9,11.01"/></svg>',
            error: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>',
            warning: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
            info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>'
        };
        return icons[type] || icons.info;
    }

    // ==================== 工具方法 ====================

    log(message, type = 'info') {
        const prefix = '[MemoryForensics]';
        const logMsg = `${prefix} ${message}`;
        switch (type) {
            case 'error':
                console.error(logMsg);
                break;
            case 'warning':
                console.warn(logMsg);
                break;
            default:
                console.log(logMsg);
        }
    }

    countPlugins(plugins) {
        let count = 0;
        for (const category in plugins) {
            if (Array.isArray(plugins[category])) {
                count += plugins[category].length;
            }
        }
        return count;
    }

    getPluginDisplayName(pluginId) {
        const names = {
            'pslist': '进程列表',
            'pstree': '进程树',
            'psscan': '进程扫描',
            'netscan': '网络连接',
            'filescan': '文件扫描',
            'cmdline': '命令行参数',
            'malfind': '恶意代码查找'
        };
        return names[pluginId] || pluginId.toUpperCase();
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    formatSize(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    getMockResult(pluginId) {
        const mockData = {
            'pslist': {
                plugin: 'pslist',
                results: [
                    { pid: 4, ppid: 0, name: 'System', threads: 124, handles: 0, session_id: 0, create_time: '2025-01-26 10:00:00' },
                    { pid: 896, ppid: 4, name: 'smss.exe', threads: 3, handles: 45, session_id: 0, create_time: '2025-01-26 10:00:05' },
                    { pid: 2456, ppid: 1180, name: 'svchost.exe', threads: 24, handles: 678, session_id: 0, create_time: '2025-01-26 10:01:00' },
                    { pid: 3568, ppid: 2456, name: 'docker.exe', threads: 8, handles: 234, session_id: 1, create_time: '2025-01-26 10:05:00' }
                ]
            },
            'netscan': {
                plugin: 'netscan',
                results: [
                    { protocol: 'TCP', local_address: '192.168.1.100', local_port: 54321, remote_address: '142.250.185.78', remote_port: 443, state: 'ESTABLISHED', process_name: 'chrome.exe', pid: 7890 }
                ]
            },
            'filescan': {
                plugin: 'filescan',
                results: [
                    { offset: '0xffffa8091d567890', file_name: 'flag.txt', path: 'C:\\Temp\\flag.txt', size: 45, number_of_links: 1 }
                ]
            },
            'cmdline': {
                plugin: 'cmdline',
                results: [
                    { pid: 8901, name: 'python.exe', command_line: 'python.exe C:\\Users\\user\\script.py --arg1 value1' }
                ]
            },
            'malfind': {
                plugin: 'malfind',
                results: [
                    { pid: 2456, process_name: 'svchost.exe', address: '0x1a2b3c4d5e6f', size: 4096, protection: 'PAGE_EXECUTE_READWRITE', suspicious: true, reason: 'Injected code' }
                ]
            }
        };

        return {
            status: 'success',
            data: mockData[pluginId] || { plugin: pluginId, results: [] },
            cached: false
        };
    }

    /**
     * 模拟延迟（演示模式）
     */
    async delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * 获取模拟结果（演示模式）
     */
    getMockResult(pluginId) {
        const mockData = {
            'pslist': {
                plugin: 'pslist',
                results: [
                    { pid: 7890, ppid: 1234, name: 'chrome.exe', threads: 45, handles: 1234, session_id: 1, create_time: '2025-01-26 10:00:00' },
                    { pid: 4567, ppid: 1234, name: 'explorer.exe', threads: 23, handles: 890, session_id: 1, create_time: '2025-01-26 09:55:00' },
                    { pid: 1234, ppid: 1180, name: 'svchost.exe', threads: 15, handles: 456, session_id: 0, create_time: '2025-01-26 09:50:00' },
                    { pid: 2456, ppid: 1180, name: 'svchost.exe', threads: 24, handles: 678, session_id: 0, create_time: '2025-01-26 10:01:00' },
                    { pid: 3568, ppid: 2456, name: 'docker.exe', threads: 8, handles: 234, session_id: 1, create_time: '2025-01-26 10:05:00' }
                ]
            },
            'netscan': {
                plugin: 'netscan',
                results: [
                    { protocol: 'TCP', local_address: '192.168.1.100', local_port: 54321, remote_address: '142.250.185.78', remote_port: 443, state: 'ESTABLISHED', process_name: 'chrome.exe', pid: 7890 }
                ]
            },
            'filescan': {
                plugin: 'filescan',
                results: [
                    { offset: '0xffffa8091d567890', file_name: 'flag.txt', path: 'C:\\Temp\\flag.txt', size: 45, number_of_links: 1 }
                ]
            },
            'cmdline': {
                plugin: 'cmdline',
                results: [
                    { pid: 8901, name: 'python.exe', command_line: 'python.exe C:\\Users\\user\\script.py --arg1 value1' }
                ]
            },
            'malfind': {
                plugin: 'malfind',
                results: [
                    { pid: 2456, process_name: 'svchost.exe', address: '0x1a2b3c4d5e6f', size: 4096, protection: 'PAGE_EXECUTE_READWRITE', suspicious: true, reason: 'Injected code' }
                ]
            }
        };

        return {
            status: 'success',
            data: mockData[pluginId] || { plugin: pluginId, results: [] },
            cached: false
        };
    }

    /**
     * 检查许可证状态
     */
    async checkLicenseStatus() {
        this.log('checkLicenseStatus: 开始检查');

        if (!this.api) {
            this.log('checkLicenseStatus: this.api 为空', 'error');
            return;
        }

        // 先测试API是否工作
        try {
            this.log('checkLicenseStatus: 测试API连接...');
            const testResult = await this.api.test_api();
            this.log('checkLicenseStatus: 测试成功 ' + JSON.stringify(testResult));
        } catch (error) {
            this.log('checkLicenseStatus: 测试API失败 ' + error.message, 'error');
        }

        this.log('checkLicenseStatus: 调用 get_license_status');
        try {
            const result = await this.api.get_license_status();
            this.log('checkLicenseStatus: 收到响应 ' + JSON.stringify(result));

            if (result.status === 'success' && result.data && result.data.valid) {
                // 许可证有效，隐藏激活界面，显示主界面
                this.log('许可证有效');
                this.hideLicenseScreen();
                // 继续正常初始化
                await this.loadSystemInfo();
                await this.loadAvailablePlugins();
            } else {
                // 许可证无效，显示激活界面
                this.log('许可证未激活或已过期');
                this.showLicenseScreen();
            }
        } catch (error) {
            this.log('检查许可证失败: ' + error.message, 'error');
            console.error('License check error:', error);
            // 错误时也显示激活界面
            this.showLicenseScreen();
        }
    }

    /**
     * 激活许可证
     */
    async activateLicense() {
        if (!this.api) return;

        const input = document.getElementById('licenseKeyInput');
        const messageDiv = document.getElementById('licenseMessage');
        const btn = document.getElementById('activateBtn');
        const btnText = document.getElementById('activateBtnText');

        const licenseKey = input ? input.value.trim() : '';

        if (!licenseKey) {
            this.showLicenseMessage('请输入激活码', 'error');
            return;
        }

        // 禁用按钮
        btn.disabled = true;
        btnText.textContent = '激活中...';

        try {
            const result = await this.api.activate_license(licenseKey);

            if (result.status === 'success') {
                this.showLicenseMessage(result.message, 'success');

                // 激活成功，等待1秒后提示重启
                setTimeout(() => {
                    if (result.require_restart) {
                        this.toast('success', '激活成功', '请重启应用以完成激活');
                        setTimeout(() => {
                            this.api.exit();
                        }, 2000);
                    }
                }, 1000);
            } else {
                this.showLicenseMessage(result.message || '激活失败', 'error');
            }
        } catch (error) {
            this.showLicenseMessage('激活失败: ' + error.message, 'error');
        } finally {
            // 恢复按钮
            btn.disabled = false;
            btnText.textContent = '激活';
        }
    }

    /**
     * 显示激活界面
     */
    showLicenseScreen() {
        const licenseScreen = document.getElementById('licenseScreen');
        const splashScreen = document.getElementById('splashScreen');
        const mainContent = document.querySelector('.main-container');
        const header = document.querySelector('.header');

        // 隐藏启动画面和主界面
        if (splashScreen) splashScreen.style.display = 'none';
        if (mainContent) mainContent.style.display = 'none';
        if (header) header.style.display = 'none';

        // 显示激活界面
        if (licenseScreen) licenseScreen.style.display = 'flex';

        // 加载机器码
        this.loadMachineCode();
    }

    /**
     * 加载并显示机器码
     */
    async loadMachineCode() {
        const machineCodeValue = document.getElementById('machineCodeValue');
        if (!machineCodeValue) {
            console.error('[loadMachineCode] 找不到 machineCodeValue 元素');
            return;
        }

        console.log('[loadMachineCode] 开始加载机器码');
        console.log('[loadMachineCode] this.api:', this.api);

        if (!this.api) {
            console.log('[loadMachineCode] 演示模式：使用模拟机器码');
            this.updateMachineCodeDisplay('DEMO-MACH-CODE');
            return;
        }

        try {
            console.log('[loadMachineCode] 调用 api.get_license_status()');
            machineCodeValue.textContent = '正在获取...';

            const result = await this.api.get_license_status();
            console.log('[loadMachineCode] API返回:', result);
            this.log('许可证状态API返回: ' + JSON.stringify(result));

            if (result && result.status === 'success' && result.data && result.data.machine_code) {
                this.updateMachineCodeDisplay(result.data.machine_code);
                console.log('[loadMachineCode] 机器码设置成功:', result.data.machine_code);
                this.log('机器码获取成功: ' + result.data.machine_code);
            } else {
                console.error('[loadMachineCode] 返回格式错误:', result);
                this.log('无法从许可证状态获取机器码: ' + JSON.stringify(result), 'error');
                machineCodeValue.textContent = '错误: ' + JSON.stringify(result || '无响应');
            }
        } catch (error) {
            console.error('[loadMachineCode] 异常:', error);
            this.log('获取机器码异常: ' + error.message, 'error');
            machineCodeValue.textContent = '异常: ' + error.message;
        }
    }

    /**
     * 更新机器码显示
     */
    updateMachineCodeDisplay(machineCode) {
        const machineCodeValue = document.getElementById('machineCodeValue');
        if (machineCodeValue) {
            machineCodeValue.textContent = machineCode;
        }
    }

    /**
     * 复制机器码到剪贴板
     */
    async copyMachineCode() {
        const machineCodeValue = document.getElementById('machineCodeValue');
        if (!machineCodeValue) return;

        const machineCode = machineCodeValue.textContent;

        try {
            await navigator.clipboard.writeText(machineCode);
            this.toast('success', '复制成功', '机器码已复制到剪贴板');
        } catch (error) {
            // 降级方案：使用传统方法
            const textArea = document.createElement('textarea');
            textArea.value = machineCode;
            textArea.style.position = 'fixed';
            textArea.style.opacity = '0';
            document.body.appendChild(textArea);
            textArea.select();
            try {
                document.execCommand('copy');
                this.toast('success', '复制成功', '机器码已复制到剪贴板');
            } catch (err) {
                this.toast('error', '复制失败', '无法复制机器码');
            }
            document.body.removeChild(textArea);
        }
    }

    /**
     * 隐藏激活界面
     */
    hideLicenseScreen() {
        const licenseScreen = document.getElementById('licenseScreen');
        const splashScreen = document.getElementById('splashScreen');

        // 隐藏激活界面
        if (licenseScreen) licenseScreen.style.display = 'none';

        // 显示主界面
        const mainContent = document.querySelector('.main-container');
        const header = document.querySelector('.header');
        if (mainContent) mainContent.style.display = 'flex';
        if (header) header.style.display = 'flex';

        // 隐藏启动画面
        if (splashScreen) {
            splashScreen.classList.add('hidden');
            setTimeout(() => splashScreen.style.display = 'none', 300);
        }
    }

    /**
     * 显示许可证消息
     */
    showLicenseMessage(message, type = '') {
        const messageDiv = document.getElementById('licenseMessage');
        if (messageDiv) {
            messageDiv.textContent = message;
            messageDiv.className = 'license-message ' + type;
        }
    }
}

// 初始化应用
const app = new ForensicsApp();

// DOM加载完成后初始化
document.addEventListener('DOMContentLoaded', () => {
    app.init().catch(error => {
        console.error('应用初始化失败:', error);
    });
});

// 暴露到全局
window.app = app;
