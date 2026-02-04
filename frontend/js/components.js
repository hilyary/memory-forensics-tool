/**
 * UI Components - 组件库
 * 提供可复用的UI组件
 */

class Components {
    /**
     * 创建模态框
     */
    static modal(options = {}) {
        const {
            title = '',
            content = '',
            footer = '',
            closable = true,
            onClose = null
        } = options;

        // 创建遮罩层
        const overlay = document.createElement('div');
        overlay.className = 'modal-overlay';

        // 创建模态框
        const modal = document.createElement('div');
        modal.className = 'modal';

        modal.innerHTML = `
            <div class="modal-header">
                <h3 class="modal-title">${title}</h3>
                ${closable ? `
                    <button class="modal-close">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                            <line x1="18" y1="6" x2="6" y2="18"/>
                            <line x1="6" y1="6" x2="18" y2="18"/>
                        </svg>
                    </button>
                ` : ''}
            </div>
            <div class="modal-body">${content}</div>
            ${footer ? `<div class="modal-footer">${footer}</div>` : ''}
        `;

        overlay.appendChild(modal);
        document.body.appendChild(overlay);

        // 关闭处理
        const close = () => {
            overlay.style.animation = 'fadeOut 0.2s ease forwards';
            setTimeout(() => {
                overlay.remove();
                if (onClose) onClose();
            }, 200);
        };

        if (closable) {
            modal.querySelector('.modal-close')?.addEventListener('click', close);
            overlay.addEventListener('click', (e) => {
                if (e.target === overlay) close();
            });
        }

        return { overlay, modal, close };
    }

    /**
     * 创建确认对话框
     */
    static confirm(options = {}) {
        const {
            title = '确认',
            message = '确定要执行此操作吗？',
            confirmText = '确定',
            cancelText = '取消'
        } = options;

        return new Promise((resolve) => {
            const { close } = this.modal({
                title,
                content: `<p style="color: var(--text-secondary);">${message}</p>`,
                footer: `
                    <button class="btn btn-ghost" data-action="cancel">${cancelText}</button>
                    <button class="btn btn-primary" data-action="confirm">${confirmText}</button>
                `,
                onClose: () => resolve(false)
            });

            const modal = document.querySelector('.modal');
            modal.querySelector('[data-action="confirm"]')?.addEventListener('click', () => {
                close();
                resolve(true);
            });
            modal.querySelector('[data-action="cancel"]')?.addEventListener('click', () => close());
        });
    }

    /**
     * 创建输入对话框
     */
    static prompt(options = {}) {
        const {
            title = '输入',
            label = '请输入内容：',
            placeholder = '',
            defaultValue = ''
        } = options;

        return new Promise((resolve) => {
            const inputId = 'prompt-input-' + Date.now();

            const { close } = this.modal({
                title,
                content: `
                    <div class="input-group">
                        <label class="input-label" for="${inputId}">${label}</label>
                        <input type="text" id="${inputId}" class="input-field" placeholder="${placeholder}" value="${defaultValue}">
                    </div>
                `,
                footer: `
                    <button class="btn btn-ghost" data-action="cancel">取消</button>
                    <button class="btn btn-primary" data-action="confirm">确定</button>
                `,
                onClose: () => resolve(null)
            });

            const input = document.getElementById(inputId);
            input.focus();
            input.select();

            const modal = document.querySelector('.modal');
            modal.querySelector('[data-action="confirm"]')?.addEventListener('click', () => {
                close();
                resolve(input.value);
            });
            modal.querySelector('[data-action="cancel"]')?.addEventListener('click', () => close());

            input.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    close();
                    resolve(input.value);
                } else if (e.key === 'Escape') {
                    close();
                    resolve(null);
                }
            });
        });
    }

    /**
     * 创建选择对话框
     */
    static select(options = {}) {
        const {
            title = '选择',
            label = '请选择：',
            items = [],
            defaultIndex = 0
        } = options;

        return new Promise((resolve) => {
            const selectId = 'select-input-' + Date.now();

            const { close } = this.modal({
                title,
                content: `
                    <div class="input-group">
                        <label class="input-label" for="${selectId}">${label}</label>
                        <select id="${selectId}" class="select-field">
                            ${items.map((item, index) => `
                                <option value="${index}" ${index === defaultIndex ? 'selected' : ''}>${item}</option>
                            `).join('')}
                        </select>
                    </div>
                `,
                footer: `
                    <button class="btn btn-ghost" data-action="cancel">取消</button>
                    <button class="btn btn-primary" data-action="confirm">确定</button>
                `,
                onClose: () => resolve(null)
            });

            const select = document.getElementById(selectId);

            const modal = document.querySelector('.modal');
            modal.querySelector('[data-action="confirm"]')?.addEventListener('click', () => {
                close();
                resolve(parseInt(select.value));
            });
            modal.querySelector('[data-action="cancel"]')?.addEventListener('click', () => close());
        });
    }

    /**
     * 显示进度条
     */
    static progress(options = {}) {
        const {
            title = '处理中...',
            total = 100,
            current = 0
        } = options;

        const barId = 'progress-bar-' + Date.now();

        const { overlay, modal, close } = this.modal({
            title,
            content: `
                <div class="progress-bar">
                    <div class="progress-bar-fill" id="${barId}" style="width: ${(current / total) * 100}%"></div>
                </div>
                <div style="text-align: center; margin-top: 12px; color: var(--text-secondary); font-size: 13px;">
                    <span id="${barId}-current">${current}</span> / ${total}
                </div>
            `,
            footer: '',
            closable: false
        });

        return {
            close,
            update: (value) => {
                const percent = Math.min((value / total) * 100, 100);
                const fill = document.getElementById(barId);
                const currentEl = document.getElementById(barId + '-current');
                if (fill) fill.style.width = percent + '%';
                if (currentEl) currentEl.textContent = value;
            }
        };
    }

    /**
     * 显示详情面板
     */
    static showDetails(options = {}) {
        const {
            title = '详细信息',
            data = {},
            monospace = []
        } = options;

        const { close } = this.modal({
            title,
            content: `
                <div class="details-content">
                    <div class="details-grid">
                        ${Object.entries(data).map(([key, value]) => `
                            <div class="detail-item">
                                <div class="detail-key">${key}</div>
                                <div class="detail-value ${monospace.includes(key) ? 'monospace' : ''}">${value}</div>
                            </div>
                        `).join('')}
                    </div>
                </div>
            `,
            footer: `
                <button class="btn btn-primary" data-action="close">关闭</button>
            `
        });

        document.querySelector('[data-action="close"]')?.addEventListener('click', close);
    }
}

/**
 * 工具函数
 */
class Utils {
    /**
     * 格式化时间戳
     */
    static formatTime(timestamp) {
        if (!timestamp) return '-';
        const date = new Date(timestamp);
        return date.toLocaleString('zh-CN', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    }

    /**
     * 格式化文件大小
     */
    static formatSize(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    /**
     * 格式化数字
     */
    static formatNumber(num) {
        return new Intl.NumberFormat('zh-CN').format(num);
    }

    /**
     * 转义HTML
     */
    static escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    /**
     * 高亮关键词
     */
    static highlightKeywords(text, keywords) {
        let result = text;
        keywords.forEach(keyword => {
            const regex = new RegExp(`(${keyword})`, 'gi');
            result = result.replace(regex, '<span class="highlight">$1</span>');
        });
        return result;
    }

    /**
     * 复制到剪贴板
     */
    static async copyToClipboard(text) {
        try {
            await navigator.clipboard.writeText(text);
            return true;
        } catch {
            // 降级方案
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.opacity = '0';
            document.body.appendChild(textarea);
            textarea.select();
            try {
                document.execCommand('copy');
                document.body.removeChild(textarea);
                return true;
            } catch {
                document.body.removeChild(textarea);
                return false;
            }
        }
    }

    /**
     * 下载文件
     */
    static downloadFile(content, filename, mimeType = 'text/plain') {
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        link.click();
        URL.revokeObjectURL(url);
    }

    /**
     * 防抖
     */
    static debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    /**
     * 节流
     */
    static throttle(func, limit) {
        let inThrottle;
        return function executedFunction(...args) {
            if (!inThrottle) {
                func(...args);
                inThrottle = true;
                setTimeout(() => inThrottle = false, limit);
            }
        };
    }

    /**
     * 延迟执行
     */
    static delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
}

// 全局快捷键
document.addEventListener('keydown', (e) => {
    // Ctrl/Cmd + K: 快速搜索
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        // TODO: 实现快速搜索功能
    }

    // Escape: 关闭模态框
    if (e.key === 'Escape') {
        const overlay = document.querySelector('.modal-overlay');
        if (overlay) {
            overlay.remove();
        }
    }
});

// 导出
window.Components = Components;
window.Utils = Utils;
