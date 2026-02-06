#!/usr/bin/env python3
"""
析镜激活码生成Web服务

使用方法:
    python tools/license_web.py

访问:
    用户版: http://localhost:5000 (固定365天)
    管理员版: http://localhost:5000/admin (可自定义天数)

环境变量:
    PORT - 端口号（默认5000）
    SECRET_KEY - Flask密钥（可选）
    LENS_SECRET_KEY - 许可证签名密钥（生产环境必须设置）

安全特性:
- 输入验证和清理
- 错误消息不暴露内部信息
- 日志记录
"""

import sys
import os
import logging
from flask import Flask, render_template, request, jsonify
from datetime import datetime
from functools import wraps

# 添加项目根目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backend.license_manager import OfflineLicenseManager

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'lensanalysis-license-web-2024')

license_manager = OfflineLicenseManager()


@app.route('/')
def index():
    """用户版主页 - 固定365天"""
    return render_template('user.html')


@app.route('/admin')
def admin():
    """管理员版主页 - 可自定义天数"""
    return render_template('admin.html')


@app.route('/api/generate', methods=['POST'])
def generate_license():
    """生成激活码API"""
    # 记录请求信息（不记录敏感数据）
    client_ip = request.remote_addr
    logger.info(f"激活码生成请求来自: {client_ip}")

    try:
        data = request.get_json()

        # 防止 JSON 解析失败
        if not data:
            logger.warning(f"无效的请求数据，来自: {client_ip}")
            return jsonify({
                'success': False,
                'error': '无效的请求数据'
            }), 400

        machine_code = data.get('machine_code', '').strip()
        user_id = data.get('user_id', '').strip()
        days = data.get('days', 365)

        # 验证机器码
        if not machine_code:
            return jsonify({
                'success': False,
                'error': '请输入机器码'
            }), 400

        # 验证用户ID
        if not user_id:
            return jsonify({
                'success': False,
                'error': '请输入用户ID'
            }), 400

        # 验证用户ID格式（使用 license_manager 的验证函数）
        valid, error = license_manager.validate_user_id(user_id)
        if not valid:
            logger.warning(f"无效的用户ID '{user_id}'，来自: {client_ip}")
            return jsonify({
                'success': False,
                'error': f'用户ID格式错误: {error}'
            }), 400

        # 验证机器码格式
        valid, error = license_manager.verify_machine_code(machine_code)
        if not valid:
            logger.warning(f"无效的机器码 '{machine_code}'，来自: {client_ip}")
            return jsonify({
                'success': False,
                'error': f'机器码格式错误: {error}'
            }), 400

        # 验证并转换天数
        try:
            days = float(days)
            if days < 0:
                return jsonify({
                    'success': False,
                    'error': '有效期不能为负数'
                }), 400
            if days > 36500:
                return jsonify({
                    'success': False,
                    'error': '有效期过长（最多100年）'
                }), 400
        except (ValueError, TypeError):
            return jsonify({
                'success': False,
                'error': '有效期格式错误'
            }), 400

        # 生成激活码
        license_key = license_manager.generate_license(machine_code, user_id, days)

        logger.info(f"成功生成激活码: 用户={user_id}, 机器码={machine_code[:8]}****, 有效期={days}天, IP={client_ip}")

        return jsonify({
            'success': True,
            'data': {
                'license_key': license_key,
                'machine_code': machine_code,
                'user_id': user_id,
                'days': days,
                'expiry': '永久' if days == 0 else f'{days}天'
            }
        })

    except ValueError as e:
        # ValueError 通常是由于参数验证失败
        logger.warning(f"参数验证失败: {e}, IP={client_ip}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400
    except Exception as e:
        # 记录详细错误但不暴露给客户端
        logger.error(f"生成激活码失败: {e}, IP={client_ip}")
        return jsonify({
            'success': False,
            'error': '生成激活码失败，请检查输入参数'
        }), 500


@app.route('/api/verify', methods=['POST'])
def verify_machine_code():
    """验证机器码格式"""
    client_ip = request.remote_addr

    try:
        data = request.get_json()

        if not data:
            return jsonify({
                'success': False,
                'error': '无效的请求数据'
            }), 400

        machine_code = data.get('machine_code', '').strip()

        valid, error = license_manager.verify_machine_code(machine_code)

        return jsonify({
            'success': True,
            'valid': valid,
            'error': error
        })

    except Exception as e:
        logger.error(f"验证机器码失败: {e}, IP={client_ip}")
        return jsonify({
            'success': False,
            'error': '验证失败'
        }), 500


# 添加安全头
@app.after_request
def add_security_headers(response):
    """添加安全响应头"""
    # 防止点击劫持
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # 防止 MIME 类型嗅探
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # 启用 XSS 保护
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


def main():
    """启动Web服务"""
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '127.0.0.1')  # 默认只监听本地

    # 检查是否在生产环境使用默认密钥
    if not os.environ.get('LENS_SECRET_KEY'):
        logger.warning("⚠️  警告: 使用默认密钥！生产环境请设置 LENS_SECRET_KEY 环境变量")

    print("=" * 60)
    print("析镜 LensAnalysis - 激活码生成Web服务")
    print("=" * 60)
    print(f"启动时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"服务地址: http://{host}:{port}")
    print(f"管理界面: http://{host}:{port}/admin")
    print(f"环境: 生产模式" if os.environ.get('FLASK_ENV') != 'development' else "环境: 开发模式")
    print("=" * 60)
    print()

    # 生产环境建议
    if os.environ.get('FLASK_ENV') != 'development':
        print("提示: 生产环境建议：")
        print("  1. 设置 LENS_SECRET_KEY 环境变量")
        print("  2. 使用 gunicorn 启动:")
        print(f"     gunicorn -w 4 -b {host}:{port} tools.license_web:app")
        print("  3. 配置反向代理 (nginx)")
        print()

    app.run(
        host=host,
        port=port,
        debug=os.environ.get('FLASK_ENV') == 'development'
    )


if __name__ == '__main__':
    main()
