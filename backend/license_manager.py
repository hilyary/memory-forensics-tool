"""
离线许可证管理器 - 机器绑定版本

激活流程：
1. 用户启动软件，显示机器码
2. 用户在公众号发送机器码给管理员
3. 管理员使用机器码生成激活码
4. 用户输入激活码激活软件

安全特性：
- HMAC-SHA256 签名验证
- 机器码绑定
- 时间戳验证
- 许可证文件完整性校验
"""
import os
import json
import hmac
import hashlib
import time
import platform
import uuid
from pathlib import Path
from typing import Tuple, Dict, Optional
import logging

logger = logging.getLogger(__name__)


class OfflineLicenseManager:
    """离线许可证管理器 - 机器绑定版本"""

    def __init__(self):
        # 使用统一的用户数据目录
        self.license_dir = self._get_user_data_dir()
        self.license_file = self.license_dir / "license.json"

        # 密钥：使用环境变量或默认值（后期可以改为从配置文件读取）
        # 生产环境建议设置环境变量: LENS_SECRET_KEY
        self.secret_key = os.environ.get(
            'LENS_SECRET_KEY',
            # 使用更复杂的默认密钥，包含多个混淆字符串
            'LENS_2024_OFFLINE_KEY_' + hashlib.sha256(b'lensanalysis').hexdigest()[:16]
        )

        # 确保目录存在
        self.license_dir.mkdir(parents=True, exist_ok=True)

    def _get_user_data_dir(self) -> Path:
        """获取用户数据目录（与其他模块保持一致）"""
        system = platform.system()

        if system == 'Darwin':  # macOS
            # macOS: ~/Library/Application Support/LensAnalysis
            app_data = Path.home() / 'Library' / 'Application Support' / 'LensAnalysis'
        elif system == 'Windows':  # Windows
            # Windows: %APPDATA%/LensAnalysis
            app_data = Path(os.environ.get('APPDATA', Path.home() / 'AppData' / 'Roaming')) / 'LensAnalysis'
        else:  # Linux 和其他
            # Linux: ~/.local/share/LensAnalysis (遵循 XDG 规范)
            app_data = Path(os.environ.get('XDG_DATA_HOME', Path.home() / '.local' / 'share')) / 'LensAnalysis'

        return app_data

    def get_machine_code(self) -> str:
        """
        获取机器码

        机器码由以下信息生成：
        - 主机名
        - CPU/机器类型
        - MAC地址（网卡）
        - 系统版本

        Returns:
            机器码（16位，便于用户复制）
        """
        try:
            # 收集机器信息
            hostname = platform.node()
            machine = platform.machine()
            system = platform.system()
            mac = self._get_mac_address()

            # 组合信息
            machine_info = f"{hostname}-{machine}-{system}-{mac}"

            # 生成机器码
            machine_hash = hashlib.sha256(machine_info.encode()).hexdigest()

            # 取前16位作为机器码（4-4-4-4格式，方便用户复制）
            machine_code = '-'.join([
                machine_hash[0:4],
                machine_hash[4:8],
                machine_hash[8:12],
                machine_hash[12:16]
            ]).upper()

            return machine_code
        except Exception as e:
            logger.error(f"生成机器码失败: {e}")
            # 降级方案：使用随机数
            return hashlib.sha256(str(uuid.getnode()).encode()).hexdigest()[:16].upper()

    def _get_mac_address(self) -> str:
        """获取第一个MAC地址"""
        try:
            import socket
            # 获取本机MAC地址
            mac_num = uuid.getnode()
            mac_hex = ':'.join(f'{(mac_num >> i) & 0xff:02x}' for i in range(0, 8*6, 8))[::-1]
            return mac_hex.replace(':', '')
        except Exception as e:
            logger.error(f"获取MAC地址失败: {e}")
            # 降级方案使用更多随机性，避免不同机器生成相同机器码
            import random
            # 使用时间戳+随机数作为降级方案
            fallback_data = f"{platform.node()}-{time.time()}-{random.randint(0, 1000000)}"
            return hashlib.sha256(fallback_data.encode()).hexdigest()[:12]

    def verify_machine_code(self, machine_code: str) -> Tuple[bool, str]:
        """
        验证机器码格式是否正确

        Args:
            machine_code: 用户输入的机器码

        Returns:
            (是否有效, 错误信息)
        """
        if not machine_code:
            return False, "机器码不能为空"

        # 检查格式：4-4-4-4
        parts = machine_code.split('-')
        if len(parts) != 4:
            return False, "机器码格式错误，应为XXXX-XXXX-XXXX-XXXX"

        for part in parts:
            if len(part) != 4 or not part.isalnum():
                return False, "机器码包含非法字符"

        return True, ""

    def validate_user_id(self, user_id: str) -> Tuple[bool, str]:
        """
        验证用户ID是否有效（防止注入攻击）

        Args:
            user_id: 用户ID

        Returns:
            (是否有效, 错误信息)
        """
        if not user_id:
            return False, "用户ID不能为空"

        # 长度限制：1-50字符
        if len(user_id) > 50:
            return False, "用户ID过长（最多50字符）"

        # 只允许字母、数字、下划线、中划线、点
        import re
        if not re.match(r'^[\w\-\.]+$', user_id):
            return False, "用户ID只能包含字母、数字、下划线、中划线和点"

        # 不能以点开头或结尾（防止文件名问题）
        if user_id.startswith('.') or user_id.endswith('.'):
            return False, "用户ID不能以点开头或结尾"

        return True, ""

    def generate_license(self, machine_code: str, user_id: str, days: float = 0) -> str:
        """
        为特定机器生成激活码（管理员使用）

        Args:
            machine_code: 用户的机器码
            user_id: 用户标识
            days: 有效期天数，0表示永久

        Returns:
            激活码
        """
        # 验证机器码格式
        valid, error = self.verify_machine_code(machine_code)
        if not valid:
            raise ValueError(f"无效的机器码: {error}")

        # 验证用户ID
        valid, error = self.validate_user_id(user_id)
        if not valid:
            raise ValueError(f"无效的用户ID: {error}")

        # 计算过期时间（确保是整数）
        current_time = int(time.time())

        # 验证天数范围
        if days < 0:
            raise ValueError("有效期不能为负数")

        if days > 36500:  # 最多100年
            raise ValueError("有效期过长（最多100年）")

        expiry = 0 if days == 0 else current_time + int(days * 86400)

        # 生成签名：完整机器码+用户ID+过期时间
        machine_full = machine_code.replace('-', '')
        data_to_sign = f"{machine_full}-{user_id}-{expiry}"
        signature = hmac.new(
            self.secret_key.encode(),
            data_to_sign.encode(),
            hashlib.sha256
        ).hexdigest()  # 使用完整的64位签名，提高安全性

        # 激活码格式: LENS-机器码前8位-用户ID-过期时间-签名
        # 机器码只显示前8位（为了方便输入），但签名用完整机器码
        machine_short = machine_full[:8]
        license_key = f"LENS-{machine_short}-{user_id}-{expiry}-{signature}"

        return license_key

    def activate_license(self, license_key: str) -> Tuple[bool, str]:
        """
        激活许可证（用户端使用）

        Args:
            license_key: 激活码

        Returns:
            (是否成功, 消息)
        """
        # 临时文件路径（用于原子写入）
        temp_file = self.license_file.with_suffix('.tmp')

        try:
            # 解析激活码
            parts = license_key.split('-')
            # 激活码格式: LENS-机器码前8位-用户ID-过期时间-签名
            if len(parts) != 5 or parts[0] != "LENS":
                return False, "无效的激活码格式"

            machine_short = parts[1]  # 机器码前8位（只是显示用）
            user_id = parts[2]        # 用户ID
            expiry = int(parts[3])     # 过期时间
            signature = '-'.join(parts[4:])  # 签名

            # 验证用户ID（防止注入攻击）
            valid, error = self.validate_user_id(user_id)
            if not valid:
                return False, f"无效的用户ID: {error}"

            # 验证过期时间范围（防止负数绕过）
            if expiry < 0:
                return False, "激活码无效：过期时间异常"

            # 合理的未来时间限制（不能超过当前时间+100年）
            max_expiry = int(time.time()) + (36500 * 86400)
            if expiry > max_expiry:
                return False, "激活码无效：过期时间过远"

            # 验证签名：使用完整机器码
            current_machine = self.get_machine_code().replace('-', '')

            # 验证激活码中的机器码前8位是否匹配当前机器
            if not current_machine.startswith(machine_short):
                return False, "激活码与当前机器不匹配"

            data_to_sign = f"{current_machine}-{user_id}-{expiry}"

            expected_sig = hmac.new(
                self.secret_key.encode(),
                data_to_sign.encode(),
                hashlib.sha256
            ).hexdigest()  # 使用完整的64位签名

            if not hmac.compare_digest(signature, expected_sig):
                return False, "激活码无效或与当前机器不匹配"

            # 检查过期时间
            if expiry > 0 and time.time() > expiry:
                return False, "激活码已过期"

            # 保存许可证（带签名保护）
            license_data = {
                'key': license_key,
                'user': user_id,
                'machine_code': self.get_machine_code(),
                'expiry': expiry,
                'activated_at': int(time.time())
            }

            # 生成许可证文件签名，防止篡改
            license_json = json.dumps(license_data, sort_keys=True)
            license_signature = hmac.new(
                self.secret_key.encode(),
                license_json.encode(),
                hashlib.sha256
            ).hexdigest()

            # 保存许可证和签名
            save_data = {
                'license': license_data,
                'signature': license_signature
            }

            # 先写入临时文件，然后原子性移动（防止写入失败留下损坏文件）
            with open(temp_file, 'w') as f:
                json.dump(save_data, f, indent=2)

            # 原子性替换文件
            temp_file.replace(self.license_file)

            # 返回成功消息
            if expiry == 0:
                return True, f"激活成功！欢迎，{user_id}（永久许可）"
            else:
                from datetime import datetime
                expiry_date = datetime.fromtimestamp(expiry).strftime("%Y年%m月%d日")
                return True, f"激活成功！欢迎，{user_id}（有效期至 {expiry_date}）"

        except ValueError:
            # 清理临时文件
            if temp_file.exists():
                temp_file.unlink()
            return False, "激活码格式错误"
        except Exception as e:
            logger.error(f"激活失败: {e}")
            # 清理临时文件
            if temp_file.exists():
                temp_file.unlink()
            return False, f"激活失败: {str(e)}"

    def check_license(self) -> Tuple[bool, str, Dict]:
        """
        检查许可证是否有效

        Returns:
            (是否有效, 消息, 许可证信息)
        """
        if not self.license_file.exists():
            return False, "未激活", {}

        try:
            with open(self.license_file, 'r') as f:
                save_data = json.load(f)

            # 检查签名（防止文件被篡改）
            if 'signature' in save_data and 'license' in save_data:
                license_data = save_data['license']
                stored_signature = save_data['signature']

                # 重新计算签名
                license_json = json.dumps(license_data, sort_keys=True)
                expected_signature = hmac.new(
                    self.secret_key.encode(),
                    license_json.encode(),
                    hashlib.sha256
                ).hexdigest()

                # 验证签名
                if not hmac.compare_digest(stored_signature, expected_signature):
                    logger.error("许可证文件签名验证失败，文件可能被篡改")
                    return False, "许可证文件已损坏", {}
            else:
                # 旧格式兼容（没有签名的许可证）
                license_data = save_data

            # 检查机器码是否匹配（防止复制许可证文件）
            current_machine = self.get_machine_code()
            if license_data.get('machine_code') != current_machine:
                return False, "许可证与当前机器不匹配", {}

            # 检查是否过期
            expiry = license_data.get('expiry', 0)
            if expiry > 0 and time.time() > expiry:
                return False, "许可证已过期", license_data

            return True, f"许可证有效：{license_data.get('user', '')}", license_data

        except Exception as e:
            logger.error(f"许可证验证失败: {e}")
            return False, f"许可证文件损坏: {str(e)}", {}

    def get_license_info(self) -> Optional[Dict]:
        """获取当前许可证信息"""
        if not self.license_file.exists():
            return None
        try:
            with open(self.license_file, 'r') as f:
                save_data = json.load(f)
                # 新格式：{'license': {...}, 'signature': '...'}
                # 旧格式：直接是许可证数据
                if 'license' in save_data:
                    return save_data['license']
                return save_data
        except:
            return None

    def deactivate_license(self) -> Tuple[bool, str]:
        """取消激活（删除本地许可证）"""
        try:
            if self.license_file.exists():
                self.license_file.unlink()
            return True, "已取消激活"
        except Exception as e:
            return False, f"取消激活失败: {str(e)}"


# 为了兼容旧代码，保留别名
LicenseManager = OfflineLicenseManager
