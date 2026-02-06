"""
析镜许可证管理器
用于管理软件激活和许可证验证
"""
import os
import json
import hmac
import hashlib
import time
from typing import Tuple, Dict, Optional
import logging

logger = logging.getLogger(__name__)


class LicenseManager:
    """许可证管理器"""

    def __init__(self):
        # 许可证存储路径
        self.license_dir = os.path.expanduser("~/.lensanalysis")
        self.license_file = os.path.join(self.license_dir, "license.json")
        self.machine_id_file = os.path.join(self.license_dir, "machine_id")

        # 密钥（实际应该放在环境变量或配置文件中）
        self.secret_key = "LENS_ANALYSIS_2024_SECRET_KEY_CHANGE_ME_IN_PRODUCTION"

        # 确保目录存在
        os.makedirs(self.license_dir, exist_ok=True)

        # 获取或生成机器ID
        self.machine_id = self._get_or_create_machine_id()

    def _get_or_create_machine_id(self) -> str:
        """获取或创建机器ID"""
        if os.path.exists(self.machine_id_file):
            with open(self.machine_id_file, 'r') as f:
                return f.read().strip()

        # 生成新的机器ID
        import platform
        import uuid

        # 使用机器唯一标识
        machine_info = f"{platform.node()}-{platform.machine()}-{uuid.getnode()}"
        machine_id = hashlib.sha256(machine_info.encode()).hexdigest()[:16]

        with open(self.machine_id_file, 'w') as f:
            f.write(machine_id)

        return machine_id

    def check_license(self) -> Tuple[bool, str, Dict]:
        """
        检查许可证是否有效

        Returns:
            (是否有效, 消息, 许可证信息)
        """
        if not os.path.exists(self.license_file):
            return False, "未激活", {}

        try:
            with open(self.license_file, 'r') as f:
                license_data = json.load(f)

            # 检查许可证格式
            required_fields = ['key', 'user', 'expiry', 'signature']
            if not all(field in license_data for field in required_fields):
                return False, "许可证格式错误", {}

            # 验证签名
            if not self._verify_signature(license_data):
                return False, "许可证签名无效", {}

            # 检查是否过期
            expiry_time = license_data.get('expiry', 0)
            if expiry_time > 0 and time.time() > expiry_time:
                return False, "许可证已过期", license_data

            # 检查机器绑定（如果启用）
            if license_data.get('machine_bound', False):
                if license_data.get('machine_id') != self.machine_id:
                    return False, "许可证与当前机器不匹配", license_data

            return True, "许可证有效", license_data

        except Exception as e:
            logger.error(f"许可证验证失败: {e}")
            return False, f"许可证文件损坏: {str(e)}", {}

    def _verify_signature(self, license_data: Dict) -> bool:
        """验证许可证签名"""
        signature = license_data.get('signature', '')
        data_to_sign = f"{license_data['key']}-{license_data['user']}-{license_data['expiry']}"

        if license_data.get('machine_bound', False):
            data_to_sign += f"-{license_data.get('machine_id', '')}"

        expected = hmac.new(
            self.secret_key.encode(),
            data_to_sign.encode(),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(signature, expected)

    def activate_license(self, license_key: str) -> Tuple[bool, str]:
        """
        激活许可证

        Args:
            license_key: 许可证密钥

        Returns:
            (是否成功, 消息)
        """
        # 先尝试本地验证
        is_valid, license_info = self._parse_and_verify_license(license_key)

        if not is_valid:
            # 尝试在线验证（如果配置了服务器）
            return self._online_verify(license_key)

        # 保存许可证
        try:
            with open(self.license_file, 'w') as f:
                json.dump(license_info, f, indent=2)

            user = license_info.get('user', '用户')
            expiry = license_info.get('expiry', 0)

            if expiry == 0:
                return True, f"激活成功！欢迎，{user}（永久许可）"
            else:
                from datetime import datetime
                expiry_date = datetime.fromtimestamp(expiry).strftime("%Y-%m-%d")
                return True, f"激活成功！欢迎，{user}（有效期至 {expiry_date}）"

        except Exception as e:
            logger.error(f"保存许可证失败: {e}")
            return False, f"激活失败: {str(e)}"

    def _parse_and_verify_license(self, license_key: str) -> Tuple[bool, Optional[Dict]]:
        """
        解析并验证许可证密钥

        密钥格式: LENS-用户ID-过期时间戳-签名
        例如: LENS-user123-1735689600-a1b2c3d4...
        """
        try:
            parts = license_key.split('-')
            if len(parts) < 4 or parts[0] != "LENS":
                return False, None

            key_id = parts[1]
            expiry = int(parts[2])
            signature = '-'.join(parts[3:])

            # 重新计算签名验证
            data_to_sign = f"{key_id}-user-{expiry}"
            expected_signature = hmac.new(
                self.secret_key.encode(),
                data_to_sign.encode(),
                hashlib.sha256
            ).hexdigest()[:16]

            if not hmac.compare_digest(signature, expected_signature):
                return False, None

            # 构建许可证信息
            license_info = {
                'key': license_key,
                'user': f"用户_{key_id}",
                'expiry': expiry,
                'signature': signature,
                'machine_bound': False,
                'activated_at': int(time.time())
            }

            return True, license_info

        except Exception as e:
            logger.error(f"解析许可证失败: {e}")
            return False, None

    def _online_verify(self, license_key: str) -> Tuple[bool, str]:
        """
        在线验证许可证（预留接口）

        后期可以接入付费系统，通过服务器验证
        """
        # 目前暂时关闭在线验证，使用本地验证
        # 后期可以启用：
        # import requests
        # try:
        #     response = requests.post(
        #         "https://api.example.com/license/verify",
        #         json={
        #             "license_key": license_key,
        #             "machine_id": self.machine_id,
        #             "product": "lensanalysis"
        #         },
        #         timeout=10
        #     )
        #     if response.status_code == 200:
        #         data = response.json()
        #         if data.get('valid'):
        #             # 保存许可证
        #             license_info = data['license_info']
        #             with open(self.license_file, 'w') as f:
        #                 json.dump(license_info, f)
        #             return True, "在线激活成功"
        #         return False, data.get('message', '在线验证失败')
        #     return False, "服务器连接失败"
        # except Exception as e:
        #     return False, f"网络错误: {str(e)}"

        return False, "无效的许可证密钥"

    def deactivate_license(self) -> Tuple[bool, str]:
        """取消激活"""
        try:
            if os.path.exists(self.license_file):
                os.remove(self.license_file)
            return True, "已取消激活"
        except Exception as e:
            return False, f"取消激活失败: {str(e)}"

    def get_license_info(self) -> Optional[Dict]:
        """获取当前许可证信息"""
        if not os.path.exists(self.license_file):
            return None

        try:
            with open(self.license_file, 'r') as f:
                return json.load(f)
        except:
            return None
