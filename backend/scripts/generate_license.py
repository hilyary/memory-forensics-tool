#!/usr/bin/env python3
"""
析镜许可证生成工具

用于生成用户激活码

使用方法:
    # 生成永久许可证
    python backend/scripts/generate_license.py user123

    # 生成有时限的许可证（365天）
    python backend/scripts/generate_license.py user123 --days 365

    # 生成指定过期时间的许可证
    python backend/scripts/generate_license.py user123 --expiry 2025-12-31

    # 批量生成
    python backend/scripts/generate_license.py user1 user2 user3
"""
import sys
import os
import hmac
import hashlib
import argparse
from datetime import datetime, timedelta


def generate_license(user_id: str, expiry_timestamp: int = 0) -> str:
    """
    生成许可证密钥

    Args:
        user_id: 用户ID
        expiry_timestamp: 过期时间戳（0表示永久）

    Returns:
        许可证密钥
    """
    # 密钥（必须与 license_manager.py 中的相同）
    secret_key = "LENS_ANALYSIS_2024_SECRET_KEY_CHANGE_ME_IN_PRODUCTION"

    # 构建签名数据
    data_to_sign = f"{user_id}-user-{expiry_timestamp}"

    # 生成签名
    signature = hmac.new(
        secret_key.encode(),
        data_to_sign.encode(),
        hashlib.sha256
    ).hexdigest()[:16]

    # 构建许可证密钥: LENS-用户ID-过期时间-签名
    license_key = f"LENS-{user_id}-{expiry_timestamp}-{signature}"

    return license_key


def main():
    parser = argparse.ArgumentParser(description='析镜许可证生成工具')
    parser.add_argument('users', nargs='+', help='用户ID（可以多个）')
    parser.add_argument('--days', type=int, default=0,
                       help='有效期天数（0表示永久）')
    parser.add_argument('--expiry', type=str,
                       help='过期日期（格式：YYYY-MM-DD）')
    parser.add_argument('--output', type=str,
                       help='输出到文件')

    args = parser.parse_args()

    # 计算过期时间戳
    if args.expiry:
        expiry_date = datetime.strptime(args.expiry, '%Y-%m-%d')
        expiry_timestamp = int(expiry_date.timestamp())
    elif args.days > 0:
        expiry_date = datetime.now() + timedelta(days=args.days)
        expiry_timestamp = int(expiry_date.timestamp())
    else:
        expiry_timestamp = 0  # 永久

    # 生成许可证
    licenses = []
    for user_id in args.users:
        license_key = generate_license(user_id, expiry_timestamp)
        licenses.append({
            'user_id': user_id,
            'license_key': license_key,
            'expiry': expiry_timestamp,
            'expiry_date': datetime.fromtimestamp(expiry_timestamp) if expiry_timestamp > 0 else '永久'
        })

    # 输出结果
    print("\n" + "="*70)
    print("析镜许可证生成结果")
    print("="*70)

    for lic in licenses:
        print(f"\n用户ID: {lic['user_id']}")
        print(f"激活码: {lic['license_key']}")
        print(f"有效期: {lic['expiry_date']}")

    print("\n" + "="*70)

    # 保存到文件（可选）
    if args.output:
        with open(args.output, 'w') as f:
            for lic in licenses:
                f.write(f"{lic['user_id']},{lic['license_key']},{lic['expiry']}\n")
        print(f"\n已保存到: {args.output}")

    print("\n使用说明:")
    print("1. 将激活码发送给用户")
    print("2. 用户在软件中输入激活码即可激活")
    print("3. 目前为免费使用，后期可调整为付费模式")


if __name__ == '__main__':
    main()
