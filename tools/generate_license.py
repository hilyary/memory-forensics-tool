#!/usr/bin/env python3
"""
析镜激活码生成工具 - 离线机器绑定版本

管理员工具：根据用户机器码生成激活码

使用方法:
    # 为特定机器生成永久激活码
    python tools/generate_license.py ABCD1234-EFGH-5678-IJKL user123

    # 为特定机器生成限时激活码（30天）
    python tools/generate_license.py ABCD1234-EFGH-5678-IJKL user123 --days 30

    # 批量生成
    python tools/generate_license.py ABCD1234-EFGH-5678-IJKL user1 user2 user3 --days 365

激活流程：
1. 用户启动软件，获取机器码（16位，格式：XXXX-XXXX-XXXX-XXXX）
2. 用户在公众号发送机器码给管理员
3. 管理员使用本工具生成激活码
4. 管理员将激活码发送给用户
5. 用户在软件中输入激活码完成激活
"""
import sys
import os
import argparse

# 添加项目根目录到路径，以便导入 license_manager
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from backend.license_manager import OfflineLicenseManager


def generate_license_code(machine_code: str, user_id: str, days: int = 0) -> str:
    """
    生成激活码

    Args:
        machine_code: 用户的机器码（16位）
        user_id: 用户ID
        days: 有效期天数（0表示永久）

    Returns:
        激活码
    """
    manager = OfflineLicenseManager()

    try:
        license_key = manager.generate_license(machine_code, user_id, days)
        return license_key, None
    except Exception as e:
        return None, str(e)


def main():
    parser = argparse.ArgumentParser(
        description='析镜激活码生成工具 - 离线机器绑定版本',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  %(prog)s ABCD1234-EFGH-5678-IJKL user123
  %(prog)s ABCD1234-EFGH-5678-IJKL user123 --days 30
  %(prog)s ABCD1234-EFGH-5678-IJKL user1 user2 user3 --days 365

激活流程:
  1. 用户启动软件获取机器码
  2. 用户在公众号发送机器码
  3. 使用本工具生成激活码
  4. 将激活码发送给用户
        """
    )

    parser.add_argument('machine_code', help='用户的机器码（16位）')
    parser.add_argument('user_id', nargs='+', help='用户ID（可以多个）')
    parser.add_argument('--days', type=int, default=0,
                       help='有效期天数（默认0表示永久）')
    parser.add_argument('--output', type=str,
                       help='输出到文件（CSV格式）')

    args = parser.parse_args()

    # 验证机器码格式
    manager = OfflineLicenseManager()
    valid, error = manager.verify_machine_code(args.machine_code)
    if not valid:
        print(f"❌ 错误：{error}")
        print(f"   机器码应为16位，格式：XXXX-XXXX-XXXX-XXXX")
        return 1

    # 为每个用户生成激活码
    licenses = []
    for user_id in args.user_id:
        license_key, error = generate_license_code(args.machine_code, user_id, args.days)
        if license_key:
            licenses.append({
                'machine_code': args.machine_code,
                'user_id': user_id,
                'license_key': license_key,
                'days': args.days,
                'expiry': '永久' if args.days == 0 else f'{args.days}天'
            })
        else:
            print(f"❌ 为用户 {user_id} 生成失败: {error}")

    # 输出结果
    if not licenses:
        print("❌ 未生成任何激活码")
        return 1

    print("\n" + "="*70)
    print("析镜激活码生成结果")
    print("="*70)
    print(f"\n机器码: {args.machine_code}")
    print(f"有效期: {args.days}天" if args.days > 0 else "有效期: 永久")
    print()

    for lic in licenses:
        print(f"用户: {lic['user_id']}")
        print(f"激活码: {lic['license_key']}")
        print()

    print("="*70)

    # 保存到文件（可选）
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write("# 析镜激活码列表\n")
                f.write(f"# 机器码: {args.machine_code}\n")
                f.write(f"# 生成时间: {__import__('datetime').datetime.now()}\n")
                f.write("\n")
                for lic in licenses:
                    f.write(f"{lic['user_id']},{lic['license_key']},{lic['days']}\n")
            print(f"\n✅ 已保存到: {args.output}")
        except Exception as e:
            print(f"\n⚠️  保存文件失败: {e}")

    print("\n📋 使用说明:")
    print("1. 将激活码发送给用户")
    print("2. 用户在软件的激活界面输入激活码")
    print("3. 激活成功后重启软件即可使用")

    return 0


if __name__ == '__main__':
    sys.exit(main())
