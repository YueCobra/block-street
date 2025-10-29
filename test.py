# import requests
# from bs4 import BeautifulSoup
# import re
# url = "https://blockstreet.money/dashboard"
#
# response = requests.get(url)
# print(response.status_code)
# print(response.text)
#
# # 解析HTML
# soup = BeautifulSoup(response.text, 'html.parser')
#
# # 查找包含hash的JS文件
# script_tags = soup.find_all('script', src=re.compile(r'/js/index-\w+\.js'))
#
# if not script_tags:
#     print("未找到目标JS文件")
#
# # 获取第一个匹配的JS文件URL
# script_src = script_tags[0]['src']
#
# # 处理相对路径
# if script_src.startswith('//'):
#     js_url = 'https:' + script_src
# elif script_src.startswith('/'):
#     # 构建完整URL
#     from urllib.parse import urljoin
#
#     js_url = urljoin(url, script_src)
# else:
#     js_url = script_src
#
#
# print(f"找到JS文件: {js_url}")
# # 下载JS内容
# js_response = requests.get(js_url)
# js_response.raise_for_status()
# print(f"内容：js_response.text= {js_response.text}")
import requests
import json
from datetime import datetime


def test_public_keys_api_sync():
    """同步测试公钥接口"""
    base_url = "http://localhost:8080"

    try:
        # 测试获取所有公钥
        print("=== 测试 GET /public-keys ===")
        response = requests.get(f"{base_url}/public-keys", timeout=10)

        print(f"状态码: {response.status_code}")
        print(f"响应头: {dict(response.headers)}")

        if response.status_code == 200:
            data = response.json()
            print(f"响应数据: {json.dumps(data, indent=2, ensure_ascii=False)}")

            # 验证响应结构
            if data.get("success"):
                public_keys = data["data"]["public_keys"]
                count = data["data"]["count"]
                last_update = data["data"]["last_update"]

                print(f"\n✅ 接口测试成功:")
                print(f"   公钥数量: {count}")
                print(f"   最后更新: {last_update}")
                print(f"   公钥示例: {public_keys[0][:50] + '...' if public_keys else '无'}")
            else:
                print(f"❌ 接口返回失败: {data.get('error', '未知错误')}")
        else:
            print(f"❌ 请求失败，状态码: {response.status_code}")
            print(f"响应内容: {response.text}")

    except requests.exceptions.ConnectionError:
        print("❌ 连接失败，请确保服务正在运行")
    except requests.exceptions.Timeout:
        print("❌ 请求超时")
    except Exception as e:
        print(f"❌ 测试失败: {e}")


def test_all_endpoints():
    """测试所有端点"""
    base_url = "http://localhost:8080"
    endpoints = [
        "/",
        "/public-keys",
        "/public-keys/count",
        "/health"
    ]

    for endpoint in endpoints:
        print(f"\n=== 测试 {endpoint} ===")
        try:
            response = requests.get(f"{base_url}{endpoint}", timeout=5)
            print(f"状态码: {response.status_code}")

            if response.status_code == 200:
                data = response.json()
                print(f"响应: {json.dumps(data, indent=2, ensure_ascii=False)}")
            else:
                print(f"响应: {response.text}")

        except Exception as e:
            print(f"请求失败: {e}")


def test_refresh_endpoint():
    """测试手动刷新接口"""
    base_url = "http://localhost:8080"

    print("\n=== 测试 POST /refresh ===")
    try:
        response = requests.post(f"{base_url}/refresh", timeout=30)
        print(f"状态码: {response.status_code}")

        if response.status_code == 200:
            data = response.json()
            print(f"响应: {json.dumps(data, indent=2, ensure_ascii=False)}")
        else:
            print(f"响应: {response.text}")

    except Exception as e:
        print(f"刷新测试失败: {e}")


if __name__ == "__main__":
    # 运行同步测试
    test_public_keys_api_sync()
    test_all_endpoints()
    test_refresh_endpoint()