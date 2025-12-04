import asyncio
import json
import re

import httpx
import requests
from bs4 import BeautifulSoup
from loguru import logger
# RSA公钥列表
BLOCK_STREET_RSA_PUBLIC_KEYS = [
    """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzpG+3W5mvFXBmJSDiDc
VyEZrR7rsJHHNb7bPLPSdwDBDfrg3EaPH88WAhLMqHx2MwSPLcG44eU7ICJ/l0xL
hZGx8NiqZnkwKrOKzBUyY6+ZlaOZZvRp9WTP+vVDeApW+3dftq8jJm9C1F+2v6cU
8VXjEnH/QVx6I/7zhdf15aQxm28JTj5z1jlfER04qUWZV+EcktG/f7frjYw0YhsZ
HqzeKwU0ggUiIDfcXlsNRbx4rrFwh1+c1Yy8ctb3+PQY8/EOgVgEEKPR1vFnC6me
R4ooXjx9psXL2dt37+8BOi1Ja/ruG6uoCJKr7jMF7dND5p0kbbAZPHfZKoiYAKhc
bwIDAQAB
-----END PUBLIC KEY-----""",
    """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxX8AFdH2X9GmVO50msDy
zAcfdhNwNQsjHLSk1NVk/EkrEGngajAydd9/DN7FdtUck816riO20/uhwqFfEPb3
Nd74t3DBM2TLvw4foVbssaR9SER2G0DJOi5bKEDNhaVeg03H1/X1/qZiKv38LSwY
VgWi+yiVJ1n18elbE5NRD2Wv2ybqdZ2TIVOIrGtneUhbN0CrrxdeuO0/yqitohnC
Bm+rwQO4FXqnD3MKmCTBQD8bBFWaHw2ow2CX8vXMuPJBYEk0b8tYMzbxWJUnoVDq
tDjYj5L10R/MtFDRvaRG/E3igTcYF0QRPfvP78kCwY2QIXnRZEjliEfoku42YL0R
ZwIDAQAB
-----END PUBLIC KEY-----""",
"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxkEVgGx/dKn8axHe0B3T
yCqHjE62ofCO8E8mCKsZj7Kx/wTHqKAZpF/55pFGkF3gr9sLLQcx21VfEZsGIJ8q
YOndyZDuB06b5JE0Xu26g5iwMW/xkBtIm8eMr8L+ApHU2hml0KqHGdULeSNcLRiu
CHGnP+W2zjLnzl47HTNPPEFkFbSe8RBVQ0SediY+RzLVFX89Tpt3NMMvYs8ng9wi
/cDIbUXgMIpYdiHfaW28X9GoUXKJmP4pB5rEXk0J22bKcRsopECOudu5Am4dCrDn
kbxrUxQR4dNSiyOKFkarARvkWOukcvNXHTg58z6+uzg9kVRSaVV2hShoY0Dwfg++
qwIDAQAB
-----END PUBLIC KEY-----"""
]

def extract_rsa_public_keys_advanced(js_content):
    """
    更精确地提取RSA公钥数组，保持原始顺序
    """
    """
       修复的公钥提取函数
       """
    # 方法1：精确匹配数组内容
    pattern1 = r'const\s+rsaPublicKeys\s*=\s*\[([\s\S]*?)\]'
    match = re.search(pattern1, js_content)

    if match:
        keys_section = match.group(1)
        logger.debug("找到密钥数组区域")

        # 提取单个公钥（避免重复匹配）
        key_pattern = r'`-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----`'
        raw_keys = re.findall(key_pattern, keys_section)

        # 清理格式
        cleaned_keys = []
        for key in raw_keys:
            # 移除反引号
            clean_key = key.strip('`')
            # 移除可能的重复包装
            clean_key = remove_duplicate_wrapping(clean_key)
            cleaned_keys.append(clean_key)

        return cleaned_keys

    # 方法2：直接在整个内容中搜索（但只取前3个）
    key_pattern = r'`-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----`'
    all_keys = re.findall(key_pattern, js_content)

    if all_keys:
        # 只取前3个，避免匹配到其他地方的公钥
        cleaned_keys = []
        for key in all_keys[:3]:
            clean_key = key.strip('`')
            clean_key = remove_duplicate_wrapping(clean_key)
            cleaned_keys.append(clean_key)
        return cleaned_keys

    return []


def remove_duplicate_wrapping(pem_key):
    """
    移除重复的PEM包装
    """
    # 统计BEGIN和END标记的数量
    begin_count = pem_key.count('-----BEGIN PUBLIC KEY-----')
    end_count = pem_key.count('-----END PUBLIC KEY-----')

    if begin_count > 1 or end_count > 1:
        logger.info(f"检测到重复包装: {begin_count}个BEGIN, {end_count}个END")

        # 提取最内层的公钥内容
        # 找到最后一个BEGIN和第一个END之间的内容
        last_begin = pem_key.rfind('-----BEGIN PUBLIC KEY-----') + 27
        first_end = pem_key.find('-----END PUBLIC KEY-----')

        if last_begin < first_end:
            key_content = pem_key[last_begin:first_end].strip()
            # 重新构建标准的PEM格式
            clean_pem = f"-----BEGIN PUBLIC KEY-----\n{key_content}\n-----END PUBLIC KEY-----"
            return clean_pem

    return pem_key
def save_public_keys_to_array(public_keys, output_file=None):
    """
    将提取的公钥保存为Python数组格式
    """
    python_code = "BLOCK_STREET_RSA_PUBLIC_KEYS = [\n"

    for i, key in enumerate(public_keys):
        # 将公钥格式化为多行字符串
        formatted_key = key.replace('\\n', '\n')  # 处理可能的转义字符
        python_code += f'    """{formatted_key}"""'
        if i < len(public_keys) - 1:
            python_code += ","
        python_code += "\n"

    python_code += "]"

    if output_file:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(python_code)
        logger.info(f"公钥数组已保存到: {output_file}")

    return python_code


# 完整流程
def process_js_file(js_file_path, output_file=None):
    """
    完整处理流程：读取JS文件 -> 提取公钥 -> 生成Python数组
    """
    try:
        # 读取JS文件
        with open(js_file_path, 'r', encoding='utf-8') as f:
            js_content = f.read()

        # 提取公钥
        public_keys = extract_rsa_public_keys_advanced(js_content)

        if not public_keys:
            logger.info("未提取到公钥")
            return None

        logger.info(f"成功提取 {len(public_keys)} 个公钥")

        # 生成Python代码
        python_code = save_public_keys_to_array(public_keys, output_file)

        return public_keys, python_code

    except Exception as e:
        logger.info(f"处理失败: {e}")
        return None

def sync_get_block_street_public_keys_from_website():
    url = "https://blockstreet.money/dashboard"
    return get_public_keys_from_website(url)
async def get_block_street_public_keys_from_website(proxy=None):
    """
    从网站直接获取JS文件并提取公钥
    """
    try:
        url = "https://blockstreet.money/dashboard"
        # 获取网页内容
        async with httpx.AsyncClient(timeout=30,proxy=proxy) as client:
            response =await client.get(url)
            # print(response.text)
            # 解析HTML
            soup = BeautifulSoup(response.text, 'html.parser')

            # 查找包含hash的JS文件
            # script_tags = soup.find_all('script', src=re.compile(r'/js/index-\w+\.js'))
            script_tags = soup.find_all('script', src=re.compile(r'/js/index-[^/]+\.js'))

            if not script_tags:
                logger.info("未找到目标JS文件")

            # 获取第一个匹配的JS文件URL
            script_src = script_tags[0]['src']

            # 处理相对路径
            if script_src.startswith('//'):
                js_url = 'https:' + script_src
            elif script_src.startswith('/'):
                # 构建完整URL
                from urllib.parse import urljoin

                js_url = urljoin(url, script_src)
            else:
                js_url = script_src

            # logger.info(f"找到JS文件: {js_url}")
            # 下载JS内容
            js_response = await client.get(js_url)
            js_content = js_response.text
            # logger.info(f"内容：js_response.text= {js_response.text}")

            # 提取公钥
            public_keys = extract_rsa_public_keys_advanced(js_content)

            # recaptcha_site_key = extract_recaptcha_site_key(js_content)
            logger.debug(f"public_keys: {public_keys}")


            return public_keys

    except Exception as e:
        logger.info(f"获取公钥失败: {e}")
        return None,None


def extract_recaptcha_site_key(js_content):
    """
    从JavaScript内容中提取RECAPTCHA_SITE_KEY
    """
    # 匹配 RECAPTCHA_SITE_KEY 的模式
    pattern = r'RECAPTCHA_SITE_KEY\s*=\s*["\']([^"\']+)["\']'

    match = re.search(pattern, js_content)
    if match:
        return match.group(1)
    else:
        return None

def get_public_keys_from_website(url):
    """
    从网站直接获取JS文件并提取公钥
    """
    try:
        # 获取网页内容
        response = requests.get(url)
        response.raise_for_status()

        # 解析HTML
        soup = BeautifulSoup(response.text, 'html.parser')

        # 查找包含hash的JS文件
        script_tags = soup.find_all('script', src=re.compile(r'/js/index-\w+\.js'))

        if not script_tags:
            logger.info("未找到目标JS文件")
            return None

        # 获取第一个匹配的JS文件URL
        script_src = script_tags[0]['src']

        # 处理相对路径
        if script_src.startswith('//'):
            js_url = 'https:' + script_src
        elif script_src.startswith('/'):
            # 构建完整URL
            from urllib.parse import urljoin

            js_url = urljoin(url, script_src)
        else:
            js_url = script_src

        # logger.info(f"找到JS文件: {js_url}")
        # 下载JS内容
        js_response = requests.get(js_url)
        js_response.raise_for_status()
        js_content = js_response.text
        # logger.info(f"内容：js_response.text= {js_response.text}")
        # 提取公钥
        public_keys = extract_rsa_public_keys_advanced(js_content)

        return public_keys

    except Exception as e:
        logger.info(f"获取公钥失败: {e}")
        return None


async def test_public_keys_api_async():
    """异步测试公钥接口 - httpx版本"""
    base_url = "http://localhost:8080"
    try:
        # 测试获取所有公钥
        logger.info("=== 获取公钥本地请求 GET /public-keys ===")
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{base_url}/public-keys")

            logger.info(f"状态码: {response.status_code}")
            logger.info(f"响应头: {dict(response.headers)}")

            if response.status_code == 200:
                data = response.json()
                # logger.info(f"响应数据: {json.dumps(data, indent=2, ensure_ascii=False)}")

                # 验证响应结构
                if data.get("success"):
                    public_keys = data["data"]["public_keys"]
                    # count = data["data"]["count"]
                    # last_update = data["data"]["last_update"]

                    # logger.info(f"\n✅ 接口测试成功:")
                    # logger.info(f"   公钥数量: {count}")
                    # logger.info(f"   最后更新: {last_update}")
                    # logger.info(f"   公钥示例: {public_keys[0][:50] + '...' if public_keys else '无'}")
                    return public_keys
                else:
                    logger.error(f"❌ 接口返回失败: {data.get('error', '未知错误')}")
                    return None
            else:
                logger.error(f"❌ 请求失败，状态码: {response.status_code}")
                logger.error(f"响应内容: {response.text}")
                return None

    except httpx.ConnectError:
        logger.error("❌ 连接失败，请确保服务正在运行")
        return None

    except httpx.TimeoutException:
        logger.error("❌ 请求超时")
        return None

    except Exception as e:
        logger.error(f"❌ 测试失败: {e}")
        return None


async def main():
    public_key = await get_block_street_public_keys_from_website()
    logger.info(public_key)
if __name__ == '__main__':
    asyncio.run(main())