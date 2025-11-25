import asyncio
from config import Config
countries = [
        "us",
        "hk",
        "jp",
        "ca",
    ]
import string
import random
import httpx
from loguru import logger
def generate_random_string(length=16):
    # 定义字符集，包括字母和数字
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string

async def get_dynamic_ip_time(t=5,country=None):
    if Config.PROXY_ACCOUNT is None:
        logger.error(f"proxy not configured")
        return None
    """异步获取代理 可指定国家"""
    logger.info(f"开始获取ip...")
    for i in range(3):
        rand_session = generate_random_string(16)
        if country is None:
            country = random.choice(countries)
        # proxy = f"http://{Config.PROXY_ACCOUNT}-region-{country}-session-{rand_session}-sessTime-{t}:{Config.PROXY_PASSWORD}@{Config.PROXY_HOST}"
        proxy = f"http://{Config.PROXY_ACCOUNT}-sessid-{rand_session}-sessTime-{t}:{Config.PROXY_PASSWORD}@{Config.PROXY_HOST}"
        logger.debug(f"{proxy}")

        # 检查IP
        try:
            async with httpx.AsyncClient(timeout=15,proxy = proxy) as client:
                response =await client.get('https://api64.ipify.org?format=json')
                logger.success(f"获取到代理IP:{response.json()['ip']}")
                return proxy
        except Exception as e:
            logger.error("获取代理IP发生错误:", e)
            await asyncio.sleep(0.5)

    return None


def get_dynamitc_ip_no_test(t=5):
    """随机获取一个ip 不做测试"""
    rand_session = generate_random_string(16)
    country = random.choice(countries)
    proxy = f"http://{Config.PROXY_ACCOUNT}-region-{country}-session-{rand_session}-sessTime-{t}:{Config.PROXY_PASSWORD}@{Config.PROXY_HOST}"
    return proxy


def sync_get_ip(t=120):
    import requests
    for i in range(3):
        rand_session = generate_random_string(16)
        country = random.choice(countries)
        proxy = f"http://{Config.PROXY_ACCOUNT}-region-{country}-session-{rand_session}-sessTime-{t}:{Config.PROXY_PASSWORD}@{Config.PROXY_HOST}"
        logger.info(f"{proxy}")
        proxies = {
            "http": proxy,  # 替换为你的代理地址
            "https": proxy  # 替换为你的代理地址
        }
        # 检查IP
        try:
            response = requests.get('https://api64.ipify.org?format=json', proxies=proxies)
            print("当前代理IP:", response.json()['ip'])
            return proxy
        except Exception as e:
            print("发生错误:", e)

    return None
def sync_get_sockes_ip(t=120):
    import requests
    for i in range(3):
        rand_session = generate_random_string(16)
        country = random.choice(countries)
        proxy = f"socks5://{Config.PROXY_ACCOUNT}-region-{country}-session-{rand_session}-sessTime-{t}:{Config.PROXY_PASSWORD}@{Config.PROXY_HOST}"
        logger.info(f"{proxy}")
        proxies = {
            "http": proxy,  # 替换为你的代理地址
            "https": proxy  # 替换为你的代理地址
        }
        # 检查IP
        try:
            response = requests.get('https://api64.ipify.org?format=json', proxies=proxies)
            print("当前代理IP:", response.json()['ip'])
            return proxy
        except Exception as e:
            print("发生错误:", e)

    return None


def test_proxy(proxy):
    import requests
    try:
        # 使用代理发送请求
        response = requests.get('http://httpbin.org/ip', proxies={"http": proxy, "https": proxy}, timeout=5)
        # 检查状态码
        if response.status_code == 200:
            print(f"代理 {proxy} 可用，响应内容：{response.json()}")
        else:
            print(f"代理 {proxy} 不可用，状态码：{response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"代理 {proxy} 不可用，错误：{e}")




if __name__ == '__main__':
    asyncio.run(get_dynamic_ip_time())

