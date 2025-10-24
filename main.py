import asyncio
import json
import os
import string
import sys
import time

import httpx
from eth_account.messages import encode_defunct
# from lxml.parser import result
from web3 import AsyncHTTPProvider, AsyncWeb3, Web3
from loguru import logger
from captcha import captcha_cloudflare_turnstile, solve_recaptcha
from fake_useragent import UserAgent
import random
import aiofiles
import asyncio
from pathlib import Path
from typing import Union

from secret import encrypt_sign_verify_payload,BlockStreetEncryptedPayload

customer_cf_url_file = 'customer_cf_url.txt'
customer_cf_urls = [] #可用打码地址


def load_customer_cf_urls():
    try:
        global customer_cf_urls
        # 获取当前目录
        if getattr(sys, 'frozen', False):
            # 如果是打包后的 EXE
            current_dir = os.path.dirname(sys.executable)
        else:
            # 如果是脚本
            current_dir = os.path.dirname(os.path.abspath(__file__))

        files_path = current_dir
        wallets_list = []

        for filename in os.listdir(files_path):
            if filename.endswith('customer_cf_url.txt'):
                file_path = os.path.join(files_path, filename)

                lines = []
                # 读取文件并写入列表
                with open(file_path, 'r', encoding='utf-8') as file:
                    lines = file.readlines()
                # 去除每行末尾的换行符
                lines = [line.strip() for line in lines]
                # 打印结果
                wallets_list = wallets_list + lines
        customer_cf_urls = wallets_list

    except Exception as e:
        print(f"erro: {e}")
        return None
def generate_random_cf_url():
    global customer_cf_urls
    if len(customer_cf_urls) >0:
        cf_url =random.choice(customer_cf_urls)
        logger.info(f"customer_cf_url: {cf_url}")
        return cf_url
    logger.warning(f"customer_cf_url: wu")
    return ''

async def append_wallet_address(file_path: Union[str, Path], wallet_address: str, check_duplicate: bool = True):
    """
    异步追加钱包地址到.txt文件

    Args:
        file_path: 文件路径
        wallet_address: 钱包地址
        check_duplicate: 是否检查重复地址
    """
    try:
        # 确保文件存在
        path = Path(file_path)

        # 检查重复地址
        if check_duplicate and path.exists():
            async with aiofiles.open(path, 'r', encoding='utf-8') as f:
                content = await f.read()
                if wallet_address in content:
                    print(f"钱包地址已存在: {wallet_address}")
                    return False

        # 追加写入文件
        async with aiofiles.open(path, 'a', encoding='utf-8') as f:
            await f.write(f"{wallet_address}\n")

        print(f"成功写入钱包地址: {wallet_address}")
        return True

    except Exception as e:
        print(f"写入钱包地址时出错: {e}")
        return False

countries = [
        "us",
        "uk",
        "jp",
        "fr",
        "ca",
        "in"

    ]
def generate_random_string(length=16):
    # 定义字符集，包括字母和数字
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string

async def get_dynamic_ip_time(t=5,country=None):
    """异步获取代理 可指定国家"""
    logger.debug(f"开始获取ip...")
    for i in range(3):
        rand_session = generate_random_string(16)
        if country is None:
            country = random.choice(countries)
            # "http://03091493-zone-custom-sessid-PcxZ9MwM7ERwR18K-sessTime-5:uPbMOOcC@na.proxys5.net:6200"
        # proxy = f"http://{Config.PROXY_ACCOUNT}-region-{country}-session-{rand_session}-sessTime-{t}:{Config.PROXY_PASSWORD}@{Config.PROXY_HOST}"
        proxy = f"http://03091493-zone-custom-sessid-{rand_session}-sessTime-{t}:uPbMOOcC@na.proxys5.net:6200"
        logger.info(f"{proxy}")

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
def get_random_ua():
    """使用 fake-useragent 库生成随机 UA"""
    try:
        ua = UserAgent()
        return ua.random
    except:
        # 备用方案
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"

# 安装：pip install fake-useragent

def load_wallets():
    try:
        # 获取当前目录
        if getattr(sys, 'frozen', False):
            # 如果是打包后的 EXE
            current_dir = os.path.dirname(sys.executable)
        else:
            # 如果是脚本
            current_dir = os.path.dirname(os.path.abspath(__file__))
            # current_dir =os.path.dirname(current_dir)
        # 获取父目录
        files_path = os.path.join(current_dir, 'files')
        wallets_list = []

        for filename in os.listdir(files_path):
            if filename.endswith('.txt'):
                file_path = os.path.join(files_path, filename)

                lines = []
                # 读取文件并写入列表
                with open(file_path, 'r', encoding='utf-8') as file:
                    lines = file.readlines()  # 读取每一行并保存到列表中
                # 去除每行末尾的换行符
                lines = [line.strip() for line in lines]
                # 打印结果
                wallets_list = wallets_list + lines
        return wallets_list

    except Exception as e:
        print(f"erro: {e}")
        return None
def load_invite_codes():
    try:
        # 获取当前目录
        if getattr(sys, 'frozen', False):
            # 如果是打包后的 EXE
            current_dir = os.path.dirname(sys.executable)
        else:
            # 如果是脚本
            current_dir = os.path.dirname(os.path.abspath(__file__))
            # current_dir =os.path.dirname(current_dir)
        # 获取父目录
        #files_path = os.path.join(current_dir, 'files')
        wallets_list = []

        for filename in os.listdir(current_dir):
            if filename.endswith('invite_code_list.txt'):
                file_path = os.path.join(current_dir, filename)

                lines = []
                # 读取文件并写入列表
                with open(file_path, 'r', encoding='utf-8') as file:
                    lines = file.readlines()  # 读取每一行并保存到列表中
                # 去除每行末尾的换行符
                lines = [line.strip() for line in lines]
                # 打印结果
                wallets_list = wallets_list + lines
        return wallets_list

    except Exception as e:
        logger.error(f"erro: {e}")
        return None

example_msg="""
blockstreet.money wants you to sign in with your Ethereum account:
0xDE75246436987d0cdaD15af7b573D91b6e66CA9a

Welcome to Block Street

URI: https://blockstreet.money
Version: 1
Chain ID: 1
Nonce: 2KpAAbGrWew1et4n
Issued At: 2025-10-10T02:06:52.383Z
Expiration Time: 2025-10-10T02:08:52.383Z"""
import requests

from datetime import datetime, timezone, timedelta
import aiofiles

rpc_url_22 = ""
lock = asyncio.Lock()
invite_code_list = 'invite_code_list_new.txt'
class BlockStreet:
    def __init__(self, idx, pk,proxy):
        self.ua = get_random_ua()
        self.idx = idx
        self.pk = pk
        self.proxy = proxy
        self.web3 = AsyncWeb3(AsyncHTTPProvider())
        self.http = httpx.AsyncClient(timeout=25,proxy=proxy,http2=True,verify=False)
        self.address = self.web3.eth.account.from_key(self.pk).address
        self.yescaptcha_type = False


        # self.customer_captcha_url = 'http://45.195.111.3:7001/'
    async def close(self):
        await self.http.aclose()

    def get_sigin_params(self, nonce):
        """
        生成以太坊登录签名消息

        Args:
            address (str): 以太坊地址
            nonce (str): 随机数

        Returns:
            str: 格式化的签名消息
        """
        # 当前时间作为发布时间
        issued_at = datetime.now(timezone.utc)
        # 过期时间为2分钟后
        expiration_time = issued_at + timedelta(minutes=2)

        # 格式化时间字符串
        issued_at_str = issued_at.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        expiration_time_str = expiration_time.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


        message = f"""blockstreet.money wants you to sign in with your Ethereum account:
{self.address}

Welcome to Block Street

URI: https://blockstreet.money
Version: 1
Chain ID: 1
Nonce: {nonce}
Issued At: {issued_at_str}
Expiration Time: {expiration_time_str}"""

        signature = self.sign_msg(message)
        json_data = {
            'address': self.address,
            'nonce': nonce,
            'signature': signature,
            'chainId': 1,
            'issuedAt': issued_at_str,
            'expirationTime': expiration_time_str,
            'invite_code': '',
        }
        return json_data

    async def get_nonce(self,retry=0):
        cookies = {
            'gfsessionid': '',
        }

        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'cache-control': 'no-cache',
            'origin': 'https://blockstreet.money',
            'pragma': 'no-cache',
            'priority': 'u=1, i',
            'referer': 'https://blockstreet.money/',
            'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.ua,
            # 'cookie': 'gfsessionid=',
        }
        params = {
            'address': self.address,
        }
        try:
            response = await self.http.get('https://api.blockstreet.money/api/account/signnonce', cookies=cookies,
                                           headers=headers,params=params)
            logger.debug(response.text)
            if response.status_code == 200:
                self.is_registered = response.json()['data']['is_register']
                signnonce = response.json()['data']['signnonce']
                logger.info(f"signnonce ={signnonce}")
                return signnonce
            else:
                if retry < 2:
                    await asyncio.sleep(1)
                    return await self.get_nonce(retry + 1)
                else:
                    return None

        except Exception as e:
            logger.error(f"idx={self.idx}, e={e}")
            if retry < 2:
                await asyncio.sleep(1)
                return await self.get_nonce(retry + 1)
            else:
                return None

    async def write_invite_code(self, invite_code: str):
        """异步写入单个地址"""
        async with lock:  # 使用锁保证线程安全
            async with aiofiles.open(invite_code_list, 'a', encoding='utf-8') as f:
                await f.write(f"{invite_code}\n")

    def sign_msg(self,msg):
        signable_msg = encode_defunct(text=msg)  # 或 encode_defunct(hexstr=msg) 如果是 hex

        sign = self.web3.eth.account.sign_message(signable_msg, self.pk)
        signature = sign.signature.hex()
        signature_hex_with_0x = "0x" + signature  # 带 0x

        return signature_hex_with_0x
    async def share(self):
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'cache-control': 'no-cache',
            # 'content-length': '0',
            'origin': 'https://blockstreet.money',
            'pragma': 'no-cache',
            'priority': 'u=1, i',
            'referer': 'https://blockstreet.money/',
            'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.ua,
            # 'cookie': 'gfsessionid=1tsh5bt1mo9xyrddeb6wflc2qrvaublj',
        }

        try:
            response = await self.http.post('https://api.blockstreet.money/api/share', headers=headers)
            logger.debug(response.json())
        except Exception as e:
            logger.error(e)
            pass

    async def get_customer_hcaptcha(self):
        re_captcha_key = '6Ld-0_ErAAAAACHvVQQLpjeEeXEKiIKvTCk-5emf'
        site_url = "https://blockstreet.money"

        headers = {
            'Content-Type': 'application/json'
        }
        data = {
            'type': 'recaptchav2',
            'websiteUrl': site_url,
            'websiteKey': re_captcha_key,
            'authToken': 'KiiCBkoBGgCWuObuGUiY8jXRJh5r7ZKU',
            'method':"image"#"audio" 或"image"
        }

        try:
            url = generate_random_cf_url()
            response = await httpx.AsyncClient(timeout=50).post(url, headers=headers, data=json.dumps(data))
            result = response.json()

            if result.get('code') == 200:
                logger.info('recaptchav2 token:', result.get('token'))
                return result.get('token')
            else:
                print('Error:', result.get('message'))
                return None

        except requests.exceptions.RequestException as e:
            logger.error('Request error:', e)
            return None
        except json.JSONDecodeError as e:
            logger.error('JSON decode error:', e)
            return None
    async def get_recaptcha_capsolver(self):
        # site_key = '0x4AAAAAABpfyUqunlqwRBYN'
        re_captcha_key = '6Ld-0_ErAAAAACHvVQQLpjeEeXEKiIKvTCk-5emf'
        json_data = {
            "task":
                {
                    "type": "ReCaptchaV2TaskProxyLess",
                    "websiteURL": "https://blockstreet.money/dashboard",
                    "websiteKey": re_captcha_key,
                    "proxy":self.proxy
                }
        }
        try:
            result = await solve_recaptcha(json_data)
            logger.info(f"result = {result}")
            gRecaptchaResponse = result['gRecaptchaResponse']
            # ua = result['userAgent']
            return gRecaptchaResponse
        except Exception as e:
            logger.error(e)
            pass

        return None
    async def get_captcha_yescaptcha(self):
        # site_key = '0x4AAAAAABpfyUqunlqwRBYN'
        re_captcha_key = '6Ld-0_ErAAAAACHvVQQLpjeEeXEKiIKvTCk-5emf'
        json_data = {
            "task":
                {
                    "type": "RecaptchaV2TaskProxyless",
                    "websiteURL": "https://blockstreet.money",
                    "websiteKey": re_captcha_key,
                    "isInvisible": True,
                }
        }
        try:
            result = await captcha_cloudflare_turnstile(json_data)
            logger.debug(f"result = {result}")
            gRecaptchaResponse = result['gRecaptchaResponse']
            # ua = result['userAgent']
            return gRecaptchaResponse
        except Exception as e:
            logger.error(e)
            pass

        return None
    async def get_captcha(self):
        if self.yescaptcha_type:
            return await self.get_captcha_yescaptcha()
        else:
            return await self.get_captcha_cf_api()


    async def get_captcha_cf_api(self):
        site_key = '0x4AAAAAABpfyUqunlqwRBYN'
        site_url = "https://blockstreet.money/dashboard"


        headers = {
            'Content-Type': 'application/json'
        }
        data = {
            'type': 'cftoken',
            'websiteUrl': site_url,
            'websiteKey': site_key,
            'authToken': 'KiiCBkoBGgCWuObuGUiY8jXRJh5r7ZKU',
        }

        try:
            url = generate_random_cf_url()
            response = await httpx.AsyncClient(timeout=50).post(url, headers=headers, data=json.dumps(data))
            result = response.json()

            if result.get('code') == 200:
                logger.success('Turnstile token:', result.get('token'))
                return result.get('token')
            else:
                print('Error:', result.get('message'))
                return None

        except requests.exceptions.RequestException as e:
            print('Request error:', e)
            return None
        except json.JSONDecodeError as e:
            print('JSON decode error:', e)
            return None

    async def get_info(self):
        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'cache-control': 'no-cache',
            'origin': 'https://blockstreet.money',
            'pragma': 'no-cache',
            'priority': 'u=1, i',
            'referer': 'https://blockstreet.money/',
            'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.ua,
            # 'cookie': 'gfsessionid=1gbsbllzgsd4e0dde9wsvdgdnqxvsrka',
        }

        try:
            response = await self.http.get('https://api.blockstreet.money/api/account/info', headers=headers)
            if response.json()['code'] == 0:
                invite_code = response.json()['data']['invite_code']
                logger.info(f"idx:invite_code = {invite_code}")
                await self.write_invite_code(invite_code)
        except Exception as e:
            logger.error(f"get_info error:{e}")
            pass

    async def earn_info(self):

        headers = {
            'accept': 'application/json, text/plain, */*',
            'accept-language': 'zh-CN,zh;q=0.9,en;q=0.8',
            'cache-control': 'no-cache',
            'origin': 'https://blockstreet.money',
            'pragma': 'no-cache',
            'priority': 'u=1, i',
            'referer': 'https://blockstreet.money/',
            'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-site',
            'user-agent': self.ua,
            # 'cookie': 'gfsessionid=1je8ekhb3dufg0ddgti7nen5885i0ld7',
        }

        try:
            response = await self.http.get('https://api.blockstreet.money/api/earn/info', headers=headers)
            logger.success(f"idx= {self.idx},余额信息:{response.json()}")
        except Exception as e:
            logger.error(e)
    async def login(self,invite_code=None):
        signnonce = await self.get_nonce()
        await asyncio.sleep(0.2)
        if signnonce is None:
            logger.error(f"nonce is None Stop")
            return False
        json_data = self.get_sigin_params(signnonce)
        if invite_code is None:
            logger.info(f"没有可用的邀请码，不填")
        else:
            # 设置获取到的邀请码
            json_data['invite_code'] = invite_code

        #加密
        result = encrypt_sign_verify_payload(json_data)
        headers = {
            'host': 'api.blockstreet.money',
            'sec-ch-ua-platform': '"Windows"',
            'timestamp': str(result.timestamp),
            'signature': result.encrypted_key,
            'fingerprint': 'cf512bce53173c6c27488c72f88e8cb6',
            'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
            'sec-ch-ua-mobile': '?0',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
            'accept': 'application/json, text/plain, */*',
            'content-type': 'application/x-www-form-urlencoded',
            'abs': 'a8790953a40f4d7eba761c79cfddf918',
            'token': result.iv,
            'origin': 'https://blockstreet.money',
            'sec-fetch-site': 'same-site',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            'referer': 'https://blockstreet.money/',
            # 'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': 'zh-CN,zh;q=0.9',
            'priority': 'u=1, i',
        }
        if self.is_registered:
            recapcha_response = await self.get_recaptcha_capsolver()
            if recapcha_response is None:
                logger.error(f"recaptcha response is None")
                return False
            headers.update({'recapcha-response': recapcha_response})

        data = result.cipher_text
        logger.debug(f"加密结果= {data}")
        try:
            response = await self.http.post('https://api.blockstreet.money/api/account/signverify',
                                            headers=headers,
                                            data=result.cipher_text,
                                            )

            if response.json()['code'] == 0:
                logger.success(f"idx ={self.idx},login success:{response.json()}")
                return True
            elif response.json()['code'] == 5017:
                logger.error(f"idx ={self.idx},login failed:{response.json()}")
                await append_wallet_address("5017_faile_wallets.txt", self.pk)
            else:
                logger.error(f"idx ={self.idx},login fail:{response.json()}")
                return False

        except Exception as e:
            logger.error(f"idx ={self.idx},login exception:{e}")
            return False

def get_one_invite_code():
    invite_code_list =load_invite_codes()
    if len(invite_code_list) == 0:
        return None
    return random.choice(invite_code_list)
async def wait_a_bit():
    await asyncio.sleep(random.randint(1,3))
async def run_task(idx,pk):
    # try:
        logger.info(f"idx = {idx}, Starting task...")
        proxy = await get_dynamic_ip_time()
        if proxy is None:
            logger.warning(f"proxy is None Continue")
        block_street = BlockStreet(idx, pk,proxy)
        invite_code = get_one_invite_code()
        #login
        if await block_street.login(invite_code):
            await wait_a_bit()
            #获取邀请码
            # await block_street.get_info()
            # await wait_a_bit()
            #share
            await block_street.share()
            await wait_a_bit()
            #查看余额信息
            await block_street.earn_info()
            await wait_a_bit()
        await block_street.close()
        logger.success(f"idx = {idx}, Finish task")
    # except Exception as e:
    #     logger.error(e)
    #     pass
async def limit_semaphore(idx,pk,semaphore):
    async with semaphore:
        await run_task(idx,pk)

async def main(concurrency):
    load_customer_cf_urls()
    wallets = load_wallets()
    # while True:
    print(f"启动时间：{time.time()}")
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [limit_semaphore(idx, pk, semaphore) for idx, pk in enumerate(wallets)]
    await asyncio.gather(*tasks)
    logger.success(f"完成一次循环")
    print(f"跑一次的时间：{time.time()}")


async def test_captcha():
    re_captcha_key = '6Ld-0_ErAAAAACHvVQQLpjeEeXEKiIKvTCk-5emf'
    json_data = {
        "task":
            {
                "type": "ReCaptchaV2TaskProxyLess",
                "websiteURL": "https://blockstreet.money/dashboard",
                "websiteKey": re_captcha_key,
                # "proxy": self.proxy
            }
    }
    result = await solve_recaptcha(json_data)
    logger.info(f"result = {result}")

if __name__ == '__main__':
    # concurrency = 1
    # str_input = input("请输入并发数量不输入回车默认为1:")
    # try:
    #     concurrency = int(str_input)
    # except ValueError:
    #     logger.error("输入错误 默认启动1个线程")
    #     concurrency = 1
    #     time.sleep(0.5)

        # 捕获 SIGINT 信号
    asyncio.run(main(10))
    # 等待用户输入
    # time.sleep(0.2)
    # try:
    #     input("按 Enter 键退出程序...")
    # except ValueError:
    #     logger.error("输出错误")


