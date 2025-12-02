import asyncio
import base64
import json
import math
import os
import re
import string
import sys
import time
import uuid

from firstmail import FirstMail

import httpx
from eth_account.messages import encode_defunct
from web3 import AsyncHTTPProvider, AsyncWeb3
from loguru import logger
# 或者更简单的配置方式
# 移除默认的处理器
# logger.remove()
# logger.add(sys.stderr, level="INFO")
from block_street_rsa_config import get_block_street_public_keys_from_website
from captcha import solve_recaptcha, nocattcha_solve_recaptcha
from fake_useragent import UserAgent
import random
import asyncio
from pathlib import Path
from typing import Union

from ip import get_dynamic_ip_time
from secret import new_encrypt_sign_verify_payload, aes_cbc_decrypt
import requests
from datetime import datetime, timezone, timedelta
import aiofiles
customer_cf_url_file = 'customer_cf_url.txt'
customer_cf_urls = [] #可用打码地址
logger.remove()
logger.add(sys.stderr, level="INFO")
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

def generate_random_string(length=16):
    # 定义字符集，包括字母和数字
    characters = string.ascii_letters + string.digits
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string
def get_random_ua():
    """使用 fake-useragent 库生成随机 UA"""
    try:
        ua = UserAgent()
        return ua.random
    except:
        # 备用方案
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
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
def read_email_accounts(file_path='firtmail_account.txt'):
    """
    读取邮箱账号文件
    文件格式：一行一个账号，邮箱:密码
    """
    accounts = []

    if getattr(sys, 'frozen', False):
        # 如果是打包后的 EXE
        current_dir = os.path.dirname(sys.executable)
    else:
        # 如果是脚本
        current_dir = os.path.dirname(os.path.abspath(__file__))


    # parent_dir = os.path.dirname(current_dir)
    # 获取父目录
    files_path = os.path.join(current_dir, 'firtmail_account.txt')

    try:
        with open(files_path, 'r', encoding='utf-8') as file:
            for line_num, line in enumerate(file, 1):
                line = line.strip()
                if line and not line.startswith('#'):  # 跳过空行和注释行
                    if ':' in line:
                        email, password = line.split(':', 1)  # 只分割一次，防止密码中有冒号
                        email = email.strip()
                        password = password.strip()
                        accounts.append({
                            'email': email,
                            'password': password,
                            'line_number': line_num
                        })
                    else:
                        print(f"警告: 第{line_num}行格式错误，缺少冒号分隔符: {line}")

        print(f"成功读取 {len(accounts)} 个邮箱账号")
        return accounts

    except FileNotFoundError:
        print(f"错误: 文件 {file_path} 不存在")
        return []
    except Exception as e:
        print(f"读取文件时出错: {e}")
        return []


rpc_url_22 = ""
lock = asyncio.Lock()
invite_code_list = 'invite_code_list_new.txt'

import asyncio
from contextlib import asynccontextmanager


class EmailClientManager:
    """邮箱客户端管理器"""

    def __init__(self, max_connections=10):
        self.semaphore = asyncio.Semaphore(max_connections)

    @asynccontextmanager
    async def get_client(self, email, password):
        """上下文管理器，确保资源正确释放"""
        async with self.semaphore:
            client = None
            try:
                client = FirstMail(email, password)
                yield client
            finally:
                if client:
                    try:
                        client.close()
                    except Exception as e:
                        logger.warning(f"关闭客户端时出错: {e}")
# 全局客户端管理器
email_client_manager = EmailClientManager()
class BlockStreet:
    def __init__(self, idx, pk,proxy,email=None,email_pwd=None,public_keys=None):
        self.ua = get_random_ua()
        self.idx = idx
        self.pk = pk
        self.email=email
        self.email_pwd = email_pwd
        self.proxy = proxy
        self.web3 = AsyncWeb3(AsyncHTTPProvider())
        self.http = httpx.AsyncClient(timeout=25,proxy=proxy,verify=False,http2=True)
        self.address = self.web3.eth.account.from_key(self.pk).address
        self.chain_id = 1
        self.public_keys = public_keys
        self.abs = "166cdba1e92744e9b8869563b6ab6215"
        self.fingerprint = '499cf510f0e1f45295b32dd9cb229abc'
        self.recaptcha_keys =[]
        self.version = "0.1.3"

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
Chain ID: {self.chain_id}
Nonce: {nonce}
Issued At: {issued_at_str}
Expiration Time: {expiration_time_str}"""

        signature = self.sign_msg(message)
        json_data = {
            'address': self.address,
            'nonce': nonce,
            'signature': signature,
            'chainId': self.chain_id,
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
            'host': 'api.blockstreet.money',
            'sec-ch-ua-platform': '"Windows"',
            'user-agent': self.ua,
            'accept': 'application/json, text/plain, */*',
            'fingerprint': self.fingerprint,
            'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
            'sec-ch-ua-mobile': '?0',
            'origin': 'https://blockstreet.money',
            'sec-fetch-site': 'same-site',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            'referer': 'https://blockstreet.money/',
            # 'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': 'zh-CN,zh;q=0.9',
            'priority': 'u=1, i',
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
                # logger.info(f"signnonce ={signnonce}")
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
            await self.http.post('https://api.blockstreet.money/api/share', headers=headers)
            # logger.debug(response.json())
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
                logger.error('Error:', result.get('message'))
                return None

        except requests.exceptions.RequestException as e:
            logger.error('Request error:', e)
            return None
        except json.JSONDecodeError as e:
            logger.error('JSON decode error:', e)
            return None
    async def get_recaptcha_capsolver(self,site_key):
        # site_key = '0x4AAAAAABpfyUqunlqwRBYN'
        # re_captcha_key = '6Ld-0_ErAAAAACHvVQQLpjeEeXEKiIKvTCk-5emf'
        # rr="6Lf-rfgrAAAAAGNmE_Y4php5cLwsjUc_KSagV4Pw"
        # re_captcha_key = '6LdcygQsAAAAABMaL8amPoIFkGXBbNcH5rmE0Rfg'
        # if self.recaptcha_site_key is not None:
        #     re_captcha_key = self.recaptcha_site_key
        json_data = {
                "referer": "https://blockstreet.money/dashboard",
                "sitekey": site_key,
                "size":"normal",
                "title":"BlockStreet",
                'sa':'email-code',
                # "apiDomain": "",
        }
        # if self.proxy is not None:
        #     json_data['proxy'] = self.proxy
        try:
            result = await nocattcha_solve_recaptcha(json_data)
            logger.info(f"result = {result}")
            gRecaptchaResponse = result['data']['token']
            return gRecaptchaResponse
        except Exception as e:
            logger.error(e)
            pass

        return None

    async def get_site_keys(self):
        url = "https://api.blockstreet.money/api/account/data"

        secret_result =await new_encrypt_sign_verify_payload({},self.public_keys)
        c = {
            'token':secret_result.iv,
            'signature':secret_result.encrypted_key,
            'timestamp':str(secret_result.timestamp),
            'abs':self.abs
        }
        aes_key = secret_result.aes_key
        # print(f"iv ={secret_result.iv}")
        try:
            response = await self.http.get(url, headers=c)
            data = response.json()['data']['data']
            decrypted_data = aes_cbc_decrypt(data, aes_key, secret_result.iv)
            # decrypted_result = base64.b64encode(decrypted_data).decode('ascii')
            # 直接转换
            self.recaptcha_keys = json.loads(decrypted_data.decode('utf-8'))
            # print(self.recaptcha_keys)
            return self.recaptcha_keys
        except Exception as e:
            logger.error(e)
            return []

    async def get_email_code_with_retry(self, max_retries=3):
        """带重试的获取验证码方法"""
        for attempt in range(max_retries):
            try:
                logger.info(f"尝试获取验证码 (第 {attempt + 1} 次)...")

                code = await self.get_email_code()
                if code:
                    return code

                # 等待后重试
                if attempt < max_retries - 1:
                    wait_time = 5 * (attempt + 1)  # 递增等待时间
                    logger.info(f"等待 {wait_time} 秒后重试...")
                    await asyncio.sleep(wait_time)

            except Exception as e:
                logger.error(f"第 {attempt + 1} 次尝试失败: {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(5)

        logger.error(f"经过 {max_retries} 次尝试后仍失败")
        return None

    async def get_email_code(self):
        """使用连接池获取验证码"""
        try:
            async with email_client_manager.get_client(self.email, self.email_pwd) as client:
                last_email = client.get_last_mail()
                if last_email:
                    logger.info(f"找到邮件 - 主题: {last_email.subject}")

                    if "BlockStreet Verification Code" in last_email.subject:
                        pattern = r'<h2[^>]*>(\d{6})</h2>'
                        matches = re.findall(pattern, last_email.body)
                        if matches:
                            code = matches[0]
                            logger.info(f"成功提取验证码: {code}")
                            return code

                return None

        except Exception as e:
            logger.error(f"获取验证码失败: {e}")
            return None


    async def send_email(self):

        n = await self.get_site_keys()

        s = int(time.time()*1000)

        # 计算天数（86400000毫秒=1天）
        days = s // 86400000
        # 对数组长度取模得到索引
        o = n[days % len(n)]
        # logger.debug(f"n = {n},s = {s},days = {days},o = {o}")
        headers = {
            # 'content-length': '29',
            'sec-ch-ua-platform': '"Windows"',
            'fingerprint': self.fingerprint,
            'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
            'sec-ch-ua-mobile': '?0',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
            'accept': 'application/json, text/plain, */*',
            'content-type': 'application/json',
            'origin': 'https://blockstreet.money',
            'sec-fetch-site': 'same-site',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            'referer': 'https://blockstreet.money/',
            # 'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': 'zh-CN,zh;q=0.9',
            'priority': 'u=1, i'

        }
        recapcha_response = await self.get_recaptcha_capsolver(o)
        if recapcha_response is None:
            logger.error(f"recaptcha response is None")
            return False
        send_success = False
        # try:
        headers.update({'recapcha-response': recapcha_response,'version':self.version,'timestamp':str(s)})
        params = {
            'email': self.email
        }
        logger.debug(f"send_email_params={params}")
        response = await self.http.post('https://api.blockstreet.money/api/account/email/send', params=params,
                                        headers=headers)
        logger.debug(f"status_code = {response.status_code},response = {response.text}")
        if response.status_code == 200 and response.json()['code']==0:
            send_success = True
        else:
            logger.error(f"status_code = {response.status_code},response = {response.text}")

        return send_success

        # except Exception as e:
        #     logger.error(f"idx = {self.idx},send_email error: {e}")
        #     return False
        # if send_success:
            # code_email = await temp_email.wait_for_new_mail()
            # logger.info(f"code_email = {code_email}")

    async def bind_email(self,code):
        json_data= {
            "email": self.email,
            "code":code
        }
        headers = {
            'host': 'api.blockstreet.money',
            # 'content-length': '45',
            'sec-ch-ua-platform': '"Windows"',
            'user-agent': self.ua,
            'accept': 'application/json, text/plain, */*',
            'fingerprint': '5e057a6a0c646c361885fa9a591879ac',
            'content-type': 'application/json',
            'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
            'sec-ch-ua-mobile': '?0',
            'origin': 'https://blockstreet.money',
            'sec-fetch-site': 'same-site',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            'referer': 'https://blockstreet.money/',
            # 'accept-encoding': 'gzip, deflate, br, zstd',
            'accept-language': 'zh-CN,zh;q=0.9',
            'priority': 'u=1, i',
        }

        response = await self.http.post("https://api.blockstreet.money/api/account/email/bind",json=json_data,headers=headers)
        logger.debug(response.json())


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
        if self.is_registered:
            if invite_code is None:
                logger.info(f"没有可用的邀请码，不填")
            else:
                # 设置获取到的邀请码
                json_data['invite_code'] = invite_code
        #加密
        result = await new_encrypt_sign_verify_payload(json_data,self.public_keys)

        headers = {
            'host': 'api.blockstreet.money',
            'sec-ch-ua-platform': '"Windows"',
            'timestamp': str(result.timestamp),
            'signature': result.encrypted_key,
            'fingerprint': self.fingerprint,
            'sec-ch-ua': '"Google Chrome";v="141", "Not?A_Brand";v="8", "Chromium";v="141"',
            'sec-ch-ua-mobile': '?0',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
            'accept': 'application/json, text/plain, */*',
            'content-type': 'application/x-www-form-urlencoded',
            'abs': self.abs,
            'token': result.iv,
            'origin': 'https://blockstreet.money',
            'sec-fetch-site': 'same-site',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            'referer': 'https://blockstreet.money/',
            'accept-language': 'zh-CN,zh;q=0.9',
            'priority': 'u=1, i',
        }
        # if self.is_registered:
        #     recapcha_response = await self.get_recaptcha_capsolver()
        #     if recapcha_response is None:
        #         logger.error(f"recaptcha response is None")
        #         return False
        #     headers.update({'recapcha-response': recapcha_response})
        logger.debug(headers)
        # cf_token = await self.get_captcha_cf_api()
        # if cf_token is not None
        #     headers.update({'cf-token': cf_token})
        # try:
        response = await self.http.post('https://api.blockstreet.money/api/account/signverify',
                                        headers=headers,
                                        data=result.cipher_text,
                                        )

        if response.json()['code'] == 0:
            logger.success(f"idx ={self.idx},login success:{response.json()}")
            if response.json()['data']['need_bind_email']:
                logger.info(f"idx={self.idx},need bind email，start！")
                bind = os.getenv('BIND_EMAIL')
                if bind =="1":
                    logger.debug(f"配置为继续绑定")
                    if await self.send_email():
                        await asyncio.sleep(2)
                        email_code = await self.get_email_code_with_retry(3)
                        await  self.bind_email(email_code)
                        return True
                    else:
                        return False
                else:
                    logger.debug(f"配置为不继续绑定")

                    return False
            else:
                return True
        elif response.json()['code'] == 5017:
            logger.error(f"idx ={self.idx},login failed:{response.json()}")
            await append_wallet_address("5017_faile_wallets.txt", self.pk)
        else:
            logger.error(f"idx ={self.idx},login fail:{response.json()}")
            return False

        # except Exception as e:
        #     logger.error(f"idx ={self.idx},login exception:{e}")
        #     return False

def get_one_invite_code():
    invite_code_list =load_invite_codes()
    if len(invite_code_list) == 0:
        return None
    return random.choice(invite_code_list)
async def wait_a_bit():
    await asyncio.sleep(random.randint(1,3))


# 全局统计变量和锁
success_count = 0
fail_count = 0
current_cycle = 0
stats_lock = asyncio.Lock()  # 添加锁保护统计变量

async def run_task(idx,pk,email_account):
    global success_count, fail_count
    try:
        #先获取公钥

        logger.info(f"idx = {idx}, Starting task...")
        # proxy = None
        proxy = await get_dynamic_ip_time()
        if proxy is None:
            logger.warning(f"proxy is None Continue")

        public_keys =await get_block_street_public_keys_from_website()
        await wait_a_bit()
        logger.debug(email_account)
        # return
        block_street = BlockStreet(
            idx=idx,
            pk=pk,
            proxy=proxy,
            email=email_account['email'],
            email_pwd=email_account['password'],
            public_keys=public_keys
        )
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
            # 使用锁保护成功计数
            async with stats_lock:
                success_count += 1
        else:
            # 使用锁保护失败计数
            async with stats_lock:
                fail_count += 1
        await block_street.close()

        async with stats_lock:
            logger.warning(
                f"=== 第 {current_cycle} 次循环统计 ===\n"
                f"成功总数: {success_count}\n"
                f"失败总数: {fail_count}\n"
                f"总计任务: {success_count + fail_count}\n"
                f"成功率: {(success_count / (success_count + fail_count)) * 100:.2f}%" if (
                                                                                                      success_count + fail_count) > 0 else "N/A"
            )
        # sleep_time = random.randint(20,30)
        # logger.info(f"idx = {idx}, 休眠{sleep_time}s")
        # await asyncio.sleep(sleep_time)
    except Exception as e:
        logger.error(e)
        pass
async def limit_semaphore(idx,pk,email_account,semaphore):
    async with semaphore:
        await run_task(idx,pk,email_account)

async def main_work(concurrency):
    logger.info(f"开始任务")
    wallets = load_wallets()
    emails = read_email_accounts()
    if len(wallets) == 0:
        logger.error("no wallets found")
        return

    if len(emails) == 0:
        logger.error("no email accounts found")
        return
    min_len =len(wallets)

    if len(wallets) != len(emails):
        logger.warning(f"钱包数量({len(wallets)})与邮箱数量({len(emails)})不匹配,取数量小的运行")
        min_len = min(len(wallets), len(emails))

    wallets = wallets[:min_len]
    emails= emails[:min_len]
    #测试
    # wallets = wallets[29011:]
    # emails = emails[29011:]
    #配置是否循环一直跑：
    cycle =os.getenv('CYCLE')
    #循环次数
    if cycle=="1":
        logger.info(f"循环一直跑")
        while True:
            global success_count, fail_count, current_cycle
            async with stats_lock:
                success_count = 0
                fail_count = 0
                current_cycle += 1
            semaphore = asyncio.Semaphore(concurrency)
            tasks = []

            for idx, (pk, email_account) in enumerate(zip(wallets, emails)):
                task = limit_semaphore(idx, pk, email_account, semaphore)
                tasks.append(task)
            await asyncio.gather(*tasks)
            logger.success(f"完成一次循环")
    else:
        logger.info(f"仅跑一次")
        semaphore = asyncio.Semaphore(concurrency)
        tasks = []

        for idx, (pk, email_account) in enumerate(zip(wallets, emails)):
            task = limit_semaphore(idx, pk, email_account, semaphore)
            tasks.append(task)
        await asyncio.gather(*tasks)
        logger.success(f"完成一次循环")


if __name__ == "__main__":
    # 运行主程序
    currency = os.getenv("THREAD")
    if currency:
        logger.info(f"启动的线程为:{currency}")
        asyncio.run(main_work(concurrency=int(currency)))
    else:
        logger.info(f"启动的线程为:1")

        asyncio.run(main_work(concurrency=1))

