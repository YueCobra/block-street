import os
from dotenv import load_dotenv

load_dotenv()  # 加载 .env 文件

class Config:
    #代理信息
    #2 dynamic account
    PROXY_ACCOUNT = os.getenv('PROXY_ACCOUNT')
    PROXY_PASSWORD=os.getenv('PROXY_PASSWORD')
    PROXY_HOST = os.getenv('PROXY_HOST')

    YESCAPTCHA_KEY= os.getenv('YESCAPTCHA_KEY')

    # 非敏感配置可以直接写在这里