import httpx
import asyncio
import os
from dotenv import load_dotenv
from loguru import logger

# 加载.env文件
load_dotenv()



# developerid"0gM2rA"
# 读取API密钥
capsolver_api_key = os.getenv('CAPSOLVER_API_KEY')
yescaptcha_api_key=os.getenv('YESCAPTCHA_API_KEY')


yescaptcha_api_url=os.getenv("YESCAPTCHA_API_URL")
capsolver_api_url=os.getenv('CAPSOLVER_API_URL')
capsolver_appid = '75628CA9-CC8D-48BB-AB31-A63A9585E94B'


two_captcha_api_key = os.getenv("TWOCPATCHA_API_KEY")
two_captcha_api_url = os.getenv("TWOCAPTCHA_API_URL")

nocaptcha_api_key = os.getenv('NOCAPTCHA_API_KEY')

if two_captcha_api_key:
    captcha_type = 'twocaptcha'
elif yescaptcha_api_key:
    captcha_type ='yescaptcha'
elif capsolver_api_key:
    captcha_type = "capsolver"

nocaptcha_url = "http://api.nocaptcha.io/api/wanda/recaptcha/enterprise"

async def nocattcha_solve_recaptcha(json_data):
    async with httpx.AsyncClient(timeout=60) as client:
        headers = {
            'User-Token':nocaptcha_api_key,
            'Content-Type':'application/json',
            'Developer-Id':'0gM2rA'
        }
        logger.debug(f"拼接后的提交为：{json_data}")
        resp = await client.post(nocaptcha_url, json=json_data,headers=headers)
        return resp.json()

async def twocaptcha_solver_recaptcha(json_data):
    async with httpx.AsyncClient(timeout=25) as client:
        json_data = {**json_data, **{"clientKey": two_captcha_api_key}}
        logger.debug(f"拼接后的提交为：{json_data}")
        resp = await client.post(two_captcha_api_url + 'createTask', json=json_data)
        if "taskId" in resp.json():
            taskId = resp.json()["taskId"]
            while True:  # 重试两次
                resp = await get_captcha_result(taskId)
                if resp["errorId"] == 0:
                    if resp["status"] == "ready":
                        logger.success("识别成功")
                        solution = resp["solution"]
                        return solution
                    elif resp["status"] == "processing":
                        logger.info("识别中...请等待2s后查询识别结果")
                        await asyncio.sleep(2)
                else:
                    logger.error(f"识别失败：{resp['errorDescription']}")
                    return None
        else:
            logger.warning(f"taskId 不存在，识别请求发送有问题 {resp.json()}")
            return None

async def capsolver_solve(json_data):
    async with httpx.AsyncClient(timeout=25) as client:
        json_data = {**json_data, **{"clientKey": capsolver_api_key}}
        logger.debug(f"拼接后的提交为：{json_data}")
        resp = await client.post(capsolver_api_url + 'createTask', json=json_data)
        logger.debug(f"识别任务提交结果：{resp.text}")
        await asyncio.sleep(1)
        if "taskId" in resp.json():
            taskId = resp.json()["taskId"]
            while True:  # 重试两次
                resp = await get_captcha_result(taskId)
                # logger.debug(resp)
                if resp["errorId"] == 0:
                    if resp["status"] == "ready":
                        logger.success("识别成功")
                        solution = resp["solution"]
                        return solution
                    await asyncio.sleep(2)
                elif resp["status"] == "failed":
                    logger.info(f"Solve failed! response:{resp.text}")
                    return None
                else:
                    logger.error(f"识别失败：{resp['errorDescription']}")
                    return None
        else:
            logger.warning(f"taskId 不存在，识别请求发送有问题 {resp.json()}")
            return None
async def yescaptcha_solve(json_data):
    async with httpx.AsyncClient(timeout=25) as client:
        json_data = {**json_data,**{"clientKey":yescaptcha_api_key,"softID":"72106"}}
        logger.debug(f"拼接后的提交为：{json_data}")
        resp = await client.post(yescaptcha_api_url+'createTask',json=json_data)
        if "taskId" in resp.json():
            taskId = resp.json()["taskId"]
            while True:  # 重试两次
                resp = await get_captcha_result(taskId)
                if resp["errorId"] == 0:
                    if resp["status"] == "ready":
                        logger.success("识别成功")
                        solution = resp["solution"]
                        return solution
                    elif resp["status"] == "processing":
                        logger.info("识别中...请等待2s后查询识别结果")
                        await asyncio.sleep(2)
                else:
                    logger.error(f"识别失败：{resp['errorDescription']}")
                    return None
        else:
            logger.warning(f"taskId 不存在，识别请求发送有问题 {resp.json()}")
            return None
async def solve_recaptcha_by_capsover_sdk(json_data):
    async with httpx.AsyncClient(timeout=25) as client:
        json_data = {**json_data, **{"clientKey": capsolver_api_key}}
        logger.debug(f"拼接后的提交为：{json_data}")
        res = await client.post("https://api.capsolver.com/createTask", json=json_data)
        resp = res.json()
        task_id = resp.get("taskId")
        if not task_id:
            print("Failed to create task:", res.text)
            return
        print(f"Got taskId: {task_id} / Getting result...")



async def solve_recaptcha(json_data):
    if captcha_type =='twocaptcha':
        logger.info("twocaptcha")
        return await twocaptcha_solver_recaptcha(json_data)
    elif captcha_type =='yescaptcha':
        logger.info("yescaptcha")
        return await yescaptcha_solve(json_data)

    elif captcha_type == 'capsolver':
        logger.info("capsolver")
        return await capsolver_solve(json_data)

    else:
        return {'error':1,'message':"未配置captcha key"}

async def get_captcha_result(task_id):
        if captcha_type == "twocaptcha":
            async with httpx.AsyncClient(timeout=30) as client:

                json_data = {
                    "clientKey": capsolver_api_key,
                    "taskId": task_id
                }
                try:
                    resp = await client.post(two_captcha_api_url + 'getTaskResult', json=json_data)
                    logger.debug(resp.text)
                    return resp.json()
                # except httpx.TimeoutException:
                except Exception as e:
                    return {"errorId": 0, "errorDescription": "自定义错误：请求出错了"}
        elif captcha_type == "capsolver":
            async with httpx.AsyncClient(timeout=30) as client:

                json_data = {
                    "clientKey": capsolver_api_key,
                    "taskId": task_id
                }
                try:
                    resp = await client.post(capsolver_api_url + 'getTaskResult', json=json_data)
                    logger.debug(resp.text)
                    return resp.json()
                # except httpx.TimeoutException:
                except Exception as e:
                    return {"errorId": 0, "errorDescription": "自定义错误：请求出错了"}
        else:
            async with httpx.AsyncClient(timeout=30) as client:

                json_data = {
                    "clientKey": yescaptcha_api_key,
                    "taskId": task_id
                }
                try:
                    resp = await client.post(yescaptcha_api_url + 'getTaskResult', json=json_data)
                    return resp.json()
                except Exception as e:
                    return {"errorId": 1, "errorDescription": "自定义错误：请求崩溃了"}