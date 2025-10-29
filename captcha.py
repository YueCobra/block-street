import httpx
import asyncio
import os
from dotenv import load_dotenv
from loguru import logger

# 加载.env文件
load_dotenv()




# 读取API密钥
capsolver_api_key = os.getenv('CAPSOLVER_API_KEY')
yescaptcha_api_key=os.getenv('YESCAPTCHA_API_KEY')


yescaptcha_api_url=os.getenv("YESCAPTCHA_API_URL")
capsolver_api_url=os.getenv('CAPSOLVER_API_URL')
capsolver_appid = '75628CA9-CC8D-48BB-AB31-A63A9585E94B'

if yescaptcha_api_key:
    captcha_type ='yescaptcha'
elif capsolver_api_key:
    captcha_type = "capsolver"


async def capsolver_solve(json_data):
    async with httpx.AsyncClient(timeout=25) as client:
        json_data = {**json_data, **{"clientKey": capsolver_api_key, "appId": capsolver_appid}}
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
async def solve_recaptcha(json_data):
    if captcha_type =='yescaptcha':
        return await yescaptcha_solve(json_data)

    elif captcha_type == 'capsolver':
        return await capsolver_solve(json_data)

    else:
        return {'error':1,'message':"未配置captcha key"}

async def get_captcha_result(task_id):
        if captcha_type == "capsolver":
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