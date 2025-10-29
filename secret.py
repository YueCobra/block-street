import base64
import json
import time
import os

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import struct
import binascii

from block_street_rsa_config import get_block_street_public_keys_from_website, test_public_keys_api_async


def block_street_get_visitor_id():
    """
    完全复现 Go 版本的 blockStreetGetVisitorID
    """
    global _block_street_visitor_id

    if _block_street_visitor_id is None:
        try:
            visitor_id = generate_visitor_id()
            _block_street_visitor_id = visitor_id
        except Exception:
            # 如果生成失败，使用默认值
            _block_street_visitor_id = "00000000000000000000000000000011"

    return _block_street_visitor_id


def generate_visitor_id():
    """
    完全复现 Go 版本的 generateVisitorID
    """
    while True:
        # 生成 16 字节随机数，相当于 Go 的 crand.Read(buf)
        buf = os.urandom(16)

        # 转换为 bytearray 以便修改
        buf_array = bytearray(buf)

        # 设置版本位：buf[6] = (buf[6] & 0x0f) | 0x40
        buf_array[6] = (buf_array[6] & 0x0f) | 0x40

        # 设置变体位：buf[8] = (buf[8] & 0x3f) | 0x80
        buf_array[8] = (buf_array[8] & 0x3f) | 0x80

        # 转换为十六进制字符串，相当于 Go 的 hex.EncodeToString(buf)
        hex_str = binascii.hexlify(buf_array).decode('ascii')

        # 检查条件：len(hexStr) >= 2 && hexStr[len(hexStr)-2] == '1'
        if len(hex_str) >= 2 and hex_str[len(hex_str) - 2] == '1':
            return hex_str


class BlockStreetEncryptedPayload:
    def __init__(self, cipher_text, iv, encrypted_key, timestamp):
        self.cipher_text = cipher_text
        self.iv = iv
        self.encrypted_key = encrypted_key
        self.timestamp = timestamp


# RSA公钥列表（与Go代码中的相同）
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

# 缓存RSA密钥
_rsa_keys = None
_rsa_keys_error = None

_block_street_visitor_id = None


def encrypt_aes_key_with_rsa(rsa_public_key_pem, aes_key_bytes):
    """
    对应 JavaScript 的 encryptAesKeyWithRsa 函数
    """
    try:
        # 加载RSA公钥
        public_key = serialization.load_pem_public_key(
            rsa_public_key_pem.encode('ascii'),
            backend=default_backend()
        )

        # 将AES密钥转为Base64字符串（对应 CryptoJS.enc.Base64.stringify(a)）
        aes_key_base64 = base64.b64encode(aes_key_bytes).decode('ascii')

        # RSA加密（使用PKCS1v15填充，对应JSEncrypt的默认方式）
        encrypted = public_key.encrypt(
            aes_key_base64.encode('ascii'),
            padding.PKCS1v15()
        )

        # 返回Base64编码的加密结果
        return base64.b64encode(encrypted).decode('ascii')

    except Exception as e:
        raise Exception(f"RSA加密失败: {str(e)}")

async def load_rsa_dynamic_keys(dynamic_keys):
    """加载并缓存RSA公钥"""
    global _rsa_keys, _rsa_keys_error
    if dynamic_keys is None:
        dynamic_keys = BLOCK_STREET_RSA_PUBLIC_KEYS
    if _rsa_keys is not None:
        if _rsa_keys_error:
            raise _rsa_keys_error
        return _rsa_keys

    try:
        keys = []
        for idx, pem_str in enumerate(dynamic_keys):
            public_key = serialization.load_pem_public_key(
                pem_str.encode(),
                backend=default_backend()
            )
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ValueError(f"Unexpected RSA public key type at index {idx}: {type(public_key)}")
            keys.append(public_key)

        _rsa_keys = keys
        return keys
    except Exception as e:
        _rsa_keys_error = e
        raise e

def ensure_block_street_rsa_keys():
    """加载并缓存RSA公钥"""
    global _rsa_keys, _rsa_keys_error

    if _rsa_keys is not None:
        if _rsa_keys_error:
            raise _rsa_keys_error
        return _rsa_keys

    try:
        keys = []
        for idx, pem_str in enumerate(BLOCK_STREET_RSA_PUBLIC_KEYS):
            public_key = serialization.load_pem_public_key(
                pem_str.encode(),
                backend=default_backend()
            )
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise ValueError(f"Unexpected RSA public key type at index {idx}: {type(public_key)}")
            keys.append(public_key)

        _rsa_keys = keys
        return keys
    except Exception as e:
        _rsa_keys_error = e
        raise e


def pkcs7_pad(data, block_size):
    """PKCS7填充"""
    if block_size <= 0:
        return data

    padding = block_size - len(data) % block_size
    if padding == 0:
        padding = block_size

    return data + bytes([padding] * padding)


def index_for_timestamp(timestamp, modulus):
    """根据时间戳计算RSA密钥索引"""
    if modulus <= 0:
        return 0

    # 模拟Go中的大数运算：id = timestamp * 2, index = id % modulus
    id_value = timestamp * 2
    index = id_value % modulus
    return index


def encrypt_sign_verify_payload(payload):
    """
    加密签名验证载荷

    Args:
        payload: 要加密的字典对象

    Returns:
        BlockStreetEncryptedPayload对象
    """
    # 确保RSA密钥已加载
    rsa_keys = ensure_block_street_rsa_keys()

    # 序列化payload为JSON
    try:
        payload_json = json.dumps(payload).encode('utf-8')
    except Exception as e:
        raise ValueError(f"Failed to marshal signverify payload: {e}")

    # 生成AES密钥和IV
    aes_key = os.urandom(32)  # 32 bytes for AES-256
    iv = os.urandom(16)  # 16 bytes for AES block size

    # AES-CBC加密
    try:
        # PKCS7填充
        padded_data = pkcs7_pad(payload_json, 16)  # AES block size is 16

        # 创建加密器
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # 加密数据
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    except Exception as e:
        raise ValueError(f"Failed to encrypt with AES: {e}")

    # 获取时间戳
    timestamp = int(time.time() * 1000)  # 毫秒时间戳

    # 选择RSA密钥
    key_index = index_for_timestamp(timestamp, len(rsa_keys))
    if key_index < 0 or key_index >= len(rsa_keys):
        raise ValueError(f"RSA key index out of bounds: {key_index}")

    selected_rsa_key = rsa_keys[key_index]

    # 用RSA加密AES密钥
    try:
        aes_key_base64 = base64.b64encode(aes_key).decode('ascii')
        encrypted_key = selected_rsa_key.encrypt(
            aes_key_base64.encode('ascii'),
            padding.PKCS1v15()
        )
    except Exception as e:
        raise ValueError(f"Failed to encrypt AES key: {e}")

    # 返回加密结果
    return BlockStreetEncryptedPayload(
        cipher_text=base64.b64encode(ciphertext).decode('ascii'),
        iv=base64.b64encode(iv).decode('ascii'),
        encrypted_key=base64.b64encode(encrypted_key).decode('ascii'),
        timestamp=timestamp
    )

async def new_encrypt_sign_verify_payload(payload,public_keys):
    """
    加密签名验证载荷

    Args:
        payload: 要加密的字典对象

    Returns:
        BlockStreetEncryptedPayload对象
    """
    # 确保RSA密钥已加载
    rsa_keys =await load_rsa_dynamic_keys(public_keys)

    # 序列化payload为JSON
    try:
        payload_json = json.dumps(payload).encode('utf-8')
    except Exception as e:
        raise ValueError(f"Failed to marshal signverify payload: {e}")

    # 生成AES密钥和IV
    aes_key = os.urandom(32)  # 32 bytes for AES-256
    iv = os.urandom(16)  # 16 bytes for AES block size

    # AES-CBC加密
    try:
        # PKCS7填充
        padded_data = pkcs7_pad(payload_json, 16)  # AES block size is 16

        # 创建加密器
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # 加密数据
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    except Exception as e:
        raise ValueError(f"Failed to encrypt with AES: {e}")

    # 获取时间戳
    timestamp = int(time.time() * 1000)  # 毫秒时间戳

    # 选择RSA密钥
    key_index = index_for_timestamp(timestamp, len(rsa_keys))
    if key_index < 0 or key_index >= len(rsa_keys):
        raise ValueError(f"RSA key index out of bounds: {key_index}")

    selected_rsa_key = rsa_keys[key_index]

    # 用RSA加密AES密钥
    try:
        aes_key_base64 = base64.b64encode(aes_key).decode('ascii')
        encrypted_key = selected_rsa_key.encrypt(
            aes_key_base64.encode('ascii'),
            padding.PKCS1v15()
        )
    except Exception as e:
        raise ValueError(f"Failed to encrypt AES key: {e}")

    # 返回加密结果
    return BlockStreetEncryptedPayload(
        cipher_text=base64.b64encode(ciphertext).decode('ascii'),
        iv=base64.b64encode(iv).decode('ascii'),
        encrypted_key=base64.b64encode(encrypted_key).decode('ascii'),
        timestamp=timestamp
    )

# 使用示例
if __name__ == "__main__":
    # 示例payload
    params = {
        'address': '0xDE75246436987d0cdaD15af7b573D91b6e66CA9a',
        'nonce': 'Ns6c9YX0jdwf1KaP',
        'signature': '0xd8aee11ef10d1db0132cb28cbb234e3757563ff55d44eded88cd8bdb3073167469518a60ed6c16dbc0019ef47a6810930ac06e098e7e5e7095f62c5ac23a5ad61b',
        'chainId': '1',
        'issuedAt': '2025-10-22T11:14:20.068Z',
        'expirationTime': '2025-10-22T11:16:20.068Z'
    }

    try:
        # 加密payload
        encrypted_result = encrypt_sign_verify_payload(params)

        print("加密成功!")
        print(f"Cipher Text: {encrypted_result.cipher_text[:50]}...")
        print(f"IV: {encrypted_result.iv}")
        print(f"Encrypted Key: {encrypted_result.encrypted_key[:50]}...")
        print(f"Timestamp: {encrypted_result.timestamp}")

    except Exception as e:
        print(f"加密失败: {e}")