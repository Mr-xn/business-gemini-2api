"""Business Gemini OpenAPI 兼容服务
整合JWT获取和聊天功能，提供OpenAPI接口
支持多账号轮训
支持图片输出（OpenAI格式）
"""

import json
import time
import hmac
import hashlib
import base64
import uuid
import threading
import os
import re
import shutil
import mimetypes
import requests
from pathlib import Path
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import builtins
import secrets
import ipaddress
from flask import Flask, request, Response, jsonify, send_from_directory, abort
from flask_cors import CORS
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from collections import defaultdict
from threading import Lock

# SSL警告配置
# 注意：禁用SSL验证存在安全风险，建议仅在开发环境使用
import urllib3
ssl_verify_enabled = os.getenv("SSL_VERIFY", "false").lower() == "true"
if not ssl_verify_enabled:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    print("[安全警告] SSL证书验证已禁用。建议在生产环境中启用SSL验证（设置环境变量 SSL_VERIFY=true）")

# 配置
CONFIG_FILE = Path(__file__).parent / "business_gemini_session.json"

# 图片缓存配置
IMAGE_CACHE_DIR = Path(__file__).parent / "image"
IMAGE_CACHE_HOURS = 1  # 图片缓存时间（小时）
IMAGE_CACHE_DIR.mkdir(exist_ok=True)

# API endpoints
BASE_URL = "https://biz-discoveryengine.googleapis.com/v1alpha/locations/global"
CREATE_SESSION_URL = f"{BASE_URL}/widgetCreateSession"
STREAM_ASSIST_URL = f"{BASE_URL}/widgetStreamAssist"
LIST_FILE_METADATA_URL = f"{BASE_URL}/widgetListSessionFileMetadata"
ADD_CONTEXT_FILE_URL = f"{BASE_URL}/widgetAddContextFile"
GETOXSRF_URL = "https://business.gemini.google/auth/getoxsrf"

# 账号错误冷却时间（秒）
AUTH_ERROR_COOLDOWN_SECONDS = 900      # 凭证错误，15分钟
RATE_LIMIT_COOLDOWN_SECONDS = 300      # 触发限额，5分钟
GENERIC_ERROR_COOLDOWN_SECONDS = 120   # 其他错误的短暂冷却
LOG_LEVELS = {"DEBUG": 10, "INFO": 20, "ERROR": 40}
DEFAULT_LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
CURRENT_LOG_LEVEL_NAME = DEFAULT_LOG_LEVEL if DEFAULT_LOG_LEVEL in LOG_LEVELS else "INFO"
CURRENT_LOG_LEVEL = LOG_LEVELS[CURRENT_LOG_LEVEL_NAME]
ADMIN_SECRET_KEY = None
API_TOKENS = set()

# 速率限制配置
RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "60"))  # 每分钟请求数
RATE_LIMIT_WINDOW = 60  # 时间窗口（秒）

# 速率限制存储
rate_limit_storage = defaultdict(list)
rate_limit_lock = Lock()

try:
    from zoneinfo import ZoneInfo
except ImportError:
    ZoneInfo = None

# Flask应用
app = Flask(__name__, static_folder='.')
# CORS 配置：仅允许特定来源，或从环境变量读取
allowed_origins = os.getenv("CORS_ORIGINS", "*")
if allowed_origins == "*":
    print("[安全警告] CORS配置为允许所有来源。建议在生产环境中限制CORS_ORIGINS。")
CORS(app, resources={r"/*": {"origins": allowed_origins}})


def check_rate_limit(identifier: str) -> bool:
    """检查速率限制，返回是否允许请求"""
    if not RATE_LIMIT_ENABLED:
        return True
    
    with rate_limit_lock:
        now = time.time()
        # 清理过期的记录
        rate_limit_storage[identifier] = [
            ts for ts in rate_limit_storage[identifier]
            if now - ts < RATE_LIMIT_WINDOW
        ]
        
        # 检查是否超过限制
        if len(rate_limit_storage[identifier]) >= RATE_LIMIT_REQUESTS:
            return False
        
        # 记录本次请求
        rate_limit_storage[identifier].append(now)
        return True


def rate_limit(func):
    """速率限制装饰器"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        # 使用IP地址作为标识符
        identifier = request.remote_addr or "unknown"
        if not check_rate_limit(identifier):
            return jsonify({"error": "请求过于频繁，请稍后再试"}), 429
        return func(*args, **kwargs)
    return wrapper


@app.after_request
def add_security_headers(response):
    """添加安全响应头"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    # 移除可能泄露服务器信息的头
    response.headers.pop('Server', None)
    return response


def _infer_log_level(text: str) -> str:
    t = text.strip()
    if t.startswith("[DEBUG]"):
        return "DEBUG"
    if t.startswith("[ERROR]") or t.startswith("[!]"):
        return "ERROR"
    return "INFO"


_original_print = builtins.print


def filtered_print(*args, **kwargs):
    """简单的日志过滤，根据全局日志级别屏蔽低级别输出"""
    level = kwargs.pop("_level", None)
    sep = kwargs.get("sep", " ")
    text = sep.join(str(a) for a in args)
    level_name = (level or _infer_log_level(text)).upper()
    if LOG_LEVELS.get(level_name, LOG_LEVELS["INFO"]) >= CURRENT_LOG_LEVEL:
        _original_print(*args, **kwargs)


builtins.print = filtered_print


def set_log_level(level: str, persist: bool = False):
    """设置全局日志级别"""
    global CURRENT_LOG_LEVEL_NAME, CURRENT_LOG_LEVEL
    lvl = (level or "").upper()
    if lvl not in LOG_LEVELS:
        raise ValueError(f"无效日志级别: {level}")
    CURRENT_LOG_LEVEL_NAME = lvl
    CURRENT_LOG_LEVEL = LOG_LEVELS[lvl]
    if persist and globals().get("account_manager") and account_manager.config is not None:
        account_manager.config["log_level"] = lvl
        account_manager.save_config()
    _original_print(f"[LOG] 当前日志级别: {CURRENT_LOG_LEVEL_NAME}")


class AccountError(Exception):
    """基础账号异常"""

    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


class AccountAuthError(AccountError):
    """凭证/权限相关异常"""


class AccountRateLimitError(AccountError):
    """配额或限流异常"""


class AccountRequestError(AccountError):
    """其他请求异常"""


class NoAvailableAccount(AccountError):
    """无可用账号异常"""


def get_admin_secret_key() -> str:
    """获取/初始化后台密钥"""
    global ADMIN_SECRET_KEY
    if ADMIN_SECRET_KEY:
        return ADMIN_SECRET_KEY
    if account_manager.config is None:
        # 移除不安全的默认值，强制使用环境变量或自动生成
        env_secret = os.getenv("ADMIN_SECRET_KEY")
        if env_secret:
            ADMIN_SECRET_KEY = env_secret
        else:
            # 自动生成强密钥
            ADMIN_SECRET_KEY = secrets.token_urlsafe(32)
            print("[安全警告] ADMIN_SECRET_KEY 未设置，已自动生成。请保存此密钥以便重启后使用。")
        return ADMIN_SECRET_KEY
    secret = account_manager.config.get("admin_secret_key") or os.getenv("ADMIN_SECRET_KEY")
    if not secret:
        secret = secrets.token_urlsafe(32)
        account_manager.config["admin_secret_key"] = secret
        account_manager.save_config()
    ADMIN_SECRET_KEY = secret
    return ADMIN_SECRET_KEY


def load_api_tokens():
    """从配置加载用户访问token"""
    global API_TOKENS
    API_TOKENS = set()
    if not account_manager.config:
        return
    tokens = account_manager.config.get("api_tokens") or account_manager.config.get("api_token")
    if isinstance(tokens, str):
        if tokens.strip():  # 过滤空字符串
            API_TOKENS.add(tokens)
    elif isinstance(tokens, list):
        for t in tokens:
            if isinstance(t, str) and t.strip():  # 过滤空字符串
                API_TOKENS.add(t)


def persist_api_tokens():
    if account_manager.config is None:
        account_manager.config = {}
    # 过滤空 token
    account_manager.config["api_tokens"] = [t for t in API_TOKENS if t.strip()]
    account_manager.save_config()


def get_admin_password_hash() -> Optional[str]:
    if account_manager.config:
        return account_manager.config.get("admin_password_hash")
    return None


def set_admin_password(password: str):
    if not password:
        raise ValueError("密码不能为空")
    if account_manager.config is None:
        account_manager.config = {}
    account_manager.config["admin_password_hash"] = generate_password_hash(password)
    account_manager.save_config()


def is_valid_api_token(token: str) -> bool:
    if not token:
        return False
    if verify_admin_token(token):
        return True
    return token in API_TOKENS


def require_api_auth(func):
    """开放接口需要 api_token 或 admin token"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = (
            request.headers.get("X-API-Token")
            or request.headers.get("Authorization", "").replace("Bearer ", "")
            or request.cookies.get("admin_token")
        )
        if not is_valid_api_token(token):
            return jsonify({"error": "未授权"}), 401
        return func(*args, **kwargs)
    return wrapper


def create_admin_token(exp_seconds: int = 86400) -> str:
    payload = {
        "exp": time.time() + exp_seconds,
        "ts": int(time.time())
    }
    payload_b = json.dumps(payload, separators=(",", ":")).encode()
    b64 = base64.urlsafe_b64encode(payload_b).decode().rstrip("=")
    secret = get_admin_secret_key().encode()
    signature = hmac.new(secret, b64.encode(), hashlib.sha256).hexdigest()
    return f"{b64}.{signature}"


def verify_admin_token(token: str) -> bool:
    if not token:
        return False
    try:
        b64, sig = token.split(".", 1)
    except ValueError:
        return False
    expected_sig = hmac.new(get_admin_secret_key().encode(), b64.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected_sig, sig):
        return False
    padding = '=' * (-len(b64) % 4)
    try:
        payload = json.loads(base64.urlsafe_b64decode(b64 + padding).decode())
    except Exception:
        return False
    if payload.get("exp", 0) < time.time():
        return False
    return True


def require_admin(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = (
            request.headers.get("X-Admin-Token")
            or request.headers.get("Authorization", "").replace("Bearer ", "")
            or request.cookies.get("admin_token")
        )
        if not verify_admin_token(token):
            return jsonify({"error": "未授权"}), 401
        return func(*args, **kwargs)
    return wrapper


def seconds_until_next_pt_midnight(now_ts: Optional[float] = None) -> int:
    """计算距离下一个 PT 午夜的秒数，用于配额冷却"""
    now_utc = datetime.now(timezone.utc) if now_ts is None else datetime.fromtimestamp(now_ts, tz=timezone.utc)
    if ZoneInfo:
        pt_tz = ZoneInfo("America/Los_Angeles")
        now_pt = now_utc.astimezone(pt_tz)
    else:
        # 兼容旧版本 Python 的简易回退（不考虑夏令时）
        now_pt = now_utc - timedelta(hours=8)

    tomorrow = (now_pt + timedelta(days=1)).date()
    midnight_pt = datetime.combine(tomorrow, datetime.min.time(), tzinfo=now_pt.tzinfo)
    delta = (midnight_pt - now_pt).total_seconds()
    return max(0, int(delta))


class AccountManager:
    """多账号管理器，支持轮训策略"""
    
    def __init__(self):
        self.config = None
        self.accounts = []  # 账号列表
        self.current_index = 0  # 当前轮训索引
        self.account_states = {}  # 账号状态: {index: {jwt, jwt_time, session, available, cooldown_until, cooldown_reason}}
        self.lock = threading.Lock()
        self.auth_error_cooldown = AUTH_ERROR_COOLDOWN_SECONDS
        self.rate_limit_cooldown = RATE_LIMIT_COOLDOWN_SECONDS
        self.generic_error_cooldown = GENERIC_ERROR_COOLDOWN_SECONDS
    
    def load_config(self):
        """加载配置"""
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                self.config = json.load(f)
                if "log_level" in self.config:
                    try:
                        set_log_level(self.config.get("log_level"), persist=False)
                    except Exception:
                        pass
                if "admin_secret_key" in self.config:
                    global ADMIN_SECRET_KEY
                    ADMIN_SECRET_KEY = self.config.get("admin_secret_key")
                load_api_tokens()
                self.accounts = self.config.get("accounts", [])
                # 初始化账号状态
                for i, acc in enumerate(self.accounts):
                    available = acc.get("available", True)  # 默认可用
                    self.account_states[i] = {
                        "jwt": None,
                        "jwt_time": 0,
                        "session": None,
                        "available": available,
                        "cooldown_until": acc.get("cooldown_until"),
                        "cooldown_reason": acc.get("unavailable_reason") or acc.get("cooldown_reason") or ""
                    }
        return self.config
    
    def save_config(self):
        """保存配置到文件"""
        if self.config and CONFIG_FILE.exists():
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(self.config, f, indent=4, ensure_ascii=False)
    
    def mark_account_unavailable(self, index: int, reason: str = ""):
        """标记账号不可用"""
        with self.lock:
            if 0 <= index < len(self.accounts):
                self.accounts[index]["available"] = False
                self.accounts[index]["unavailable_reason"] = reason
                self.accounts[index]["unavailable_time"] = datetime.now().isoformat()
                self.account_states[index]["available"] = False
                self.save_config()
                print(f"[!] 账号 {index} 已标记为不可用: {reason}")

    def mark_account_cooldown(self, index: int, reason: str = "", cooldown_seconds: Optional[int] = None):
        """临时拉黑账号（冷却），在冷却时间内不会被选择"""
        if cooldown_seconds is None:
            cooldown_seconds = self.generic_error_cooldown

        with self.lock:
            if 0 <= index < len(self.accounts):
                now_ts = time.time()
                new_until = now_ts + cooldown_seconds
                state = self.account_states.setdefault(index, {})
                current_until = state.get("cooldown_until") or 0
                # 如果已有更长的冷却，则不重复更新
                if current_until > now_ts and current_until >= new_until:
                    return

                until = max(new_until, current_until)
                state["cooldown_until"] = until
                state["cooldown_reason"] = reason
                state["jwt"] = None
                state["jwt_time"] = 0
                state["session"] = None

                # 在配置中记录冷却信息，便于前端展示
                self.accounts[index]["cooldown_until"] = until
                self.accounts[index]["unavailable_reason"] = reason
                self.accounts[index]["unavailable_time"] = datetime.now().isoformat()

                self.save_config()
                print(f"[!] 账号 {index} 进入冷却 {cooldown_seconds} 秒: {reason}")

    def _is_in_cooldown(self, index: int, now_ts: Optional[float] = None) -> bool:
        """检查账号是否处于冷却期"""
        now_ts = now_ts or time.time()
        state = self.account_states.get(index, {})
        cooldown_until = state.get("cooldown_until")
        if not cooldown_until:
            return False
        return now_ts < cooldown_until

    def get_next_cooldown_info(self) -> Optional[dict]:
        """获取最近即将结束冷却的账号信息"""
        now_ts = time.time()
        candidates = []
        for idx, state in self.account_states.items():
            cooldown_until = state.get("cooldown_until")
            if cooldown_until and cooldown_until > now_ts and state.get("available", True):
                candidates.append((cooldown_until, idx))
        if not candidates:
            return None
        cooldown_until, idx = min(candidates, key=lambda x: x[0])
        return {"index": idx, "cooldown_until": cooldown_until}

    def is_account_available(self, index: int) -> bool:
        """计算账号当前是否可用（考虑冷却和手动禁用）"""
        state = self.account_states.get(index, {})
        if not state.get("available", True):
            return False
        return not self._is_in_cooldown(index)
    
    def get_available_accounts(self):
        """获取可用账号列表"""
        now_ts = time.time()
        available_accounts = []
        for i, acc in enumerate(self.accounts):
            state = self.account_states.get(i, {})
            if not state.get("available", True):
                continue
            if self._is_in_cooldown(i, now_ts):
                continue
            available_accounts.append((i, acc))
        return available_accounts
    
    def get_next_account(self):
        """轮训获取下一个可用账号"""
        with self.lock:
            available = self.get_available_accounts()
            if not available:
                cooldown_info = self.get_next_cooldown_info()
                if cooldown_info:
                    remaining = int(max(0, cooldown_info["cooldown_until"] - time.time()))
                    raise NoAvailableAccount(f"没有可用的账号（最近冷却账号 {cooldown_info['index']}，约 {remaining} 秒后可重试）")
                raise NoAvailableAccount("没有可用的账号")
            
            # 轮训选择
            self.current_index = self.current_index % len(available)
            idx, account = available[self.current_index]
            self.current_index = (self.current_index + 1) % len(available)
            return idx, account
    
    def get_account_count(self):
        """获取账号数量统计"""
        total = len(self.accounts)
        available = len(self.get_available_accounts())
        return total, available


# 全局账号管理器
account_manager = AccountManager()


class FileManager:
    """文件管理器 - 管理上传文件的映射关系（OpenAI file_id <-> Gemini fileId）"""
    
    def __init__(self):
        self.files: Dict[str, Dict] = {}  # openai_file_id -> {gemini_file_id, session_name, filename, mime_type, size, created_at}
    
    def add_file(self, openai_file_id: str, gemini_file_id: str, session_name: str, 
                 filename: str, mime_type: str, size: int) -> Dict:
        """添加文件映射"""
        file_info = {
            "id": openai_file_id,
            "gemini_file_id": gemini_file_id,
            "session_name": session_name,
            "filename": filename,
            "mime_type": mime_type,
            "bytes": size,
            "created_at": int(time.time()),
            "purpose": "assistants",
            "object": "file"
        }
        self.files[openai_file_id] = file_info
        return file_info
    
    def get_file(self, openai_file_id: str) -> Optional[Dict]:
        """获取文件信息"""
        return self.files.get(openai_file_id)
    
    def get_gemini_file_id(self, openai_file_id: str) -> Optional[str]:
        """获取 Gemini 文件ID"""
        file_info = self.files.get(openai_file_id)
        return file_info.get("gemini_file_id") if file_info else None
    
    def delete_file(self, openai_file_id: str) -> bool:
        """删除文件映射"""
        if openai_file_id in self.files:
            del self.files[openai_file_id]
            return True
        return False
    
    def list_files(self) -> List[Dict]:
        """列出所有文件"""
        return list(self.files.values())
    
    def get_session_for_file(self, openai_file_id: str) -> Optional[str]:
        """获取文件关联的会话名称"""
        file_info = self.files.get(openai_file_id)
        return file_info.get("session_name") if file_info else None


# 全局文件管理器
file_manager = FileManager()


def get_ssl_verify() -> bool:
    """获取SSL验证配置"""
    return os.getenv("SSL_VERIFY", "false").lower() == "true"


def check_proxy(proxy: str) -> bool:
    """检测代理是否可用"""
    if not proxy:
        return False
    try:
        proxies = {"http": proxy, "https": proxy}
        resp = requests.get("https://www.google.com", proxies=proxies, 
                          verify=get_ssl_verify(), timeout=10)
        return resp.status_code == 200
    except:
        return False


def get_proxy() -> Optional[str]:
    """获取代理配置，根据proxy_enabled开关决定是否返回代理地址
    
    Returns:
        代理地址字符串，如果禁用代理则返回None
    """
    if account_manager.config is None:
        return None
    if not account_manager.config.get("proxy_enabled", False):
        return None
    return account_manager.config.get("proxy")


def url_safe_b64encode(data: bytes) -> str:
    """URL安全的Base64编码，不带padding"""
    return base64.urlsafe_b64encode(data).decode('utf-8').rstrip('=')


def kq_encode(s: str) -> str:
    """模拟JS的kQ函数"""
    byte_arr = bytearray()
    for char in s:
        val = ord(char)
        if val > 255:
            byte_arr.append(val & 255)
            byte_arr.append(val >> 8)
        else:
            byte_arr.append(val)
    return url_safe_b64encode(bytes(byte_arr))


def decode_xsrf_token(xsrf_token: str) -> bytes:
    """将 xsrfToken 解码为字节数组（用于HMAC签名）"""
    padding = 4 - len(xsrf_token) % 4
    if padding != 4:
        xsrf_token += '=' * padding
    return base64.urlsafe_b64decode(xsrf_token)


def create_jwt(key_bytes: bytes, key_id: str, csesidx: str) -> str:
    """创建JWT token"""
    now = int(time.time())

    header = {
        "alg": "HS256",
        "typ": "JWT",
        "kid": key_id
    }

    payload = {
        "iss": "https://business.gemini.google",
        "aud": "https://biz-discoveryengine.googleapis.com",
        "sub": f"csesidx/{csesidx}",
        "iat": now,
        "exp": now + 300,
        "nbf": now
    }

    header_b64 = kq_encode(json.dumps(header, separators=(',', ':')))
    payload_b64 = kq_encode(json.dumps(payload, separators=(',', ':')))
    message = f"{header_b64}.{payload_b64}"

    signature = hmac.new(key_bytes, message.encode('utf-8'), hashlib.sha256).digest()
    signature_b64 = url_safe_b64encode(signature)

    return f"{message}.{signature_b64}"


def get_jwt_for_account(account: dict, proxy: str) -> str:
    """为指定账号获取JWT - 支持新的Google认证流程"""
    secure_c_ses = account.get("secure_c_ses")
    host_c_oses = account.get("host_c_oses")
    csesidx = account.get("csesidx")

    if not secure_c_ses or not csesidx:
        raise ValueError("缺少 secure_c_ses 或 csesidx")

    url = f"{GETOXSRF_URL}?csesidx={csesidx}"
    proxies = {"http": proxy, "https": proxy} if proxy else None

    # 构建 Cookie 字符串，包含额外的 Cookie（用于新认证流程）
    cookie_parts = [f'__Secure-C_SES={secure_c_ses}', f'__Host-C_OSES={host_c_oses}']
    extra_cookies = account.get("extra_cookies", {})
    if extra_cookies:
        for name, value in extra_cookies.items():
            if name and value:
                cookie_parts.append(f'{name}={value}')
    cookie_str = "; ".join(cookie_parts)

    headers = {
        "accept": "*/*",
        "user-agent": account.get('user_agent', 'Mozilla/5.0'),
        "cookie": cookie_str,
        "origin": "https://business.gemini.google",
        "referer": "https://business.gemini.google/",
    }

    try:
        # 第一步：请求 getoxsrf（不跟随重定向）
        resp = requests.get(url, headers=headers, proxies=proxies, verify=get_ssl_verify(), timeout=30, allow_redirects=False)
    except requests.RequestException as e:
        raise AccountRequestError(f"获取JWT 请求失败: {e}") from e

    # 如果是302重定向到refreshcookies，需要处理新的认证流程
    if resp.status_code == 302:
        location = resp.headers.get("Location", "")
        if "refreshcookies" in location:
            print(f"[DEBUG] 检测到新认证流程，重定向到: {location[:100]}...")
            try:
                # 第二步：请求 refreshcookies
                resp2 = requests.get(location, headers=headers, proxies=proxies, verify=get_ssl_verify(), timeout=30)
                if resp2.status_code != 200:
                    raise AccountAuthError(f"refreshcookies 请求失败: {resp2.status_code}")
                
                text2 = resp2.text
                if text2.startswith(")]}'\\n") or text2.startswith(")]}'"):
                    text2 = text2[4:].strip()
                
                data2 = json.loads(text2)
                setocookie_url_b64 = data2.get("setocookieUrl")
                if not setocookie_url_b64:
                    raise AccountAuthError(f"refreshcookies 响应缺少 setocookieUrl: {data2}")
                
                # 解码 setocookieUrl
                padding = 4 - len(setocookie_url_b64) % 4
                if padding != 4:
                    setocookie_url_b64 += '=' * padding
                setocookie_url = base64.urlsafe_b64decode(setocookie_url_b64).decode('utf-8')
                print(f"[DEBUG] setocookie URL: {setocookie_url[:100]}...")
                
                # 第三步：请求 setocookie（不跟随重定向）
                resp3 = requests.get(setocookie_url, headers=headers, proxies=proxies, verify=get_ssl_verify(), timeout=30, allow_redirects=False)
                
                # setocookie 可能返回302重定向回 getoxsrf，也可能直接返回结果
                if resp3.status_code == 302:
                    final_location = resp3.headers.get("Location", "")
                    if "getoxsrf" in final_location:
                        # 最终请求 getoxsrf
                        resp = requests.get(final_location, headers=headers, proxies=proxies, verify=get_ssl_verify(), timeout=30)
                    else:
                        raise AccountAuthError(f"setocookie 重定向到未知地址: {final_location}")
                elif resp3.status_code == 200:
                    resp = resp3
                else:
                    raise AccountAuthError(f"setocookie 请求失败: {resp3.status_code} - {resp3.text[:200]}")
                    
            except json.JSONDecodeError as e:
                raise AccountAuthError(f"解析refreshcookies响应失败: {e}") from e
            except Exception as e:
                if isinstance(e, (AccountAuthError, AccountRequestError)):
                    raise
                raise AccountAuthError(f"新认证流程失败: {e}") from e
        else:
            raise AccountAuthError(f"获取JWT 302重定向到未知地址: {location}")

    if resp.status_code != 200:
        raise_for_account_response(resp, "获取JWT")

    # 处理Google安全前缀
    text = resp.text
    if text.startswith(")]}'\\n") or text.startswith(")]}'"):
        text = text[4:].strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise AccountAuthError(f"解析JWT响应失败: {e}") from e

    key_id = data.get("keyId")
    xsrf_token = data.get("xsrfToken")
    if not key_id or not xsrf_token:
        raise AccountAuthError(f"JWT 响应缺少 keyId/xsrfToken: {data}")

    # 使用脱敏的日志输出，避免信息泄露
    csesidx = account.get('csesidx', 'unknown')
    csesidx_masked = f"{csesidx[:4]}***{csesidx[-4:]}" if len(csesidx) > 8 else "***"
    print(f"账号: {csesidx_masked} 账号可用! key_id: {key_id[:8]}***")

    key_bytes = decode_xsrf_token(xsrf_token)

    return create_jwt(key_bytes, key_id, csesidx)


def build_cookie_string(account: dict) -> str:
    """从账号配置构建完整的 Cookie 字符串"""
    if not account:
        return ""
    
    cookie_parts = []
    
    # 主要 Cookie
    if account.get("secure_c_ses"):
        cookie_parts.append(f'__Secure-C_SES={account["secure_c_ses"]}')
    if account.get("host_c_oses"):
        cookie_parts.append(f'__Host-C_OSES={account["host_c_oses"]}')
    
    # 额外的 Cookie
    extra_cookies = account.get("extra_cookies", {})
    if extra_cookies:
        for name, value in extra_cookies.items():
            if name and value:
                cookie_parts.append(f'{name}={value}')
    
    return "; ".join(cookie_parts)


def get_headers(jwt: str, account: dict = None) -> dict:
    """获取请求头，可选包含 Cookie"""
    headers = {
        "accept": "*/*",
        "accept-encoding": "gzip, deflate, br, zstd",
        "accept-language": "zh-CN,zh;q=0.9,en;q=0.8",
        "authorization": f"Bearer {jwt}",
        "content-type": "application/json",
        "origin": "https://business.gemini.google",
        "referer": "https://business.gemini.google/",
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
        "x-server-timeout": "1800",
    }
    
    # 如果提供了账号配置，添加 Cookie
    if account:
        cookie_str = build_cookie_string(account)
        if cookie_str:
            headers["cookie"] = cookie_str
    
    return headers


def raise_for_account_response(resp: requests.Response, action: str):
    """根据响应状态抛出对应的账号异常"""
    status = resp.status_code
    body_preview = resp.text[:500] if resp.text else ""
    lower_body = body_preview.lower()

    if status in (401, 403):
        raise AccountAuthError(f"{action} 认证失败: {status} - {body_preview}", status)
    if status == 429 or "quota" in lower_body or "exceed" in lower_body or "limit" in lower_body:
        raise AccountRateLimitError(f"{action} 触发限额: {status} - {body_preview}", status)

    raise AccountRequestError(f"{action} 请求失败: {status} - {body_preview}", status)


def ensure_jwt_for_account(account_idx: int, account: dict):
    """确保指定账号的JWT有效，必要时刷新"""
    print(f"[DEBUG][ensure_jwt_for_account] 开始 - 账号索引: {account_idx}, CSESIDX: {account.get('csesidx')}")
    start_time = time.time()
    with account_manager.lock:
        state = account_manager.account_states[account_idx]
        jwt_age = time.time() - state["jwt_time"] if state["jwt"] else float('inf')
        print(f"[DEBUG][ensure_jwt_for_account] JWT状态 - 存在: {state['jwt'] is not None}, 年龄: {jwt_age:.2f}秒")
        if state["jwt"] is None or jwt_age > 240:
            print(f"[DEBUG][ensure_jwt_for_account] 需要刷新JWT...")
            proxy = get_proxy()
            try:
                refresh_start = time.time()
                state["jwt"] = get_jwt_for_account(account, proxy)
                state["jwt_time"] = time.time()
                print(f"[DEBUG][ensure_jwt_for_account] JWT刷新成功 - 耗时: {time.time() - refresh_start:.2f}秒")
            except Exception as e:
                print(f"[DEBUG][ensure_jwt_for_account] JWT刷新失败: {e}")
                raise
        else:
            print(f"[DEBUG][ensure_jwt_for_account] 使用缓存JWT")
        print(f"[DEBUG][ensure_jwt_for_account] 完成 - 总耗时: {time.time() - start_time:.2f}秒")
        return state["jwt"]


def create_chat_session(jwt: str, team_id: str, proxy: str, account: dict = None) -> str:
    """创建会话，返回session ID"""
    print(f"[DEBUG][create_chat_session] 开始 - team_id: {team_id}")
    start_time = time.time()
    session_id = uuid.uuid4().hex[:12]
    print(f"[DEBUG][create_chat_session] 生成session_id: {session_id}")
    body = {
        "configId": team_id,
        "additionalParams": {"token": "-"},
        "createSessionRequest": {
            "session": {"name": session_id, "displayName": session_id}
        }
    }

    proxies = {"http": proxy, "https": proxy} if proxy else None
    print(f"[DEBUG][create_chat_session] 发送请求到: {CREATE_SESSION_URL}")
    print(f"[DEBUG][create_chat_session] 使用代理: {proxy}")
    
    request_start = time.time()
    try:
        resp = requests.post(
            CREATE_SESSION_URL,
            headers=get_headers(jwt, account),
            json=body,
            proxies=proxies,
            verify=get_ssl_verify(),
            timeout=30
        )
    except requests.RequestException as e:
        raise AccountRequestError(f"创建会话请求失败: {e}") from e
    print(f"[DEBUG][create_chat_session] 请求完成 - 状态码: {resp.status_code}, 耗时: {time.time() - request_start:.2f}秒")

    if resp.status_code != 200:
        print(f"[DEBUG][create_chat_session] 请求失败 - 响应: {resp.text[:500]}")
        if resp.status_code == 401:
            print(f"[DEBUG][create_chat_session] 401错误 - 可能是team_id填错了")
        raise_for_account_response(resp, "创建会话")

    data = resp.json()
    session_name = data.get("session", {}).get("name")
    print(f"[DEBUG][create_chat_session] 完成 - session_name: {session_name}, 总耗时: {time.time() - start_time:.2f}秒")
    return session_name


def ensure_session_for_account(account_idx: int, account: dict):
    """确保指定账号的会话有效"""
    print(f"[DEBUG][ensure_session_for_account] 开始 - 账号索引: {account_idx}")
    start_time = time.time()
    
    jwt_start = time.time()
    jwt = ensure_jwt_for_account(account_idx, account)
    print(f"[DEBUG][ensure_session_for_account] JWT获取完成 - 耗时: {time.time() - jwt_start:.2f}秒")
    
    with account_manager.lock:
        state = account_manager.account_states[account_idx]
        print(f"[DEBUG][ensure_session_for_account] 当前session状态: {state['session'] is not None}")
        if state["session"] is None:
            print(f"[DEBUG][ensure_session_for_account] 需要创建新session...")
            proxy = get_proxy()
            team_id = account.get("team_id")
            session_start = time.time()
            state["session"] = create_chat_session(jwt, team_id, proxy, account)
            print(f"[DEBUG][ensure_session_for_account] Session创建完成 - 耗时: {time.time() - session_start:.2f}秒")
        else:
            print(f"[DEBUG][ensure_session_for_account] 使用缓存session: {state['session']}")
        
        print(f"[DEBUG][ensure_session_for_account] 完成 - 总耗时: {time.time() - start_time:.2f}秒")
        return state["session"], jwt, account.get("team_id")


# ==================== 文件上传功能 ====================

def upload_file_to_gemini(jwt: str, session_name: str, team_id: str, 
                          file_content: bytes, filename: str, mime_type: str,
                          proxy: str = None) -> str:
    """
    上传文件到 Gemini，返回 Gemini 的 fileId
    
    Args:
        jwt: JWT 认证令牌
        session_name: 会话名称
        team_id: 团队ID
        file_content: 文件内容（字节）
        filename: 文件名
        mime_type: MIME 类型
        proxy: 代理地址
    
    Returns:
        str: Gemini 返回的 fileId
    """
    start_time = time.time()
    print(f"[DEBUG][upload_file_to_gemini] 开始上传文件: {filename}, MIME类型: {mime_type}, 文件大小: {len(file_content)} bytes")
    
    encode_start = time.time()
    file_contents_b64 = base64.b64encode(file_content).decode('utf-8')
    print(f"[DEBUG][upload_file_to_gemini] Base64编码完成 - 耗时: {time.time() - encode_start:.2f}秒, 编码后大小: {len(file_contents_b64)} chars")
    
    body = {
        "addContextFileRequest": {
            "fileContents": file_contents_b64,
            "fileName": filename,
            "mimeType": mime_type,
            "name": session_name
        },
        "additionalParams": {"token": "-"},
        "configId": team_id
    }
    
    proxies = {"http": proxy, "https": proxy} if proxy else None
    print(f"[DEBUG][upload_file_to_gemini] 准备发送请求到: {ADD_CONTEXT_FILE_URL}")
    print(f"[DEBUG][upload_file_to_gemini] 使用代理: {proxy if proxy else '无'}")
    
    request_start = time.time()
    try:
        resp = requests.post(
            ADD_CONTEXT_FILE_URL,
            headers=get_headers(jwt),
            json=body,
            proxies=proxies,
            verify=get_ssl_verify(),
            timeout=60
        )
    except requests.RequestException as e:
        raise AccountRequestError(f"文件上传请求失败: {e}") from e
    print(f"[DEBUG][upload_file_to_gemini] 请求完成 - 耗时: {time.time() - request_start:.2f}秒, 状态码: {resp.status_code}")
    
    if resp.status_code != 200:
        print(f"[DEBUG][upload_file_to_gemini] 上传失败 - 响应内容: {resp.text[:500]}")
        raise_for_account_response(resp, "文件上传")
    
    parse_start = time.time()
    data = resp.json()
    file_id = data.get("addContextFileResponse", {}).get("fileId")
    print(f"[DEBUG][upload_file_to_gemini] 解析响应完成 - 耗时: {time.time() - parse_start:.2f}秒")
    
    if not file_id:
        print(f"[DEBUG][upload_file_to_gemini] 响应中未找到fileId - 响应数据: {data}")
        raise ValueError(f"响应中未找到 fileId: {data}")
    
    print(f"[DEBUG][upload_file_to_gemini] 上传成功 - fileId: {file_id}, 总耗时: {time.time() - start_time:.2f}秒")
    return file_id


# ==================== 图片处理功能 ====================

@dataclass
class ChatImage:
    """表示生成的图片"""
    url: Optional[str] = None
    base64_data: Optional[str] = None
    mime_type: str = "image/png"
    local_path: Optional[str] = None
    file_id: Optional[str] = None
    file_name: Optional[str] = None


@dataclass
class ChatResponse:
    """聊天响应，包含文本和图片"""
    text: str = ""
    images: List[ChatImage] = field(default_factory=list)
    thoughts: List[str] = field(default_factory=list)


def cleanup_expired_images():
    """清理过期的缓存图片"""
    if not IMAGE_CACHE_DIR.exists():
        return
    
    now = time.time()
    max_age_seconds = IMAGE_CACHE_HOURS * 3600
    
    for filepath in IMAGE_CACHE_DIR.iterdir():
        if filepath.is_file():
            try:
                file_age = now - filepath.stat().st_mtime
                if file_age > max_age_seconds:
                    filepath.unlink()
                    print(f"[图片缓存] 已删除过期图片: {filepath.name}")
            except Exception as e:
                print(f"[图片缓存] 删除失败: {filepath.name}, 错误: {e}")


def save_image_to_cache(image_data: bytes, mime_type: str = "image/png", filename: Optional[str] = None) -> str:
    """保存图片到缓存目录，返回文件名"""
    IMAGE_CACHE_DIR.mkdir(exist_ok=True)
    
    # 确定文件扩展名
    ext_map = {
        "image/png": ".png",
        "image/jpeg": ".jpg",
        "image/gif": ".gif",
        "image/webp": ".webp",
    }
    ext = ext_map.get(mime_type, ".png")
    
    if filename:
        # 确保有正确的扩展名
        if not any(filename.endswith(e) for e in ext_map.values()):
            filename = f"{filename}{ext}"
    else:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"gemini_{timestamp}_{uuid.uuid4().hex[:8]}{ext}"
    
    filepath = IMAGE_CACHE_DIR / filename
    with open(filepath, "wb") as f:
        f.write(image_data)
    
    return filename


def parse_base64_data_url(data_url: str) -> Optional[Dict]:
    """解析 base64 data URL，返回 {type, mime_type, data} 或 None"""
    if not data_url or not data_url.startswith("data:"):
        return None
    
    # base64格式: data:image/png;base64,xxxxx
    match = re.match(r"data:([^;]+);base64,(.+)", data_url)
    if match:
        return {
            "type": "base64",
            "mime_type": match.group(1),
            "data": match.group(2)
        }
    return None


def extract_images_from_files_array(files: List[Dict]) -> List[Dict]:
    """从 files 数组中提取图片（支持内联 base64 格式）
    
    支持格式:
    {
        "data": "data:image/png;base64,xxxxx",
        "type": "image",
        "detail": "high"  # 可选
    }
    
    返回: 图片列表 [{type: 'base64', mime_type: ..., data: ...}]
    """
    images = []
    for file_item in files:
        if not isinstance(file_item, dict):
            continue
        
        file_type = file_item.get("type", "")
        
        # 只处理图片类型
        if file_type != "image":
            continue
        
        data = file_item.get("data", "")
        if data:
            parsed = parse_base64_data_url(data)
            if parsed:
                images.append(parsed)
    
    return images


def extract_images_from_openai_content(content: Any) -> tuple[str, List[Dict]]:
    """从OpenAI格式的content中提取文本和图片
    
    返回: (文本内容, 图片列表[{type: 'base64'|'url', data: ...}])
    """
    if isinstance(content, str):
        return content, []
    
    if not isinstance(content, list):
        return str(content), []
    
    text_parts = []
    images = []
    
    for item in content:
        if not isinstance(item, dict):
            continue
        
        item_type = item.get("type", "")
        
        if item_type == "text":
            text_parts.append(item.get("text", ""))
        
        elif item_type == "image_url":
            image_url_obj = item.get("image_url", {})
            if isinstance(image_url_obj, str):
                url = image_url_obj
            else:
                url = image_url_obj.get("url", "")
            
            parsed = parse_base64_data_url(url)
            if parsed:
                images.append(parsed)
            elif url:
                # 普通URL
                images.append({
                    "type": "url",
                    "url": url
                })
        
        # 支持直接的 image 类型（带 data 字段）
        elif item_type == "image" and item.get("data"):
            parsed = parse_base64_data_url(item.get("data"))
            if parsed:
                images.append(parsed)
    
    return "\n".join(text_parts), images


def download_image_from_url(url: str, proxy: Optional[str] = None) -> tuple[bytes, str]:
    """从URL下载图片，返回(图片数据, mime_type)"""
    # 安全检查：防止SSRF攻击
    from urllib.parse import urlparse
    
    try:
        parsed = urlparse(url)
        
        # 只允许 http 和 https 协议
        if parsed.scheme not in ('http', 'https'):
            raise ValueError(f"不支持的协议: {parsed.scheme}")
        
        # 禁止访问内网地址
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("无效的URL")
            
        # 检查是否是本地主机名（字符串检查）
        if hostname.lower() in ('localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]'):
            raise ValueError("禁止访问本地地址")
            
        # 尝试解析为IP地址并检查
        try:
            ip = ipaddress.ip_address(hostname)
            # 禁止访问私有IP地址
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                raise ValueError("禁止访问内网地址")
        except ValueError:
            # hostname 不是IP地址（可能是域名），进行DNS解析检查
            import socket
            try:
                resolved_ip = socket.gethostbyname(hostname)
                ip = ipaddress.ip_address(resolved_ip)
                if ip.is_private or ip.is_loopback or ip.is_link_local:
                    raise ValueError("禁止访问内网地址（DNS解析）")
            except (socket.gaierror, ValueError):
                # DNS解析失败或IP检查失败，继续执行（可能是外网域名）
                pass
        
        # 限制文件大小，防止DoS
        proxies = {"http": proxy, "https": proxy} if proxy else None
        resp = requests.get(url, proxies=proxies, verify=get_ssl_verify(), timeout=60, stream=True)
        resp.raise_for_status()
        
        # 检查内容大小
        content_length = resp.headers.get('Content-Length')
        max_size = 10 * 1024 * 1024  # 10MB
        if content_length and int(content_length) > max_size:
            raise ValueError(f"文件过大: {content_length} 字节")
        
        # 分块读取内容，限制总大小
        content = b''
        for chunk in resp.iter_content(chunk_size=8192):
            content += chunk
            if len(content) > max_size:
                raise ValueError("文件过大")
        
        content_type = resp.headers.get("Content-Type", "image/png")
        # 提取主mime类型
        mime_type = content_type.split(";")[0].strip()
        
        return content, mime_type
    except Exception as e:
        print(f"[安全] 下载图片失败: {e}")
        raise


def get_session_file_metadata(jwt: str, session_name: str, team_id: str, proxy: Optional[str] = None) -> Dict:
    """获取会话中的文件元数据（AI生成的图片）"""
    body = {
        "configId": team_id,
        "additionalParams": {"token": "-"},
        "listSessionFileMetadataRequest": {
            "name": session_name,
            "filter": "file_origin_type = AI_GENERATED"
        }
    }
    
    proxies = {"http": proxy, "https": proxy} if proxy else None
    resp = requests.post(
        LIST_FILE_METADATA_URL,
        headers=get_headers(jwt),
        json=body,
        proxies=proxies,
        verify=get_ssl_verify(),
        timeout=30
    )
    
    if resp.status_code != 200:
        print(f"[图片] 获取文件元数据失败: {resp.status_code}")
        return {}
    
    data = resp.json()
    # 返回 fileId -> metadata 的映射
    result = {}
    file_metadata_list = data.get("listSessionFileMetadataResponse", {}).get("fileMetadata", [])
    for meta in file_metadata_list:
        file_id = meta.get("fileId")
        if file_id:
            result[file_id] = meta
    return result


def build_download_url(session_name: str, file_id: str) -> str:
    """构造正确的下载URL"""
    return f"https://biz-discoveryengine.googleapis.com/v1alpha/{session_name}:downloadFile?fileId={file_id}&alt=media"


def download_file_with_jwt(jwt: str, session_name: str, file_id: str, proxy: Optional[str] = None) -> bytes:
    """使用JWT认证下载文件"""
    url = build_download_url(session_name, file_id)
    proxies = {"http": proxy, "https": proxy} if proxy else None
    
    resp = requests.get(
        url,
        headers=get_headers(jwt),
        proxies=proxies,
        verify=get_ssl_verify(),
        timeout=120,
        allow_redirects=True
    )
    
    resp.raise_for_status()
    content = resp.content
    
    # 检测是否为base64编码的内容
    try:
        text_content = content.decode("utf-8", errors="ignore").strip()
        if text_content.startswith("iVBORw0KGgo") or text_content.startswith("/9j/"):
            # 是base64编码，需要解码
            return base64.b64decode(text_content)
    except Exception:
        pass
    
    return content


def upload_inline_image_to_gemini(jwt: str, session_name: str, team_id: str, 
                                   image_data: Dict, proxy: str = None) -> Optional[str]:
    """上传内联图片到 Gemini，返回 fileId"""
    try:
        ext_map = {"image/png": ".png", "image/jpeg": ".jpg", "image/gif": ".gif", "image/webp": ".webp"}
        
        if image_data.get("type") == "base64":
            mime_type = image_data.get("mime_type", "image/png")
            file_content = base64.b64decode(image_data.get("data", ""))
            ext = ext_map.get(mime_type, ".png")
            filename = f"inline_{uuid.uuid4().hex[:8]}{ext}"
        elif image_data.get("type") == "url":
            file_content, mime_type = download_image_from_url(image_data.get("url"), proxy)
            ext = ext_map.get(mime_type, ".png")
            filename = f"url_{uuid.uuid4().hex[:8]}{ext}"
        else:
            return None
        
        return upload_file_to_gemini(jwt, session_name, team_id, file_content, filename, mime_type, proxy)
    except AccountError:
        # 让账号相关错误向上抛出，以便触发冷却
        raise
    except Exception:
        return None


def stream_chat_with_images(jwt: str, sess_name: str, message: str, 
                            proxy: str, team_id: str, file_ids: List[str] = None, 
                            account: dict = None, model_id: str = "gemini-3-pro-preview",
                            include_thought: bool = False) -> ChatResponse:
    """发送消息并流式接收响应
    
    Args:
        model_id: 使用的模型ID，如 gemini-3-pro-preview, gemini-2.5-flash 等
        include_thought: 是否包含思考过程
    """
    query_parts = [{"text": message}]
    request_file_ids = file_ids if file_ids else []
    
    body = {
        "configId": team_id,
        "additionalParams": {"token": "-"},
        "streamAssistRequest": {
            "session": sess_name,
            "query": {"parts": query_parts},
            "filter": "",
            "fileIds": request_file_ids,
            "answerGenerationMode": "NORMAL",
            "assistGenerationConfig":{
                "modelId": model_id
            },
            "toolsSpec": {
                "webGroundingSpec": {},
                "toolRegistry": "default_tool_registry",
                "imageGenerationSpec": {},
                "videoGenerationSpec": {}
            },
            "languageCode": "zh-CN",
            "userMetadata": {"timeZone": "Etc/GMT-8"},
            "assistSkippingMode": "REQUEST_ASSIST"
        }
    }

    proxies = {"http": proxy, "https": proxy} if proxy else None
    
    try:
        resp = requests.post(
            STREAM_ASSIST_URL,
            headers=get_headers(jwt, account),
            json=body,
            proxies=proxies,
            verify=False,
            timeout=120,
            stream=True
        )
    except requests.RequestException as e:
        raise AccountRequestError(f"聊天请求失败: {e}") from e

    if resp.status_code != 200:
        raise_for_account_response(resp, "聊天请求")

    # 收集完整响应
    full_response = ""
    for line in resp.iter_lines():
        if line:
            full_response += line.decode('utf-8') + "\n"

    # 解析响应
    result = ChatResponse()
    texts = []
    file_ids = []  # 收集需要下载的文件 {fileId, mimeType}
    current_session = None
    
    try:
        data_list = json.loads(full_response)
        for data in data_list:
            sar = data.get("streamAssistResponse")
            if not sar:
                continue
            
            # 获取session信息
            session_info = sar.get("sessionInfo", {})
            if session_info.get("session"):
                current_session = session_info["session"]
            
            # 检查顶层的generatedImages
            for gen_img in sar.get("generatedImages", []):
                parse_generated_image(gen_img, result, proxy)
            
            answer = sar.get("answer") or {}
            
            # 检查answer级别的generatedImages
            for gen_img in answer.get("generatedImages", []):
                parse_generated_image(gen_img, result, proxy)
            
            for reply in answer.get("replies", []):
                # 检查reply级别的generatedImages
                for gen_img in reply.get("generatedImages", []):
                    parse_generated_image(gen_img, result, proxy)
                
                gc = reply.get("groundedContent", {})
                content = gc.get("content", {})
                text = content.get("text", "")
                thought = content.get("thought", False)
                
                # 检查file字段（图片生成的关键）
                file_info = content.get("file")
                if file_info and file_info.get("fileId"):
                    file_ids.append({
                        "fileId": file_info["fileId"],
                        "mimeType": file_info.get("mimeType", "image/png"),
                        "fileName": file_info.get("name")
                    })
                
                # 解析图片数据
                parse_image_from_content(content, result, proxy)
                parse_image_from_content(gc, result, proxy)
                
                # 检查attachments
                for att in reply.get("attachments", []) + gc.get("attachments", []) + content.get("attachments", []):
                    parse_attachment(att, result, proxy)
                
                # 收集文本内容
                if text:
                    if thought:
                        # 思考过程用特殊格式标记
                        if include_thought:
                            texts.append(f"<think>\n{text}\n</think>\n")
                    else:
                        texts.append(text)

        # 处理通过fileId引用的图片
        if file_ids and current_session:
            try:
                file_metadata = get_session_file_metadata(jwt, current_session, team_id, proxy)
                for finfo in file_ids:
                    fid = finfo["fileId"]
                    mime = finfo["mimeType"]
                    fname = finfo.get("fileName")
                    meta = file_metadata.get(fid)

                    if meta:
                        fname = fname or meta.get("name")
                        session_path = meta.get("session") or current_session
                    else:
                        session_path = current_session

                    try:
                        image_data = download_file_with_jwt(jwt, session_path, fid, proxy)
                        filename = None
                        local_path = None
                        b64_data = base64.b64encode(image_data).decode("utf-8")

                        # 仅在 URL 模式下缓存到本地以便通过 /image/ 访问
                        if not is_base64_output_mode():
                            filename = save_image_to_cache(image_data, mime, fname)
                            local_path = str(IMAGE_CACHE_DIR / filename)

                        img = ChatImage(
                            file_id=fid,
                            file_name=filename,
                            mime_type=mime,
                            local_path=local_path,
                            base64_data=b64_data,
                        )
                        result.images.append(img)
                        if filename:
                            print(f"[图片] 已保存: {filename}")
                    except Exception as e:
                        print(f"[图片] 下载失败 (fileId={fid}): {e}")
            except Exception as e:
                print(f"[图片] 获取文件元数据失败: {e}")

    except json.JSONDecodeError:
        pass

    result.text = "".join(texts)
    return result


def stream_chat_realtime(jwt: str, sess_name: str, message: str, 
                         proxy: str, team_id: str, file_ids: List[str] = None, 
                         account: dict = None, account_csesidx: str = None,
                         model_name: str = "gemini-enterprise",
                         model_id: str = "gemini-3-pro-preview",
                         include_thought: bool = False):
    """真正的流式聊天 - 逐块返回响应
    
    这是一个生成器函数，在接收到 Gemini 每个数据块时立即 yield OpenAI 格式的 SSE 事件。
    使用正则表达式直接从原始数据中提取文本，实现真正的实时流式输出。
    
    Args:
        model_id: 使用的模型ID，如 gemini-3-pro-preview, gemini-2.5-flash 等
        include_thought: 是否包含思考过程
    
    Yields:
        str: SSE 格式的数据行，如 "data: {...}\n\n"
    """
    import re
    
    query_parts = [{"text": message}]
    request_file_ids = file_ids if file_ids else []
    
    body = {
        "configId": team_id,
        "additionalParams": {"token": "-"},
        "streamAssistRequest": {
            "session": sess_name,
            "query": {"parts": query_parts},
            "filter": "",
            "fileIds": request_file_ids,
            "answerGenerationMode": "NORMAL",
            "assistGenerationConfig":{
                "modelId": model_id
            },
            "toolsSpec": {
                "webGroundingSpec": {},
                "toolRegistry": "default_tool_registry",
                "imageGenerationSpec": {},
                "videoGenerationSpec": {}
            },
            "languageCode": "zh-CN",
            "userMetadata": {"timeZone": "Etc/GMT-8"},
            "assistSkippingMode": "REQUEST_ASSIST"
        }
    }

    proxies = {"http": proxy, "https": proxy} if proxy else None
    chunk_id = f"chatcmpl-{uuid.uuid4().hex[:8]}"
    
    try:
        resp = requests.post(
            STREAM_ASSIST_URL,
            headers=get_headers(jwt, account),
            json=body,
            proxies=proxies,
            verify=False,
            timeout=120,
            stream=True
        )
    except requests.RequestException as e:
        error_chunk = {
            "id": chunk_id,
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model_name,
            "account_csesidx": account_csesidx,
            "choices": [{
                "index": 0,
                "delta": {"content": f"[请求错误: {e}]"},
                "finish_reason": None
            }]
        }
        yield f"data: {json.dumps(error_chunk, ensure_ascii=False)}\n\n"
        yield "data: [DONE]\n\n"
        return

    if resp.status_code != 200:
        error_text = resp.text[:200] if resp.text else f"HTTP {resp.status_code}"
        error_chunk = {
            "id": chunk_id,
            "object": "chat.completion.chunk",
            "created": int(time.time()),
            "model": model_name,
            "account_csesidx": account_csesidx,
            "choices": [{
                "index": 0,
                "delta": {"content": f"[API错误: {error_text}]"},
                "finish_reason": None
            }]
        }
        yield f"data: {json.dumps(error_chunk, ensure_ascii=False)}\n\n"
        yield "data: [DONE]\n\n"
        return

    # 使用正则表达式直接提取文本内容
    # Gemini 响应中文本格式: "text":"内容" 或 "text": "内容"
    import re
    buffer = ""
    last_extracted_len = 0  # 已提取的文本总长度
    
    # 匹配 "text":"..." 内容的正则，支持转义字符
    text_pattern = re.compile(r'"text"\s*:\s*"((?:[^"\\]|\\.)*)"')
    
    # 思考过程的格式特征：粗体标题，如 **Some Title**\n
    # 这类内容通常是思考过程，可以直接过滤
    thought_header_pattern = re.compile(r'^\*\*[A-Z][^*]*\*\*\\n$')
    
    # 已输出的文本内容（用于去重）
    output_texts = []
    
    # 使用 iter_lines 接收数据（通常更快）
    for line in resp.iter_lines(decode_unicode=True):
        if line:
            if isinstance(line, bytes):
                line = line.decode('utf-8', errors='replace')
            buffer += line
            
            # 查找所有 "text":"..." 匹配
            for match in text_pattern.finditer(buffer):
                text_content = match.group(1)
                
                # 跳过已输出的内容
                if text_content in output_texts:
                    continue
                output_texts.append(text_content)
                
                # 解码 JSON 转义字符
                try:
                    decoded_text = json.loads(f'"{text_content}"')
                except:
                    decoded_text = text_content
                
                # 检查是否是思考过程（根据格式判断）
                # 思考过程特征：短文本 + 粗体标题格式
                is_thought = (
                    len(decoded_text) < 100 and 
                    decoded_text.startswith('**') and 
                    decoded_text.rstrip().endswith('**')
                )
                
                # 跳过思考过程内容（除非用户明确要求）
                if is_thought:
                    if include_thought:
                        output_text = f"<think>\n{decoded_text}\n</think>\n"
                    else:
                        continue  # 跳过思考内容
                else:
                    output_text = decoded_text
                
                # 立即输出，不做额外的字符分割
                # SSE 本身会处理流式传输
                chunk = {
                    "id": chunk_id,
                    "object": "chat.completion.chunk",
                    "created": int(time.time()),
                    "model": model_name,
                    "account_csesidx": account_csesidx,
                    "choices": [{
                        "index": 0,
                        "delta": {"content": output_text},
                        "finish_reason": None
                    }]
                }
                yield f"data: {json.dumps(chunk, ensure_ascii=False)}\n\n"
    
    # 发送结束标记
    end_chunk = {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": model_name,
        "choices": [{
            "index": 0,
            "delta": {},
            "finish_reason": "stop"
        }]
    }
    yield f"data: {json.dumps(end_chunk, ensure_ascii=False)}\n\n"
    yield "data: [DONE]\n\n"


def parse_generated_image(gen_img: Dict, result: ChatResponse, proxy: Optional[str] = None):
    """解析generatedImages中的图片"""
    image_data = gen_img.get("image")
    if not image_data:
        return
    
    # 检查base64数据
    b64_data = image_data.get("bytesBase64Encoded")
    if b64_data:
        try:
            mime_type = image_data.get("mimeType", "image/png")
            filename = None
            local_path = None

            # 仅在 URL 模式下落盘缓存
            if not is_base64_output_mode():
                decoded = base64.b64decode(b64_data)
                filename = save_image_to_cache(decoded, mime_type)
                local_path = str(IMAGE_CACHE_DIR / filename)

            img = ChatImage(
                base64_data=b64_data,
                mime_type=mime_type,
                file_name=filename,
                local_path=local_path,
            )
            result.images.append(img)
            if filename:
                print(f"[图片] 已保存: {filename}")
        except Exception as e:
            print(f"[图片] 解析base64失败: {e}")


def parse_image_from_content(content: Dict, result: ChatResponse, proxy: Optional[str] = None):
    """从content中解析图片"""
    # 检查inlineData
    inline_data = content.get("inlineData")
    if inline_data:
        b64_data = inline_data.get("data")
        if b64_data:
            try:
                mime_type = inline_data.get("mimeType", "image/png")
                filename = None
                local_path = None

                if not is_base64_output_mode():
                    decoded = base64.b64decode(b64_data)
                    filename = save_image_to_cache(decoded, mime_type)
                    local_path = str(IMAGE_CACHE_DIR / filename)

                img = ChatImage(
                    base64_data=b64_data,
                    mime_type=mime_type,
                    file_name=filename,
                    local_path=local_path,
                )
                result.images.append(img)
                if filename:
                    print(f"[图片] 已保存: {filename}")
            except Exception as e:
                print(f"[图片] 解析inlineData失败: {e}")


def parse_attachment(att: Dict, result: ChatResponse, proxy: Optional[str] = None):
    """解析attachment中的图片"""
    # 检查是否是图片类型
    mime_type = att.get("mimeType", "")
    if not mime_type.startswith("image/"):
        return
    
    # 检查base64数据
    b64_data = att.get("data") or att.get("bytesBase64Encoded")
    if b64_data:
        try:
            filename = None
            local_path = None

            if not is_base64_output_mode():
                decoded = base64.b64decode(b64_data)
                filename = att.get("name") or None
                filename = save_image_to_cache(decoded, mime_type, filename)
                local_path = str(IMAGE_CACHE_DIR / filename)

            img = ChatImage(
                base64_data=b64_data,
                mime_type=mime_type,
                file_name=filename,
                local_path=local_path,
            )
            result.images.append(img)
            if filename:
                print(f"[图片] 已保存: {filename}")
        except Exception as e:
            print(f"[图片] 解析attachment失败: {e}")


# ==================== OpenAPI 接口 ====================

@app.route('/v1/models', methods=['GET'])
@require_api_auth
@rate_limit
def list_models():
    """获取模型列表"""
    models_config = account_manager.config.get("models", [])
    models_data = []
    
    for model in models_config:
        models_data.append({
            "id": model.get("id", "gemini-enterprise"),
            "object": "model",
            "created": int(time.time()),
            "owned_by": "google",
            "permission": [],
            "root": model.get("id", "gemini-enterprise"),
            "parent": None
        })
    
    # 如果没有配置模型，返回默认模型
    if not models_data:
        models_data.append({
            "id": "gemini-enterprise",
            "object": "model",
            "created": int(time.time()),
            "owned_by": "google",
            "permission": [],
            "root": "gemini-enterprise",
            "parent": None
        })
    
    return jsonify({"object": "list", "data": models_data})


@app.route('/v1/files', methods=['POST'])
@require_api_auth
@rate_limit
def upload_file():
    """OpenAI 兼容的文件上传接口"""
    import traceback
    request_start_time = time.time()
    print(f"\n{'='*60}")
    print(f"[文件上传] ===== 接口调用开始 =====")
    print(f"[文件上传] 请求时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    try:
        # 检查是否有文件
        step_start = time.time()
        print(f"[文件上传] 步骤1: 检查请求中的文件...")
        if 'file' not in request.files:
            print(f"[文件上传] 错误: 请求中没有文件")
            return jsonify({"error": {"message": "No file provided", "type": "invalid_request_error"}}), 400
        
        file = request.files['file']
        if file.filename == '':
            print(f"[文件上传] 错误: 文件名为空")
            return jsonify({"error": {"message": "No file selected", "type": "invalid_request_error"}}), 400
        print(f"[文件上传] 步骤1完成: 文件名={file.filename}, 耗时={time.time()-step_start:.3f}秒")
        
        # 获取文件内容和MIME类型
        step_start = time.time()
        print(f"[文件上传] 步骤2: 读取文件内容...")
        file_content = file.read()
        mime_type = file.content_type or mimetypes.guess_type(file.filename)[0] or 'application/octet-stream'
        print(f"[文件上传] 步骤2完成: 文件大小={len(file_content)}字节, MIME类型={mime_type}, 耗时={time.time()-step_start:.3f}秒")
        
        # 获取账号信息
        available_accounts = account_manager.get_available_accounts()
        if not available_accounts:
            next_cd = account_manager.get_next_cooldown_info()
            wait_msg = ""
            if next_cd:
                wait_msg = f"（最近冷却账号 {next_cd['index']}，约 {int(next_cd['cooldown_until']-time.time())} 秒后可重试）"
            return jsonify({"error": {"message": f"没有可用的账号{wait_msg}", "type": "rate_limit"}}), 429

        max_retries = len(available_accounts)
        last_error = None
        gemini_file_id = None
        print(f"[文件上传] 步骤3: 开始尝试上传, 最大重试次数={max_retries}")
        
        for retry_idx in range(max_retries):
            retry_start = time.time()
            print(f"\n[文件上传] --- 第{retry_idx+1}次尝试 ---")
            account_idx = None
            try:
                # 获取账号
                step_start = time.time()
                print(f"[文件上传] 步骤3.{retry_idx+1}.1: 获取下一个可用账号...")
                account_idx, account = account_manager.get_next_account()
                print(f"[文件上传] 步骤3.{retry_idx+1}.1完成: 账号索引={account_idx}, CSESIDX={account.get('csesidx')}, 耗时={time.time()-step_start:.3f}秒")
                
                # 确保会话有效
                step_start = time.time()
                print(f"[文件上传] 步骤3.{retry_idx+1}.2: 确保会话有效(JWT+Session)...")
                session, jwt, team_id = ensure_session_for_account(account_idx, account)
                print(f"[文件上传] 步骤3.{retry_idx+1}.2完成: session={session}, team_id={team_id}, 耗时={time.time()-step_start:.3f}秒")
                
                proxy = get_proxy()
                print(f"[文件上传] 代理设置: {proxy}")
                
                # 上传文件到 Gemini
                step_start = time.time()
                print(f"[文件上传] 步骤3.{retry_idx+1}.3: 上传文件到Gemini...")
                gemini_file_id = upload_file_to_gemini(jwt, session, team_id, file_content, file.filename, mime_type, proxy)
                print(f"[文件上传] 步骤3.{retry_idx+1}.3完成: gemini_file_id={gemini_file_id}, 耗时={time.time()-step_start:.3f}秒")
                
                if gemini_file_id:
                    # 生成 OpenAI 格式的 file_id
                    step_start = time.time()
                    print(f"[文件上传] 步骤4: 生成OpenAI格式响应...")
                    openai_file_id = f"file-{uuid.uuid4().hex[:24]}"
                    
                    # 保存映射关系
                    file_manager.add_file(
                        openai_file_id=openai_file_id,
                        gemini_file_id=gemini_file_id,
                        session_name=session,
                        filename=file.filename,
                        mime_type=mime_type,
                        size=len(file_content)
                    )
                    print(f"[文件上传] 步骤4完成: openai_file_id={openai_file_id}, 耗时={time.time()-step_start:.3f}秒")
                    
                    total_time = time.time() - request_start_time
                    print(f"\n[文件上传] ===== 上传成功 =====")
                    print(f"[文件上传] 总耗时: {total_time:.3f}秒")
                    print(f"{'='*60}\n")
                    
                    # 返回 OpenAI 格式响应
                    return jsonify({
                        "id": openai_file_id,
                        "object": "file",
                        "bytes": len(file_content),
                        "created_at": int(time.time()),
                        "filename": file.filename,
                        "purpose": request.form.get('purpose', 'assistants')
                    })
                else:
                    print(f"[文件上传] 警告: gemini_file_id为空")
            
            except AccountRateLimitError as e:
                last_error = e
                if account_idx is not None:
                    pt_wait = seconds_until_next_pt_midnight()
                    cooldown_seconds = max(account_manager.rate_limit_cooldown, pt_wait)
                    account_manager.mark_account_cooldown(account_idx, str(e), cooldown_seconds)
                print(f"[文件上传] 第{retry_idx+1}次尝试失败(限额): {e}")
                print(f"[文件上传] 本次尝试耗时: {time.time()-retry_start:.3f}秒")
                continue
            except AccountAuthError as e:
                last_error = e
                if account_idx is not None:
                    account_manager.mark_account_cooldown(account_idx, str(e), account_manager.auth_error_cooldown)
                print(f"[文件上传] 第{retry_idx+1}次尝试失败(凭证): {e}")
                print(f"[文件上传] 本次尝试耗时: {time.time()-retry_start:.3f}秒")
                continue
            except AccountRequestError as e:
                last_error = e
                if account_idx is not None:
                    account_manager.mark_account_cooldown(account_idx, str(e), account_manager.generic_error_cooldown)
                print(f"[文件上传] 第{retry_idx+1}次尝试失败(请求异常): {e}")
                print(f"[文件上传] 本次尝试耗时: {time.time()-retry_start:.3f}秒")
                continue
            except NoAvailableAccount as e:
                last_error = e
                print(f"[文件上传] 无可用账号: {e}")
                break
            except Exception as e:
                last_error = e
                print(f"[文件上传] 第{retry_idx+1}次尝试失败: {type(e).__name__}: {e}")
                print(f"[文件上传] 堆栈跟踪:\n{traceback.format_exc()}")
                print(f"[文件上传] 本次尝试耗时: {time.time()-retry_start:.3f}秒")
                if account_idx is None:
                    break
                continue
        
        total_time = time.time() - request_start_time
        print(f"\n[文件上传] ===== 所有重试均失败 =====")
        error_message = last_error or "没有可用的账号"
        print(f"[文件上传] 最后错误: {error_message}")
        print(f"[文件上传] 总耗时: {total_time:.3f}秒")
        print(f"{'='*60}\n")
        status_code = 429 if isinstance(last_error, (AccountRateLimitError, NoAvailableAccount)) else 500
        err_type = "rate_limit" if status_code == 429 else "api_error"
        return jsonify({"error": {"message": f"文件上传失败: {error_message}", "type": err_type}}), status_code
        
    except Exception as e:
        total_time = time.time() - request_start_time
        print(f"\n[文件上传] ===== 发生异常 =====")
        print(f"[文件上传] 错误类型: {type(e).__name__}")
        print(f"[文件上传] 错误信息: {e}")
        print(f"[文件上传] 堆栈跟踪:\n{traceback.format_exc()}")
        print(f"[文件上传] 总耗时: {total_time:.3f}秒")
        print(f"{'='*60}\n")
        return jsonify({"error": {"message": str(e), "type": "api_error"}}), 500


@app.route('/v1/files', methods=['GET'])
@require_api_auth
def list_files():
    """获取已上传文件列表"""
    files = file_manager.list_files()
    return jsonify({
        "object": "list",
        "data": [{
            "id": f["openai_file_id"],
            "object": "file",
            "bytes": f.get("size", 0),
            "created_at": f.get("created_at", int(time.time())),
            "filename": f.get("filename", ""),
            "purpose": "assistants"
        } for f in files]
    })


@app.route('/v1/files/<file_id>', methods=['GET'])
@require_api_auth
def get_file(file_id):
    """获取文件信息"""
    file_info = file_manager.get_file(file_id)
    if not file_info:
        return jsonify({"error": {"message": "File not found", "type": "invalid_request_error"}}), 404
    
    return jsonify({
        "id": file_info["openai_file_id"],
        "object": "file",
        "bytes": file_info.get("size", 0),
        "created_at": file_info.get("created_at", int(time.time())),
        "filename": file_info.get("filename", ""),
        "purpose": "assistants"
    })


@app.route('/v1/files/<file_id>', methods=['DELETE'])
@require_api_auth
def delete_file(file_id):
    """删除文件"""
    if file_manager.delete_file(file_id):
        return jsonify({
            "id": file_id,
            "object": "file",
            "deleted": True
        })
    return jsonify({"error": {"message": "File not found", "type": "invalid_request_error"}}), 404


@app.route('/v1/chat/completions', methods=['POST'])
@require_api_auth
@rate_limit
def chat_completions():
    """聊天对话接口（支持图片输入输出）"""
    try:
        # 每次请求时清理过期图片
        cleanup_expired_images()
        
        data = request.json
        messages = data.get('messages', [])
        prompts = data.get('prompts', [])  # 支持替代格式
        stream = data.get('stream', False)
        requested_model = data.get('model', 'gemini-enterprise')  # 保存请求的模型名称
        include_thought = data.get('include_thought', False)  # 是否包含思考过程
        
        # 模型ID映射：将请求的模型名称映射为 Gemini 支持的模型ID
        # 从配置中获取模型映射，格式：{"id": "模型名", "name": "显示名称"}
        models_config = account_manager.config.get("models", [])
        models_mapping = {m.get("id", ""): m.get("id", "") for m in models_config}  # id -> id 映射
        # 如果请求的模型在配置中存在，使用配置的ID；否则直接使用请求的模型名
        model_id = models_mapping.get(requested_model, requested_model)

        # 提取用户消息、图片和文件ID
        user_message = ""
        input_images = []
        input_file_ids = []  # OpenAI file_id 列表
        
        # 处理标准 OpenAI messages 格式
        for msg in messages:
            if msg.get('role') == 'user':
                content = msg.get('content', '')
                text, images = extract_images_from_openai_content(content)
                if text:
                    user_message = text
                input_images.extend(images)
                
                # 提取文件ID（支持多种格式）
                if isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict):
                            # 格式1: {"type": "file", "file_id": "xxx"}
                            if item.get('type') == 'file' and item.get('file_id'):
                                input_file_ids.append(item['file_id'])
                            # 格式2: {"type": "file", "file": {"file_id": "xxx"}}
                            elif item.get('type') == 'file' and isinstance(item.get('file'), dict):
                                file_obj = item['file']
                                # 支持 file_id 或 id 两种字段名
                                fid = file_obj.get('file_id') or file_obj.get('id')
                                if fid:
                                    input_file_ids.append(fid)
        
        # 处理替代 prompts 格式（支持内联 base64 图片）
        # 格式: {"prompts": [{"role": "user", "text": "...", "files": [{"data": "data:image...", "type": "image"}]}]}
        for prompt in prompts:
            if prompt.get('role') == 'user':
                # 提取文本
                prompt_text = prompt.get('text', '')
                if prompt_text and not user_message:
                    user_message = prompt_text
                elif prompt_text:
                    user_message = prompt_text  # 使用最新的用户消息
                
                # 提取内联 files 数组中的图片
                files_array = prompt.get('files', [])
                if files_array:
                    images_from_files = extract_images_from_files_array(files_array)
                    input_images.extend(images_from_files)
        
        # 将 OpenAI file_id 转换为 Gemini fileId
        gemini_file_ids = []
        for fid in input_file_ids:
            gemini_fid = file_manager.get_gemini_file_id(fid)
            if gemini_fid:
                gemini_file_ids.append(gemini_fid)
        
        if not user_message and not input_images and not gemini_file_ids:
            return jsonify({"error": "No user message found"}), 400
        
        # 检查是否指定了特定账号
        specified_account_id = data.get('account_id')
        
        # ========== 流式模式处理 ==========
        if stream:
            # 获取账号信息
            if specified_account_id is not None:
                # 使用指定的账号
                accounts = account_manager.accounts
                if specified_account_id < 0 or specified_account_id >= len(accounts):
                    return jsonify({"error": f"无效的账号ID: {specified_account_id}"}), 400
                account = accounts[specified_account_id]
                if not account.get('enabled', True):
                    return jsonify({"error": f"账号 {specified_account_id} 已禁用"}), 400
                cooldown_until = account.get('cooldown_until', 0)
                if cooldown_until > time.time():
                    return jsonify({"error": f"账号 {specified_account_id} 正在冷却中，请稍后重试"}), 429
                account_idx = specified_account_id
            else:
                # 轮训获取账号
                available_accounts = account_manager.get_available_accounts()
                if not available_accounts:
                    next_cd = account_manager.get_next_cooldown_info()
                    wait_msg = ""
                    if next_cd:
                        wait_msg = f"（最近冷却账号 {next_cd['index']}，约 {int(next_cd['cooldown_until']-time.time())} 秒后可重试）"
                    return jsonify({"error": f"没有可用的账号{wait_msg}"}), 429
                account_idx, account = account_manager.get_next_account()
            
            try:
                session, jwt, team_id = ensure_session_for_account(account_idx, account)
                proxy = get_proxy()
                
                # 上传内联图片获取 fileId
                for img in input_images:
                    uploaded_file_id = upload_inline_image_to_gemini(jwt, session, team_id, img, proxy)
                    if uploaded_file_id:
                        gemini_file_ids.append(uploaded_file_id)
                
                # 获取账号标识
                used_account_csesidx = account.get('csesidx', f'账号{account_idx}')
                
                # 真正的流式响应
                def generate_stream():
                    for chunk in stream_chat_realtime(
                        jwt, session, user_message, proxy, team_id, 
                        gemini_file_ids, account, used_account_csesidx,
                        model_name=requested_model,
                        model_id=model_id,
                        include_thought=include_thought
                    ):
                        yield chunk
                
                # 创建响应并设置必要的头部禁用缓冲
                response = Response(generate_stream(), mimetype='text/event-stream')
                response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
                response.headers['X-Accel-Buffering'] = 'no'  # 禁用 nginx 缓冲
                response.headers['Connection'] = 'keep-alive'
                return response
                
            except (AccountRateLimitError, AccountAuthError, AccountRequestError) as e:
                account_manager.mark_account_cooldown(account_idx, str(e), account_manager.generic_error_cooldown)
                return jsonify({"error": f"账号请求失败: {e}"}), 500
            except Exception as e:
                return jsonify({"error": str(e)}), 500
        
        # ========== 非流式模式处理 ==========
        if specified_account_id is not None:
            # 使用指定的账号
            accounts = account_manager.accounts
            if specified_account_id < 0 or specified_account_id >= len(accounts):
                return jsonify({"error": f"无效的账号ID: {specified_account_id}"}), 400
            account = accounts[specified_account_id]
            if not account.get('enabled', True):
                return jsonify({"error": f"账号 {specified_account_id} 已禁用"}), 400
            # 检查是否在冷却中
            cooldown_until = account.get('cooldown_until', 0)
            if cooldown_until > time.time():
                return jsonify({"error": f"账号 {specified_account_id} 正在冷却中，请稍后重试"}), 429
            
            max_retries = 1
            last_error = None
            chat_response = None
            account_idx = specified_account_id
            try:
                session, jwt, team_id = ensure_session_for_account(account_idx, account)
                proxy = get_proxy()
                
                for img in input_images:
                    uploaded_file_id = upload_inline_image_to_gemini(jwt, session, team_id, img, proxy)
                    if uploaded_file_id:
                        gemini_file_ids.append(uploaded_file_id)
                
                chat_response = stream_chat_with_images(jwt, session, user_message, proxy, team_id, gemini_file_ids, account, model_id=model_id, include_thought=include_thought)
            except (AccountRateLimitError, AccountAuthError, AccountRequestError) as e:
                last_error = e
                account_manager.mark_account_cooldown(account_idx, str(e), account_manager.generic_error_cooldown)
            except Exception as e:
                last_error = e
        else:
            # 轮训获取账号
            available_accounts = account_manager.get_available_accounts()
            if not available_accounts:
                next_cd = account_manager.get_next_cooldown_info()
                wait_msg = ""
                if next_cd:
                    wait_msg = f"（最近冷却账号 {next_cd['index']}，约 {int(next_cd['cooldown_until']-time.time())} 秒后可重试）"
                return jsonify({"error": f"没有可用的账号{wait_msg}"}), 429

            max_retries = len(available_accounts)
            last_error = None
            chat_response = None
            
            for retry_idx in range(max_retries):
                account_idx = None
                try:
                    account_idx, account = account_manager.get_next_account()
                    session, jwt, team_id = ensure_session_for_account(account_idx, account)
                    proxy = get_proxy()
                    
                    # 上传内联图片获取 fileId
                    for img in input_images:
                        uploaded_file_id = upload_inline_image_to_gemini(jwt, session, team_id, img, proxy)
                        if uploaded_file_id:
                            gemini_file_ids.append(uploaded_file_id)
                    
                    chat_response = stream_chat_with_images(jwt, session, user_message, proxy, team_id, gemini_file_ids, account, model_id=model_id, include_thought=include_thought)
                    break
                except AccountRateLimitError as e:
                    last_error = e
                    if account_idx is not None:
                        pt_wait = seconds_until_next_pt_midnight()
                        cooldown_seconds = max(account_manager.rate_limit_cooldown, pt_wait)
                        account_manager.mark_account_cooldown(account_idx, str(e), cooldown_seconds)
                    print(f"[聊天] 第{retry_idx+1}次尝试失败(限额): {e}")
                    continue
                except AccountAuthError as e:
                    last_error = e
                    if account_idx is not None:
                        account_manager.mark_account_cooldown(account_idx, str(e), account_manager.auth_error_cooldown)
                    print(f"[聊天] 第{retry_idx+1}次尝试失败(凭证): {e}")
                    continue
                except AccountRequestError as e:
                    last_error = e
                    if account_idx is not None:
                        account_manager.mark_account_cooldown(account_idx, str(e), account_manager.generic_error_cooldown)
                    print(f"[聊天] 第{retry_idx+1}次尝试失败(请求异常): {e}")
                    continue
                except Exception as e:
                    last_error = e
                    print(f"[聊天] 第{retry_idx+1}次尝试失败: {type(e).__name__}: {e}")
                    if account_idx is None:
                        break
                    continue
        
        if chat_response is None:
            error_message = last_error or "没有可用的账号"
            status_code = 429 if isinstance(last_error, (AccountRateLimitError, NoAvailableAccount)) else 500
            return jsonify({"error": f"所有账号请求失败: {error_message}"}), status_code

        # 获取使用的账号csesidx
        used_account_csesidx = None
        if account_idx is not None and account_idx < len(account_manager.accounts):
            used_account = account_manager.accounts[account_idx]
            used_account_csesidx = used_account.get('csesidx', f'账号{account_idx}')

        # 构建响应内容（包含图片）
        response_content = build_openai_response_content(chat_response, request.host_url)

        # 非流式响应
        response = {
            "id": f"chatcmpl-{uuid.uuid4().hex[:8]}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": requested_model,
            "account_csesidx": used_account_csesidx,
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": response_content
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": len(user_message),
                "completion_tokens": len(chat_response.text),
                "total_tokens": len(user_message) + len(chat_response.text)
            }
        }
        return jsonify(response)

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


def get_image_base_url(fallback_host_url: str) -> str:
    """获取图片基础URL
    
    优先使用配置文件中的 image_base_url，否则使用请求的 host_url
    """
    configured_url = account_manager.config.get("image_base_url", "").strip()
    if configured_url:
        # 确保以 / 结尾
        if not configured_url.endswith("/"):
            configured_url += "/"
        return configured_url
    return fallback_host_url


def is_base64_output_mode() -> bool:
    try:
        if account_manager.config:
            mode = account_manager.config.get("image_output_mode") or "url"
            if isinstance(mode, str) and mode.lower() == "base64":
                return True
    except Exception:
        pass
    return False


def build_openai_response_content(chat_response: ChatResponse, host_url: str) -> str:
    """构建OpenAI格式的响应内容

    返回纯文本，如果有图片可根据配置选择:
    - url: 在文本末尾追加图片URL（默认行为）
    - base64: 在文本末尾追加 data:image/...;base64,...
    """
    result_text = chat_response.text

    if not chat_response.images:
        return result_text

    # 从配置读取图片输出模式，默认 url
    image_mode = "base64" if is_base64_output_mode() else "url"

    image_lines = []

    if image_mode == "base64":
        # 优先使用已有的base64数据（使用 Markdown 图片语法，方便前端渲染）
        for img in chat_response.images:
            if img.base64_data:
                mime = img.mime_type or "image/png"
                image_lines.append(f"![image](data:{mime};base64,{img.base64_data})")

        # 若部分图片没有base64数据，降级为URL形式，同样用 Markdown 图片语法
        base_url = get_image_base_url(host_url)
        for img in chat_response.images:
            if not img.base64_data and img.file_name:
                image_lines.append(f"![image]({base_url}image/{img.file_name})")
    else:
        # 传统URL模式
        base_url = get_image_base_url(host_url)
        for img in chat_response.images:
            if img.file_name:
                image_lines.append(f"{base_url}image/{img.file_name}")

    if image_lines:
        if result_text:
            result_text += "\n\n"
        result_text += "\n".join(image_lines)

    return result_text


# ==================== 图片服务接口 ====================

@app.route('/image/<path:filename>')
def serve_image(filename):
    """提供缓存图片的访问"""
    # 安全检查：防止路径遍历
    # 使用更严格的路径验证
    try:
        # 规范化路径并检查是否在允许的目录内
        safe_path = Path(filename).resolve()
        cache_dir = IMAGE_CACHE_DIR.resolve()
        
        # 检查路径是否在缓存目录内
        if not str(safe_path).startswith(str(cache_dir)):
            abort(404)
            
        # 额外检查：防止各种路径遍历技术
        if '..' in filename or filename.startswith('/') or '\\' in filename:
            abort(404)
    except (ValueError, OSError):
        abort(404)
    
    filepath = IMAGE_CACHE_DIR / filename
    if not filepath.exists():
        abort(404)
    
    # 确定Content-Type
    ext = filepath.suffix.lower()
    mime_types = {
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.jpeg': 'image/jpeg',
        '.gif': 'image/gif',
        '.webp': 'image/webp',
    }
    mime_type = mime_types.get(ext, 'application/octet-stream')
    
    return send_from_directory(IMAGE_CACHE_DIR, filename, mimetype=mime_type)


@app.route('/health', methods=['GET'])
def health_check():
    """健康检查"""
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})


@app.route('/api/status', methods=['GET'])
@require_admin
def system_status():
    """获取系统状态"""
    total, available = account_manager.get_account_count()
    proxy_url = account_manager.config.get("proxy")
    proxy_enabled = account_manager.config.get("proxy_enabled", False)
    effective_proxy = get_proxy()  # 实际使用的代理（考虑开关状态）
    
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "accounts": {
            "total": total,
            "available": available
        },
        "proxy": {
            "url": proxy_url,
            "enabled": proxy_enabled,
            "effective": effective_proxy,  # 实际生效的代理地址
            "available": check_proxy(effective_proxy) if effective_proxy else False
        },
        "models": account_manager.config.get("models", [])
    })


# ==================== 管理接口 ====================

@app.route('/')
def index():
    """返回管理页面"""
    return send_from_directory('.', 'index.html')

@app.route('/chat_history.html')
@require_admin
def chat_history():
    """返回聊天记录页面"""
    return send_from_directory('.', 'chat_history.html')

@app.route('/api/accounts', methods=['GET'])
@require_admin
def get_accounts():
    """获取账号列表"""
    accounts_data = []
    now_ts = time.time()
    for i, acc in enumerate(account_manager.accounts):
        state = account_manager.account_states.get(i, {})
        cooldown_until = state.get("cooldown_until")
        cooldown_active = bool(cooldown_until and cooldown_until > now_ts)
        effective_available = state.get("available", True) and not cooldown_active

        # 返回完整值用于编辑，前端显示时再截断
        accounts_data.append({
            "id": i,
            "team_id": acc.get("team_id", ""),
            "secure_c_ses": acc.get("secure_c_ses", ""),
            "host_c_oses": acc.get("host_c_oses", ""),
            "csesidx": acc.get("csesidx", ""),
            "user_agent": acc.get("user_agent", ""),
            "available": effective_available,
            "unavailable_reason": acc.get("unavailable_reason", ""),
            "cooldown_until": cooldown_until if cooldown_active else None,
            "cooldown_reason": state.get("cooldown_reason", ""),
            "has_jwt": state.get("jwt") is not None
        })
    return jsonify({"accounts": accounts_data})


@app.route('/api/accounts', methods=['POST'])
@require_admin
def add_account():
    """添加账号"""
    data = request.json
    # 去重：基于 csesidx 或 team_id 检查
    new_csesidx = data.get("csesidx", "")
    new_team_id = data.get("team_id", "")
    for acc in account_manager.accounts:
        if new_csesidx and acc.get("csesidx") == new_csesidx:
            return jsonify({"error": "账号已存在（同 csesidx）"}), 400
        if new_team_id and acc.get("team_id") == new_team_id and new_csesidx == acc.get("csesidx"):
            return jsonify({"error": "账号已存在（同 team_id + csesidx）"}), 400

    new_account = {
        "team_id": data.get("team_id", ""),
        "secure_c_ses": data.get("secure_c_ses", ""),
        "host_c_oses": data.get("host_c_oses", ""),
        "csesidx": data.get("csesidx", ""),
        "user_agent": data.get("user_agent", "Mozilla/5.0"),
        "available": True
    }
    
    account_manager.accounts.append(new_account)
    idx = len(account_manager.accounts) - 1
    account_manager.account_states[idx] = {
        "jwt": None,
        "jwt_time": 0,
        "session": None,
        "available": True,
        "cooldown_until": None,
        "cooldown_reason": ""
    }
    account_manager.config["accounts"] = account_manager.accounts
    account_manager.save_config()
    
    return jsonify({"success": True, "id": idx})


@app.route('/api/accounts/<int:account_id>', methods=['PUT'])
@require_admin
def update_account(account_id):
    """更新账号"""
    if account_id < 0 or account_id >= len(account_manager.accounts):
        return jsonify({"error": "账号不存在"}), 404
    
    data = request.json
    acc = account_manager.accounts[account_id]
    
    if "team_id" in data:
        acc["team_id"] = data["team_id"]
    if "secure_c_ses" in data:
        acc["secure_c_ses"] = data["secure_c_ses"]
    if "host_c_oses" in data:
        acc["host_c_oses"] = data["host_c_oses"]
    if "csesidx" in data:
        acc["csesidx"] = data["csesidx"]
    if "user_agent" in data:
        acc["user_agent"] = data["user_agent"]
    
    # 同步更新config中的accounts
    account_manager.config["accounts"] = account_manager.accounts
    account_manager.save_config()
    return jsonify({"success": True})


@app.route('/api/accounts/<int:account_id>', methods=['DELETE'])
@require_admin
def delete_account(account_id):
    """删除账号"""
    if account_id < 0 or account_id >= len(account_manager.accounts):
        return jsonify({"error": "账号不存在"}), 404
    
    account_manager.accounts.pop(account_id)
    # 重建状态映射
    new_states = {}
    for i in range(len(account_manager.accounts)):
        if i < account_id:
            new_states[i] = account_manager.account_states.get(i, {})
        else:
            new_states[i] = account_manager.account_states.get(i + 1, {})
    account_manager.account_states = new_states
    account_manager.config["accounts"] = account_manager.accounts
    account_manager.save_config()
    
    return jsonify({"success": True})


@app.route('/api/accounts/<int:account_id>/toggle', methods=['POST'])
@require_admin
def toggle_account(account_id):
    """切换账号状态"""
    if account_id < 0 or account_id >= len(account_manager.accounts):
        return jsonify({"error": "账号不存在"}), 404
    
    state = account_manager.account_states.get(account_id, {})
    current = state.get("available", True)
    state["available"] = not current
    account_manager.accounts[account_id]["available"] = not current
    
    if not current:
        # 重新启用时清除错误信息
        account_manager.accounts[account_id].pop("unavailable_reason", None)
        account_manager.accounts[account_id].pop("unavailable_time", None)
        state.pop("cooldown_until", None)
        state.pop("cooldown_reason", None)
        account_manager.accounts[account_id].pop("cooldown_until", None)
    
    account_manager.save_config()
    return jsonify({"success": True, "available": not current})


@app.route('/api/accounts/<int:account_id>/refresh-cookie', methods=['POST'])
@require_admin
def refresh_account_cookies(account_id):
    """刷新账号的secure_c_ses、host_c_oses和csesidx"""
    if account_id < 0 or account_id >= len(account_manager.accounts):
        return jsonify({"error": "账号不存在"}), 404
    
    data = request.json
    acc = account_manager.accounts[account_id]
    
    # 更新Cookie字段
    if "secure_c_ses" in data:
        acc["secure_c_ses"] = data["secure_c_ses"]
    if "host_c_oses" in data:
        acc["host_c_oses"] = data["host_c_oses"]
    if "csesidx" in data and data["csesidx"]:
        acc["csesidx"] = data["csesidx"]
    
    # 清除JWT缓存，强制重新获取
    state = account_manager.account_states.get(account_id, {})
    state["jwt"] = None
    state["jwt_time"] = 0
    account_manager.account_states[account_id] = state
    
    account_manager.config["accounts"] = account_manager.accounts
    account_manager.save_config()
    
    return jsonify({"success": True, "message": "Cookie已刷新"})


@app.route('/api/accounts/<int:account_id>/test', methods=['GET'])
@require_admin
def test_account(account_id):
    """测试账号JWT获取"""
    if account_id < 0 or account_id >= len(account_manager.accounts):
        return jsonify({"error": "账号不存在"}), 404
    
    account = account_manager.accounts[account_id]
    proxy = account_manager.config.get("proxy")
    
    try:
        jwt = get_jwt_for_account(account, proxy)
        return jsonify({"success": True, "message": "JWT获取成功"})
    except AccountRateLimitError as e:
        pt_wait = seconds_until_next_pt_midnight()
        cooldown_seconds = max(account_manager.rate_limit_cooldown, pt_wait)
        account_manager.mark_account_cooldown(account_id, str(e), cooldown_seconds)
        return jsonify({"success": False, "message": str(e), "cooldown": cooldown_seconds})
    except AccountAuthError as e:
        account_manager.mark_account_cooldown(account_id, str(e), account_manager.auth_error_cooldown)
        return jsonify({"success": False, "message": str(e), "cooldown": account_manager.auth_error_cooldown})
    except AccountRequestError as e:
        account_manager.mark_account_cooldown(account_id, str(e), account_manager.generic_error_cooldown)
        return jsonify({"success": False, "message": str(e), "cooldown": account_manager.generic_error_cooldown})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})


@app.route('/api/models', methods=['GET'])
@require_admin
def get_models_config():
    """获取模型配置"""
    models = account_manager.config.get("models", [])
    return jsonify({"models": models})


@app.route('/api/models', methods=['POST'])
@require_admin
def add_model():
    """添加模型"""
    data = request.json
    new_model = {
        "id": data.get("id", ""),
        "name": data.get("name", ""),
        "description": data.get("description", ""),
        "context_length": data.get("context_length", 32768),
        "max_tokens": data.get("max_tokens", 8192),
        "enabled": data.get("enabled", True)
    }
    
    if "models" not in account_manager.config:
        account_manager.config["models"] = []
    
    account_manager.config["models"].append(new_model)
    account_manager.save_config()
    
    return jsonify({"success": True})


@app.route('/api/models/<model_id>', methods=['PUT'])
@require_admin
def update_model(model_id):
    """更新模型"""
    models = account_manager.config.get("models", [])
    for model in models:
        if model.get("id") == model_id:
            data = request.json
            if "name" in data:
                model["name"] = data["name"]
            if "description" in data:
                model["description"] = data["description"]
            if "context_length" in data:
                model["context_length"] = data["context_length"]
            if "max_tokens" in data:
                model["max_tokens"] = data["max_tokens"]
            if "enabled" in data:
                model["enabled"] = data["enabled"]
            account_manager.save_config()
            return jsonify({"success": True})
    
    return jsonify({"error": "模型不存在"}), 404


@app.route('/api/models/<model_id>', methods=['DELETE'])
@require_admin
def delete_model(model_id):
    """删除模型"""
    models = account_manager.config.get("models", [])
    for i, model in enumerate(models):
        if model.get("id") == model_id:
            models.pop(i)
            account_manager.save_config()
            return jsonify({"success": True})
    
    return jsonify({"error": "模型不存在"}), 404


@app.route('/api/config', methods=['GET'])
@require_admin
def get_config():
    """获取完整配置"""
    return jsonify(account_manager.config)


@app.route('/api/config', methods=['PUT'])
@require_admin
def update_config():
    """更新配置"""
    data = request.json or {}
    if "proxy" in data:
        account_manager.config["proxy"] = data["proxy"]
    if "log_level" in data:
        try:
            set_log_level(data["log_level"], persist=True)
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    if "image_output_mode" in data:
        mode = data["image_output_mode"]
        if isinstance(mode, str) and mode.lower() in ("url", "base64"):
            account_manager.config["image_output_mode"] = mode.lower()
    account_manager.save_config()
    return jsonify({"success": True})


@app.route('/api/logging', methods=['GET', 'POST'])
@require_admin
def logging_config():
    """获取或设置日志级别"""
    if request.method == 'GET':
        return jsonify({
            "level": CURRENT_LOG_LEVEL_NAME,
            "levels": list(LOG_LEVELS.keys())
        })
    
    data = request.json or {}
    level = data.get("level", "").upper()
    if level not in LOG_LEVELS:
        return jsonify({"error": "无效日志级别"}), 400
    
    set_log_level(level, persist=True)
    return jsonify({"success": True, "level": CURRENT_LOG_LEVEL_NAME})


@app.route('/api/auth/login', methods=['POST'])
@rate_limit
def admin_login():
    """后台登录，返回 token。若尚未设置密码，则首次设置。"""
    data = request.json or {}
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "密码不能为空"}), 400
    
    stored_hash = get_admin_password_hash()
    if stored_hash:
        if not check_password_hash(stored_hash, password):
            return jsonify({"error": "密码错误"}), 401
    else:
        # 首次设置密码
        set_admin_password(password)
    
    token = create_admin_token()
    resp = jsonify({"token": token, "level": CURRENT_LOG_LEVEL_NAME})
    # 根据环境自动设置secure标志
    is_production = os.getenv("FLASK_ENV") == "production" or os.getenv("ENVIRONMENT") == "production"
    resp.set_cookie(
        "admin_token",
        token,
        max_age=86400,
        httponly=True,
        secure=is_production,  # 生产环境使用HTTPS
        samesite="Lax",
        path="/"
    )
    return resp


@app.route('/api/tokens', methods=['GET', 'POST'])
@require_admin
def manage_tokens():
    """获取或创建API访问Token"""
    if request.method == 'GET':
        return jsonify({"tokens": list(API_TOKENS)})
    
    data = request.json or {}
    token = data.get("token")
    if not token:
        token = secrets.token_urlsafe(32)
    if not isinstance(token, str) or len(token) < 8:
        return jsonify({"error": "Token格式不合法"}), 400
    if token in API_TOKENS:
        return jsonify({"error": "Token已存在"}), 400
    
    API_TOKENS.add(token)
    persist_api_tokens()
    return jsonify({"success": True, "token": token})


@app.route('/api/tokens/<token>', methods=['DELETE'])
@require_admin
def delete_token(token):
    """删除指定API Token"""
    if token in API_TOKENS:
        API_TOKENS.remove(token)
        persist_api_tokens()
        return jsonify({"success": True})
    return jsonify({"error": "Token不存在"}), 404


@app.route('/api/config/import', methods=['POST'])
@require_admin
def import_config():
    """导入配置"""
    try:
        data = request.json
        account_manager.config = data
        if data.get("log_level"):
            try:
                set_log_level(data.get("log_level"), persist=False)
            except Exception:
                pass
        if data.get("admin_secret_key"):
            global ADMIN_SECRET_KEY
            ADMIN_SECRET_KEY = data.get("admin_secret_key")
        else:
            get_admin_secret_key()
        load_api_tokens()
        account_manager.accounts = data.get("accounts", [])
        # 重建账号状态
        account_manager.account_states = {}
        for i, acc in enumerate(account_manager.accounts):
            available = acc.get("available", True)
            account_manager.account_states[i] = {
                "jwt": None,
                "jwt_time": 0,
                "session": None,
                "available": available,
                "cooldown_until": acc.get("cooldown_until"),
                "cooldown_reason": acc.get("unavailable_reason") or acc.get("cooldown_reason") or ""
            }
        account_manager.save_config()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/proxy/test', methods=['POST'])
@require_admin
def test_proxy():
    """测试代理"""
    data = request.json
    proxy_url = data.get("proxy") or account_manager.config.get("proxy")
    
    if not proxy_url:
        return jsonify({"success": False, "message": "未配置代理地址"})
    
    available = check_proxy(proxy_url)
    return jsonify({
        "success": available,
        "message": "代理可用" if available else "代理不可用或连接超时"
    })


@app.route('/api/proxy/status', methods=['GET'])
@require_admin
def get_proxy_status():
    """获取代理状态"""
    proxy = account_manager.config.get("proxy")
    if not proxy:
        return jsonify({"enabled": False, "url": None, "available": False})
    
    available = check_proxy(proxy)
    return jsonify({
        "enabled": True,
        "url": proxy,
        "available": available
    })


@app.route('/api/config/export', methods=['GET'])
@require_admin
def export_config():
    """导出配置"""
    return jsonify(account_manager.config)


def print_startup_info():
    """打印启动信息"""
    print("="*60)
    print("Business Gemini OpenAPI 服务 (多账号轮训版)")
    print("支持图片输入输出 (OpenAI格式)")
    print("="*60)
    
    # 检测配置文件是否存在，不存在则从 .example 复制初始化
    example_file = Path(__file__).parent / "business_gemini_session.json.example"
    if not CONFIG_FILE.exists():
        if example_file.exists():
            shutil.copy(example_file, CONFIG_FILE)
            print(f"\n[初始化] 配置文件不存在，已从 {example_file.name} 复制创建")
        else:
            print(f"\n[警告] 配置文件和示例文件都不存在，请创建 {CONFIG_FILE.name}")
    
    # 加载配置
    account_manager.load_config()
    get_admin_secret_key()
    
    # 代理信息
    proxy = account_manager.config.get("proxy")
    print(f"\n[代理配置]")
    print(f"  地址: {proxy or '未配置'}")
    if proxy:
        proxy_available = check_proxy(proxy)
        print(f"  状态: {'✓ 可用' if proxy_available else '✗ 不可用'}")
    
    # 图片缓存信息
    print(f"\n[图片缓存]")
    print(f"  目录: {IMAGE_CACHE_DIR}")
    print(f"  缓存时间: {IMAGE_CACHE_HOURS} 小时")
    
    # 账号信息
    total, available = account_manager.get_account_count()
    print(f"\n[账号配置]")
    print(f"  总数量: {total}")
    print(f"  可用数量: {available}")
    
    for i, acc in enumerate(account_manager.accounts):
        state = account_manager.account_states.get(i, {})
        is_available = account_manager.is_account_available(i)
        status = "✓" if is_available else "✗"
        team_id = acc.get("team_id", "未知") + "..."
        cooldown_until = state.get("cooldown_until")
        extra = ""
        if cooldown_until and cooldown_until > time.time():
            remaining = int(cooldown_until - time.time())
            extra = f" (冷却中 ~{remaining}s)"
        print(f"  [{i}] {status} team_id: {team_id}{extra}")
    
    # 模型信息
    models = account_manager.config.get("models", [])
    print(f"\n[模型配置]")
    if models:
        for model in models:
            print(f"  - {model.get('id')}: {model.get('name', '')}")
    else:
        print("  - gemini-enterprise (默认)")
    
    print(f"\n[接口列表]")
    print("  GET  /v1/models           - 获取模型列表")
    print("  POST /v1/chat/completions - 聊天对话 (支持图片)")
    print("  GET  /v1/status           - 系统状态")
    print("  GET  /health              - 健康检查")
    print("  GET  /image/<filename>    - 获取缓存图片")
    print("\n" + "="*60)
    print("启动服务...")


if __name__ == '__main__':
    print_startup_info()
    
    if not account_manager.accounts:
        print("[!] 警告: 没有配置任何账号")
    
    app.run(host='0.0.0.0', port=8000, debug=False)
