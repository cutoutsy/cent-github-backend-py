from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
from typing import Optional, Dict, List
import requests
import os
import secrets
import json
import base64
import hmac
import hashlib
import time
from urllib.parse import urlencode, urlparse, parse_qs
from dotenv import load_dotenv
from workers import WorkerEntrypoint

# 加载环境变量
load_dotenv()

app = FastAPI()

# 配置模板
templates = Jinja2Templates(directory="templates")

# 配置CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://apps-sl.danlu.netease.com:37175",
        "http://localhost:3000",
        "http://127.0.0.1:3000"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# GitHub OAuth配置
GITHUB_CLIENT_ID = os.environ.get('GITHUB_CLIENT_ID')
GITHUB_CLIENT_SECRET = os.environ.get('GITHUB_CLIENT_SECRET')
GITHUB_APP_SLUG = os.environ.get('GITHUB_APP_SLUG', 'your-app-slug')
ENCRYPTION_SECRETS = os.environ.get('ENCRYPTION_SECRETS', secrets.token_hex(32))
GITHUB_AUTHORIZE_URL = 'https://github.com/login/oauth/authorize'
GITHUB_TOKEN_URL = 'https://github.com/login/oauth/access_token'
GITHUB_API_BASE_URL = 'https://api.github.com'

# 常量
INVALID_REDIRECT_MSG = "Invalid redirect URL"

# Pydantic模型
class TokenData(BaseModel):
    refreshToken: str

class UserInfo(BaseModel):
    id: int
    login: str
    name: Optional[str] = None
    email: Optional[str] = None
    avatar_url: Optional[str] = None

def encode_state(return_url: str, secret_key: str) -> str:
    """编码 state 参数，包含返回URL和时间戳"""
    try:
        timestamp = int(time.time())
        data = {
            'return_url': return_url,
            'timestamp': timestamp
        }
        
        json_data = json.dumps(data)
        encoded_data = base64.b64encode(json_data.encode()).decode()
        
        signature = hmac.new(
            secret_key.encode(),
            encoded_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        state = f"{encoded_data}.{signature}"
        return state
    except Exception as e:
        raise ValueError(f"Failed to encode state: {str(e)}")

def decode_state(state: str, secret_key: str) -> str:
    """解码并验证 state 参数"""
    try:
        parts = state.split('.')
        if len(parts) != 2:
            raise ValueError("Invalid state format")
        
        encoded_data, signature = parts
        
        expected_signature = hmac.new(
            secret_key.encode(),
            encoded_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            raise ValueError("Invalid state signature")
        
        json_data = base64.b64decode(encoded_data.encode()).decode()
        data = json.loads(json_data)
        
        timestamp = data.get('timestamp', 0)
        current_time = int(time.time())
        if current_time - timestamp > 3600:
            raise ValueError("State has expired")
        
        return data['return_url']
    except Exception as e:
        raise ValueError(f"Failed to decode state: {str(e)}")

def is_valid_redirect(url: str) -> bool:
    """验证重定向URL的有效性"""
    try:
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return False
        
        if parsed.scheme not in ['http', 'https']:
            return False
        
        return True
    except:
        return False

def get_user_info(access_token: str) -> Optional[Dict]:
    """获取GitHub用户信息"""
    headers = {
        'Authorization': f'token {access_token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    response = requests.get(f'{GITHUB_API_BASE_URL}/user', headers=headers)
    if response.status_code == 200:
        user_data = response.json()
        
        email_response = requests.get(f'{GITHUB_API_BASE_URL}/user/emails', headers=headers)
        if email_response.status_code == 200:
            emails = email_response.json()
            primary_email = next((email['email'] for email in emails if email['primary']), None)
            if primary_email:
                user_data['email'] = primary_email
        
        return user_data
    return None

def get_user_repos(access_token: str, per_page: int = 10) -> List[Dict]:
    """获取用户的仓库信息"""
    headers = {
        'Authorization': f'token {access_token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    params = {
        'sort': 'updated',
        'per_page': per_page
    }
    
    response = requests.get(f'{GITHUB_API_BASE_URL}/user/repos', headers=headers, params=params)
    if response.status_code == 200:
        return response.json()
    return []

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """主页"""
    return templates.TemplateResponse("index.html", {"request": request, "user_info": None})

@app.get("/api/github-oauth/authorize")
async def login(request: Request):
    """GitHub OAuth登录（使用新的高级回调）"""
    if not GITHUB_CLIENT_ID:
        raise HTTPException(status_code=500, detail="GitHub Client ID not configured")
    
    return_url = str(request.query_params.get('redirect_uri', request.url_for('index')))
    state = encode_state(return_url, ENCRYPTION_SECRETS)
    
    params = {
        'client_id': GITHUB_CLIENT_ID,
        'scope': 'repo read:user user:email',
        'state': state
    }
    
    github_auth_url = f"{GITHUB_AUTHORIZE_URL}?{urlencode(params)}"
    return RedirectResponse(url=github_auth_url)

@app.get("/api/github-oauth/authorized")
async def github_oauth_authorized(request: Request):
    """GitHub OAuth回调处理"""
    try:
        code = request.query_params.get('code')
        state = request.query_params.get('state')
        
        if not code or not state:
            raise HTTPException(status_code=400, detail='Missing "code" or "state" query parameter.')
        
        try:
            app_return_url = decode_state(state, ENCRYPTION_SECRETS)
        except ValueError as err:
            raise HTTPException(status_code=400, detail=str(err))
        
        if not is_valid_redirect(app_return_url):
            raise HTTPException(status_code=400, detail=INVALID_REDIRECT_MSG)
        
        token_response = requests.post(
            GITHUB_TOKEN_URL,
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            json={
                'client_id': GITHUB_CLIENT_ID,
                'client_secret': GITHUB_CLIENT_SECRET,
                'code': code,
            }
        )
        
        if not token_response.ok:
            raise HTTPException(status_code=500, detail="Failed to exchange code for access token.")
        
        token_data = token_response.json()
        
        if 'error' in token_data or 'access_token' not in token_data:
            error_msg = token_data.get('error', 'Unknown error')
            raise HTTPException(status_code=400, detail=f"GitHub returned an error: {error_msg}")
        
        # 构建重定向URL
        parsed_return_url = urlparse(app_return_url)
        query_params = parse_qs(parsed_return_url.query)
        query_params['github_authorized'] = [json.dumps(token_data)]
        
        new_query = urlencode(query_params, doseq=True)
        redirect_url = f"{parsed_return_url.scheme}://{parsed_return_url.netloc}{parsed_return_url.path}"
        if new_query:
            redirect_url += f"?{new_query}"
        
        return RedirectResponse(url=redirect_url)
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/github-oauth/refresh-token")
async def refresh_github_token(token_data: TokenData):
    """刷新 GitHub token"""
    try:
        token_response = requests.post(
            GITHUB_TOKEN_URL,
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            json={
                'client_id': GITHUB_CLIENT_ID,
                'client_secret': GITHUB_CLIENT_SECRET,
                'grant_type': 'refresh_token',
                'refresh_token': token_data.refreshToken,
            }
        )
        
        if not token_response.ok:
            raise HTTPException(status_code=500, detail="Failed to refresh token")
        
        token_data = token_response.json()
        
        if 'error' in token_data or 'access_token' not in token_data:
            error_msg = token_data.get('error', 'Unknown error')
            raise HTTPException(status_code=400, detail=f"GitHub returned an error: {error_msg}")
        
        return token_data
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        import asgi

        return await asgi.fetch(app, request.js_object, self.env)
# if __name__ == "__main__":
#     import uvicorn
    
#     if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
#         print("警告: 请设置环境变量 GITHUB_CLIENT_ID 和 GITHUB_CLIENT_SECRET")
#         print("请参考 README.md 获取详细配置说明")
    
#     uvicorn.run(app, host="0.0.0.0", port=5000)