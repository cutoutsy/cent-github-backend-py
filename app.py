from flask import Flask, request, session, redirect, url_for, render_template, jsonify, abort
import requests
import os
from urllib.parse import urlencode, urlparse, parse_qs
import secrets
import json
import base64
import hmac
import hashlib
import time
from dotenv import load_dotenv
from flask_cors import CORS, cross_origin

# 加载环境变量
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))

# 全局 CORS 配置
CORS(app, origins=[
    "http://apps-sl.danlu.netease.com:37175",
    "http://localhost:3000",
    "http://127.0.0.1:3000"
], supports_credentials=True)

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

def encode_state(return_url, secret_key):
    """
    编码 state 参数，包含返回URL和时间戳
    """
    try:
        # 创建包含返回URL和时间戳的数据
        timestamp = int(time.time())
        data = {
            'return_url': return_url,
            'timestamp': timestamp
        }
        
        # 将数据转换为JSON字符串
        json_data = json.dumps(data)
        
        # 使用base64编码
        encoded_data = base64.b64encode(json_data.encode()).decode()
        
        # 创建HMAC签名
        signature = hmac.new(
            secret_key.encode(),
            encoded_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        # 组合编码数据和签名
        state = f"{encoded_data}.{signature}"
        return state
    except Exception as e:
        raise ValueError(f"Failed to encode state: {str(e)}")

def decode_state(state, secret_key):
    """
    解码并验证 state 参数
    """
    try:
        # 分离数据和签名
        parts = state.split('.')
        if len(parts) != 2:
            raise ValueError("Invalid state format")
        
        encoded_data, signature = parts
        
        # 验证签名
        expected_signature = hmac.new(
            secret_key.encode(),
            encoded_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        if not hmac.compare_digest(signature, expected_signature):
            raise ValueError("Invalid state signature")
        
        # 解码数据
        json_data = base64.b64decode(encoded_data.encode()).decode()
        data = json.loads(json_data)
        
        # 检查时间戳（可选：防止过期的state）
        timestamp = data.get('timestamp', 0)
        current_time = int(time.time())
        # state有效期为1小时
        if current_time - timestamp > 3600:
            raise ValueError("State has expired")
        
        return data['return_url']
    except Exception as e:
        raise ValueError(f"Failed to decode state: {str(e)}")

def is_valid_redirect(url):
    """
    验证重定向URL的有效性
    """
    try:
        parsed = urlparse(url)
        # 检查是否为有效的URL
        if not parsed.scheme or not parsed.netloc:
            return False
        
        # 只允许https和http协议
        if parsed.scheme not in ['http', 'https']:
            return False
        
        # 可以添加更多的安全检查，比如域名白名单等
        # 这里简化处理，实际应用中应该有更严格的验证
        return True
    except:
        return False

@app.route('/')
def index():
    """主页"""
    user_info = session.get('user_info')
    return render_template('index.html', user_info=user_info)

@app.route('/api/github-oauth/authorize')
def login():
    """GitHub OAuth登录（使用新的高级回调）"""
    if not GITHUB_CLIENT_ID:
        return jsonify({'error': 'GitHub Client ID not configured'}), 500
    
    # 获取返回URL，默认为当前域名的根目录
    return_url = request.args.get('redirect_uri', url_for('index', _external=True))
    
    # 创建加密的state参数
    state = encode_state(return_url, ENCRYPTION_SECRETS)
    
    params = {
        'client_id': GITHUB_CLIENT_ID,
        'redirect_uri': url_for('github_oauth_authorized', _external=True),
        'scope': 'repo read:user user:email',  # 添加repo权限以访问私有仓库
        'state': state
    }
    
    github_auth_url = f"{GITHUB_AUTHORIZE_URL}?{urlencode(params)}"
    print("github_auth_url: ", github_auth_url)
    return redirect(github_auth_url)

@app.route('/api/github-oauth/authorize-simple')
def login_simple():
    """GitHub OAuth登录（简化版本）"""
    if not GITHUB_CLIENT_ID:
        return jsonify({'error': 'GitHub Client ID not configured'}), 500
    
    params = {
        'client_id': GITHUB_CLIENT_ID,
        'redirect_uri': url_for('callback', _external=True),
        'scope': 'repo read:user user:email',  # 添加repo权限以访问私有仓库
        'state': secrets.token_urlsafe(32)
    }
    
    # 保存state到session以防止CSRF攻击
    session['oauth_state'] = params['state']
    
    github_auth_url = f"{GITHUB_AUTHORIZE_URL}?{urlencode(params)}"
    return redirect(github_auth_url)

@app.route('/callback')
def callback():
    """GitHub OAuth回调处理（简化版本）"""
    error = request.args.get('error')
    if error:
        return render_template('error.html', error=error)
    
    code = request.args.get('code')
    state = request.args.get('state')
    
    # 验证state参数
    if not state or state != session.get('oauth_state'):
        return render_template('error.html', error='Invalid state parameter')
    
    if not code:
        return render_template('error.html', error='Authorization code not received')
    
    # 交换code获取access token
    token_data = {
        'client_id': GITHUB_CLIENT_ID,
        'client_secret': GITHUB_CLIENT_SECRET,
        'code': code,
        'redirect_uri': url_for('callback', _external=True)
    }
    
    headers = {'Accept': 'application/json'}
    token_response = requests.post(GITHUB_TOKEN_URL, data=token_data, headers=headers)
    
    if token_response.status_code != 200:
        return render_template('error.html', error='Failed to get access token')
    
    token_json = token_response.json()
    access_token = token_json.get('access_token')
    
    if not access_token:
        return render_template('error.html', error='Access token not received')
    
    # 使用access token获取用户信息
    user_info = get_user_info(access_token)
    if user_info:
        session['user_info'] = user_info
        session['access_token'] = access_token
        # 清除oauth_state
        session.pop('oauth_state', None)
        return redirect(url_for('profile'))
    else:
        return render_template('error.html', error='Failed to get user information')

@app.route('/api/github-oauth/authorized')
def github_oauth_authorized():
    """
    路由: /api/github-oauth/authorized
    描述: 这是 GitHub 授权后的回调地址。
    流程:
    1. 从查询参数中获取 code 和 state。
    2. 验证 state 的有效性。
    3. 使用 code 向 GitHub 交换 User Access Token。
    4. 使用 Token 调用 GitHub API 检查用户是否已安装该 App。
    5. 根据安装状态，将用户智能分流到"应用首页"或"App 安装页"。
    """
    try:
        # 步骤 1: 获取查询参数
        code = request.args.get('code')
        state = request.args.get('state')
        print("code: ", code, state)
        # 验证参数
        if not code or not state:
            abort(400, description='Missing "code" or "state" query parameter.')
        
        # 步骤 2: 解码并验证 state
        try:
            app_return_url = decode_state(state, ENCRYPTION_SECRETS)
            print("State validation successful.")
        except ValueError as err:
            print(f"Invalid state received: {err}")
            abort(400, description=str(err))
        
        # 验证重定向URL的有效性
        if not is_valid_redirect(app_return_url):
            abort(400, description=INVALID_REDIRECT_MSG)
        
        return_url = urlparse(app_return_url)
        
        # 步骤 3: 使用 code 交换 Access Token
        print("Exchanging code for access token...")
        print(f"GitHub Token URL: {GITHUB_TOKEN_URL}")
        print(f"Client ID: {GITHUB_CLIENT_ID[:8]}...")  # 只显示前8位用于调试
        
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
                    'code': code,
                },
                timeout=10  # 添加10秒超时
            )
            print(f"Token response status: {token_response.status_code}")
            print(f"Token response headers: {dict(token_response.headers)}")
            
        except requests.exceptions.Timeout:
            print("ERROR: Request to GitHub token endpoint timed out")
            abort(500, description="GitHub authentication service is not responding. Please try again later.")
        except requests.exceptions.ConnectionError as e:
            print(f"ERROR: Connection error when contacting GitHub: {e}")
            abort(500, description="Unable to connect to GitHub authentication service. Please check your network connection.")
        except requests.exceptions.RequestException as e:
            print(f"ERROR: Request failed: {e}")
            abort(500, description="Authentication request failed. Please try again.")
        
        if not token_response.ok:
            error_body = token_response.text
            print(f"Failed to get access token: {error_body}")
            abort(500, description="Failed to exchange code for access token.")
        
        token_data = token_response.json()
        
        if 'error' in token_data or 'access_token' not in token_data:
            print(f"Error in token response from GitHub: {token_data}")
            error_msg = token_data.get('error', 'Unknown error')
            abort(400, description=f"GitHub returned an error: {error_msg}")
        
        access_token = token_data['access_token']
        print("Successfully obtained access token.")
        
        # 步骤 4: 检查用户 App 安装状态（可选）
        app_installation_check = os.environ.get('ENABLE_APP_INSTALLATION_CHECK', 'false').lower() == 'true'
        user_has_app_installed = False
        
        if app_installation_check:
            print("Checking user installation status...")
            try:
                headers={
                        'Authorization': f'Bearer {access_token}',
                        'Accept': 'application/vnd.github.v3+json',
                        'User-Agent': f'{GITHUB_APP_SLUG} (Python Flask App)',
                    }
                print("headers: ", headers)
                installations_response = requests.get(
                    f"{GITHUB_API_BASE_URL}/user/installations",
                    headers={
                        'Authorization': f'Bearer {access_token}',
                        'Accept': 'application/vnd.github.v3+json',
                        'User-Agent': f'{GITHUB_APP_SLUG} (Python Flask App)',
                    }
                )
                
                if installations_response.ok:
                    installations_data = installations_response.json()
                    user_has_app_installed = (
                        installations_data.get('total_count', 0) > 0 and 
                        len(installations_data.get('installations', [])) > 0
                    )
                    print(f"App installation check successful. User has app: {user_has_app_installed}")
                else:
                    error_body = installations_response.text
                    print(f"App installation check failed (this is normal for OAuth Apps): {error_body}")
                    # 对于OAuth App，这是预期的错误，我们假设用户已授权
                    user_has_app_installed = True
                    
            except Exception as e:
                print(f"App installation check failed with exception: {e}")
                # 如果检查失败，假设用户已授权（兼容OAuth App）
                user_has_app_installed = True
        else:
            print("App installation check disabled. Treating user as authorized.")
            user_has_app_installed = True
        
        # 步骤 5: 智能分流
        if user_has_app_installed:
            # 情况 A: 已安装 App 或使用 OAuth App (授权用户)
            print("User is authorized. Redirecting to dashboard.")
            print("app_return_url: ", app_return_url)
            # 构建重定向URL
            parsed_return_url = urlparse(app_return_url)
            query_params = parse_qs(parsed_return_url.query)
            
            # 添加授权信息作为查询参数
            query_params['github_authorized'] = [json.dumps(token_data)]
            
            # 重新构建URL
            new_query = urlencode(query_params, doseq=True)
            redirect_url = f"{parsed_return_url.scheme}://{parsed_return_url.netloc}{parsed_return_url.path}"
            print("redirect_url: ", redirect_url)
            if new_query:
                redirect_url += f"?{new_query}"
            
            return redirect(redirect_url)
        else:
            # 情况 B: 未安装 App (新用户) - 仅适用于GitHub App
            print("User has not installed the app. Redirecting to installation page.")
            
            # 构建GitHub App安装URL
            install_url = f"https://github.com/apps/{GITHUB_APP_SLUG}/installations/new"
            install_params = {'state': state}
            full_install_url = f"{install_url}?{urlencode(install_params)}"
            
            return redirect(full_install_url)
    
    except Exception as e:
        print(f"Unexpected error in github_oauth_authorized: {e}")
        abort(500, description="Internal server error")

@app.route('/profile')
def profile():
    """用户个人资料页面"""
    user_info = session.get('user_info')
    if not user_info:
        return redirect(url_for('index'))
    
    # 获取用户的仓库信息
    access_token = session.get('access_token')
    repos = get_user_repos(access_token) if access_token else []
    
    return render_template('profile.html', user_info=user_info, repos=repos)

@app.route('/logout')
def logout():
    """退出登录"""
    session.clear()
    return redirect(url_for('index'))

def get_user_info(access_token):
    """获取GitHub用户信息"""
    headers = {
        'Authorization': f'token {access_token}',
        'Accept': 'application/vnd.github.v3+json'
    }
    
    response = requests.get(f'{GITHUB_API_BASE_URL}/user', headers=headers)
    if response.status_code == 200:
        user_data = response.json()
        
        # 获取用户邮箱信息
        email_response = requests.get(f'{GITHUB_API_BASE_URL}/user/emails', headers=headers)
        emails = []
        if email_response.status_code == 200:
            emails = email_response.json()
            # 找到主要邮箱
            primary_email = next((email['email'] for email in emails if email['primary']), None)
            if primary_email:
                user_data['email'] = primary_email
        
        return user_data
    return None

@app.route('/api/github-oauth/refresh-token', methods=['POST'])
def refresh_github_token():
    """
    刷新 GitHub token
    """
    try:
        # 获取请求体中的JSON数据
        # if not request.is_json:
        #     print("Request is not JSON: ", request.data)
        #     return jsonify({'error': 'Request must be JSON'}), 400
        print("Request is not JSON: ", request.data, str(request.data))
        data = json.loads(request.data.decode('utf-8'))
        refresh_token = data.get('refreshToken')
        
        if not refresh_token:
            return jsonify({'error': 'invalid refresh token.'}), 500
        
        # 向GitHub发送刷新token的请求
        token_response = requests.post(
            'https://github.com/login/oauth/access_token',
            headers={
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            json={
                'client_id': GITHUB_CLIENT_ID,
                'client_secret': GITHUB_CLIENT_SECRET,
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token,
            }
        )
        
        if not token_response.ok:
            error_body = token_response.text
            print(f"Failed to get access token: {error_body}")
            return jsonify({'error': 'Failed to exchange code for access token.'}), 500
        
        token_data = token_response.json()
        
        if 'error' in token_data or 'access_token' not in token_data:
            print(f"Error in token response from GitHub: {token_data}")
            error_msg = token_data.get('error', 'Unknown error')
            return jsonify({'error': f'GitHub returned an error: {error_msg}'}), 400
        
        return jsonify(token_data)
        
    except Exception as e:
        print(f"Unexpected error in refresh_github_token: {e}")
        return jsonify({'error': 'Internal server error'}), 500

def get_user_repos(access_token, per_page=10):
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

if __name__ == '__main__':
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        print("警告: 请设置环境变量 GITHUB_CLIENT_ID 和 GITHUB_CLIENT_SECRET")
        print("请参考 README.md 获取详细配置说明")
    
    app.run(debug=True, host='0.0.0.0', port=5000)