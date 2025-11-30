// public/script.js

const TOKEN_KEY = 'auth_token';
const API_BASE = '/api';

/**
 * 助手函数：发送带认证的 API 请求
 * @param {string} url
 * @param {string} method
 * @param {object} body
 */
async function fetchApi(url, method = 'GET', body = null) {
    const token = localStorage.getItem(TOKEN_KEY);
    const headers = {
        'Content-Type': 'application/json',
    };
    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    const config = {
        method,
        headers,
    };
    if (body) {
        config.body = JSON.stringify(body);
    }

    const response = await fetch(`${API_BASE}${url}`, config);
    return response.json();
}

// --- 界面切换 ---

function updateUI() {
    const token = localStorage.getItem(TOKEN_KEY);
    const loggedIn = !!token;

    document.getElementById('login-section').style.display = loggedIn ? 'none' : 'block';
    document.getElementById('reset-password-section').style.display = 'none'; // 确保重置界面隐藏
    document.getElementById('core-section').style.display = loggedIn ? 'block' : 'none';
    document.getElementById('logout-btn').style.display = loggedIn ? 'block' : 'none';
}

// --- 1. 登录与登出 ---

document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;
    const msgEl = document.getElementById('login-message');

    try {
        const result = await fetchApi('/login', 'POST', { username, password });
        if (result.success && result.token) {
            localStorage.setItem(TOKEN_KEY, result.token);
            msgEl.textContent = '登录成功！';
            updateUI();
        } else {
            msgEl.textContent = result.message || '登录失败。';
        }
    } catch (error) {
        msgEl.textContent = '网络错误或服务器无响应。';
    }
});

document.getElementById('logout-btn').addEventListener('click', () => {
    localStorage.removeItem(TOKEN_KEY);
    updateUI();
});

// --- 2. 音乐识别 (处理文件上传) ---

document.getElementById('identify-btn').addEventListener('click', async () => {
    const fileInput = document.getElementById('audio-file');
    const resultEl = document.getElementById('identify-result');
    const file = fileInput.files[0];

    if (!file) {
        resultEl.textContent = '请选择一个音频文件。';
        return;
    }

    resultEl.textContent = '正在上传和识别...';

    // 使用 FormData 发送文件
    const formData = new FormData();
    formData.append('audio', file);

    const token = localStorage.getItem(TOKEN_KEY);
    try {
        const response = await fetch(`${API_BASE}/identify`, {
            method: 'POST',
            // 注意：当使用 FormData 时，浏览器会自动设置 Content-Type: multipart/form-data
            headers: {
                'Authorization': `Bearer ${token}`, 
            },
            body: formData,
        });

        const result = await response.json();
        resultEl.textContent = JSON.stringify(result, null, 2);
    } catch (error) {
        resultEl.textContent = '识别过程中发生错误。';
    }
});


// --- 3. 账户管理 (绑定手机 & 修改密码) ---

// 绑定手机
document.getElementById('bind-phone-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const phone = document.getElementById('new-phone').value;
    const msgEl = document.getElementById('account-message');

    const result = await fetchApi('/user/bind-phone', 'POST', { phone });
    msgEl.textContent = result.success ? '手机号绑定成功！' : result.message;
});

// 发送修改密码验证码
document.getElementById('send-code-change-btn').addEventListener('click', async () => {
    const msgEl = document.getElementById('account-message');
    msgEl.textContent = '请求发送中...';
    
    // 实际应调用后端 API 来发送验证码到已绑定的手机号
    const result = await fetchApi('/user/send-code-for-change-password', 'POST', {}); 

    msgEl.textContent = result.success ? '验证码已发送到您绑定的手机。' : result.message;
});

// 修改密码
document.getElementById('change-password-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const oldPassword = document.getElementById('old-password').value;
    const newPassword = document.getElementById('new-password').value;
    const smsCode = document.getElementById('sms-code-change').value;
    const msgEl = document.getElementById('account-message');

    const result = await fetchApi('/user/change-password', 'POST', { oldPassword, newPassword, smsCode });
    msgEl.textContent = result.success ? '密码修改成功！请重新登录。' : result.message;
    if (result.success) {
        localStorage.removeItem(TOKEN_KEY);
        updateUI();
    }
});

// --- 4. 密码重置流程 ---

document.getElementById('forgot-password-link').addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('login-section').style.display = 'none';
    document.getElementById('reset-password-section').style.display = 'block';
});

document.getElementById('back-to-login').addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('reset-password-section').style.display = 'none';
    document.getElementById('login-section').style.display = 'block';
});

// 重置密码：请求短信验证码
document.getElementById('reset-password-request-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const phone = document.getElementById('reset-phone').value;
    const msgEl = document.getElementById('reset-message');
    
    const result = await fetchApi('/reset-password-request', 'POST', { phone });

    if (result.success) {
        msgEl.textContent = '验证码已发送。请检查手机并输入新密码。';
        document.getElementById('reset-password-request-form').style.display = 'none';
        document.getElementById('reset-password-confirm-form').style.display = 'block';
    } else {
        msgEl.textContent = result.message || '请求失败。请确认手机号已绑定。';
    }
});

// 重置密码：确认新密码
document.getElementById('reset-password-confirm-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    // 注意：需要确保后端使用缓存的手机号，或将手机号也发送过去
    const phone = document.getElementById('reset-phone').value; 
    const newPassword = document.getElementById('reset-new-password').value;
    const smsCode = document.getElementById('reset-sms-code').value;
    const msgEl = document.getElementById('reset-message');

    const result = await fetchApi('/reset-password-confirm', 'POST', { phone, newPassword, smsCode });

    if (result.success) {
        msgEl.textContent = '密码重置成功！请返回登录。';
        document.getElementById('reset-password-confirm-form').style.display = 'none';
        document.getElementById('back-to-login').style.display = 'block';
    } else {
        msgEl.textContent = result.message || '重置失败。验证码或手机号错误。';
    }
});


// 初始化：在页面加载完成后执行一次
document.addEventListener('DOMContentLoaded', updateUI);