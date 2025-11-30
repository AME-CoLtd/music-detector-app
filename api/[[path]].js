// api/[[path]].js - 最终修复版本

import { Upstash } from '../src/upstash-client.js';
import {
  handleAuth,
  handleAdminInit,
  handlePasswordReset,
  handleUserUpdate,
  handleIdentify,
} from '../src/worker-handlers.js'; 

const APP_JSON = 'application/json';

// --- 请求头兼容层 ---
function getHeader(request, headerName) {
    // 检查是否是 WHATWG Request 对象
    if (request.headers && typeof request.headers.get === 'function') {
        return request.headers.get(headerName);
    }
    // 否则，假定是 Node.js http 兼容对象，使用小写键
    if (request.headers && typeof request.headers[headerName.toLowerCase()] !== 'undefined') {
        return request.headers[headerName.toLowerCase()];
    }
    return null;
}
// --- ---------------- ---


const jsonResponse = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': APP_JSON, 'Access-Control-Allow-Origin': '*' },
  });

/**
 * 认证函数 (检查 Upstash 中的 Session Token)
 */
async function authenticateToken(token, upstashClient) {
    if (!token) return false;
    const username = await upstashClient.getSession(token); 
    return !!username;
}


/**
 * Vercel Serverless Function 处理程序
 * @param {Request} request
 */
export default async function (request) {
    
    // ⚠️ 修复：使用 getHeader 函数获取 host 和 Authorization
    const host = getHeader(request, 'Host');
    
    // 构建完整的 URL 对象
    const fullUrl = new URL(request.url, `https://${host}`);
    const path = fullUrl.pathname;
    
    const env = process.env;
    const upstashClient = Upstash(env); 

    // 1. 初始化管理员账户和加密密钥 
    try {
        await handleAdminInit(env, upstashClient); 
    } catch (e) {
        console.error("Initialization Failed:", e.message);
        return jsonResponse({ success: false, message: `Server initialization failed: ${e.message}` }, 500);
    }

    // 2. 认证检查
    const authHeader = getHeader(request, 'Authorization'); // 使用兼容函数
    const token = authHeader?.startsWith('Bearer ') ? authHeader.substring(7) : null;
    let isAuthenticated = false;

    if (!['/api/login', '/api/reset-password-request', '/api/reset-password-confirm', '/api/user/send-code-for-change-password'].includes(path)) {
      isAuthenticated = await authenticateToken(token, upstashClient);
      if (!isAuthenticated) {
        return jsonResponse({ success: false, message: 'Unauthorized' }, 401);
      }
    }
    
    // 3. 路由处理
    switch (path) {
        case '/api/login':
            return handleAuth(request, env, upstashClient);

        case '/api/identify':
            return handleIdentify(request, env, upstashClient); 

        case '/api/user/bind-phone':
            return handleUserUpdate(request, env, upstashClient, 'phone'); 

        case '/api/user/change-password':
            return handleUserUpdate(request, env, upstashClient, 'password'); 
            
        case '/api/user/send-code-for-change-password':
            return handleUserUpdate(request, env, upstashClient, 'send_code'); 

        case '/api/reset-password-request':
            return handlePasswordReset(request, env, upstashClient, 'request'); 

        case '/api/reset-password-confirm':
            return handlePasswordReset(request, env, upstashClient, 'confirm'); 

        default:
            return jsonResponse({ success: false, message: 'API Not Found' }, 404);
    }
}