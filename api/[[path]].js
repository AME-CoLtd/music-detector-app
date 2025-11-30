// api/[[path]].js

// 注意：已移除 export const config，改为 Node.js 默认识别

import { Upstash } from '../src/upstash-client.js';
import {
  handleAuth,
  handleAdminInit,
  handlePasswordReset,
  handleUserUpdate,
  handleIdentify,
} from '../src/worker-handlers.js'; 

const APP_JSON = 'application/json';

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
 */
export default async function (request) {
    const url = new URL(request.url);
    const path = url.pathname;
    
    const env = process.env;
    const upstashClient = Upstash(env); 

    // 1. 初始化管理员账户和加密密钥 
    try {
        await handleAdminInit(env, upstashClient); 
    } catch (e) {
        console.error("Initialization Failed:", e.message);
        // 如果初始化失败，说明密钥或Upstash连接有问题，返回服务器错误
        return jsonResponse({ success: false, message: 'Server initialization failed' }, 500);
    }

    // 2. 认证检查
    const authHeader = request.headers.get('Authorization');
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