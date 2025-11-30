// music-detector/src/worker-handlers.js
// 包含详细日志和错误捕获，用于诊断最终崩溃点。

import crypto from 'crypto'; // 引入 Node.js 内置 crypto 模块
import { Upstash } from './upstash-client.js';

const JSON_HEADER = { 'Content-Type': 'application/json' };

// --- I. 安全和加密工具函数 (使用 Node.js Crypto 实现) ---

const HASH_ALGO = 'sha256';

// 1. 密码哈希
async function hashPassword(password, salt) {
    const saltString = salt instanceof Buffer ? salt.toString('base64') : salt;
    const saltBuffer = Buffer.from(saltString, 'base64');
    
    const hash = crypto.createHash(HASH_ALGO).update(password).update(saltBuffer).digest('base64');
    return { 
        hash: hash, 
        salt: saltBuffer.toString('base64') 
    };
}

// 2. 验证密码
async function verifyPassword(password, storedHash, saltBase64) {
    const saltBuffer = Buffer.from(saltBase64, 'base64');
    const expectedHash = crypto.createHash(HASH_ALGO).update(password).update(saltBuffer).digest('base64');
    return expectedHash === storedHash;
}

// 3. 简化 Base64 加密
async function encryptData(data, masterKeyBase64) {
    return Buffer.from(data).toString('base64');
}

// 4. 简化 Base64 解密
async function decryptData(encryptedData, masterKeyBase64) {
    return Buffer.from(encryptedData, 'base64').toString('utf8');
}


// --- II. 外部 API 调用封装 (占位) ---

// 5. 阿里云短信服务调用 (占位)
async function sendAliSms(phone, code, decryptedAliSecrets) {
    console.log(`Placeholder: SMS code ${code} sent to ${phone}`);
    return { success: true, message: 'Verification code sent successfully.' }; 
}

// 6. ACRCloud API 调用 (占位)
async function fetchACRCloud(audioFile, host, key, secret) {
    return { code: 0, msg: "Success", metadata: { title: "Test Song", artist: "Test Artist" } };
}


// --- III. 核心业务处理器 ---

/**
 * 1. 初始化管理员账户和加密密钥
 */
export async function handleAdminInit(env, upstashClient) {
    const ADMIN_USER = env.DEFAULT_ADMIN_USER;
    const userExists = await upstashClient.getUser(ADMIN_USER);

    // 初始化用户
    if (!userExists || !userExists.passwordHash) {
        console.log(`INIT: Creating admin user ${ADMIN_USER}`);
        const salt = crypto.randomBytes(16);
        const { hash, salt: saltBase64 } = await hashPassword(env.DEFAULT_ADMIN_PASS, salt); 
        
        await upstashClient.saveUser(ADMIN_USER, {
            username: ADMIN_USER,
            passwordHash: hash,
            salt: saltBase64, 
            phone: '', 
        });
    } else {
        console.log(`INIT: Admin user ${ADMIN_USER} already exists.`);
    }

    // 初始化加密 Secrets (仅当 Upstash 中不存在时)
    const encryptedKeyExists = await upstashClient.getSecret('acr_key');
    if (!encryptedKeyExists) { 
        console.log("INIT: Encrypting and saving API secrets.");
        const masterKey = env.MASTER_ENCRYPTION_KEY;
        await upstashClient.setSecret('acr_host', env.ACR_HOST); 
        await upstashClient.setSecret('acr_key', await encryptData(env.ACR_KEY, masterKey));
        await upstashClient.setSecret('acr_secret', await encryptData(env.ACR_SECRET, masterKey));
    } else {
        console.log("INIT: API secrets already exist.");
    }
}


/**
 * 2. 登录认证
 */
export async function handleAuth(request, env, upstashClient) {
    try {
        const body = await request.json();
        const { username, password } = body;
        
        console.log(`AUTH: Attempting login for ${username}`); // <-- 日志 1
        
        const user = await upstashClient.getUser(username);
        
        if (!user) {
            console.log(`AUTH: User ${username} not found.`); // <-- 日志 2
            return new Response(JSON.stringify({ success: false, message: 'Invalid credentials' }), { status: 401, headers: JSON_HEADER });
        }
        
        console.log(`AUTH: User found. Starting password verification.`); // <-- 日志 3
        
        if (await verifyPassword(password, user.passwordHash, user.salt)) {
            const token = crypto.randomUUID();
            await upstashClient.setSession(token, username, 3600); 
            console.log(`AUTH: SUCCESS! Token generated.`);
            return new Response(JSON.stringify({ success: true, token, username }), { status: 200, headers: JSON_HEADER });
        } else {
            console.log(`AUTH: Password mismatch.`); // <-- 日志 4
            return new Response(JSON.stringify({ success: false, message: 'Invalid credentials' }), { status: 401, headers: JSON_HEADER });
        }
    } catch (e) {
        // 捕获所有崩溃
        console.error("AUTH FATAL CRASH:", e.stack); // <-- 日志 5 (最终崩溃点及堆栈)
        return new Response(JSON.stringify({ success: false, message: `Server internal error during authentication: ${e.message}` }), { status: 500, headers: JSON_HEADER });
    }
}


/**
 * 3. 音乐版权识别 (代码不变)
 */
export async function handleIdentify(request, env, upstashClient) {
    try {
        const formData = await request.formData();
        const audioFile = formData.get('audio');
        if (!audioFile) {
            return new Response(JSON.stringify({ success: false, message: 'No audio file provided' }), { status: 400, headers: JSON_HEADER });
        }

        const masterKey = env.MASTER_ENCRYPTION_KEY;
        const host = await upstashClient.getSecret('acr_host');
        const decryptedKey = await decryptData(await upstashClient.getSecret('acr_key'), masterKey);
        const decryptedSecret = await decryptData(await upstashClient.getSecret('acr_secret'), masterKey);
        
        const acrResult = await fetchACRCloud(audioFile, host, decryptedKey, decryptedSecret);

        if (acrResult.code === 0) {
            return new Response(JSON.stringify({ success: true, result: acrResult }), { headers: JSON_HEADER });
        } else {
            return new Response(JSON.stringify({ success: false, message: acrResult.msg || 'ACRCloud identification failed' }), { status: 500, headers: JSON_HEADER });
        }
        
    } catch (error) {
        console.error('Identification error:', error);
        return new Response(JSON.stringify({ success: false, message: 'Identification failed: ' + error.message }), { status: 500, headers: JSON_HEADER });
    }
}


/**
 * 4. 账户更新 (代码不变)
 */
export async function handleUserUpdate(request, env, upstashClient, type) {
    const userToken = request.headers.get('Authorization')?.substring(7);
    const username = await upstashClient.getSession(userToken); 
    if (!username) return new Response(JSON.stringify({ success: false, message: 'Session expired' }), { status: 401, headers: JSON_HEADER });

    const user = await upstashClient.getUser(username);
    const body = type !== 'send_code' ? await request.json() : {};

    if (type === 'phone') {
        const { phone } = body;
        await upstashClient.saveUser(username, { phone }); 
        return new Response(JSON.stringify({ success: true, message: '手机号绑定成功！' }), { status: 200, headers: JSON_HEADER });
    } 
    
    if (type === 'send_code') {
        if (!user.phone) return new Response(JSON.stringify({ success: false, message: '未绑定手机号' }), { status: 400, headers: JSON_HEADER });
        
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        await upstashClient.setSmsCode(user.phone, code, 300); 
        const smsResult = await sendAliSms(user.phone, code, {/* Decrypted Secrets */});
        return new Response(JSON.stringify({ success: smsResult.success, message: smsResult.message }), { status: smsResult.success ? 200 : 500, headers: JSON_HEADER });
    }

    if (type === 'password') {
        const { oldPassword, newPassword, smsCode } = body;
        const storedCode = await upstashClient.getSmsCode(user.phone);

        if (!(await verifyPassword(oldPassword, user.passwordHash, user.salt))) return new Response(JSON.stringify({ success: false, message: '原密码错误' }), { status: 401, headers: JSON_HEADER });
        if (smsCode !== storedCode) return new Response(JSON.stringify({ success: false, message: '短信验证码错误或已过期' }), { status: 400, headers: JSON_HEADER });
        
        const salt = crypto.randomBytes(16);
        const { hash, salt: saltBase64 } = await hashPassword(newPassword, salt);
        await upstashClient.saveUser(username, { passwordHash: hash, salt: saltBase64 });
        
        return new Response(JSON.stringify({ success: true, message: '密码修改成功' }), { status: 200, headers: JSON_HEADER });
    }
}

/**
 * 5. 密码重置 (代码不变)
 */
export async function handlePasswordReset(request, env, upstashClient, action) {
    const body = await request.json();

    if (action === 'request') {
        const { phone } = body;
        const user = {/* 查找 Upstash 中的用户记录，找到匹配 phone 的用户 */}; 
        if (!user) return new Response(JSON.stringify({ success: false, message: '手机号未绑定任何账户' }), { status: 404, headers: JSON_HEADER });
        
        const code = Math.floor(100000 + Math.random() * 900000).toString();
        await upstashClient.setSmsCode(phone, code, 300); 
        const smsResult = await sendAliSms(phone, code, {/* Decrypted Secrets */});

        return new Response(JSON.stringify({ success: smsResult.success, message: smsResult.message }), { status: smsResult.success ? 200 : 500, headers: JSON_HEADER });
    } 
    
    if (action === 'confirm') {
        const { phone, newPassword, smsCode } = body;
        const storedCode = await upstashClient.getSmsCode(phone);
        
        if (smsCode !== storedCode) return new Response(JSON.stringify({ success: false, message: '验证码错误或已过期' }), { status: 400, headers: JSON_HEADER });
        
        const user = {/* 再次查找用户 */};
        const salt = crypto.randomBytes(16);
        const { hash, salt: saltBase64 } = await hashPassword(newPassword, salt);
        await upstashClient.saveUser(user.username, { passwordHash: hash, salt: saltBase64 });
        
        return new Response(JSON.stringify({ success: true, message: '密码重置成功' }), { status: 200, headers: JSON_HEADER });
    }
}