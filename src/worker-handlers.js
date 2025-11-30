// src/worker-handlers.js - Cloudflare Worker Web Crypto API 优化版

// ⚠️ 注意：Worker 环境自带 Web Crypto API，无需 import 'crypto' 或 Buffer

import { Upstash } from './upstash-client.js';

const JSON_HEADER = { 'Content-Type': 'application/json' };
const HASH_ALGO = 'SHA-256'; // Web Crypto 标准

// --- I. 安全和加密工具函数 (使用 Web Crypto API 实现) ---

// 1. 密码哈希 (PBKDF2 - Workers 标准)
async function hashPassword(password, salt) {
    const passwordBytes = new TextEncoder().encode(password);
    
    const key = await crypto.subtle.importKey(
        'raw', 
        passwordBytes, 
        { name: 'PBKDF2' }, 
        false, 
        ['deriveBits']
    );
    
    const hashBytes = await crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000, 
            hash: HASH_ALGO,
        },
        key,
        256
    );
    
    const hash = btoa(String.fromCharCode(...new Uint8Array(hashBytes)));
    return { 
        hash: hash, 
        salt: btoa(String.fromCharCode(...new Uint8Array(salt)))
    };
}

// 2. 验证密码
async function verifyPassword(password, storedHash, saltBase64) {
    const saltBytes = new Uint8Array(atob(saltBase64).split('').map(c => c.charCodeAt(0)));
    const { hash } = await hashPassword(password, saltBytes);
    return hash === storedHash;
}

// 3. AES-GCM 加密 (用于 ACR/AliSMS Secrets)
async function encryptData(data, masterKeyBase64) {
    const keyBytes = new Uint8Array(atob(masterKeyBase64).split('').map(c => c.charCodeAt(0)));
    const iv = crypto.getRandomValues(new Uint8Array(12)); 
    
    const key = await crypto.subtle.importKey(
        'raw', 
        keyBytes, 
        { name: 'AES-GCM' }, 
        false, 
        ['encrypt']
    );
    
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: iv }, 
        key, 
        new TextEncoder().encode(data)
    );
    
    const ivBase64 = btoa(String.fromCharCode(...new Uint8Array(iv)));
    const cipherBase64 = btoa(String.fromCharCode(...new Uint8Array(encrypted)));
    
    return ivBase64 + ':' + cipherBase64;
}

// 4. AES-GCM 解密
async function decryptData(encryptedData, masterKeyBase64) {
    const [ivBase64, cipherBase64] = encryptedData.split(':');
    if (!ivBase64 || !cipherBase64) throw new Error("Invalid encrypted data format.");

    const keyBytes = new Uint8Array(atob(masterKeyBase64).split('').map(c => c.charCodeAt(0)));
    const iv = new Uint8Array(atob(ivBase64).split('').map(c => c.charCodeAt(0)));
    const cipher = new Uint8Array(atob(cipherBase64).split('').map(c => c.charCodeAt(0)));
    
    const key = await crypto.subtle.importKey(
        'raw', 
        keyBytes, 
        { name: 'AES-GCM' }, 
        false, 
        ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: iv }, 
        key, 
        cipher
    );
    
    return new TextDecoder().decode(decrypted);
}


// --- II. 外部 API 调用封装 (占位) ---

async function sendAliSms(phone, code, decryptedAliSecrets) {
    console.log(`Worker Placeholder: SMS code ${code} sent to ${phone}`);
    return { success: true, message: 'Verification code sent successfully.' }; 
}

async function fetchACRCloud(audioFile, host, key, secret) {
    console.log(`Worker Placeholder: Identifying audio against ${host}`);
    return { code: 0, msg: "Success", metadata: { title: "Test Song", artist: "Test Artist" } };
}


// --- III. 核心业务处理器 ---

/**
 * 1. 初始化管理员账户和加密密钥
 */
export async function handleAdminInit(env, upstashClient) {
    const ADMIN_USER = env.DEFAULT_ADMIN_USER;
    const userExists = await upstashClient.getUser(ADMIN_USER);

    if (!userExists || !userExists.passwordHash) {
        console.log(`INIT: Creating admin user ${ADMIN_USER}`);
        const salt = crypto.getRandomValues(new Uint8Array(16)); 
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
    const body = await request.json(); 
    const { username, password } = body;
    
    console.log(`AUTH: Attempting login for ${username}`); 
    
    const user = await upstashClient.getUser(username);
    
    if (user && await verifyPassword(password, user.passwordHash, user.salt)) {
        const token = crypto.randomUUID();
        await upstashClient.setSession(token, username, 3600); 
        console.log(`AUTH: SUCCESS! Token generated.`);
        return new Response(JSON.stringify({ success: true, token, username }), { status: 200, headers: JSON_HEADER });
    }
    return new Response(JSON.stringify({ success: false, message: 'Invalid credentials' }), { status: 401, headers: JSON_HEADER });
}


/**
 * 3. 音乐版权识别
 */
export async function handleIdentify(request, env, upstashClient) {
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
}


/**
 * 4. 账户更新 (绑定手机/修改密码/发送验证码)
 */
export async function handleUserUpdate(request, env, upstashClient, type)  { // ⚠️ EXPORT 修复在这里
    const userToken = request.headers.get('Authorization')?.substring(7);
    const username = await upstashClient.getSession(userToken); 
    if (!username) return new Response(JSON.stringify({ success: false, message: 'Session expired' }), { status: 401, headers: JSON_HEADER });

    const user = await upstashClient.getUser(username);
    const body = type !== 'send_code' ? await request.json() : {}; // Worker 环境支持 request.json()

    if (type === 'phone') {
        const { phone } = body;
        await upstashClient.saveUser(username, { phone }); 
        return new Response(JSON.stringify({ success: true, message: '手机号绑定成功！' }), { status: 200, headers: JSON_HEADER });
    } 
    
    if (type === 'send_code') {
        if (!user.phone) return new Response(JSON.stringify({ success: false, message: '未绑定手机号' }), { status: 400, headers: JSON_HEADER });
        
        const code = crypto.randomUUID().substring(0,6); // 简化验证码生成
        await upstashClient.setSmsCode(user.phone, code, 300); 
        const smsResult = await sendAliSms(user.phone, code, {/* Decrypted Secrets */});
        return new Response(JSON.stringify({ success: smsResult.success, message: smsResult.message }), { status: smsResult.success ? 200 : 500, headers: JSON_HEADER });
    }

    if (type === 'password') {
        const { oldPassword, newPassword, smsCode } = body;
        const storedCode = await upstashClient.getSmsCode(user.phone);

        if (!(await verifyPassword(oldPassword, user.passwordHash, user.salt))) return new Response(JSON.stringify({ success: false, message: '原密码错误' }), { status: 401, headers: JSON_HEADER });
        if (smsCode !== storedCode) return new Response(JSON.stringify({ success: false, message: '短信验证码错误或已过期' }), { status: 400, headers: JSON_HEADER });
        
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const { hash, salt: saltBase64 } = await hashPassword(newPassword, salt);
        await upstashClient.saveUser(username, { passwordHash: hash, salt: saltBase64 });
        
        return new Response(JSON.stringify({ success: true, message: '密码修改成功' }), { status: 200, headers: JSON_HEADER });
    }
}

/**
 * 5. 密码重置
 */
export async function handlePasswordReset(request, env, upstashClient, action) { // ⚠️ EXPORT 修复在这里
    const body = await request.json();

    if (action === 'request') {
        const { phone } = body;
        const user = {/* 查找 Upstash 中的用户记录，找到匹配 phone 的用户 */}; 
        if (!user) return new Response(JSON.stringify({ success: false, message: '手机号未绑定任何账户' }), { status: 404, headers: JSON_HEADER });
        
        const code = crypto.randomUUID().substring(0,6); 
        await upstashClient.setSmsCode(phone, code, 300); 
        const smsResult = await sendAliSms(phone, code, {/* Decrypted Secrets */});

        return new Response(JSON.stringify({ success: smsResult.success, message: smsResult.message }), { status: smsResult.success ? 200 : 500, headers: JSON_HEADER });
    } 
    
    if (action === 'confirm') {
        const { phone, newPassword, smsCode } = body;
        const storedCode = await upstashClient.getSmsCode(phone);
        
        if (smsCode !== storedCode) return new Response(JSON.stringify({ success: false, message:}