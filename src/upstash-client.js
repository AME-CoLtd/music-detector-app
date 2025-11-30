// src/upstash-client.js
// Upstash Redis REST API 客户端封装 (包含 URL 缺失检查)

/**
 * 封装 Upstash Redis REST API 调用
 * @param {object} env Worker的环境变量 (包含 UPSTASH_REDIS_REST_URL/TOKEN)
 * @param {string} command Redis 命令 (例如: GET, HSET, EXPIRE)
 * @param {Array<string | number>} args 命令参数
 */
async function upstashExecute(env, command, ...args) {
    
    // CRITICAL CHECK: 如果 URL 变量缺失，立即抛出错误，而不是让 Node.js 抛出不明确的 TypeError
    if (!env.UPSTASH_REDIS_REST_URL) {
        console.error("CRITICAL ERROR: UPSTASH_REDIS_REST_URL is missing!");
        // 抛出明确的错误信息，便于调试
        throw new Error("Missing Upstash URL environment variable."); 
    }
    
    // 构建 REST API URL: [URL]/[COMMAND]/[ARG1]/[ARG2]/...
    const url = `${env.UPSTASH_REDIS_REST_URL}/${command}/${args.map(a => encodeURIComponent(String(a))).join('/')}`;
    
    try {
        const response = await fetch(url, {
            method: 'GET', // Upstash REST API 多数命令使用 GET
            headers: {
                Authorization: `Bearer ${env.UPSTASH_REDIS_REST_TOKEN}`,
            },
        });
        
        if (!response.ok) {
             console.error(`Upstash HTTP Error: ${response.status} ${response.statusText} for command: ${command}`);
             throw new Error(`Upstash API call failed: ${response.statusText}`);
        }
        
        const data = await response.json();
        if (data.error) {
            console.error('Upstash Redis Error:', data.error, 'for command:', command);
            throw new Error(`Upstash Redis Error: ${data.error}`);
        }
        
        return data.result; // 返回 Redis 命令的结果
        
    } catch (error) {
        // 捕获任何网络或解析错误
        console.error('Upstash API execution failed:', error);
        throw new Error(`Upstash Execution Error: ${error.message}`);
    }
}

/**
 * 导出一个 Upstash 客户端对象，用于业务逻辑调用
 * @param {object} env 环境变量 (process.env)
 */
export const Upstash = (env) => ({
    
    // --- 用户数据 (使用 Hash 存储，键 user:username) ---
    async getUser(username) {
        const result = await upstashExecute(env, 'HGETALL', `user:${username}`);
        if (!result || result.length === 0) return null;
        
        const userObj = {};
        for (let i = 0; i < result.length; i += 2) {
            userObj[result[i]] = result[i + 1];
        }
        return userObj;
    },
    
    saveUser(username, userObj) {
        const hsetArgs = Object.entries(userObj).flat(); 
        if (hsetArgs.length === 0) return Promise.resolve();
        return upstashExecute(env, 'HSET', `user:${username}`, ...hsetArgs);
    },

    // --- 会话存储 (使用 String 存储，键 session:token) ---
    setSession: (token, username, ttlSeconds = 3600) => 
        upstashExecute(env, 'SET', `session:${token}`, username, 'EX', ttlSeconds),
    
    getSession: (token) => upstashExecute(env, 'GET', `session:${token}`),

    // --- 加密配置和验证码存储 (使用 String 存储) ---

    setSecret: (key, value) => upstashExecute(env, 'SET', `secret:${key}`, value),

    getSecret: (key) => upstashExecute(env, 'GET', `secret:${key}`),
    
    setSmsCode: (phone, code, ttlSeconds = 300) => 
        upstashExecute(env, 'SET', `sms:${phone}`, code, 'EX', ttlSeconds),

    getSmsCode: (phone) => upstashExecute(env, 'GET', `sms:${phone}`),
});