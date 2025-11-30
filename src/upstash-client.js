// src/upstash-client.js - 最终修复版本

/**
 * 封装 Upstash Redis REST API 调用 (强制使用 POST /pipeline)
 * @param {object} env Worker的环境变量 (包含 UPSTASH_REDIS_REST_URL/TOKEN)
 * @param {string} command Redis 命令 (例如: GET, HSET, EXPIRE)
 * @param {Array<string | number>} args 命令参数
 */
async function upstashExecute(env, command, ...args) {
    
    if (!env.UPSTASH_REDIS_REST_URL) {
        console.error("CRITICAL ERROR: UPSTASH_REDIS_REST_URL is missing!");
        throw new Error("Missing Upstash URL environment variable."); 
    }
    
    // 强制使用 Upstash 的 /pipeline endpoint 来发送命令
    const url = `${env.UPSTASH_REDIS_REST_URL}/pipeline`;
    
    // 构造 JSON 格式的命令数组: [["COMMAND", "ARG1", "ARG2"]]
    const body = JSON.stringify([
        [command, ...args]
    ]);
    
    try {
        const response = await fetch(url, {
            method: 'POST', // 必须是 POST 方法
            headers: {
                'Authorization': `Bearer ${env.UPSTASH_REDIS_REST_TOKEN}`,
                'Content-Type': 'application/json', // 必须设置内容类型
            },
            body: body, 
        });
        
        if (!response.ok) {
             console.error(`Upstash HTTP Error: ${response.status} ${response.statusText} for command: ${command}`);
             throw new Error(`Upstash API call failed: ${response.statusText}`);
        }
        
        const data = await response.json();
        
        // 管道模式返回的是一个数组，我们只取第一个结果
        const result = data[0]; 
        
        if (result.error) {
            console.error('Upstash Redis Error:', result.error, 'for command:', command);
            throw new Error(`Upstash Redis Error: ${result.error}`);
        }
        
        return result.result; // 返回 Redis 命令的结果
        
    } catch (error) {
        console.error('Upstash API execution failed:', error);
        throw new Error(`Upstash Execution Error: ${error.message}`);
    }
}

/**
 * 导出一个 Upstash 客户端对象，用于业务逻辑调用
 * @param {object} env 环境变量 (process.env)
 */
export const Upstash = (env) => ({
    
    // --- 用户数据 (使用 Hash 存储) ---
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

    // --- 会话存储/Secrets (使用 String 存储) ---
    setSession: (token, username, ttlSeconds = 3600) => 
        upstashExecute(env, 'SET', `session:${token}`, username, 'EX', ttlSeconds),
    
    getSession: (token) => upstashExecute(env, 'GET', `session:${token}`),

    setSecret: (key, value) => upstashExecute(env, 'SET', `secret:${key}`, value),

    getSecret: (key) => upstashExecute(env, 'GET', `secret:${key}`),
    
    setSmsCode: (phone, code, ttlSeconds = 300) => 
        upstashExecute(env, 'SET', `sms:${phone}`, code, 'EX', ttlSeconds),

    getSmsCode: (phone) => upstashExecute(env, 'GET', `sms:${phone}`),
});