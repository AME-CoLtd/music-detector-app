// src/upstash-client.js
// Upstash Redis REST API 客户端封装

/**
 * 封装 Upstash Redis REST API 调用
 * @param {object} env Worker的环境变量 (包含 UPSTASH_REDIS_REST_URL/TOKEN)
 * @param {string} command Redis 命令 (例如: GET, HSET, EXPIRE)
 * @param {Array<string | number>} args 命令参数
 */
async function upstashExecute(env, command, ...args) {
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
             console.error(`Upstash HTTP Error: ${response.status} ${response.statusText}`);
             throw new Error(`Upstash Error: ${response.statusText}`);
        }
        
        const data = await response.json();
        if (data.error) {
            console.error('Upstash Redis Error:', data.error);
            throw new Error(`Upstash Redis Error: ${data.error}`);
        }
        
        return data.result; // 返回 Redis 命令的结果
        
    } catch (error) {
        console.error('Upstash API call failed:', error);
        return null;
    }
}

/**
 * 导出一个 Upstash 客户端对象，用于业务逻辑调用
 * @param {object} env 环境变量 (process.env)
 */
export const Upstash = (env) => ({
    
    // --- 用户数据 (使用 Hash 存储，键 user:username) ---
    
    /**
     * 从 Hash 中获取所有用户字段
     * @param {string} username 
     * @returns {Promise<object | null>} { field1: value1, field2: value2, ... }
     */
    async getUser(username) {
        // HGETALL 返回一个数组 [key1, value1, key2, value2, ...]
        const result = await upstashExecute(env, 'HGETALL', `user:${username}`);
        if (!result || result.length === 0) return null;
        
        // 将数组转换为对象
        const userObj = {};
        for (let i = 0; i < result.length; i += 2) {
            userObj[result[i]] = result[i + 1];
        }
        return userObj;
    },
    
    /**
     * 将用户字段批量保存到 Hash
     * @param {string} username 
     * @param {object} userObj { field: value, ... }
     */
    saveUser(username, userObj) {
        const hsetArgs = Object.entries(userObj).flat(); // 展平为 [key1, value1, key2, value2, ...]
        if (hsetArgs.length === 0) return Promise.resolve();
        return upstashExecute(env, 'HSET', `user:${username}`, ...hsetArgs);
    },

    // --- 会话存储 (使用 String 存储，键 session:token) ---
    
    /**
     * 存储 Session Token，带过期时间
     * @param {string} token 
     * @param {string} username 
     * @param {number} ttlSeconds 
     */
    setSession: (token, username, ttlSeconds = 3600) => 
        upstashExecute(env, 'SET', `session:${token}`, username, 'EX', ttlSeconds),
    
    /**
     * 获取 Session Token 对应的值 (username)
     * @param {string} token 
     */
    getSession: (token) => upstashExecute(env, 'GET', `session:${token}`),

    // --- 加密配置和验证码存储 (使用 String 存储) ---

    /**
     * 存储加密后的 API 密钥
     */
    setSecret: (key, value) => upstashExecute(env, 'SET', `secret:${key}`, value),

    /**
     * 获取加密后的 API 密钥
     */
    getSecret: (key) => upstashExecute(env, 'GET', `secret:${key}`),
    
    /**
     * 短信验证码存储 (键 sms:phone，带过期时间)
     */
    setSmsCode: (phone, code, ttlSeconds = 300) => 
        upstashExecute(env, 'SET', `sms:${phone}`, code, 'EX', ttlSeconds),

    /**
     * 获取短信验证码
     */
    getSmsCode: (phone) => upstashExecute(env, 'GET', `sms:${phone}`),
});