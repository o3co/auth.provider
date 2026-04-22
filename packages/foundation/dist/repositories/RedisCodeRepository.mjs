/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import crypto from "node:crypto";
const KEY_PREFIX = "oauth:code:";
export class RedisCodeRepository {
    redis;
    defaultExpiresIn;
    constructor(redis, defaultExpiresIn = 600) {
        this.redis = redis;
        this.defaultExpiresIn = defaultExpiresIn;
    }
    static async create(config, pathResolver) {
        if (typeof config.endpointUri !== "string") {
            throw new Error('RedisCodeRepository requires "endpointUri" in config');
        }
        const { createClient } = pathResolver
            ? (await import(pathResolver("redis")))
            : await import("redis");
        const redis = createClient({
            url: config.endpointUri,
            password: typeof config.password === "string" ? config.password : undefined,
            socket: {
                reconnectStrategy: (retries) => {
                    const jitter = Math.floor(Math.random() * 200);
                    const delay = Math.min(2 ** retries * 50, 2000);
                    return delay + jitter;
                },
            },
        });
        const defaultExpiresIn = typeof config.defaultExpiresIn === "number" ? config.defaultExpiresIn : undefined;
        const repo = new RedisCodeRepository(redis, defaultExpiresIn);
        await repo.initialize();
        return repo;
    }
    async initialize() {
        await this.redis.connect();
    }
    async createCode({ code_challenge, code_challenge_method, expiresIn = this.defaultExpiresIn, }) {
        const code = crypto.randomBytes(32).toString("base64url");
        await this.redis.set(KEY_PREFIX + code, JSON.stringify({ code_challenge, code_challenge_method }), { EX: expiresIn });
        return { code, code_challenge, code_challenge_method, expiresIn };
    }
    async getByCode(code) {
        const value = await this.redis.get(KEY_PREFIX + code);
        return this.parseCodeValue(code, value);
    }
    async consumeByCode(code) {
        const value = await this.redis.getDel(KEY_PREFIX + code);
        return this.parseCodeValue(code, value);
    }
    async removeByCode(code) {
        await this.redis.del(KEY_PREFIX + code);
    }
    parseCodeValue(code, value) {
        if (!value)
            return null;
        try {
            return { ...JSON.parse(value), code };
        }
        catch (err) {
            const codeHash = crypto.createHash("sha256").update(code).digest("hex").slice(0, 16);
            console.error(`RedisCodeRepository: corrupted data for code (hash=${codeHash})`, err);
            return null;
        }
    }
}
