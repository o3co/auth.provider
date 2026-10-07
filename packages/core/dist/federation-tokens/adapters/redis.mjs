/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { decryptTokenField, encryptTokenField } from "../crypto.mjs";
import { createRedisLock } from "../lock/redis.mjs";
const DEFAULT_TTL_SECONDS = 86400;
export function createRedisFederationTokenStore(opts) {
    if (opts.encryption.mode === "required" && opts.encryption.key.length !== 32) {
        throw new Error("FederationTokenStore redis: encryption key must be 32 bytes");
    }
    const prefix = opts.keyPrefix ?? "ft:";
    const ttlSeconds = opts.ttl ?? DEFAULT_TTL_SECONDS;
    if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
        throw new Error("FederationTokenStore redis: ttl must be a positive finite number of seconds");
    }
    const storeTtlMs = ttlSeconds * 1000;
    const k = (sid, name) => `${prefix}${sid}:${name}`;
    // Advisory lock: uses a separate key namespace (lock:) so lock keys never
    // collide with token envelope keys. The lock client shim bridges the
    // variadic del(...keys) of RedisLikeClient to the single-key del(key) that
    // RedisLockClient requires.
    const lockKeyPrefix = `${prefix}lock:`;
    const lock = createRedisLock({
        client: {
            get: (key) => opts.client.get(key),
            set: (key, value, o) => opts.client.set(key, value, o),
            del: (key) => opts.client.del(key),
        },
        keyPrefix: lockKeyPrefix,
    });
    const sidPattern = (sid) => `${prefix}${sid}:*`;
    const encryptRequired = (v) => opts.encryption.mode === "allow-plaintext" ? v : encryptTokenField(v, opts.encryption.key);
    const encryptOptional = (v) => v === undefined ? undefined : encryptRequired(v);
    const decryptRequired = (v) => opts.encryption.mode === "allow-plaintext" ? v : decryptTokenField(v, opts.encryption.key);
    const decryptOptional = (v) => v === undefined ? undefined : decryptRequired(v);
    const toEnvelope = (t) => ({
        accessToken: encryptRequired(t.accessToken),
        refreshToken: encryptOptional(t.refreshToken),
        idToken: encryptOptional(t.idToken),
        expiresAtMs: t.expiresAt === null ? null : t.expiresAt.getTime(),
        tokenType: t.tokenType,
        scope: t.scope,
        rawParams: t.rawParams,
    });
    const fromEnvelope = (e) => ({
        accessToken: decryptRequired(e.accessToken),
        refreshToken: decryptOptional(e.refreshToken),
        idToken: decryptOptional(e.idToken),
        expiresAt: e.expiresAtMs === null ? null : new Date(e.expiresAtMs),
        tokenType: e.tokenType,
        scope: e.scope,
        rawParams: e.rawParams,
    });
    const writeEnv = async (sid, name, env) => {
        // Redis TTL is the store lifetime (session upper bound), NOT the access
        // token's expiresAt. The access token's expiry is preserved inside the
        // envelope so F-6 consumers can decide to refresh; the record itself
        // must outlive the access_token so the refresh_token remains available.
        await opts.client.set(k(sid, name), JSON.stringify(env), { PX: storeTtlMs });
    };
    return {
        kind: "redis",
        async attach(sid, name, tokens) {
            await writeEnv(sid, name, toEnvelope(tokens));
        },
        async get(sid, name) {
            const key = k(sid, name);
            const v = await opts.client.get(key);
            if (!v)
                return null;
            try {
                return fromEnvelope(JSON.parse(v));
            }
            catch {
                // Corrupt JSON or decrypt failure (e.g. rotated encryption key):
                // self-heal by deleting the key, mirroring UserSessionStore redis
                // adapter. Otherwise operators see repeated silent failures and
                // key/crypto mismatches surface as "missing tokens" — hard to
                // debug. Returning null after delete signals re_authentication.
                await opts.client.del(key);
                return null;
            }
        },
        async update(sid, name, tokens) {
            await writeEnv(sid, name, toEnvelope(tokens));
        },
        async deleteBySession(sid) {
            // Use SCAN (non-blocking) instead of KEYS (O(N), blocking). Each
            // batch of scanned keys is deleted before we await the next batch.
            const keysBatch = [];
            for await (const key of opts.client.scanIterator({ MATCH: sidPattern(sid), COUNT: 100 })) {
                keysBatch.push(key);
                if (keysBatch.length >= 100) {
                    await opts.client.del(...keysBatch);
                    keysBatch.length = 0;
                }
            }
            if (keysBatch.length > 0)
                await opts.client.del(...keysBatch);
        },
        async delete(sid, name) {
            await opts.client.del(k(sid, name));
        },
        acquireLock(a) {
            return lock.acquireLock(a);
        },
    };
}
