/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { defineModule, } from "@o3co/auth-provider-core";
import { z } from "zod";
import { decryptTokenField, encryptTokenField } from "./internal/crypto.mjs";
import { createRedisLock } from "./internal/lock.mjs";
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
    // collide with token envelope keys. The lock client shim bridges from
    // FederationTokenStoreClient's positional set form to the options-object
    // form that RedisLockClient requires (internal to this package).
    const lockKeyPrefix = `${prefix}lock:`;
    const lock = createRedisLock({
        client: {
            get: (key) => opts.client.get(key),
            set: (key, value, o) => {
                // RedisLockClient uses options-object form; bridge to positional form.
                if (o?.NX && o.PX !== undefined) {
                    return opts.client.set(key, value, "PX", o.PX, "NX");
                }
                if (o?.PX !== undefined) {
                    return opts.client.set(key, value, "PX", o.PX);
                }
                return Promise.resolve(null);
            },
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
        await opts.client.set(k(sid, name), JSON.stringify(env), "PX", storeTtlMs);
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
/**
 * AdapterFactory builder. Consumer wires:
 *   factory.register("redis", redisFederationTokenStoreBuilder);
 *
 * `config` shape:
 *   { client: FederationTokenStoreClient,
 *     encryption: EncryptionConfig | { mode?: "required" | "allow-plaintext", key?: Buffer | string },
 *     keyPrefix?: string,
 *     ttl?: number }
 *
 * Encryption defaults: mode = "required", key MUST be 32-byte (raw Buffer or
 * base64 string). `mode = "allow-plaintext"` emits a startup warning and is
 * intended for dev/test only (per spec §5).
 */
export const redisFederationTokenStoreBuilder = (config, _ctx) => {
    const cfg = config;
    if (!cfg.client) {
        throw new Error("federationTokenStore.redis: 'client' option is required");
    }
    const clientObj = cfg.client;
    const requiredMethods = ["get", "set", "del", "scanIterator"];
    const missing = requiredMethods.filter((m) => typeof clientObj[m] !== "function");
    if (missing.length > 0) {
        throw new Error(`federationTokenStore.redis: client is missing required method(s): ${missing.join(", ")}. ` +
            `Pass a wrapper that implements get/set/del/scanIterator (e.g. makeIoredisClients(io).federationTokenStoreClient).`);
    }
    const mode = cfg.encryption?.mode ?? "required";
    let encryption;
    if (mode === "required") {
        const rawKey = cfg.encryption?.key;
        const keyBuf = typeof rawKey === "string"
            ? Buffer.from(rawKey, "base64")
            : rawKey instanceof Buffer
                ? rawKey
                : Buffer.alloc(0);
        if (keyBuf.length !== 32) {
            throw new Error("federationTokenStore.redis: encryption.key must decode to 32 bytes (AES-256) when encryption.mode is 'required' (the default)");
        }
        encryption = { mode: "required", key: keyBuf };
    }
    else {
        // eslint-disable-next-line no-console
        console.warn("federationTokenStore.redis: running with encryption.mode = allow-plaintext. Do not use in production.");
        encryption = { mode: "allow-plaintext" };
    }
    return createRedisFederationTokenStore({
        client: cfg.client,
        encryption,
        keyPrefix: cfg.keyPrefix,
        ttl: cfg.ttl,
    });
};
/**
 * `defineModule` manifest for the redis FederationTokenStore. Static
 * composition path; for runtime-config-driven backend selection use the
 * builder above with the AdapterFactory pattern.
 *
 * configSchema: top-level key `redisFederationTokenStore` (module-namespaced
 * per master roadmap §3.5).
 *
 * `requires`: needs `federationTokenStoreClient` (per-purpose slot declared
 * in `@o3co/auth-provider-core`'s `federation-tokens/types.mts`) and
 * `config`. Encryption key is read from
 * `redisFederationTokenStore.encryptionKey` (base64 string) — operators set
 * it via env var `REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_KEY`.
 */
export const redisFederationTokenStoreModule = defineModule({
    name: "redis-federation-token-store",
    requires: ["federationTokenStoreClient", "config"],
    configSchema: z.object({
        redisFederationTokenStore: z
            .object({
            keyPrefix: z.string().default("ft:"),
            ttl: z.number().positive().default(86400),
            encryptionMode: z.enum(["required", "allow-plaintext"]).default("required"),
            encryptionKey: z.string().optional(),
        })
            .default({ keyPrefix: "ft:", ttl: 86400, encryptionMode: "required" }),
    }),
    provides: {
        federationTokenStore: (deps) => {
            const cfg = deps.config.redisFederationTokenStore;
            return redisFederationTokenStoreBuilder({
                client: deps.federationTokenStoreClient,
                encryption: { mode: cfg.encryptionMode, key: cfg.encryptionKey },
                keyPrefix: cfg.keyPrefix,
                ttl: cfg.ttl,
            }, {});
        },
    },
});
