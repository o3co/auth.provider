/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { createAdapterFactory } from "../adapters/AdapterFactory.mjs";
import { createInMemoryFederationTokenStore } from "./adapters/memory.mjs";
export function createFederationTokenStoreFactory() {
    return createAdapterFactory("FederationTokenStore");
}
export function registerBuiltinFederationTokenStores(factory) {
    factory.register("memory", () => {
        // eslint-disable-next-line no-console
        console.warn("federationTokenStore: in-memory adapter is for dev/test only — do not use in production (tokens are lost on restart, no cross-instance replication).");
        return createInMemoryFederationTokenStore();
    });
    factory.register("redis", async (config) => {
        const cfg = config;
        if (!cfg.client) {
            throw new Error("federationTokenStore.redis: 'client' option is required");
        }
        // Validate the client shape up-front so misconfiguration fails fast with
        // a clear error, not later at deleteBySession runtime. The adapter uses
        // get / set / del / scanIterator.
        const clientObj = cfg.client;
        const requiredMethods = ["get", "set", "del", "scanIterator"];
        const missing = requiredMethods.filter((m) => typeof clientObj[m] !== "function");
        if (missing.length > 0) {
            throw new Error(`federationTokenStore.redis: client is missing required method(s): ${missing.join(", ")}. ` +
                `Pass a 'redis' v5 client (or a mock that implements get/set/del/scanIterator).`);
        }
        // Default encryption.mode to "required" — the secure default, matching
        // spec Section 5 (production MUST encrypt). Operators who want the
        // plaintext dev mode must pass `encryption: { mode: "allow-plaintext" }`
        // explicitly; implicit omission no longer means "reject config", it
        // means "use the safe default".
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
        const { createRedisFederationTokenStore } = await import("./adapters/redis.mjs");
        return createRedisFederationTokenStore({
            client: cfg.client,
            encryption,
            keyPrefix: cfg.keyPrefix,
            ttl: cfg.ttl,
        });
    });
}
