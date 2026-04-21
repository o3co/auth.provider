/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { createAdapterFactory } from "../adapters/AdapterFactory.mjs";
import { createInMemoryFederationTokenStore } from "./adapters/memory.mjs";
import type { FederationTokenStoreBase, FederationTokenStoreFactory } from "./types.mjs";

export function createFederationTokenStoreFactory(): FederationTokenStoreFactory {
	return createAdapterFactory<FederationTokenStoreBase>("federationTokenStore");
}

export function registerBuiltinFederationTokenStores(factory: FederationTokenStoreFactory): void {
	factory.register("memory", () => {
		// eslint-disable-next-line no-console
		console.warn(
			"federationTokenStore: in-memory adapter is for dev/test only — do not use in production (tokens are lost on restart, no cross-instance replication).",
		);
		return createInMemoryFederationTokenStore();
	});
	factory.register("redis", async (config) => {
		const cfg = config as {
			client?: unknown;
			encryption?: { mode?: "required" | "allow-plaintext"; key?: Buffer | string };
			keyPrefix?: string;
			ttl?: number;
		};
		if (!cfg.client) {
			throw new Error("federationTokenStore.redis: 'client' option is required");
		}
		if (!cfg.encryption?.mode) {
			throw new Error(
				"federationTokenStore.redis: 'encryption.mode' is required ('required' or 'allow-plaintext')",
			);
		}
		let encryption: import("./adapters/redis.mjs").EncryptionConfig;
		if (cfg.encryption.mode === "required") {
			const rawKey = cfg.encryption.key;
			const keyBuf =
				typeof rawKey === "string"
					? Buffer.from(rawKey, "base64")
					: rawKey instanceof Buffer
						? rawKey
						: Buffer.alloc(0);
			if (keyBuf.length !== 32) {
				throw new Error(
					"federationTokenStore.redis: encryption.key must decode to 32 bytes (AES-256)",
				);
			}
			encryption = { mode: "required", key: keyBuf };
		} else {
			// eslint-disable-next-line no-console
			console.warn(
				"federationTokenStore.redis: running with encryption.mode = allow-plaintext. Do not use in production.",
			);
			encryption = { mode: "allow-plaintext" };
		}
		const { createRedisFederationTokenStore } = await import("./adapters/redis.mjs");
		return createRedisFederationTokenStore({
			client: cfg.client as Parameters<typeof createRedisFederationTokenStore>[0]["client"],
			encryption,
			keyPrefix: cfg.keyPrefix,
			ttl: cfg.ttl,
		});
	});
}

export type { FederationTokenStoreFactory };
