/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import { decryptTokenField, encryptTokenField } from "../crypto.mjs";
import type { FederationTokenStoreBase, FederationTokens } from "../types.mjs";

export interface RedisLikeClient {
	get(key: string): Promise<string | null>;
	set(key: string, value: string, opts?: { PX?: number }): Promise<string | null>;
	del(...keys: string[]): Promise<number>;
	/**
	 * Non-blocking alternative to Redis KEYS — matches redis v5 client's
	 * `scanIterator({ MATCH, COUNT })`. Cursor-based, yields matching keys in
	 * batches without blocking the server. Required for `deleteBySession` to
	 * be safe in production.
	 */
	scanIterator(opts: { MATCH: string; COUNT?: number }): AsyncIterable<string>;
}

export type EncryptionConfig = { mode: "required"; key: Buffer } | { mode: "allow-plaintext" };

export interface RedisFederationTokenStoreOptions {
	client: RedisLikeClient;
	encryption: EncryptionConfig;
	keyPrefix?: string;
	/**
	 * Redis key TTL in seconds. This is the upper bound on how long a federation
	 * token record persists; it MUST exceed the upstream federation refresh_token
	 * lifetime so that refresh flows (F-6) can still retrieve the refresh_token
	 * after the access_token has expired.
	 *
	 * Do NOT tie this TTL to `tokens.expiresAt` (the access_token expiry) —
	 * access_token expiry is kept inside the envelope for F-6 to consult at
	 * retrieval time, but the record itself lives until this store TTL elapses.
	 *
	 * Default: 86400 seconds (24 hours). Spec Section 5.2.
	 */
	ttl?: number;
}

const DEFAULT_TTL_SECONDS = 86400;

interface Envelope {
	accessToken: string;
	refreshToken?: string;
	idToken?: string;
	expiresAtMs: number;
	tokenType?: string;
	scope?: string;
	rawParams?: Record<string, unknown>;
}

export function createRedisFederationTokenStore(
	opts: RedisFederationTokenStoreOptions,
): FederationTokenStoreBase {
	if (opts.encryption.mode === "required" && opts.encryption.key.length !== 32) {
		throw new Error("FederationTokenStore redis: encryption key must be 32 bytes");
	}
	const prefix = opts.keyPrefix ?? "ft:";
	const ttlSeconds = opts.ttl ?? DEFAULT_TTL_SECONDS;
	if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
		throw new Error("FederationTokenStore redis: ttl must be a positive finite number of seconds");
	}
	const storeTtlMs = ttlSeconds * 1000;
	const k = (sid: string, name: string) => `${prefix}${sid}:${name}`;
	const sidPattern = (sid: string) => `${prefix}${sid}:*`;

	const encryptRequired = (v: string): string =>
		opts.encryption.mode === "allow-plaintext" ? v : encryptTokenField(v, opts.encryption.key);

	const encryptOptional = (v: string | undefined): string | undefined =>
		v === undefined ? undefined : encryptRequired(v);

	const decryptRequired = (v: string): string =>
		opts.encryption.mode === "allow-plaintext" ? v : decryptTokenField(v, opts.encryption.key);

	const decryptOptional = (v: string | undefined): string | undefined =>
		v === undefined ? undefined : decryptRequired(v);

	const toEnvelope = (t: FederationTokens): Envelope => ({
		accessToken: encryptRequired(t.accessToken),
		refreshToken: encryptOptional(t.refreshToken),
		idToken: encryptOptional(t.idToken),
		expiresAtMs: t.expiresAt.getTime(),
		tokenType: t.tokenType,
		scope: t.scope,
		rawParams: t.rawParams as Record<string, unknown> | undefined,
	});

	const fromEnvelope = (e: Envelope): FederationTokens => ({
		accessToken: decryptRequired(e.accessToken),
		refreshToken: decryptOptional(e.refreshToken),
		idToken: decryptOptional(e.idToken),
		expiresAt: new Date(e.expiresAtMs),
		tokenType: e.tokenType,
		scope: e.scope,
		rawParams: e.rawParams,
	});

	const writeEnv = async (sid: string, name: string, env: Envelope) => {
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
			const v = await opts.client.get(k(sid, name));
			if (!v) return null;
			try {
				return fromEnvelope(JSON.parse(v) as Envelope);
			} catch {
				return null;
			}
		},
		async update(sid, name, tokens) {
			await writeEnv(sid, name, toEnvelope(tokens));
		},
		async deleteBySession(sid) {
			// Use SCAN (non-blocking) instead of KEYS (O(N), blocking). Each
			// batch of scanned keys is deleted before we await the next batch.
			const keysBatch: string[] = [];
			for await (const key of opts.client.scanIterator({ MATCH: sidPattern(sid), COUNT: 100 })) {
				keysBatch.push(key);
				if (keysBatch.length >= 100) {
					await opts.client.del(...keysBatch);
					keysBatch.length = 0;
				}
			}
			if (keysBatch.length > 0) await opts.client.del(...keysBatch);
		},
		async delete(sid, name) {
			await opts.client.del(k(sid, name));
		},
	};
}
