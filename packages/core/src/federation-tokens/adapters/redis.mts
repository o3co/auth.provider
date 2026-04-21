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
	keys(pattern: string): Promise<string[]>;
}

export type EncryptionConfig = { mode: "required"; key: Buffer } | { mode: "allow-plaintext" };

export interface RedisFederationTokenStoreOptions {
	client: RedisLikeClient;
	encryption: EncryptionConfig;
	keyPrefix?: string;
}

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
		const remaining = env.expiresAtMs - Date.now();
		const px = remaining > 0 ? remaining : undefined;
		await opts.client.set(
			k(sid, name),
			JSON.stringify(env),
			px !== undefined ? { PX: px } : undefined,
		);
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
			const keys = await opts.client.keys(sidPattern(sid));
			if (keys.length > 0) await opts.client.del(...keys);
		},
		async delete(sid, name) {
			await opts.client.del(k(sid, name));
		},
	};
}
