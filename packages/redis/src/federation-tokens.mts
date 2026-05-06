/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

import {
	type AdapterBuilder,
	defineModule,
	type FederationTokenStoreBase,
	type FederationTokens,
	type SupportsLock,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import type { FederationTokenStoreClient } from "./clients.mjs";
import { decryptTokenField, encryptTokenField } from "./internal/crypto.mjs";
import { createRedisLock } from "./internal/lock.mjs";

export type EncryptionConfig = { mode: "required"; key: Buffer } | { mode: "allow-plaintext" };

/**
 * NODE_ENV values treated as production for the purpose of OR-12's hard guard
 * on `allow-plaintext` encryption mode. Federation tokens carry long-lived IdP
 * refresh tokens; storing them unencrypted in production is a security risk.
 */
const PRODUCTION_ENVS = new Set(["production", "staging"]);

/**
 * OR-12 — refuse to construct a federation-token store with
 * `mode = "allow-plaintext"` in production unless the operator explicitly
 * sets `FEDERATION_TOKENS_ALLOW_INSECURE=1`. Logs a CRITICAL warning when the
 * escape hatch is active. Dev/test (`NODE_ENV !== production|staging`) emits
 * a soft `console.warn` but does not throw.
 *
 * Runs at factory time before the DI container is fully wired, so direct
 * `console.*` is the appropriate emission channel (no Logger available yet).
 */
function validateEncryptionMode(mode: "required" | "allow-plaintext", nodeEnv: string): void {
	if (mode === "required") return;
	const isProduction = PRODUCTION_ENVS.has(nodeEnv);
	const allowInsecure = process.env.FEDERATION_TOKENS_ALLOW_INSECURE === "1";

	if (isProduction) {
		if (allowInsecure) {
			// Factory-time emission, no Logger available yet.
			console.error(
				`[federation-tokens] CRITICAL: running with mode="${mode}" in NODE_ENV="${nodeEnv}" ` +
					"because FEDERATION_TOKENS_ALLOW_INSECURE=1. Federation tokens (IdP refresh tokens) " +
					"are stored UNENCRYPTED. This is a security risk. Do NOT use in normal production.",
			);
			return;
		}
		throw new Error(
			`[federation-tokens] mode "${mode}" is not allowed in NODE_ENV="${nodeEnv}". ` +
				'Set mode to "required" and provide a 32-byte encryption key, OR set ' +
				"FEDERATION_TOKENS_ALLOW_INSECURE=1 to override (NOT recommended for production).",
		);
	}

	// Dev/test: warn but do not throw. Factory-time emission, no Logger available yet.
	console.warn(
		`[federation-tokens] WARNING: mode="${mode}" stores federation tokens (IdP refresh tokens) ` +
			"unencrypted. Use only in development/test environments.",
	);
}

export interface RedisFederationTokenStoreOptions {
	client: FederationTokenStoreClient;
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
	/**
	 * `number` = absolute epoch-ms of access token expiry. `null` = upstream provider
	 * issued no finite expiry (e.g. GitHub OAuth Apps classic). Stored as explicit
	 * `null` (JSON-round-trippable) so F-6 refresh logic can distinguish "no expiry"
	 * from "unknown / missing field" on future schema migrations.
	 */
	expiresAtMs: number | null;
	tokenType?: string;
	scope?: string;
	rawParams?: Record<string, unknown>;
}

export function createRedisFederationTokenStore(
	opts: RedisFederationTokenStoreOptions,
): FederationTokenStoreBase & SupportsLock {
	// OR-12: hard production guard MUST run before any encryption-key parsing
	// so the same gate fires regardless of which entry point a consumer picks.
	// `redisFederationTokenStoreBuilder` does its own pre-construction
	// validation; this guard closes the gap when consumers call this lower-
	// level factory directly (the OR-12 spec's M2 calibration delta).
	validateEncryptionMode(opts.encryption.mode, process.env.NODE_ENV ?? "development");
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

	// Advisory lock: uses a separate key namespace (lock:) so lock keys never
	// collide with token envelope keys. The lock client shim bridges from
	// FederationTokenStoreClient's positional set form to the options-object
	// form that RedisLockClient requires (internal to this package).
	const lockKeyPrefix = `${prefix}lock:`;
	const lock = createRedisLock({
		client: {
			set: (key, value, o) => {
				// RedisLockClient uses options-object form; bridge to positional form.
				if (o?.NX && o.PX !== undefined) {
					return opts.client.set(key, value, "PX", o.PX, "NX") as Promise<string | null>;
				}
				if (o?.PX !== undefined) {
					return opts.client.set(key, value, "PX", o.PX) as Promise<string | null>;
				}
				// CR-5 fix: unknown option shape is a programming error, not a silent
				// no-op. The pre-D-9 silent `Promise.resolve(null)` fallback caused
				// the lock acquire loop to spin until timeout when the bridge was
				// passed a non-standard option shape.
				throw new Error(
					"FederationTokenStore lock bridge: unrecognized set() option shape. " +
						"Expected { PX: number } or { PX: number, NX: true }.",
				);
			},
			compareAndDelete: (key, expected) => opts.client.compareAndDelete(key, expected),
		},
		keyPrefix: lockKeyPrefix,
	});
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
		expiresAtMs: t.expiresAt === null ? null : t.expiresAt.getTime(),
		tokenType: t.tokenType,
		scope: t.scope,
		rawParams: t.rawParams as Record<string, unknown> | undefined,
	});

	const fromEnvelope = (e: Envelope): FederationTokens => ({
		accessToken: decryptRequired(e.accessToken),
		refreshToken: decryptOptional(e.refreshToken),
		idToken: decryptOptional(e.idToken),
		expiresAt: e.expiresAtMs === null ? null : new Date(e.expiresAtMs),
		tokenType: e.tokenType,
		scope: e.scope,
		rawParams: e.rawParams,
	});

	const writeEnv = async (sid: string, name: string, env: Envelope) => {
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
			if (!v) return null;
			try {
				return fromEnvelope(JSON.parse(v) as Envelope);
			} catch {
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
export const redisFederationTokenStoreBuilder: AdapterBuilder<FederationTokenStoreBase> = (
	config,
	_ctx,
) => {
	const cfg = config as {
		client?: unknown;
		encryption?: { mode?: "required" | "allow-plaintext"; key?: Buffer | string };
		keyPrefix?: string;
		ttl?: number;
	};
	if (!cfg.client) {
		throw new Error("federationTokenStore.redis: 'client' option is required");
	}
	const clientObj = cfg.client as Record<string, unknown>;
	// `compareAndDelete` is required by the advisory-lock release path (D-9).
	// Validate it here so a custom client missing the method fails at builder
	// time with a clear message rather than at first lock release with an
	// obscure `TypeError`.
	const requiredMethods = ["get", "set", "del", "scanIterator", "compareAndDelete"] as const;
	const missing = requiredMethods.filter((m) => typeof clientObj[m] !== "function");
	if (missing.length > 0) {
		throw new Error(
			`federationTokenStore.redis: client is missing required method(s): ${missing.join(", ")}. ` +
				`Pass a wrapper that implements get/set/del/scanIterator/compareAndDelete (e.g. makeIoredisClients(io).federationTokenStoreClient).`,
		);
	}
	const mode = cfg.encryption?.mode ?? "required";
	const nodeEnv = process.env.NODE_ENV ?? "development";
	// OR-12: hard production guard (throws on plaintext in production unless
	// FEDERATION_TOKENS_ALLOW_INSECURE=1). Validate before constructing the
	// EncryptionConfig so the failure surfaces before any key parsing.
	validateEncryptionMode(mode, nodeEnv);
	let encryption: EncryptionConfig;
	if (mode === "required") {
		const rawKey = cfg.encryption?.key;
		const keyBuf =
			typeof rawKey === "string"
				? Buffer.from(rawKey, "base64")
				: rawKey instanceof Buffer
					? rawKey
					: Buffer.alloc(0);
		if (keyBuf.length !== 32) {
			throw new Error(
				"federationTokenStore.redis: encryption.key must decode to 32 bytes (AES-256) when encryption.mode is 'required' (the default)",
			);
		}
		encryption = { mode: "required", key: keyBuf };
	} else {
		encryption = { mode: "allow-plaintext" };
	}
	return createRedisFederationTokenStore({
		client: cfg.client as FederationTokenStoreClient,
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
	requires: ["federationTokenStoreClient", "config"] as const,
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
			const cfg = (
				deps.config as unknown as {
					redisFederationTokenStore: {
						keyPrefix: string;
						ttl: number;
						encryptionMode: "required" | "allow-plaintext";
						encryptionKey?: string;
					};
				}
			).redisFederationTokenStore;
			return redisFederationTokenStoreBuilder(
				{
					client: deps.federationTokenStoreClient,
					encryption: { mode: cfg.encryptionMode, key: cfg.encryptionKey },
					keyPrefix: cfg.keyPrefix,
					ttl: cfg.ttl,
				},
				{},
			);
		},
	},
});
