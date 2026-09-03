/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * Redis-backed `FederationTokenStore`.
 *
 * ## What is written under `${keyPrefix}${sid}:${federationName}` (#293)
 *
 * One JSON wrapper carrying a format version and the record:
 *
 * ```
 * mode = "required"         { "v": 2, "c": "<AES-256-GCM ciphertext of the JSON envelope>" }
 * mode = "allow-plaintext"  { "v": 2, "p": { ...envelope } }
 * ```
 *
 * The *whole* envelope — `accessToken`, `refreshToken`, `idToken`,
 * `expiresAtMs`, `tokenType`, `scope`, `rawParams` — is one ciphertext.
 * Earlier releases encrypted the three token fields individually and wrote
 * the rest beside them in clear, which left `rawParams` readable in Redis
 * (#293). `rawParams` is the upstream IdP's raw token response: unbounded,
 * provider-specific, and it can carry anything the IdP chose to include —
 * extra tokens, expiry hints, account hints, and routinely the very tokens
 * again under their wire names. Sanitising it instead would mean maintaining
 * an allowlist per federation forever. `tokenType` and `scope` are
 * low-sensitivity, but nothing reads the stored record without decrypting
 * it — `get` → `fromEnvelope` is the only reader; the per-session index
 * under `${keyPrefix}idx:` is separate and carries only federation names.
 * One ciphertext per record is simpler and closes the class rather than the
 * instance. Under `mode = "allow-plaintext"` the envelope stays plain JSON
 * inside the same wrapper; that mode is refused outside development by
 * `validateEncryptionMode`.
 *
 * The ciphertext is bound to the Redis key it lives under — AES-GCM
 * additional authenticated data = `${keyPrefix}${sid}:${federationName}` —
 * so a value copied to another session's key (or another federation's, or
 * another prefix) fails authentication and is handled as corrupt rather than
 * read as that session's tokens.
 *
 * ### Legacy records
 *
 * A record without the `v: 2` wrapper (recognisable by `accessToken` at the
 * top level) is the pre-#293 per-field shape. `get` treats it exactly like
 * corrupt JSON or a decrypt failure: the key and its index member are
 * removed and `null` is returned, which the session layer turns into
 * re-authentication. There is deliberately no dual-read path — it would keep
 * the plaintext-readable code alive — and no in-place migration: no
 * deployment had written these records outside development when the format
 * changed. Operator consequence: records written before this version are
 * dropped on first read and the user re-federates.
 */

import {
	type AdapterBuilder,
	defineModule,
	type FederationTokenStore,
	type FederationTokens,
	type SupportsLock,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import type { FederationTokenStoreClient } from "./clients.mjs";
import { decryptTokenField, encryptTokenField } from "./internal/crypto.mjs";
import { createRedisLock } from "./internal/lock.mjs";
import { createRedisSidSet } from "./internal/redisSidSet.mjs";

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
	/**
	 * **Migration flag (#291), scheduled for removal.** Keep the legacy
	 * `SCAN MATCH ${keyPrefix}${sid}:*` sweep as a fallback at the end of
	 * `removeBySid`, in addition to the per-session key index.
	 *
	 * Records written by v0.9.x and earlier have no index entry, so an index-
	 * only `removeBySid` would walk straight past them and leave a logged-out
	 * session's upstream refresh tokens sitting in Redis until the store TTL
	 * expired them. The fallback closes that window on an upgrade.
	 *
	 * It is also what the flag costs: while enabled, every `removeBySid` still
	 * performs one keyspace scan, which is the O(keyspace) work #291 is about.
	 * The index-driven removal runs first regardless, so the deletes are always
	 * bounded; the scan is a safety net, not the mechanism.
	 *
	 * **When to turn it off**: once no session predating the upgrade can still
	 * exist — that is, once `ttl` (default 24 h) has elapsed since the last
	 * replica running the previous release stopped writing. Set it to `false`
	 * then, and logout stops touching the keyspace at all. A deployment whose
	 * Redis had no federation records before the upgrade (a fresh database, or
	 * `federationTokenStore` newly enabled) can set it to `false` immediately.
	 *
	 * **When it will be removed**: the flag and the scan path go away together
	 * once the migration window has closed — see CHANGELOG for the release that
	 * performs the removal. At that point `scanIterator` also leaves
	 * `FederationTokenStoreClient`.
	 *
	 * Default: `true` — an upgrade that changes no configuration must not
	 * silently orphan tokens.
	 */
	scanFallback?: boolean;
}

const DEFAULT_TTL_SECONDS = 86400;

/**
 * Keys removed per `UNLINK`, and members requested per `SSCAN` / `SCAN`
 * round-trip. Bounds the size of any single command `removeBySid` issues on
 * the shared connection, so neither a heavily-linked session nor a large
 * keyspace turns one logout into one enormous command.
 */
const REMOVE_BATCH_SIZE = 100;

/**
 * The record as it exists inside {@link StoredRecord}: every field in clear.
 * Under `mode = "required"` this object only ever exists as the plaintext
 * side of one AES-256-GCM operation — it is never written to Redis as-is
 * (#293).
 */
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

/**
 * Format version of {@link StoredRecord}. Version 1 is the pre-#293 per-field
 * shape, which had no version marker at all; bump this when the wrapper
 * changes shape again, and let `open` refuse what it does not know.
 */
const RECORD_VERSION = 2;

/**
 * What is actually written to Redis — see the module docblock. `c` under
 * `mode = "required"`, `p` under `mode = "allow-plaintext"`. A store in one
 * mode does not read the other's shape: a `p` record under `required` would
 * be a plaintext-readable path in production, and a `c` record under
 * `allow-plaintext` has no key to be read with.
 */
type StoredRecord =
	| { v: typeof RECORD_VERSION; c: string }
	| { v: typeof RECORD_VERSION; p: Envelope };

export function createRedisFederationTokenStore(
	opts: RedisFederationTokenStoreOptions,
): FederationTokenStore & SupportsLock {
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
	const scanFallback = opts.scanFallback ?? true;
	const k = (sid: string, name: string) => `${prefix}${sid}:${name}`;

	// #291: per-session key index. One SET per sid holding the federation
	// names attached to it, so `removeBySid` can name the keys it must delete
	// instead of hunting for them. Its own sub-namespace, like `lock:` below,
	// keeps it clear of the `${prefix}${sid}:*` envelope keyspace — the
	// migration fallback matches that pattern and must not sweep up indexes
	// belonging to other sessions.
	//
	// This shares the constraint `lock:` has carried since D-9: a sid equal to
	// a sub-namespace token ("idx", "lock") would make the two layouts
	// ambiguous. Sids are opaque generated identifiers, so this is a bound on
	// what may be passed in rather than a case to handle.
	const index = createRedisSidSet({
		client: opts.client,
		keyPrefix: `${prefix}idx:`,
		scanCount: REMOVE_BATCH_SIZE,
	});

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

	const toEnvelope = (t: FederationTokens): Envelope => ({
		accessToken: t.accessToken,
		refreshToken: t.refreshToken,
		idToken: t.idToken,
		expiresAtMs: t.expiresAt === null ? null : t.expiresAt.getTime(),
		tokenType: t.tokenType,
		scope: t.scope,
		rawParams: t.rawParams as Record<string, unknown> | undefined,
	});

	const fromEnvelope = (e: Envelope): FederationTokens => ({
		accessToken: e.accessToken,
		refreshToken: e.refreshToken,
		idToken: e.idToken,
		expiresAt: e.expiresAtMs === null ? null : new Date(e.expiresAtMs),
		tokenType: e.tokenType,
		scope: e.scope,
		rawParams: e.rawParams,
	});

	/**
	 * Wrap an envelope for the wire (#293). `key` is the Redis key the record
	 * is about to be written under; under `mode = "required"` it is the AAD
	 * the ciphertext is bound to.
	 */
	const seal = (key: string, env: Envelope): string => {
		const record: StoredRecord =
			opts.encryption.mode === "allow-plaintext"
				? { v: RECORD_VERSION, p: env }
				: {
						v: RECORD_VERSION,
						c: encryptTokenField(JSON.stringify(env), opts.encryption.key, key),
					};
		return JSON.stringify(record);
	};

	/**
	 * Inverse of `seal`. Throws on anything that is not a record this store
	 * wrote in its own mode — corrupt JSON, the pre-#293 per-field shape, a
	 * plaintext record under `mode = "required"`, a ciphertext under
	 * `mode = "allow-plaintext"`, or a ciphertext sealed for another key —
	 * and `get` turns every throw into the same self-heal. One read path, no
	 * shape sniffing: a legacy record is not "migrated", it is dropped.
	 */
	const open = (key: string, raw: string): Envelope => {
		const record = JSON.parse(raw) as Partial<Record<"v" | "c" | "p", unknown>> | null;
		if (record === null || typeof record !== "object" || record.v !== RECORD_VERSION) {
			throw new Error("FederationTokenStore redis: not a v2 record");
		}
		if (opts.encryption.mode === "allow-plaintext") {
			if (typeof record.p !== "object" || record.p === null) {
				throw new Error("FederationTokenStore redis: not a plaintext v2 record");
			}
			return record.p as Envelope;
		}
		if (typeof record.c !== "string") {
			throw new Error("FederationTokenStore redis: not an encrypted v2 record");
		}
		return JSON.parse(decryptTokenField(record.c, opts.encryption.key, key)) as Envelope;
	};

	const writeEnv = async (sid: string, name: string, env: Envelope) => {
		// Index BEFORE the envelope. A failure between the two then leaves an
		// index member pointing at a key that does not exist — harmless, the
		// removal path unlinks missing keys without complaint. The other order
		// would leave an envelope nothing knows about, which is precisely the
		// orphan this index exists to prevent.
		//
		// This costs the write path one extra round-trip. That is the trade
		// #291 makes: a write happens once when a federation is linked, while
		// the read it pays for happens on every logout and used to be
		// O(the entire keyspace).
		await index.add(sid, name, storeTtlMs);
		// Redis TTL is the store lifetime (session upper bound), NOT the access
		// token's expiresAt. The access token's expiry is preserved inside the
		// envelope so F-6 consumers can decide to refresh; the record itself
		// must outlive the access_token so the refresh_token remains available.
		const key = k(sid, name);
		await opts.client.set(key, seal(key, env), "PX", storeTtlMs);
	};

	/** Unlink `keys` in bounded batches. */
	const unlinkBatched = async (keys: AsyncIterable<string>): Promise<void> => {
		const batch: string[] = [];
		for await (const key of keys) {
			batch.push(key);
			if (batch.length >= REMOVE_BATCH_SIZE) {
				await opts.client.unlink(...batch);
				batch.length = 0;
			}
		}
		if (batch.length > 0) await opts.client.unlink(...batch);
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
				return fromEnvelope(open(key, v));
			} catch {
				// Corrupt JSON, a decrypt failure (rotated encryption key, or a
				// ciphertext sealed for another key — #293 AAD), or the pre-#293
				// per-field record: self-heal by deleting the key, mirroring the
				// UserSessionStore redis adapter. Otherwise operators see repeated
				// silent failures and key/crypto mismatches surface as "missing
				// tokens" — hard to debug. Returning null after delete signals
				// re_authentication.
				await opts.client.del(key);
				// Drop the index member too: the envelope it named is gone, and
				// an index that outlives its records makes `removeBySid` do work
				// for keys that cannot exist.
				await index.remove(sid, name);
				return null;
			}
		},
		async update(sid, name, tokens) {
			await writeEnv(sid, name, toEnvelope(tokens));
		},
		async removeBySid(sid) {
			// #291: the session's own index names the keys, so this is O(the
			// session's federations) rather than O(the keyspace). Read in
			// SSCAN pages and unlinked in bounded batches, so neither half
			// grows with how heavily linked the session is.
			await unlinkBatched(
				(async function* () {
					for await (const name of index.members(sid)) yield k(sid, name);
				})(),
			);
			await index.removeBySid(sid);

			if (!scanFallback) return;
			// Migration fallback — see `scanFallback` in the options doc. Records
			// written before the index existed have no member naming them, so
			// they are only reachable by the pattern scan the index replaced.
			// SCAN (cursor-based) rather than KEYS (O(N), blocking), and the
			// same bounded UNLINK batches.
			await unlinkBatched(
				opts.client.scanIterator({ MATCH: sidPattern(sid), COUNT: REMOVE_BATCH_SIZE }),
			);
		},
		async delete(sid, name) {
			await opts.client.del(k(sid, name));
			await index.remove(sid, name);
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
 *     ttl?: number,
 *     scanFallback?: boolean }
 *
 * Encryption defaults: mode = "required", key MUST be 32-byte (raw Buffer or
 * base64 string). `mode = "allow-plaintext"` emits a startup warning and is
 * intended for dev/test only (per spec §5).
 */
export const redisFederationTokenStoreBuilder: AdapterBuilder<FederationTokenStore> = (
	config,
	_ctx,
) => {
	const cfg = config as {
		client?: unknown;
		encryption?: { mode?: "required" | "allow-plaintext"; key?: Buffer | string };
		keyPrefix?: string;
		ttl?: number;
		scanFallback?: boolean;
	};
	if (!cfg.client) {
		throw new Error("federationTokenStore.redis: 'client' option is required");
	}
	const clientObj = cfg.client as Record<string, unknown>;
	// `compareAndDelete` is required by the advisory-lock release path (D-9);
	// `unlink` and the three SET primitives by the per-session key index
	// (#291). Validate them here so a custom client missing one fails at
	// builder time with a clear message rather than at first logout with an
	// obscure `TypeError` — on the path whose whole job is to make sure a
	// logged-out session's upstream tokens are gone.
	const requiredMethods = [
		"get",
		"set",
		"del",
		"unlink",
		"sAddWithTtl",
		"sRem",
		"sScanIterator",
		"scanIterator",
		"compareAndDelete",
	] as const;
	const missing = requiredMethods.filter((m) => typeof clientObj[m] !== "function");
	if (missing.length > 0) {
		throw new Error(
			`federationTokenStore.redis: client is missing required method(s): ${missing.join(", ")}. ` +
				`Pass a wrapper that implements ${requiredMethods.join("/")} (e.g. makeIoredisClients(io).federationTokenStoreClient).`,
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
		scanFallback: cfg.scanFallback,
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
				// #291 migration flag — see `RedisFederationTokenStoreOptions.scanFallback`
				// for what it costs while on and when to turn it off.
				scanFallback: z.boolean().default(true),
			})
			.default({
				keyPrefix: "ft:",
				ttl: 86400,
				encryptionMode: "required",
				scanFallback: true,
			}),
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
						scanFallback: boolean;
					};
				}
			).redisFederationTokenStore;
			return redisFederationTokenStoreBuilder(
				{
					client: deps.federationTokenStoreClient,
					encryption: { mode: cfg.encryptionMode, key: cfg.encryptionKey },
					keyPrefix: cfg.keyPrefix,
					ttl: cfg.ttl,
					scanFallback: cfg.scanFallback,
				},
				{},
			);
		},
	},
});
