/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */

/**
 * Redis-backed `FederationTokenStore`. `${keyPrefix}${sid}:${federationName}`
 * holds one JSON wrapper:
 *
 * ```
 * mode = "required"         { "v": 2, "g": "<generation>", "c": "<AES-256-GCM ciphertext of the JSON envelope>" }
 * mode = "allow-plaintext"  { "v": 2, "g": "<generation>", "p": { ...envelope } }
 * ```
 *
 * The whole envelope is one ciphertext, not only its token fields, so no part
 * of a record is readable without decrypting it; the per-session index under
 * `${keyPrefix}idx:` holds only federation names. `allow-plaintext` is refused
 * outside development by `validateEncryptionMode`.
 *
 * The AES-GCM additional authenticated data is the record's Redis key, so a
 * value copied under another session's, federation's or prefix's key fails
 * authentication and is treated as corrupt.
 *
 * A record without the `v: 2` wrapper (the older per-field shape, with
 * `accessToken` at the top level) is treated like corrupt JSON or a failed
 * decrypt: a read removes the key, only while it still holds the bytes read,
 * and answers `null`, and the user re-federates. Its index member stays: a
 * concurrent `attach` may have just added it, and a member naming no key is
 * harmless. There is deliberately no dual-read path, which would keep
 * plaintext-readable code alive.
 *
 * `g` is the record's store generation (docs/adapter-surface.md, "Conditional
 * writes"), outside the ciphertext, so a replica that does not know it reads
 * the record as before. Every write sets a fresh one. A record written without
 * one (by such a replica) is given one by its first versioned read, its TTL
 * kept; a conditional write against it answers `conflict`. A record `get`
 * reads that the versioned read can neither find a generation in nor mint one
 * into makes `getVersioned` reject, as an outage would: it is never removed.
 *
 * Each conditional member is one script on the record's key, refused at or
 * after a deadline the adapter stamps at issue and the server's clock judges,
 * so its write lifetime W is the write timeout plus the declared clock skew
 * (`internal/write-deadline.mts`), while the app's and Redis's clocks agree
 * within that skew. A conditional write keeps its answer under a replay key of
 * its own until the declared clock skew past its deadline, so a copy the
 * driver sends again before then answers as the first did and writes nothing,
 * even when a server whose clock lags by the skew judges it. A conditional
 * write answered `late`, like one unanswered within the write timeout, rejects
 * with an unknown outcome: the copy that answered wrote nothing, but another
 * copy may have committed, or may still commit within W. A conditional write
 * never shrinks the index, and adds to it only after `updated`, so the index
 * outlives the record it names. The store assumes acknowledged writes are not
 * rolled back (persistence, plus a failover setup that keeps acknowledged
 * writes); a deployment that accepts acknowledged-write loss on failover also
 * accepts that a conditional write may see a restored, older generation.
 */

import {
	type AdapterBuilder,
	checkDeploymentMode,
	coerceBooleanFromEnv,
	type DeploymentMode,
	decodeSealingKey,
	defineModule,
	type FederationTokenStore,
	type FederationTokens,
	isStorableExpiry,
	isStorableLifetime,
	isStoreGeneration,
	type Logger,
	newStoreGeneration,
	SEALING_KEY_BYTES,
	type StoreGeneration,
	type SupportsLock,
} from "@o3co/auth-provider-core";
import { z } from "zod";
import type { FederationTokenStoreClient } from "./clients.mjs";
import { decryptTokenField, encryptTokenField } from "./internal/crypto.mjs";
import {
	type EncryptionGuardContext,
	validateEncryptionMode,
} from "./internal/encryption-mode.mjs";

import { createRedisLock } from "./internal/lock.mjs";
import { createRedisSidSet } from "./internal/redisSidSet.mjs";
import { replayKeyOf } from "./internal/replay-key.mjs";
import { redisReference } from "./internal/section.mjs";
import { CLOCK_SKEW_MS, WRITE_TIMEOUT_MS, withWriteDeadline } from "./internal/write-deadline.mjs";

export type EncryptionConfig = { mode: "required"; key: Buffer } | { mode: "allow-plaintext" };

export type { EncryptionGuardContext };

export interface RedisFederationTokenStoreOptions {
	client: FederationTokenStoreClient;
	encryption: EncryptionConfig;
	keyPrefix?: string;
	/**
	 * Redis key TTL in seconds: how long a record persists. It MUST exceed the
	 * upstream refresh_token lifetime, so a refresh can still read the
	 * refresh_token after the access_token has expired; do not tie it to
	 * `tokens.expiresAt`, which the envelope keeps for the refresh flow.
	 * Default 86400 (24 h). A positive finite number, or construction throws; a
	 * fractional one is rounded up to a whole millisecond (`PX` takes no other).
	 */
	ttl?: number;
	/**
	 * **Migration flag, scheduled for removal.** After the index-driven removal,
	 * `removeBySid` also sweeps `SCAN MATCH ${keyPrefix}${sid}:*` to catch
	 * records written before the per-session index existed; without it their
	 * upstream refresh tokens outlive the logout until the store TTL. While on,
	 * every `removeBySid` scans the keyspace once.
	 *
	 * Turn it off once `ttl` has elapsed since the last replica running a release
	 * without the index stopped writing, or at once on a Redis that held no
	 * federation records before the upgrade. The flag, the scan path and
	 * `FederationTokenStoreClient.scanIterator` go away together (see CHANGELOG).
	 *
	 * Default `true`: an upgrade that changes no configuration must not orphan
	 * tokens.
	 */
	scanFallback?: boolean;
	/**
	 * The name the deployment selected its configuration by (see
	 * {@link EncryptionGuardContext}). Read only by the `allow-plaintext` guard,
	 * beside `NODE_ENV`; omitted, `NODE_ENV` is the sole signal.
	 */
	environment?: string;
	/**
	 * The replica count, as core's `deploymentMode` slot holds it. `"multi"`
	 * refuses `allow-plaintext` in every environment. The module passes the
	 * slot's value; a composition root that builds the store by hand passes
	 * `deploymentModeOf(config)` from `@o3co/auth-provider-core`. Anything but
	 * the three values, absence included, is a TypeError before the store is
	 * built: read as absent, it would let plaintext through under `multi`.
	 */
	deploymentMode: DeploymentMode;
	/**
	 * Where the `allow-plaintext` guard's notice goes: the module passes its
	 * optional `logger` slot, the builder its context's. Absent, `consoleLogger`.
	 * The store logs nothing else.
	 */
	logger?: Logger;
}

const DEFAULT_TTL_SECONDS = 86400;

/**
 * Keys per `UNLINK` and members per `SSCAN` / `SCAN` round-trip, so neither a
 * heavily linked session nor a large keyspace turns one logout into one
 * enormous command on the shared connection.
 */
const REMOVE_BATCH_SIZE = 100;

/**
 * The record inside {@link StoredRecord}, every field in clear. Under
 * `mode = "required"` it exists only as the plaintext side of one AES-256-GCM
 * operation, never written to Redis as-is.
 */
interface Envelope {
	accessToken: string;
	refreshToken: string | undefined;
	idToken: string | undefined;
	/**
	 * Absolute epoch-ms of access-token expiry, or `null` when the upstream
	 * issued no finite expiry (e.g. GitHub OAuth Apps). An explicit `null`, so
	 * "no expiry" stays distinct from a missing field.
	 */
	expiresAtMs: number | null;
	/**
	 * Every field is a required key, `obtainedAtMs` included, so a projection
	 * that forgets one fails to compile rather than dropping it (a dropped
	 * `tokenType` fails open). JSON drops `undefined`, so an unset key is absent
	 * on the wire, and `isEnvelope` reads it as optional.
	 */
	tokenType: string | undefined;
	scope: string | undefined;
	/** The link-time scope ceiling; `undefined` on older records. */
	grantedScope: string | undefined;
	/**
	 * Epoch-ms the access token's lifetime counts from, a whole millisecond
	 * within the Date range; `undefined` (absent on the wire) when the record
	 * has none.
	 */
	obtainedAtMs: number | undefined;
}

/**
 * Format version of {@link StoredRecord} (the unversioned per-field shape
 * counts as 1). Bump it when the wrapper changes shape; `open` refuses any
 * other.
 */
const RECORD_VERSION = 2;

/**
 * What is written to Redis (see the file header): `c` under `required`, `p`
 * under `allow-plaintext`. Neither mode reads the other's shape: a `p` record
 * under `required` would be a plaintext-readable path in production, and a `c`
 * record under `allow-plaintext` has no key to be read with. `g` is the
 * record's generation; `v` stays first, which the versioned read's mint relies
 * on.
 */
type StoredRecord =
	| { v: typeof RECORD_VERSION; g: string; c: string }
	| { v: typeof RECORD_VERSION; g: string; p: Envelope };

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
	typeof v === "object" && v !== null && !Array.isArray(v);

const isOptionalString = (v: unknown): v is string | undefined =>
	v === undefined || typeof v === "string";

/** An instant a `Date` holds as written: a whole millisecond within the Date range. */
const isInstant = (v: unknown): v is number =>
	typeof v === "number" && Number.isInteger(v) && isStorableExpiry(v);

/**
 * Shape check on the inner envelope, after unwrapping or decrypting. Without
 * it a malformed envelope (an array, no `accessToken`, `expiresAtMs: "soon"`)
 * would reach `fromEnvelope`, which does not throw, and be served on every read
 * instead of taking `get`'s self-heal. `expiresAtMs` must be present (`null`
 * means "no finite expiry"); `obtainedAtMs` may be absent. Unknown keys are
 * ignored, so adding an envelope key keeps `RECORD_VERSION` and an older
 * replica still reads its records; changing a present key's type or meaning
 * bumps it. Hand-written, not zod, to keep the read path dependency-free.
 */
function isEnvelope(value: unknown): value is Envelope {
	if (!isPlainObject(value)) return false;
	if (typeof value.accessToken !== "string" || value.accessToken.length === 0) return false;
	const expiresAtMs = value.expiresAtMs;
	if (expiresAtMs !== null && !(typeof expiresAtMs === "number" && Number.isFinite(expiresAtMs))) {
		return false;
	}
	if (
		!isOptionalString(value.refreshToken) ||
		!isOptionalString(value.idToken) ||
		!isOptionalString(value.tokenType) ||
		!isOptionalString(value.scope) ||
		!isOptionalString(value.grantedScope)
	) {
		return false;
	}
	if (value.obtainedAtMs !== undefined && !isInstant(value.obtainedAtMs)) return false;
	// An envelope carrying the retired `rawParams` field is read; the field is
	// ignored and not written back.
	return true;
}

/**
 * `obtainedAt` as the envelope holds it. An Invalid Date is written as
 * absent: read back it would make the record unreadable and lose its tokens,
 * where a record without the field loses only the refresh damping.
 */
const obtainedAtMsOf = (obtainedAt: Date | undefined): number | undefined => {
	const ms = obtainedAt?.getTime();
	return isInstant(ms) ? ms : undefined;
};

export function createRedisFederationTokenStore(
	opts: RedisFederationTokenStoreOptions,
): FederationTokenStore & SupportsLock {
	const deploymentMode = checkDeploymentMode(
		opts.deploymentMode,
		"createRedisFederationTokenStore: deploymentMode",
	);
	// The production guard runs before any key parsing, and only here: the
	// builder and the module reach it through this factory, so every entry
	// point is gated and its notice is written once per store.
	validateEncryptionMode("federation-tokens", opts.encryption.mode, {
		environment: opts.environment,
		deploymentMode,
		...(opts.logger !== undefined ? { logger: opts.logger } : {}),
	});
	// Every setting this store is given and cannot use is refused as a
	// RangeError: the key here, the TTL below, and the plaintext guard above.
	// A Buffer, not only 32 long: a JS caller's 32-character string has the
	// length, and would be used as its UTF-8 bytes.
	if (
		opts.encryption.mode === "required" &&
		(!Buffer.isBuffer(opts.encryption.key) || opts.encryption.key.length !== 32)
	) {
		throw new RangeError("FederationTokenStore redis: encryption key must be 32 bytes");
	}
	const prefix = opts.keyPrefix ?? "ft:";
	const ttlSeconds = opts.ttl ?? DEFAULT_TTL_SECONDS;
	// Its end, measured from now, must be within the Date range: past it the
	// PX is no number Redis can take, and the index write it pairs with is
	// refused after the SADD. A RangeError, as the shared expiry rule refuses
	// every lifetime.
	if (!isStorableLifetime(ttlSeconds * 1000)) {
		throw new RangeError(
			"FederationTokenStore redis: ttl must be a positive finite number of seconds that ends within the Date range",
		);
	}
	// Whole milliseconds, rounded up: a fractional `PX` is a Redis error, and
	// the index write it pairs with would be refused the same way.
	const storeTtlMs = Math.ceil(ttlSeconds * 1000);
	const scanFallback = opts.scanFallback ?? true;
	const k = (sid: string, name: string) => `${prefix}${sid}:${name}`;

	// Per-session key index: one SET per sid naming its federations, so
	// `removeBySid` deletes named keys instead of scanning. Its own `idx:`
	// sub-namespace (like `lock:`) keeps it out of the `${prefix}${sid}:*`
	// pattern the scan fallback sweeps. A sid equal to a sub-namespace token
	// ("idx", "lock") would make the layouts ambiguous; sids are opaque
	// generated identifiers, so that bounds what may be passed in.
	const index = createRedisSidSet({
		client: opts.client,
		keyPrefix: `${prefix}idx:`,
		scanCount: REMOVE_BATCH_SIZE,
	});

	// Advisory lock under its own `lock:` namespace. The shim bridges
	// FederationTokenStoreClient's positional `set` to the options-object form
	// RedisLockClient takes.
	const lockKeyPrefix = `${prefix}lock:`;
	const lock = createRedisLock({
		client: {
			set: (key, value, o) => {
				if (o?.NX && o.PX !== undefined) {
					return opts.client.set(key, value, "PX", o.PX, "NX") as Promise<string | null>;
				}
				if (o?.PX !== undefined) {
					return opts.client.set(key, value, "PX", o.PX) as Promise<string | null>;
				}
				// An unknown option shape is a programming error; answering `null`
				// would spin the acquire loop until timeout.
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
		grantedScope: t.grantedScope,
		obtainedAtMs: obtainedAtMsOf(t.obtainedAt),
	});

	const fromEnvelope = (e: Envelope): FederationTokens => ({
		accessToken: e.accessToken,
		refreshToken: e.refreshToken,
		idToken: e.idToken,
		expiresAt: e.expiresAtMs === null ? null : new Date(e.expiresAtMs),
		tokenType: e.tokenType,
		scope: e.scope,
		grantedScope: e.grantedScope,
		// Absent stays absent, not `undefined`, as core's memory store answers.
		...(e.obtainedAtMs === undefined ? {} : { obtainedAt: new Date(e.obtainedAtMs) }),
	});

	/**
	 * Wrap an envelope for the wire, at `generation`. `key` is the Redis key it
	 * is written under, and under `mode = "required"` the AAD the ciphertext is
	 * bound to.
	 */
	const seal = (key: string, env: Envelope, generation: StoreGeneration): string => {
		const record: StoredRecord =
			opts.encryption.mode === "allow-plaintext"
				? { v: RECORD_VERSION, g: generation, p: env }
				: {
						v: RECORD_VERSION,
						g: generation,
						c: encryptTokenField(JSON.stringify(env), opts.encryption.key, key),
					};
		return JSON.stringify(record);
	};

	/**
	 * Inverse of `seal`. Throws on anything but a record this store wrote in its
	 * own mode (corrupt JSON, the unversioned per-field shape, the other mode's
	 * shape, a ciphertext sealed for another key, a malformed envelope, a `g`
	 * that is no generation); a read turns every throw into the same self-heal.
	 * A record without `g` is read: a replica that does not know it wrote it.
	 */
	const open = (key: string, raw: string): Envelope => {
		const record = JSON.parse(raw) as Partial<Record<"v" | "g" | "c" | "p", unknown>> | null;
		if (record === null || typeof record !== "object" || record.v !== RECORD_VERSION) {
			throw new Error("FederationTokenStore redis: not a v2 record");
		}
		if ("g" in record && !isStoreGeneration(record.g)) {
			throw new Error("FederationTokenStore redis: malformed generation");
		}
		let inner: unknown;
		if (opts.encryption.mode === "allow-plaintext") {
			inner = record.p;
		} else {
			if (typeof record.c !== "string") {
				throw new Error("FederationTokenStore redis: not an encrypted v2 record");
			}
			inner = JSON.parse(decryptTokenField(record.c, opts.encryption.key, key));
		}
		// Under `required` the AEAD tag vouches that this store sealed these
		// bytes, so a mismatch here is a bug or a hand-edited dev record; the
		// self-heal is still the answer, not an Invalid Date.
		if (!isEnvelope(inner)) {
			throw new Error("FederationTokenStore redis: malformed envelope");
		}
		return inner;
	};

	const writeEnv = async (sid: string, name: string, env: Envelope) => {
		// Index before the envelope: a failure between them leaves an index
		// member naming a missing key, which removal tolerates, where the other
		// order would leave an envelope nothing knows about.
		await index.add(sid, name, storeTtlMs);
		// The key TTL is the store lifetime, not the access token's expiry
		// (kept in the envelope): the refresh_token must outlive the access
		// token.
		const key = k(sid, name);
		await opts.client.set(key, seal(key, env, newStoreGeneration()), "PX", storeTtlMs);
	};

	/**
	 * Removes a record this store cannot read, only while it still holds `raw`,
	 * the bytes read: a write since then is kept. The index member stays.
	 */
	const selfHeal = async (key: string, raw: string): Promise<null> => {
		await opts.client.compareAndDelete(key, raw);
		return null;
	};

	/**
	 * A conditional write whose outcome is unknown. A rejection of a
	 * conditional write means only that, never that nothing was written.
	 */
	const unknownOutcome = (operation: string, what: string, why: string): Error =>
		new Error(`FederationTokenStore (redis): ${operation} ${what}; the outcome is unknown: ${why}`);

	/**
	 * Answered `late`: the copy that answered reached the server at or after its
	 * deadline and wrote nothing, but another copy of the same write may have
	 * committed, or may still commit within W.
	 */
	const late = (operation: string): Error =>
		unknownOutcome(
			operation,
			"was answered past its deadline",
			"another copy may have committed, or may still commit within W",
		);

	/** Unanswered within the write timeout. */
	const unanswered = (operation: string) => (): Error =>
		unknownOutcome(
			operation,
			`had no answer within ${WRITE_TIMEOUT_MS} ms`,
			"it may have committed, or may still commit within W",
		);

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
			// Only absence is a clean miss: an empty string is a value `open`
			// cannot read, so it takes the same self-heal as corrupt JSON.
			if (v === null) return null;
			try {
				return fromEnvelope(open(key, v));
			} catch {
				// Corrupt JSON, a failed decrypt (rotated key, or a ciphertext
				// sealed for another key) or an unversioned record: removed rather
				// than failing on every read. `null` then means re-authenticate.
				return selfHeal(key, v);
			}
		},
		async getVersioned(sid, name) {
			const key = k(sid, name);
			const read = await opts.client.readVersioned(key, newStoreGeneration());
			if (read === null) return null;
			let value: FederationTokens;
			try {
				value = fromEnvelope(open(key, read.raw));
			} catch {
				return selfHeal(key, read.raw);
			}
			// `""` for a record `get` still serves: the read found no generation in
			// it and could not mint one. Removing it would lose tokens `get` reads,
			// so this answers as an outage would.
			if (!isStoreGeneration(read.generation)) {
				throw new Error(
					"FederationTokenStore (redis): getVersioned found no generation in a readable record and could not mint one",
				);
			}
			return { value, generation: read.generation };
		},
		async replaceIf(sid, name, expected, tokens) {
			const key = k(sid, name);
			const generation = newStoreGeneration();
			const value = seal(key, toEnvelope(tokens), generation);
			// The index's TTL raised first, so it lapses at most this step's time
			// before the record when the add after `updated` fails.
			await index.extend(sid, storeTtlMs);
			const outcome = await withWriteDeadline(
				(deadlineMs) =>
					opts.client.replaceIfGeneration(key, {
						expected,
						value,
						ttlMs: storeTtlMs,
						deadlineMs,
						replayKey: replayKeyOf(key, prefix, generation),
						clockSkewMs: CLOCK_SKEW_MS,
					}),
				unanswered("replaceIf"),
			);
			if (outcome === "late") throw late("replaceIf");
			if (outcome !== "updated") return { outcome };
			// Started after the record's write, so the index's deadline is no
			// earlier than the record's; it lists the record again if it lapsed.
			await index.add(sid, name, storeTtlMs);
			return { outcome, generation };
		},
		async removeIf(sid, name, expected) {
			const key = k(sid, name);
			const replayKey = replayKeyOf(key, prefix, newStoreGeneration());
			const outcome = await withWriteDeadline(
				(deadlineMs) =>
					opts.client.removeIfGeneration(key, {
						expected,
						deadlineMs,
						replayKey,
						clockSkewMs: CLOCK_SKEW_MS,
					}),
				unanswered("removeIf"),
			);
			if (outcome === "late") throw late("removeIf");
			return { outcome };
		},
		async update(sid, name, tokens) {
			await writeEnv(sid, name, toEnvelope(tokens));
		},
		async removeBySid(sid) {
			// The session's index names the keys: O(its federations), read in
			// SSCAN pages and unlinked in bounded batches.
			await unlinkBatched(
				(async function* () {
					for await (const name of index.members(sid)) yield k(sid, name);
				})(),
			);
			await index.removeBySid(sid);

			if (!scanFallback) return;
			// Migration fallback (see `scanFallback`): records written before the
			// index are reachable only by pattern. SCAN, not KEYS (O(N), blocking).
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
 * AdapterFactory builder. `encryption.mode` defaults to `"required"`, whose key
 * MUST be 32 bytes: a Buffer, or canonical base64 (core's `decodeSealingKey`:
 * no whitespace, the standard alphabet, its padding). The store's guard refuses
 * any other mode than the two; `allow-plaintext` warns at startup and is for
 * dev/test only. `environment` and `deploymentMode` are what that guard reads
 * ({@link EncryptionGuardContext}).
 *
 * `deploymentMode` is required in the adapter configuration — the
 * `BuilderContext` carries a lifecycle, readiness and a logger, never the
 * mode — and a composition root passes `deploymentModeOf(config)` from
 * `@o3co/auth-provider-core`. Anything but `"single"`, `"multi"` or `"unset"`,
 * absence included, is a TypeError before anything is built, the client
 * checked or the key read.
 */
export const redisFederationTokenStoreBuilder: AdapterBuilder<FederationTokenStore> = (
	config,
	ctx,
) => {
	const cfg = config as {
		client?: unknown;
		encryption?: { mode?: "required" | "allow-plaintext"; key?: Buffer | string };
		keyPrefix?: string;
		ttl?: number;
		scanFallback?: boolean;
		environment?: string;
		deploymentMode?: unknown;
	};
	const deploymentMode = checkDeploymentMode(
		cfg.deploymentMode,
		"redisFederationTokenStoreBuilder: deploymentMode",
	);
	if (!cfg.client) {
		throw new Error("federationTokenStore.redis: 'client' option is required");
	}
	const clientObj = cfg.client as Record<string, unknown>;
	// `compareAndDelete` releases the advisory lock and removes an unreadable
	// record; `unlink`, the three SET primitives and `pExpireGT` serve the
	// per-session index; the three scripts are the conditional members.
	// Checked here so a custom client
	// missing one fails at build time, not with a `TypeError` at first logout,
	// the path that must remove a logged-out session's upstream tokens.
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
		"readVersioned",
		"replaceIfGeneration",
		"removeIfGeneration",
		"pExpireGT",
	] as const;
	const missing = requiredMethods.filter((m) => typeof clientObj[m] !== "function");
	if (missing.length > 0) {
		throw new Error(
			`federationTokenStore.redis: client is missing required method(s): ${missing.join(", ")}. ` +
				`Pass a wrapper that implements ${requiredMethods.join("/")} (e.g. makeIoredisClients(io).federationTokenStoreClient).`,
		);
	}
	const mode = cfg.encryption?.mode ?? "required";
	// The production guard runs once, in the store factory, with the context's
	// logger. Nothing here can fail first: it acts only on `allow-plaintext`,
	// which reads no key.
	const guard = {
		environment: cfg.environment,
		deploymentMode,
		...(ctx?.logger !== undefined ? { logger: ctx.logger } : {}),
	};
	let encryption: EncryptionConfig;
	if (mode === "required") {
		// Core's rule for a configured key: a value an operator would have to
		// tidy up to read (a trailing newline, the URL alphabet, no padding) is
		// not the value they checked.
		const rawKey = cfg.encryption?.key;
		const keyBuf =
			typeof rawKey === "string"
				? decodeSealingKey(rawKey)
				: Buffer.isBuffer(rawKey) && rawKey.length === SEALING_KEY_BYTES
					? rawKey
					: undefined;
		if (keyBuf === undefined) {
			throw new RangeError(
				`federationTokenStore.redis: encryption.key must be canonical base64 of ${SEALING_KEY_BYTES} bytes (AES-256), or a Buffer of ${SEALING_KEY_BYTES} bytes, when encryption.mode is 'required' (the default)`,
			);
		}
		encryption = { mode: "required", key: keyBuf };
	} else {
		// Passed on as given: the store's guard refuses a mode it does not
		// know, where reading it here as plaintext would downgrade silently.
		encryption = { mode };
	}
	return createRedisFederationTokenStore({
		client: cfg.client as FederationTokenStoreClient,
		encryption,
		keyPrefix: cfg.keyPrefix,
		ttl: cfg.ttl,
		scanFallback: cfg.scanFallback,
		...guard,
	});
};

/**
 * The schema of `redis-federation-token-store {}`, the module's own section,
 * each leaf read from the string a variable carries. Strict.
 */
export const redisFederationTokenStoreSectionSchema = z
	.object({
		keyPrefix: z.string().default("ft:"),
		ttl: z.coerce.number().int().positive().default(86400),
		encryptionMode: z.enum(["required", "allow-plaintext"]).default("required"),
		encryptionKey: z.string().optional(),
		// Migration flag; see `RedisFederationTokenStoreOptions.scanFallback`.
		// An exported-but-empty variable reads as `false`, turning the safety
		// net off, so set it to `true` or `false`, never empty.
		scanFallback: coerceBooleanFromEnv.default(true),
	})
	.strict()
	.default(() => ({
		keyPrefix: "ft:",
		ttl: 86400,
		encryptionMode: "required" as const,
		scanFallback: true,
	}));

/** What a composition root tells the module that its config cannot. */
export interface RedisFederationTokenStoreModuleOptions {
	/**
	 * The name the deployment selected its configuration by — the standalone
	 * passes `CONFIG_ENV || NODE_ENV`. Read by the `allow-plaintext` guard in
	 * addition to `NODE_ENV`; see {@link EncryptionGuardContext}. Omitted, the
	 * guard reads `NODE_ENV` alone.
	 */
	readonly environment?: string;
}

/**
 * `defineModule` manifest for the Redis FederationTokenStore, built for one
 * composition root (static composition; the builder above is for runtime
 * selection). Its settings are its own section, `redis-federation-token-store`;
 * the key is its `encryptionKey` (canonical base64), which operators set
 * through `REDIS_FEDERATION_TOKEN_STORE_ENCRYPTION_KEY`.
 * `redisFederationTokenStore`, the section's old path, refuses boot naming it.
 *
 * The `allow-plaintext` guard reads the replica count from the
 * `deploymentMode` slot core fills — required, and held to its three values
 * (a TypeError otherwise), since `multi` refuses plaintext — and the selected
 * environment off `options`, since only the
 * composition root knows how it chose its config file. Its notice goes to the
 * optional `logger` slot (`consoleLogger` when empty).
 */
export function redisFederationTokenStoreModuleFor(
	options: RedisFederationTokenStoreModuleOptions = {},
) {
	return defineModule({
		name: "redis-federation-token-store",
		section: {
			schema: redisFederationTokenStoreSectionSchema,
			reference: redisReference(),
			relocatedFrom: {
				redisFederationTokenStore: { to: "", environmentVariable: null },
				"redisFederationTokenStore.keyPrefix": "keyPrefix",
				"redisFederationTokenStore.encryptionMode": "encryptionMode",
				"redisFederationTokenStore.encryptionKey": "encryptionKey",
			},
		},
		requires: ["federationTokenStoreClient", "deploymentMode"] as const,
		optional: ["logger"] as const,
		provides: {
			federationTokenStore: (deps) => {
				const cfg = deps.section;
				return redisFederationTokenStoreBuilder(
					{
						client: deps.federationTokenStoreClient,
						encryption: { mode: cfg.encryptionMode, key: cfg.encryptionKey },
						keyPrefix: cfg.keyPrefix,
						ttl: cfg.ttl,
						scanFallback: cfg.scanFallback,
						environment: options.environment,
						deploymentMode: checkDeploymentMode(
							deps.deploymentMode,
							"redis-federation-token-store: deploymentMode",
						),
					},
					deps.logger !== undefined ? { logger: deps.logger } : {},
				);
			},
		},
	});
}

/**
 * The module with no environment named: the plaintext guard reads `NODE_ENV`
 * and the `deploymentMode` slot. A composition root that selects its config by
 * another name builds its own with {@link redisFederationTokenStoreModuleFor}.
 */
export const redisFederationTokenStoreModule = redisFederationTokenStoreModuleFor();
