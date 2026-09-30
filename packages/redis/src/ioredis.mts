/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
/*
 * ioredis bindings for the client ports in `./clients.mjs`: `makeIoredisClients` for the
 * single-connection set, and separate factories for the federation grant, federation grant
 * intent and MFA stores, which run the scripts in `./ioredis/scripts/` EVALSHA-first. Published
 * as the `@o3co/auth-provider-redis/ioredis` subpath, so the main entry never pulls ioredis types
 * into a consumer's dependency closure.
 */
import { consoleLogger, type EventLogger, loggableError } from "@o3co/auth-provider-core";
import type { Redis } from "ioredis";
import type {
	AccessTokenDenylistClient,
	ChallengeStoreClient,
	CodeRepositoryClient,
	ConsentRecordFields,
	ConsentStoreClient,
	DeviceCodeStoreClient,
	DisposableRefreshTokenFamilyClient,
	FederationGrantConsentAnswered,
	FederationGrantIntentAdmission,
	FederationGrantIntentStoreClient,
	FederationGrantStoreClient,
	FederationTokenStoreClient,
	MfaFactorStoreClient,
	MfaTransactionStoreClient,
	PendingConsentStoreClient,
	RateLimiterClient,
	RateLimitIncrement,
	RefreshTokenFamilyClient,
	RefreshTokenFamilyMultiClient,
	ReplaySeenSetClient,
	SessionRPRegistryClient,
	SessionRPRegistryMultiClient,
	SessionSidSortedSetClient,
	SessionSidSortedSetMultiClient,
	SubjectRevocationClient,
	SubjectSessionIndexClient,
	SubjectSessionIndexMultiClient,
	UserSessionStoreClient,
} from "./clients.mjs";
import {
	deviceCodeRecordOf,
	fgFields,
	fgiText,
	fgNumber,
	fgWritten,
	hashFields,
} from "./ioredis/codec.mjs";
import { redisDurability } from "./ioredis/durability.mjs";
import {
	CONSENT_FIND,
	CONSENT_GRANT,
	PENDING_CONSENT_DISCARD,
	PENDING_CONSENT_SET,
	PENDING_CONSENT_TAKE,
} from "./ioredis/scripts/consent.mjs";
import type { CachedScript } from "./ioredis/scripts/define.mjs";
import {
	DEVICE_CODE_CREATE,
	DEVICE_CODE_DECIDE,
	DEVICE_CODE_FIND_PENDING,
	DEVICE_CODE_POLL,
	DEVICE_CODE_REMOVE,
} from "./ioredis/scripts/device-code.mjs";
import {
	FG_ACTIVATE,
	FG_CREATE,
	FG_NAME_INTENT,
	FG_NOTE_FAILURE,
	FG_PRUNE,
	FG_REPLACE,
	FG_REQUIRE_REAUTH,
	FG_RESERVE,
	FG_RETIRE_INTENT,
	FG_REVOKE,
	FG_SNAPSHOT,
	FG_TOUCH,
	FG_UNLOCK,
} from "./ioredis/scripts/federation-grant.mjs";
import {
	FGI_ADMIT,
	FGI_ANSWER,
	FGI_CONSUME,
	FGI_FINISH,
	FGI_PARK,
} from "./ioredis/scripts/federation-grant-intent.mjs";
import { LUA_COMPARE_AND_DELETE, LUA_COMPARE_AND_DELETE_SHA } from "./ioredis/scripts/lock.mjs";
import {
	MFA_FACTOR_UPDATE,
	MFA_SUBJECT_EXEMPT,
	MFA_SUBJECT_RESERVE,
	MFA_SUBJECT_SETTLE,
	MFA_TX_CONSUME,
	MFA_TX_CREATE,
	MFA_TX_RESERVE_ATTEMPT,
	MFA_TX_TAKE_CHALLENGE,
	MFA_TX_UPDATE,
} from "./ioredis/scripts/mfa.mjs";
import { LUA_INCREMENT_WITH_TTL } from "./ioredis/scripts/rate-limiter.mjs";
import {
	LUA_PRUNE_AND_LIST,
	LUA_PRUNE_AND_LIST_SHA,
	LUA_SET_REVOCATION_BOUNDARIES,
	LUA_SET_REVOCATION_BOUNDARIES_SHA,
	REPLACE_IF_UNCHANGED,
} from "./ioredis/scripts/user-sessions.mjs";

/** Script-cache residency flag for {@link LUA_SET_REVOCATION_BOUNDARIES}. */
let watermarkScriptCached = false;

/** Script-cache residency flag for {@link LUA_PRUNE_AND_LIST}. */
let pruneAndListScriptCached = false;

/**
 * Whether `err` is Redis's `NOSCRIPT`, the cold-cache reply to `EVALSHA` after a `SCRIPT FLUSH`
 * or a failover: the signal to fall back to `EVAL` (which reloads the script), not to fail. It
 * reads the message because ioredis's `ReplyError` carries no code (ioredis's own `Script` does
 * the same); the text decides this boolean only and is never logged or thrown.
 */
function isNoScriptError(err: unknown): boolean {
	return err instanceof Error && err.message.includes("NOSCRIPT");
}

/**
 * Run `script` EVALSHA-first, falling back to EVAL — which implicitly loads
 * it server-side — on `NOSCRIPT`. Any other error is the caller's.
 */
async function runScript(
	io: Redis,
	script: CachedScript,
	keys: readonly string[],
	args: readonly string[],
): Promise<unknown> {
	if (script.cached) {
		try {
			return await io.evalsha(script.sha, keys.length, ...keys, ...args);
		} catch (err) {
			if (!isNoScriptError(err)) throw err;
			script.cached = false;
		}
	}
	const reply = await io.eval(script.source, keys.length, ...keys, ...args);
	script.cached = true;
	return reply;
}

/**
 * Whether `LUA_COMPARE_AND_DELETE` is expected in the server's script cache: `true` lets the
 * next call use `EVALSHA`; a `NOSCRIPT` (after `SCRIPT FLUSH` or a failover) clears it, and the
 * `EVAL` fallback reloads the script and sets it again. Module-scoped, like every such flag here,
 * because the script is constant: clients in one process share the server's cache state.
 */
let scriptCached = false;

/**
 * Surfaces per-command failures from a `MULTI`/`EXEC` reply. ioredis resolves `exec()` with one
 * `[error, result]` per queued command and does not reject when one failed, so a refused
 * `PEXPIRE … NX/GT` would leave a key with no TTL while the caller is told the write worked.
 *
 * `null`, the WATCH abort, passes through: the refresh-token family's CAS loop retries on it.
 * The first failure throws, naming the operation in fixed words with the reply's error as
 * `cause`, never in the message: Redis's reply can quote the command's arguments.
 * `loggableError` projects the cause for the operator without them.
 */
function assertPipelineSucceeded(reply: unknown[] | null, operation: string): unknown[] | null {
	if (reply === null) return null;
	for (const entry of reply) {
		// ioredis tuple shape; a wrapper returning bare results simply has no
		// error slot to find, which is correct rather than silently lenient.
		const err = Array.isArray(entry) ? entry[0] : null;
		if (err) {
			throw new Error(`${operation}: a queued command failed inside MULTI/EXEC`, { cause: err });
		}
	}
	return reply;
}

/** Options for {@link makeIoredisClients}. */
export interface IoredisClientsOptions {
	/**
	 * Where errors from connections the wrapper opens itself (the refresh-token family's
	 * `duplicate()`) are reported; defaults to `consoleLogger`. An `EventLogger` rather than a
	 * `Logger`, so a composition root can pass its host logger. The `io` connection, its
	 * lifetime and its listeners stay the caller's; see the README for the listener it needs.
	 */
	readonly logger?: EventLogger;
}

/**
 * Wraps one ioredis connection into the typed clients the `@o3co/auth-provider-redis` adapters
 * need; a composition root spreads the result into `bootstrapComponents`, or wires slots one by
 * one for a mixed-backend deployment.
 *
 * Every client uses `io`; the only connection opened here is the per-rotation
 * `refreshTokenFamilyClient.duplicate()`. Connection options are therefore shared by every
 * purpose, and one that needs different failure timing (`enableOfflineQueue: false` for the
 * rate limiter, say) needs a connection of its own.
 */
export function makeIoredisClients(
	io: Redis,
	options: IoredisClientsOptions = {},
): {
	challengeStoreClient: ChallengeStoreClient;
	accessTokenDenylistClient: AccessTokenDenylistClient;
	replaySeenSetClient: ReplaySeenSetClient;
	refreshTokenFamilyClient: RefreshTokenFamilyClient;
	userSessionStoreClient: UserSessionStoreClient;
	sessionRPRegistryClient: SessionRPRegistryClient;
	sessionFamilyIndexClient: SessionSidSortedSetClient;
	sessionFederationIndexClient: SessionSidSortedSetClient;
	subjectSessionIndexClient: SubjectSessionIndexClient;
	subjectRevocationClient: SubjectRevocationClient;
	federationTokenStoreClient: FederationTokenStoreClient;
	rateLimiterClient: RateLimiterClient;
	codeRepositoryClient: CodeRepositoryClient;
	deviceCodeStoreClient: DeviceCodeStoreClient;
	consentStoreClient: ConsentStoreClient;
	pendingConsentStoreClient: PendingConsentStoreClient;
	mfaFactorStoreClient: MfaFactorStoreClient;
	mfaTransactionStoreClient: MfaTransactionStoreClient;
} {
	const logger = options.logger ?? consoleLogger;

	const challengeStoreClient: ChallengeStoreClient = {
		set: (k, v, _mode, ttl, _cond) => io.set(k, v, "PX", ttl, "NX") as Promise<"OK" | null>,
		pttl: (k) => io.pttl(k),
		del: (k) => io.del(k),
	};

	// Revoked access-token jtis. Plain PX SET (no NX): re-revoking a jti is idempotent, and the
	// last write sets the expiry.
	const accessTokenDenylistClient: AccessTokenDenylistClient = {
		set: (k, v, _mode, ttlMs) => io.set(k, v, "PX", ttlMs) as Promise<"OK">,
		exists: (k) => io.exists(k),
	};

	const replaySeenSetClient: ReplaySeenSetClient = {
		set: (k, v, _mode, ttl, _cond) => io.set(k, v, "PX", ttl, "NX") as Promise<"OK" | null>,
		exists: (k) => io.exists(k),
	};

	// RefreshTokenFamilyClient needs duplicate() returning DisposableRefreshTokenFamilyClient.
	// The duplicate is built by recursively wrapping the duplicated ioredis instance.
	const buildRefreshClient = (underlying: Redis): RefreshTokenFamilyClient => ({
		set: (k, v, _mode, ttl, _cond) => underlying.set(k, v, "PX", ttl, "NX") as Promise<"OK" | null>,
		get: (k) => underlying.get(k),
		pttl: (k) => underlying.pttl(k),
		watch: (...keys) => underlying.watch(...keys) as Promise<"OK">,
		unwatch: () => underlying.unwatch() as Promise<"OK">,
		multi: () => buildRefreshMulti(underlying.multi()),
		duplicate: () => {
			const dup = underlying.duplicate();
			// `duplicate()` copies options but not listeners, and an `error` event with no
			// listener throws and takes the process down. This connection never leaves the
			// wrapper, so the listener is ours. It logs the projection: ioredis attaches the
			// failed command to the error, and for a refused handshake that is `AUTH` with the
			// password.
			dup.on("error", (err: unknown) => {
				logger.error({ err: loggableError(err) }, "redis_duplicate_connection_error");
			});
			const inner = buildRefreshClient(dup);
			const disposable: DisposableRefreshTokenFamilyClient = {
				...inner,
				[Symbol.asyncDispose]: async () => {
					// Disposal must never fail. After a committed rotation, a rejection would
					// report failure, the client would retry with the old refresh token, and
					// replay detection would revoke the family; if the body threw, a rejecting
					// disposal would bury its error in a SuppressedError. `disconnect()` is
					// synchronous and never rejects.
					try {
						await dup.quit();
					} catch {
						dup.disconnect();
					}
				},
			};
			return disposable;
		},
	});

	const buildRefreshMulti = (p: ReturnType<Redis["multi"]>): RefreshTokenFamilyMultiClient => {
		const m: RefreshTokenFamilyMultiClient = {
			set: (k, v, _mode, ttl) => {
				p.set(k, v, "PX", ttl);
				return m;
			},
			// `null` survives as the WATCH-abort signal `updateFamily` retries on;
			// a queued SET that failed must not be reported as a committed
			// rotation.
			exec: async () => assertPipelineSucceeded(await p.exec(), "refreshTokenFamilyClient.exec"),
		};
		return m;
	};

	const refreshTokenFamilyClient = buildRefreshClient(io);

	const userSessionStoreClient: UserSessionStoreClient = {
		// Cast required because TypeScript cannot unify a single arrow function
		// against an overloaded property signature (the two `set` overloads
		// have distinct return types). The runtime branch on `cond` upholds
		// each overload's contract.
		set: ((k: string, v: string, _mode: "PX", ttl: number, cond?: "NX") =>
			cond === "NX"
				? io.set(k, v, "PX", ttl, "NX")
				: io.set(k, v, "PX", ttl)) as UserSessionStoreClient["set"],
		get: (k) => io.get(k),
		del: (k) => io.del(k),
		replaceIfUnchanged: async (k, expected, next) =>
			(await runScript(io, REPLACE_IF_UNCHANGED, [k], [expected, next])) === 1,
	};

	// `pExpireGT` is `PEXPIREAT NX` then `PEXPIREAT GT`: Redis treats a key with no TTL as
	// infinite for GT/LT/NX, so a bare GT on a fresh key would no-op and leave it persistent. NX
	// sets the first TTL; GT only raises it, so a stale `expiresAt` arriving late cannot shorten it.
	const buildRPRegistryMulti = (p: ReturnType<Redis["multi"]>): SessionRPRegistryMultiClient => {
		const m: SessionRPRegistryMultiClient = {
			hSet: (k, f, v) => {
				p.hset(k, f, v);
				return m;
			},
			pExpireAt: (k, ms) => {
				p.pexpireat(k, ms);
				return m;
			},
			pExpireGT: (k, ms) => {
				p.pexpireat(k, ms, "NX");
				p.pexpireat(k, ms, "GT");
				return m;
			},
			exec: async () => assertPipelineSucceeded(await p.exec(), "sessionRPRegistryClient.exec"),
		};
		return m;
	};

	const sessionRPRegistryClient: SessionRPRegistryClient = {
		unlink: (k) => io.unlink(k),
		hSet: (k, f, v) => io.hset(k, f, v) as Promise<number>,
		// `hscanStream` emits a flat `[field, value, field, value, …]` array per
		// cursor; re-pair it so callers never see the flattening.
		hScanIterator: (key, opts) =>
			(async function* () {
				const stream = io.hscanStream(key, { count: opts?.COUNT });
				for await (const flat of stream) {
					const pairs = flat as string[];
					for (let i = 0; i + 1 < pairs.length; i += 2) {
						yield [pairs[i] as string, pairs[i + 1] as string] as const;
					}
				}
			})(),
		multi: () => buildRPRegistryMulti(io.multi()),
		pExpireAt: (k, ms) => io.pexpireat(k, ms),
		// 1 when either NX (first write) or GT (raise) set the TTL. Returns early on NX: the GT
		// that follows a successful NX answers 0 and would misreport the first write.
		pExpireGT: async (k, ms) => {
			const nx = await io.pexpireat(k, ms, "NX");
			if (nx === 1) return nx;
			return io.pexpireat(k, ms, "GT");
		},
	};

	const buildSortedSetMulti = (p: ReturnType<Redis["multi"]>): SessionSidSortedSetMultiClient => {
		const m: SessionSidSortedSetMultiClient = {
			pExpireAt: (k, ms) => {
				p.pexpireat(k, ms);
				return m;
			},
			pExpireGT: (k, ms) => {
				p.pexpireat(k, ms, "NX");
				p.pexpireat(k, ms, "GT");
				return m;
			},
			zAdd: (k, e, opts) => {
				if (opts?.NX) p.zadd(k, "NX", e.score, e.value);
				else p.zadd(k, e.score, e.value);
				return m;
			},
			exec: async () => assertPipelineSucceeded(await p.exec(), "sessionSidSortedSetClient.exec"),
		};
		return m;
	};

	const sortedSetClient: SessionSidSortedSetClient = {
		unlink: (k) => io.unlink(k),
		multi: () => buildSortedSetMulti(io.multi()),
		pExpireAt: (k, ms) => io.pexpireat(k, ms),
		// See sessionRPRegistryClient.pExpireGT above for return-value rationale.
		pExpireGT: async (k, ms) => {
			const nx = await io.pexpireat(k, ms, "NX");
			if (nx === 1) return nx;
			return io.pexpireat(k, ms, "GT");
		},
		zAdd: (k, e, opts) =>
			opts?.NX
				? (io.zadd(k, "NX", e.score, e.value) as Promise<unknown> as Promise<number>)
				: (io.zadd(k, e.score, e.value) as Promise<unknown> as Promise<number>),
		// ioredis 6 types zrange's `stop` as `string | Buffer` (no `number`);
		// the wire protocol stringifies args anyway, so String() is lossless.
		zRange: (k, s, e) => io.zrange(k, String(s), String(e)),
		zRem: (k, m) => io.zrem(k, m) as Promise<number>,
	};

	// --- subject-keyed clients -----------------------------------------------

	const buildSubjectIndexMulti = (p: ReturnType<Redis["multi"]>) => {
		const m: SubjectSessionIndexMultiClient = {
			zAdd: (k, e) => {
				p.zadd(k, e.score, e.value);
				return m;
			},
			// Same NX-then-GT pair as the sid-keyed client, and for the same
			// reason: Redis treats a non-volatile key as having infinite TTL for
			// `GT`, so a bare `GT` silently no-ops on the first write.
			pExpireGT: (k, ms) => {
				p.pexpireat(k, ms, "NX");
				p.pexpireat(k, ms, "GT");
				return m;
			},
			exec: async () => assertPipelineSucceeded(await p.exec(), "subjectSessionIndexClient.exec"),
		};
		return m;
	};

	const subjectSessionIndexClient: SubjectSessionIndexClient = {
		multi: () => buildSubjectIndexMulti(io.multi()),
		zAdd: (k, e) => io.zadd(k, e.score, e.value) as Promise<unknown> as Promise<number>,
		async pruneExpiredAndList(key) {
			// EVALSHA-first with a NOSCRIPT fallback, as above.
			if (pruneAndListScriptCached) {
				try {
					return (await io.evalsha(LUA_PRUNE_AND_LIST_SHA, 1, key)) as string[];
				} catch (err) {
					if (!isNoScriptError(err)) throw err;
					pruneAndListScriptCached = false;
				}
			}
			const r = (await io.eval(LUA_PRUNE_AND_LIST, 1, key)) as string[];
			pruneAndListScriptCached = true;
			return r;
		},
		zRem: (k, m) => io.zrem(k, m) as Promise<number>,
		unlink: (k) => io.unlink(k),
	};

	const subjectRevocationClient: SubjectRevocationClient = {
		get: (k) => io.get(k),
		async setRevocationBoundaries(key, mode, beforeMs, expiresAtMs, grantRetentionMs) {
			// EVALSHA-first with a NOSCRIPT fallback to EVAL; see `scriptCached`.
			const args = [
				key,
				mode,
				String(beforeMs),
				String(expiresAtMs),
				String(grantRetentionMs),
			] as const;
			if (watermarkScriptCached) {
				try {
					return (await io.evalsha(LUA_SET_REVOCATION_BOUNDARIES_SHA, 1, ...args)) as string;
				} catch (err) {
					if (!isNoScriptError(err)) throw err;
					watermarkScriptCached = false;
				}
			}
			const stored = (await io.eval(LUA_SET_REVOCATION_BOUNDARIES, 1, ...args)) as string;
			// EVAL implicitly loads the script into Redis's server-side cache.
			watermarkScriptCached = true;
			return stored;
		},
	};

	const federationTokenStoreClient: FederationTokenStoreClient = {
		get: (k) => io.get(k),
		// Cast required for overloaded `set`; see UserSessionStoreClient above.
		set: ((k: string, v: string, _mode: "PX", ttl: number, cond?: "NX") =>
			cond === "NX"
				? io.set(k, v, "PX", ttl, "NX")
				: io.set(k, v, "PX", ttl)) as FederationTokenStoreClient["set"],
		del: (k) => io.del(k),
		unlink: (...keys) => io.unlink(...keys),
		// SADD and its expiry in one MULTI/EXEC, so the index key cannot be left without a TTL;
		// NX then GT as in `pExpireGT` above. MULTI rather than Lua: every command touches one
		// key, which stays valid on Cluster.
		sAddWithTtl: async (key, member, ttlMs) => {
			// EXEC succeeding does not mean the queued commands did: a refused PEXPIRE would void
			// the atomic-TTL guarantee.
			const reply = await io
				.multi()
				.sadd(key, member)
				.pexpire(key, ttlMs, "NX")
				.pexpire(key, ttlMs, "GT")
				.exec();
			assertPipelineSucceeded(reply, "federationTokenStoreClient.sAddWithTtl");
		},
		sRem: (key, member) => io.srem(key, member) as Promise<number>,
		sScanIterator: (key, opts) =>
			(async function* () {
				const stream = io.sscanStream(key, { count: opts?.COUNT });
				for await (const batch of stream) {
					for (const member of batch as string[]) yield member;
				}
			})(),
		scanIterator: ({ MATCH, COUNT }) =>
			(async function* () {
				const stream = io.scanStream({ match: MATCH, count: COUNT });
				for await (const batch of stream) {
					for (const key of batch as string[]) yield key;
				}
			})(),
		// Atomic compare-and-delete (advisory-lock release), EVALSHA-first; see `scriptCached`.
		async compareAndDelete(key, expectedValue) {
			if (scriptCached) {
				try {
					const r = (await io.evalsha(LUA_COMPARE_AND_DELETE_SHA, 1, key, expectedValue)) as number;
					return r === 1;
				} catch (err) {
					if (!isNoScriptError(err)) throw err;
					scriptCached = false;
					// Fall through to EVAL.
				}
			}
			const r = (await io.eval(LUA_COMPARE_AND_DELETE, 1, key, expectedValue)) as number;
			// EVAL loads the script into the server's cache, so the next EVALSHA hits.
			scriptCached = true;
			return r === 1;
		},
	};

	const incrementWithTtlAndPttl = async (
		k: string,
		ttlSeconds: number,
	): Promise<RateLimitIncrement> => {
		const [count, pttl] = (await io.eval(LUA_INCREMENT_WITH_TTL, 1, k, String(ttlSeconds))) as [
			number,
			number,
		];
		return { count, pttl };
	};
	const rateLimiterClient: RateLimiterClient = {
		// One script for both; the count-only method serves callers that hold this client directly.
		incrementWithTtl: async (k, ttlSeconds) => (await incrementWithTtlAndPttl(k, ttlSeconds)).count,
		incrementWithTtlAndPttl,
	};

	// Authorization codes: short-lived, high-volume records mapped directly onto ioredis commands.
	const codeRepositoryClient: CodeRepositoryClient = {
		set: (k, v, _mode, ttlMs) => io.set(k, v, "PX", ttlMs) as Promise<"OK">,
		get: (k) => io.get(k),
		getDel: (k) => io.getdel(k),
		del: (k) => io.del(k),
	};

	// Each device-code operation is one Lua script; see the `LUA_DEVICE_CODE_*` docblocks.
	const deviceCodeStoreClient: DeviceCodeStoreClient = {
		async create(keys, input) {
			const fields = Object.entries(input.fields).flatMap(([field, value]) =>
				value === undefined ? [] : [field, value],
			);
			const reply = await runScript(
				io,
				DEVICE_CODE_CREATE,
				[keys.codeKeyPrefix + input.deviceCode, keys.userKeyPrefix + input.userCode],
				[input.deviceCode, String(input.expiresAtMs), ...fields],
			);
			// 1 written, 0 a key already there. Any other reply is an error, not a collision the
			// endpoint would re-draw codes against.
			if (reply === 1) return true;
			if (reply === 0) return false;
			throw new Error(
				`deviceCodeStoreClient.create: unexpected reply from the create script (${typeof reply})`,
			);
		},
		async findPending(keys, userCode, nowMs) {
			const reply = await runScript(
				io,
				DEVICE_CODE_FIND_PENDING,
				[keys.userKeyPrefix + userCode],
				[keys.codeKeyPrefix, String(nowMs)],
			);
			return reply === null ? null : deviceCodeRecordOf(reply);
		},
		async decide(keys, userCode, nowMs, input) {
			const approval = input.decision === "approved" ? input : undefined;
			const reply = (await runScript(
				io,
				DEVICE_CODE_DECIDE,
				[keys.userKeyPrefix + userCode],
				[
					keys.codeKeyPrefix,
					String(nowMs),
					input.decision,
					approval?.subject ?? "",
					approval?.grantedScope === undefined ? "requested" : "narrow",
					JSON.stringify(approval?.grantedScope ?? []),
				],
			)) as [string, unknown?];
			switch (reply[0]) {
				case "ok":
					return { kind: "ok", fields: deviceCodeRecordOf(reply[1]) };
				case "already_decided":
					return {
						kind: "already_decided",
						status: reply[1] === "approved" ? "approved" : "denied",
					};
				case "expired":
					return { kind: "expired" };
				default:
					return { kind: "not_found" };
			}
		},
		async poll(keys, deviceCode, nowMs, slowDownIncrementSeconds) {
			const reply = (await runScript(
				io,
				DEVICE_CODE_POLL,
				[keys.codeKeyPrefix + deviceCode],
				[String(nowMs), keys.userKeyPrefix, String(slowDownIncrementSeconds)],
			)) as [string, unknown?];
			switch (reply[0]) {
				case "approved":
					return { kind: "approved", fields: deviceCodeRecordOf(reply[1]) };
				case "slow_down":
					return { kind: "slow_down", intervalSeconds: Number(reply[1]) };
				case "expired":
					return { kind: "expired" };
				case "denied":
					return { kind: "denied" };
				case "pending":
					return { kind: "pending" };
				default:
					return { kind: "not_found" };
			}
		},
		async remove(keys, deviceCode) {
			await runScript(
				io,
				DEVICE_CODE_REMOVE,
				[keys.codeKeyPrefix + deviceCode],
				[keys.userKeyPrefix],
			);
		},
	};

	// Each indivisible consent operation is one Lua script (see the `LUA_CONSENT_*` and
	// `LUA_PENDING_CONSENT_*` docblocks). A parked request and its session's index share the
	// `{pending}` hash tag, so a key a script derives is in the slot it was routed to.
	const consentStoreClient: ConsentStoreClient = {
		async find(key, nowMs) {
			const reply = (await runScript(io, CONSENT_FIND, [key], [String(nowMs)])) as
				| [string, string, string | null]
				| null;
			if (!Array.isArray(reply)) return null;
			const [scopes, grantedAt, expiresAt] = reply;
			const fields: ConsentRecordFields = {
				scopes,
				grantedAt,
				expiresAt: expiresAt ?? undefined,
			};
			return fields;
		},
		async grant(key, input) {
			await runScript(
				io,
				CONSENT_GRANT,
				[key],
				[
					String(input.nowMs),
					String(input.grantedAt),
					JSON.stringify(input.scopes),
					input.expiry === undefined ? "" : String(input.expiry.expiresAt),
					input.expiry === undefined ? "" : String(Math.ceil(input.expiry.ttlMs)),
				],
			);
		},
		async revoke(key) {
			return (await io.del(key)) > 0;
		},
	};

	const pendingConsentStoreClient: PendingConsentStoreClient = {
		async set(keys, input) {
			await runScript(
				io,
				PENDING_CONSENT_SET,
				[keys.recordKeyPrefix + input.challenge, keys.sessionKeyPrefix + input.sessionId],
				[
					String(input.nowMs),
					input.challenge,
					input.sessionId,
					String(input.expiresAt),
					String(Math.ceil(input.ttlMs)),
					input.record,
					String(input.perSessionLimit),
					keys.recordKeyPrefix,
					keys.sessionKeyPrefix,
				],
			);
		},
		async get(keys, challenge, nowMs) {
			const reply = await runScript(
				io,
				PENDING_CONSENT_TAKE,
				[keys.recordKeyPrefix + challenge],
				[String(nowMs), challenge, keys.sessionKeyPrefix, "peek"],
			);
			return typeof reply === "string" ? reply : null;
		},
		async consume(keys, challenge, nowMs) {
			const reply = await runScript(
				io,
				PENDING_CONSENT_TAKE,
				[keys.recordKeyPrefix + challenge],
				[String(nowMs), challenge, keys.sessionKeyPrefix, "spend"],
			);
			return typeof reply === "string" ? reply : null;
		},
		async discard(keys, challenge, record) {
			const reply = await runScript(
				io,
				PENDING_CONSENT_DISCARD,
				[keys.recordKeyPrefix + challenge],
				[record, challenge, keys.sessionKeyPrefix],
			);
			return reply === 1;
		},
	};

	return {
		challengeStoreClient,
		accessTokenDenylistClient,
		replaySeenSetClient,
		refreshTokenFamilyClient,
		userSessionStoreClient,
		sessionRPRegistryClient,
		sessionFamilyIndexClient: sortedSetClient,
		sessionFederationIndexClient: sortedSetClient,
		subjectSessionIndexClient,
		subjectRevocationClient,
		federationTokenStoreClient,
		rateLimiterClient,
		codeRepositoryClient,
		deviceCodeStoreClient,
		consentStoreClient,
		pendingConsentStoreClient,
		mfaFactorStoreClient: makeIoredisMfaFactorStoreClient(io),
		mfaTransactionStoreClient: makeIoredisMfaTransactionStoreClient(io),
	};
}

/**
 * The commands a federation grant store needs from its connection.
 *
 * Narrower than `Redis` on purpose: everything a write does happens inside a
 * script, and a listing's reads are routed one key at a time, so a Cluster
 * client satisfies this too — without widening the WATCH-based adapters in
 * {@link makeIoredisClients}, which a Cluster cannot serve.
 */
export interface FederationGrantRedisCommands {
	evalsha(sha: string, numkeys: number, ...args: (string | number)[]): Promise<unknown>;
	eval(script: string, numkeys: number, ...args: (string | number)[]): Promise<unknown>;
	zrange(key: string, start: number, stop: number): Promise<string[]>;
	set(
		key: string,
		value: string,
		expiryMode: "PX",
		ttlMs: number,
		condition: "NX",
	): Promise<"OK" | null>;
}

/**
 * The federation grant store's connection, separate from {@link makeIoredisClients} so that a
 * Cluster deployment can have one.
 */
export function makeIoredisFederationGrantStoreClient(
	// `Redis` beside the narrow interface: ioredis's overloaded `zrange` is not assignable to the
	// interface's signature, so a strict caller could not pass its `Redis`. A Cluster client
	// still satisfies the interface.
	io: FederationGrantRedisCommands | Redis,
): FederationGrantStoreClient {
	const connection = io as unknown as Redis;
	return {
		async createPending(grantKey, credKey, input) {
			return fgWritten(
				await runScript(
					connection,
					FG_CREATE,
					[grantKey, credKey],
					[
						fgNumber(input.nowMs),
						input.base,
						input.handle,
						fgNumber(input.intentExpiresAtMs),
						fgNumber(input.retentionMs),
					],
				),
			);
		},

		async snapshot(grantKey, credKey) {
			const reply = await runScript(connection, FG_SNAPSHOT, [grantKey, credKey], []);
			if (!Array.isArray(reply) || reply[0] !== 1) return null;
			return {
				fields: fgFields(reply[1]),
				credential: typeof reply[2] === "string" ? reply[2] : null,
			};
		},

		async nameIntent(grantKey, input) {
			return fgWritten(
				await runScript(
					connection,
					FG_NAME_INTENT,
					[grantKey],
					[fgNumber(input.nowMs), input.handle, fgNumber(input.intentExpiresAtMs)],
				),
			);
		},

		async retireIntent(grantKey, input) {
			return fgWritten(
				await runScript(
					connection,
					FG_RETIRE_INTENT,
					[grantKey],
					[fgNumber(input.nowMs), input.handle === undefined ? "0" : "1", input.handle ?? ""],
				),
			);
		},

		async activate(grantKey, credKey, input) {
			return fgWritten(
				await runScript(
					connection,
					FG_ACTIVATE,
					[grantKey, credKey],
					[
						fgNumber(input.nowMs),
						input.handle,
						input.authorization,
						fgNumber(input.expiresAtMs),
						input.identityRevision,
						input.upstreamIssuer,
						input.upstreamSubject,
						input.credential,
					],
				),
			);
		},

		async replaceCredentials(grantKey, credKey, input) {
			return fgWritten(
				await runScript(
					connection,
					FG_REPLACE,
					[grantKey, credKey],
					[
						fgNumber(input.nowMs),
						fgNumber(input.expectedVersion),
						input.credential,
						input.ineligible === null ? "0" : "1",
						input.ineligible ?? "",
					],
				),
			);
		},

		async requireReauthorization(grantKey, credKey, input) {
			return fgWritten(
				await runScript(
					connection,
					FG_REQUIRE_REAUTH,
					[grantKey, credKey],
					[fgNumber(input.nowMs), fgNumber(input.expectedVersion)],
				),
			);
		},

		async revoke(grantKey, credKey, input) {
			return fgWritten(
				await runScript(
					connection,
					FG_REVOKE,
					[grantKey, credKey],
					[fgNumber(input.atMs), input.by],
				),
			);
		},

		async noteRefreshFailure(grantKey, input) {
			return fgWritten(
				await runScript(
					connection,
					FG_NOTE_FAILURE,
					[grantKey],
					[
						fgNumber(input.nowMs),
						fgNumber(input.expectedVersion),
						fgNumber(input.atMs),
						input.kind,
						fgNumber(input.rowMs),
						input.retryAfterSeconds === undefined ? "0" : "1",
						input.retryAfterSeconds === undefined ? "" : String(input.retryAfterSeconds),
						input.upstreamCode === undefined ? "0" : "1",
						input.upstreamCode ?? "",
					],
				),
			);
		},

		async touch(grantKey, atMs) {
			await runScript(connection, FG_TOUCH, [grantKey], [fgNumber(atMs)]);
		},

		async reserve(indexKey, member, horizonMs, allowanceMs) {
			await runScript(
				connection,
				FG_RESERVE,
				[indexKey],
				[member, fgNumber(horizonMs), fgNumber(allowanceMs)],
			);
		},

		async tryLock(lockKey, token, ttlMs) {
			const reply = await io.set(lockKey, token, "PX", ttlMs, "NX");
			return reply === "OK";
		},

		async unlock(lockKey, token) {
			await runScript(connection, FG_UNLOCK, [lockKey], [token]);
		},

		async members(indexKey) {
			// Through the narrow interface, with numbers: a client written to it —
			// a Cluster's, an operator's own — is promised numbers, and the union
			// parameter above has no one `zrange` signature to call directly.
			return await (io as FederationGrantRedisCommands).zrange(indexKey, 0, -1);
		},

		async prune(indexKey, clockMs, allowanceMs) {
			await runScript(connection, FG_PRUNE, [indexKey], [fgNumber(clockMs), fgNumber(allowanceMs)]);
		},
	};
}

// --- federation grant intents -----------------------------------------------

/** What the intent scripts need of a connection: the script calls, and nothing else. */
export interface FederationGrantIntentRedisCommands {
	evalsha(sha: string, numkeys: number, ...args: (string | number)[]): Promise<unknown>;
	eval(script: string, numkeys: number, ...args: (string | number)[]): Promise<unknown>;
	hmget(key: string, ...fields: string[]): Promise<(string | null)[]>;
	exists(key: string): Promise<number>;
}

/**
 * The two reads are plain commands, not scripts: nothing is written, so
 * nothing needs to be one step with anything else. Whatever a read concludes,
 * the write that follows it — parking, answering — checks again inside its own
 * script, so a read that raced a write can only make a caller give up early,
 * never let one through.
 */
const fgiLiveUntil = (fields: readonly (string | null)[], nowMs: number): boolean => {
	const expiresAt = Number(fields[0]);
	return Number.isFinite(expiresAt) && nowMs < expiresAt;
};

const ADMISSION_REFUSALS = new Set(["limit", "collision", "closed", "expired"]);

/**
 * The federation grant intent store's connection. It may be the grant store's own: nothing
 * here needs a second one, and the keys live under a different hash tag either way.
 */
export function makeIoredisFederationGrantIntentStoreClient(
	io: FederationGrantIntentRedisCommands,
): FederationGrantIntentStoreClient {
	const connection = io as unknown as Redis;
	return {
		async admitIntent(prefix, input): Promise<FederationGrantIntentAdmission> {
			const reply = await runScript(
				connection,
				FGI_ADMIT,
				[`${prefix}i:${input.handle}`],
				[
					prefix,
					input.handle,
					input.record,
					fgNumber(input.expiresAtMs),
					fgNumber(input.nowMs),
					input.pair,
					input.counts ? "1" : "0",
					fgNumber(input.limit),
					fgNumber(input.reservationAllowanceMs),
				],
			);
			const outcome = Array.isArray(reply) ? reply[0] : undefined;
			if (outcome === "created" || outcome === "unchanged") return { outcome };
			const reason = Array.isArray(reply) ? reply[1] : undefined;
			if (outcome === "refused" && typeof reason === "string" && ADMISSION_REFUSALS.has(reason)) {
				return {
					outcome: "refused",
					reason: reason as FederationGrantIntentAdmission["reason"] & string,
				};
			}
			// A reply this release does not know is not an admission: say so rather
			// than let a record the caller believes it wrote go unwritten silently.
			throw new Error(
				"federation grant intent store: the admission script answered nothing it knows",
			);
		},

		async readIntent(prefix, handle, nowMs) {
			const fields = await io.hmget(`${prefix}i:${handle}`, "expiresAt", "closed", "record");
			if (fields[1] === "1" || !fgiLiveUntil(fields, nowMs)) return null;
			return fields[2] ?? null;
		},

		async parkConsent(prefix, input) {
			return fgiText(
				await runScript(
					connection,
					FGI_PARK,
					[`${prefix}i:${input.handle}`],
					[
						prefix,
						input.handle,
						input.challenge,
						input.record,
						input.binding,
						fgNumber(input.expiresAtMs),
						fgNumber(input.nowMs),
					],
				),
			);
		},

		async readConsent(prefix, challenge, nowMs) {
			const fields = await io.hmget(`${prefix}c:${challenge}`, "expiresAt", "intent", "record");
			if (!fgiLiveUntil(fields, nowMs) || fields[1] === null || fields[1] === undefined)
				return null;
			// While its intent is still there: a consent outliving a reclaimed intent
			// answers nothing, whichever key Redis happened to drop first.
			if ((await io.exists(`${prefix}i:${fields[1]}`)) === 0) return null;
			return fields[2] ?? null;
		},

		async answerConsent(prefix, input): Promise<FederationGrantConsentAnswered> {
			const reply = await runScript(
				connection,
				FGI_ANSWER,
				[`${prefix}c:${input.challenge}`],
				[
					prefix,
					fgNumber(input.nowMs),
					input.binding,
					input.decision,
					input.state ?? "",
					input.transaction ?? "",
					fgNumber(input.transactionExpiresAtMs ?? 0),
					input.connection ?? "",
				],
			);
			const outcome = Array.isArray(reply) ? reply[0] : undefined;
			const record = Array.isArray(reply) && typeof reply[1] === "string" ? reply[1] : undefined;
			if (outcome === "denied" || outcome === "accepted") {
				return record === undefined ? { outcome } : { outcome, record };
			}
			if (outcome === "state_collision" || outcome === "empty") return { outcome };
			throw new Error("federation grant intent store: the answer script answered nothing it knows");
		},

		async consumeTransaction(prefix, input) {
			return fgiText(
				await runScript(
					connection,
					FGI_CONSUME,
					[`${prefix}tx:${input.state}`],
					[prefix, input.connection, fgNumber(input.nowMs)],
				),
			);
		},

		async finishIntent(prefix, handle, _nowMs) {
			await runScript(connection, FGI_FINISH, [`${prefix}i:${handle}`], [prefix, handle]);
		},
	};
}

// --- MFA stores ----------------------------------------------------------------
// See packages/core/docs/adr/2026-09-25-multi-factor-authentication.md.

/**
 * The `MfaFactorStore`'s client over one ioredis connection. Also part of
 * {@link makeIoredisClients}; exported alone so a deployment can keep enrolled factors on a
 * dedicated database or instance, as the MFA ADR's durability requirements prefer.
 */
export function makeIoredisMfaFactorStoreClient(io: Redis): MfaFactorStoreClient {
	return {
		async list(key) {
			return await io.hgetall(key);
		},
		async create(key, field, value) {
			return (await io.hsetnx(key, field, value)) === 1;
		},
		async update(key, field, input) {
			const reply = await runScript(
				io,
				MFA_FACTOR_UPDATE,
				[key],
				[field, input.expectedVersion, input.nextVersion, input.mutable],
			);
			return typeof reply === "string" ? reply : null;
		},
		async remove(key, field) {
			await io.hdel(key, field);
		},
		async removeAll(key) {
			await io.del(key);
		},
		durability: () => redisDurability(io),
	};
}

const HOLDS: ReadonlySet<unknown> = new Set(["backoff", "weekly", "hard"]);

/**
 * The `MfaTransactionStore`'s client over one ioredis connection. Also part of
 * {@link makeIoredisClients}; exported alone so a deployment can give it a dedicated database
 * or instance.
 */
export function makeIoredisMfaTransactionStoreClient(io: Redis): MfaTransactionStoreClient {
	return {
		async create(key, fields, deadlineMs) {
			const reply = await runScript(
				io,
				MFA_TX_CREATE,
				[key],
				[fgNumber(deadlineMs), ...Object.entries(fields).flat()],
			);
			return reply === 1;
		},
		async read(key) {
			return await io.hgetall(key);
		},
		async update(key, input) {
			const set = Object.entries(input.set);
			const reply = await runScript(
				io,
				MFA_TX_UPDATE,
				[key],
				[
					input.expectedVersion,
					input.incarnation,
					String(set.length),
					...set.flat(),
					...input.clear,
				],
			);
			return Array.isArray(reply) ? hashFields(reply) : null;
		},
		async reserveAttempt(key, max, nowMs) {
			const reply = await runScript(
				io,
				MFA_TX_RESERVE_ATTEMPT,
				[key],
				[String(max), String(nowMs)],
			);
			const [ok, attempts] = Array.isArray(reply) ? reply : [0, 0];
			return { ok: ok === 1, attempts: Number(attempts) };
		},
		async takeChallenge(key, expectedVersion, nowMs) {
			const reply = await runScript(
				io,
				MFA_TX_TAKE_CHALLENGE,
				[key],
				[expectedVersion, String(nowMs)],
			);
			return typeof reply === "string" ? reply : null;
		},
		async consume(key, expectedVersion) {
			const reply = await runScript(io, MFA_TX_CONSUME, [key], [expectedVersion]);
			return Array.isArray(reply) ? hashFields(reply) : null;
		},
		async reserveSubjectAttempt(keys, input) {
			const { policy } = input;
			const reply = await runScript(
				io,
				MFA_SUBJECT_RESERVE,
				[keys.lock, keys.week],
				[
					String(input.nowMs),
					String(policy.threshold),
					String(policy.baseSeconds),
					String(policy.maxSeconds),
					String(policy.memorySeconds),
					String(policy.weeklyBudget),
					String(policy.hardLimit),
					input.reservation,
				],
			);
			if (Array.isArray(reply) && reply[0] === "ok") return { ok: true };
			const [outcome, hold, retry, first] = Array.isArray(reply) ? reply : [];
			if (outcome === "held" && HOLDS.has(hold) && (first === "1" || first === "0")) {
				return {
					ok: false,
					hold: hold as "backoff" | "weekly" | "hard",
					retryAfterMs: retry === "" ? null : Number(retry),
					first: first === "1",
				};
			}
			// A reply this release does not know is not a verdict: refuse the
			// attempt as an outage rather than let it through or hold it.
			throw new Error("MfaTransactionStore: the reservation script answered nothing it knows");
		},
		async settleSubjectAttempt(keys, reservation, outcome) {
			await runScript(io, MFA_SUBJECT_SETTLE, [keys.lock, keys.week], [reservation, outcome]);
		},
		async noteExemptSuccess(keys, input) {
			await runScript(io, MFA_SUBJECT_EXEMPT, [keys.lock, keys.week], [String(input.nowMs)]);
		},
		async clearSubjectState(keys) {
			await io.del(keys.lock, keys.week);
		},
		async requireEmailProof(key) {
			await io.set(key, "1");
		},
		async emailProofRequired(key) {
			return (await io.exists(key)) === 1;
		},
		async consumeEmailProof(key) {
			return (await io.del(key)) === 1;
		},
		durability: () => redisDurability(io),
	};
}
