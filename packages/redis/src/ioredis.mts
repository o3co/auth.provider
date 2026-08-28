/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import { createHash } from "node:crypto";
import { consoleLogger, type EventLogger } from "@o3co/auth-provider-core";
import type { Redis } from "ioredis";
import type {
	AccessTokenDenylistClient,
	ChallengeStoreClient,
	CodeRepositoryClient,
	DisposableRefreshTokenFamilyClient,
	FederationTokenStoreClient,
	RateLimiterClient,
	RefreshTokenFamilyClient,
	RefreshTokenFamilyMultiClient,
	ReplaySeenSetClient,
	SessionRPRegistryClient,
	SessionRPRegistryMultiClient,
	SessionSidSortedSetClient,
	SessionSidSortedSetMultiClient,
	UserSessionStoreClient,
} from "./clients.mjs";

/**
 * Rate-limit counter increment, atomic with its expiry (#269).
 *
 * `INCR` then a separate `EXPIRE` is not safe: a process death or an error
 * between the two leaves the key with no TTL, and a counter that never resets
 * 429s its client forever.
 *
 * The expiry is (re)established whenever the key has none — `TTL` returns -1
 * for a key with no expiry — rather than only on the first hit. That is what
 * repairs a key already stranded without a TTL by the previous
 * implementation; a "first hit" guard never fires for one, because its count
 * never comes back to 1. An existing expiry is left alone, so a steady stream
 * of requests cannot hold the window open by refreshing it.
 *
 * `TTL` rather than `EXPIRE ... NX`: the NX flag is Redis 7.0+, and this
 * package is used against whatever Redis the consumer runs.
 */
const LUA_INCREMENT_WITH_TTL = `
local count = redis.call('INCR', KEYS[1])
if redis.call('TTL', KEYS[1]) < 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return count
`.trim();

/**
 * Lua compare-and-delete script — atomic alternative to GET+DEL.
 * Returns 1 when the key was deleted (caller's token matched), 0 otherwise.
 * `KEYS[1]` = the lock key; `ARGV[1]` = the caller's acquire token.
 */
const LUA_COMPARE_AND_DELETE = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
else
  return 0
end
`.trim();

/**
 * Precomputed SHA-1 digest of `LUA_COMPARE_AND_DELETE`. Redis indexes its
 * server-side script cache by SHA-1 of the bytewise script source, so this
 * digest is deterministic and matches what `SCRIPT LOAD` would return. We
 * compute it once at module load and skip the extra round-trip that a
 * `SCRIPT LOAD` would cost on every cold-cache `EVAL` fallback.
 */
const LUA_COMPARE_AND_DELETE_SHA = createHash("sha1").update(LUA_COMPARE_AND_DELETE).digest("hex");

/**
 * Module-level flag tracking whether the script is currently expected to be
 * resident in the Redis server's script cache. `true` means the next call
 * may use `EVALSHA`; `false` (e.g. after a `NOSCRIPT` error from
 * `SCRIPT FLUSH` or cluster failover) means the next call must use `EVAL`,
 * which implicitly re-loads the script and lets us flip back to `true`.
 *
 * Module scope (not per-`makeIoredisClients` call) because the script is
 * constant: multiple ioredis clients in the same process share the same
 * cache state on the same Redis server.
 */
let scriptCached = false;

/**
 * Surface per-command failures from a `MULTI`/`EXEC` reply.
 *
 * ioredis resolves `exec()` with one `[error, result]` tuple per queued
 * command and **does not reject** when one of them failed — `EXEC` itself
 * succeeded, after all. Every pipeline in this file used to discard that reply,
 * so a `PEXPIRE … NX/GT` refused by an older or misconfigured Redis left the
 * key with no TTL at all while the caller was told the write went through. That
 * is the same shape as the bug #269 paid for with the rate limiter: an expiry
 * that silently never got set, on a key nothing revisits.
 *
 * `null` is not a failure and is passed through unchanged: it is the
 * WATCH-abort signal, which `refresh-token-family`'s CAS loop reads as
 * "conflict, retry". Turning that into a throw would break refresh-token
 * rotation under contention.
 *
 * The first failure wins — the reply is reported through `cause`, so the
 * driver's own message ("WRONGTYPE …", "OOM …") survives for the operator.
 */
function assertPipelineSucceeded(reply: unknown[] | null, operation: string): unknown[] | null {
	if (reply === null) return null;
	for (const entry of reply) {
		// ioredis tuple shape; a wrapper returning bare results simply has no
		// error slot to find, which is correct rather than silently lenient.
		const err = Array.isArray(entry) ? entry[0] : null;
		if (err) {
			throw new Error(
				`${operation}: a queued command failed inside MULTI/EXEC — ${String(
					err instanceof Error ? err.message : err,
				)}`,
				{ cause: err },
			);
		}
	}
	return reply;
}

/**
 * Wrap a single ioredis connection into the 11 typed client wrappers
 * needed by `@o3co/auth-provider-redis` adapters. Production consumers
 * use this factory in their composition root and spread the result into
 * `bootstrapComponents`.
 *
 * Every returned client issues its commands against the one connection passed
 * in — this factory opens nothing of its own (the sole exception is
 * `refreshTokenFamilyClient.duplicate()`, which is per rotation, not per
 * purpose). Connection-level ioredis options are therefore shared by all
 * eleven purposes, so a composition root that needs different failure timing
 * for one of them — `enableOfflineQueue: false` on the rate limiter, say —
 * has to build that purpose off a second connection deliberately (#286).
 *
 * Lives on the `@o3co/auth-provider-redis/ioredis` subpath so that consumers
 * importing the main entry (`@o3co/auth-provider-redis`) do NOT pull
 * `ioredis` types into their TypeScript dependency closure. The main entry
 * stays vendor-agnostic; only callers of `makeIoredisClients` need ioredis
 * installed. Future per-vendor wrappers (e.g. node-redis) will follow the
 * same `@o3co/auth-provider-redis/<vendor>` subpath convention.
 *
 * Per Copilot review on PR #102.
 *
 *     const io = new Redis(...);
 *     const clients = makeIoredisClients(io);
 *     await createApp({
 *         modules: [...],
 *         bootstrapComponents: { config, pathResolver, ...clients },
 *     });
 *
 * Mixed-backend deployments (e.g. memcached for ChallengeStore + redis
 * for FederationTokenStore) wire each slot individually instead of
 * spreading.
 *
 * Per Phase 10 addendum §3.
 *
 * @param options.logger — where errors from connections this wrapper opens
 *   itself (see `refreshTokenFamilyClient.duplicate()`) are reported. Defaults
 *   to `consoleLogger`. Typed as `EventLogger` rather than `Logger` because
 *   composition roots pass their host logger here, and a logger without
 *   `trace` / `fatal` / `child` cannot satisfy `Logger`. The connection passed
 *   in as `io` stays the caller's responsibility — they own its lifetime and
 *   its listeners; see the README for the listener it needs.
 */
export interface IoredisClientsOptions {
	/** See {@link makeIoredisClients}. */
	readonly logger?: EventLogger;
}

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
	federationTokenStoreClient: FederationTokenStoreClient;
	rateLimiterClient: RateLimiterClient;
	codeRepositoryClient: CodeRepositoryClient;
} {
	const logger = options.logger ?? consoleLogger;

	const challengeStoreClient: ChallengeStoreClient = {
		set: (k, v, _mode, ttl, _cond) => io.set(k, v, "PX", ttl, "NX") as Promise<"OK" | null>,
		pttl: (k) => io.pttl(k),
		del: (k) => io.del(k),
	};

	// #277: revoked access-token jtis. Plain PX SET (no NX) — re-revoking a jti
	// is idempotent and last-write-wins on the expiry.
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
			// ioredis `duplicate()` copies options but NOT event listeners, so a
			// fresh duplicate starts with zero `error` listeners — and an
			// EventEmitter `error` with none throws, taking the process down.
			// One of these is opened per refresh rotation, so a socket blip on
			// any short-lived duplicate crashed the provider. The parent
			// connection is the caller's to instrument; this one is ours,
			// because it never leaves this wrapper.
			dup.on("error", (err: unknown) => {
				logger.error({ err }, "redis_duplicate_connection_error");
			});
			const inner = buildRefreshClient(dup);
			const disposable: DisposableRefreshTokenFamilyClient = {
				...inner,
				[Symbol.asyncDispose]: async () => {
					// Disposal must never be the thing that fails. This runs on an
					// `await using` binding around a refresh rotation: if `quit()`
					// rejects after the rotation already committed, the grant reports
					// failure for committed work, the client retries with the old
					// refresh token, replay detection fires, and the whole family is
					// revoked — the user is forced to re-login. And if the body
					// already threw, a rejecting disposal wraps it in a
					// SuppressedError that hides the original.
					//
					// `disconnect()` tears the socket down synchronously and does not
					// reject, so it is the correct fallback for a connection that is
					// already gone.
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
	};

	// `pExpireGT` is implemented as `PEXPIREAT NX` followed by `PEXPIREAT GT`
	// (D-10). Redis 7.0+ treats a non-volatile key as having infinite TTL for
	// the GT/LT/NX flags, so a bare `PEXPIREAT … GT` against a freshly-created
	// key (no existing TTL) would silently no-op and leave the key persistent.
	// The NX clause sets the TTL on first write; the GT clause raises it on
	// subsequent same-sid writes only when the new ts is strictly greater
	// (preventing the CR-3 truncation race when a stale `expiresAt` value
	// arrives concurrently). Same effect in 2 commands within one pipeline.
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
		// cursor; re-pair it so callers never see the flattening (#291).
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
		// Returns 1 when either NX (first-write) or GT (raise) sets the TTL,
		// 0 otherwise. Without the early return on NX success the caller would
		// observe a "failure" (0 from the GT clause that no-ops once NX has
		// already set TTL == ms), which misreports first-write success.
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

	const federationTokenStoreClient: FederationTokenStoreClient = {
		get: (k) => io.get(k),
		// Cast required for overloaded `set`; see UserSessionStoreClient above.
		set: ((k: string, v: string, _mode: "PX", ttl: number, cond?: "NX") =>
			cond === "NX"
				? io.set(k, v, "PX", ttl, "NX")
				: io.set(k, v, "PX", ttl)) as FederationTokenStoreClient["set"],
		del: (k) => io.del(k),
		unlink: (...keys) => io.unlink(...keys),
		// #291: SADD and its expiry in one MULTI/EXEC, so the pair cannot come
		// apart and strand the index key with no TTL. `PEXPIRE … NX` +
		// `PEXPIRE … GT` is the D-10 pair: NX bootstraps the TTL (a bare GT
		// no-ops on a key Redis considers infinite-TTL), GT then raises it
		// without ever truncating a further deadline. Both flags are Redis 7.0+;
		// this package pins 7.2 LTS. MULTI rather than Lua because every command
		// touches the same single key, which keeps it valid on Cluster too.
		sAddWithTtl: async (key, member, ttlMs) => {
			// EXEC succeeding does not mean the queued commands did — inspect the
			// reply, or a refused PEXPIRE silently voids the atomic-TTL guarantee
			// this method's contract makes.
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
		// D-9: atomic compare-and-delete via Lua. EVALSHA on the hot path with a
		// precomputed module-level SHA-1; on `NOSCRIPT` (cold cache after
		// SCRIPT FLUSH or cluster failover) falls back to EVAL, which Redis
		// implicitly loads into its server-side cache so the next EVALSHA hits.
		async compareAndDelete(key, expectedValue) {
			if (scriptCached) {
				try {
					const r = (await io.evalsha(LUA_COMPARE_AND_DELETE_SHA, 1, key, expectedValue)) as number;
					return r === 1;
				} catch (err) {
					if (!(err instanceof Error) || !err.message.includes("NOSCRIPT")) throw err;
					scriptCached = false;
					// Fall through to EVAL.
				}
			}
			const r = (await io.eval(LUA_COMPARE_AND_DELETE, 1, key, expectedValue)) as number;
			// EVAL implicitly loads the script into Redis's server-side cache;
			// future EVALSHA hits with the precomputed SHA. No extra SCRIPT LOAD
			// round-trip required.
			scriptCached = true;
			return r === 1;
		},
	};

	const rateLimiterClient: RateLimiterClient = {
		incrementWithTtl: async (k, ttlSeconds) =>
			(await io.eval(LUA_INCREMENT_WITH_TTL, 1, k, String(ttlSeconds))) as number,
	};

	// OR-9: code-repository client. Codes are short-TTL (60-600s) high-volume
	// records; the four-method surface (`set`/`get`/`getDel`/`del`) maps
	// directly to ioredis primitives. Shares the same socket as the other
	// per-purpose clients.
	const codeRepositoryClient: CodeRepositoryClient = {
		set: (k, v, _mode, ttlMs) => io.set(k, v, "PX", ttlMs) as Promise<"OK">,
		get: (k) => io.get(k),
		getDel: (k) => io.getdel(k),
		del: (k) => io.del(k),
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
		federationTokenStoreClient,
		rateLimiterClient,
		codeRepositoryClient,
	};
}
