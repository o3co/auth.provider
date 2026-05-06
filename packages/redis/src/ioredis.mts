/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
import type { Redis } from "ioredis";
import type {
	ChallengeStoreClient,
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
 * Module-level cache of the SHA-1 digest returned by `SCRIPT LOAD` for
 * `LUA_COMPARE_AND_DELETE`. Lazily populated by the first `EVALSHA`
 * fallback path. Module scope (not per-`makeIoredisClients` call) because
 * the script is constant — multiple ioredis clients in the same process
 * share the same SHA on the same Redis server. The fallback path resets
 * this to `null` on `NOSCRIPT` (e.g. after `SCRIPT FLUSH` or cluster
 * failover) and re-loads on the next call.
 */
let cachedLuaSha: string | null = null;

/**
 * Wrap a single ioredis connection into the 9 typed client wrappers
 * needed by `@o3co/auth-provider-redis` adapters. Production consumers
 * use this factory in their composition root and spread the result into
 * `bootstrapComponents`.
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
 */
export function makeIoredisClients(io: Redis): {
	challengeStoreClient: ChallengeStoreClient;
	replaySeenSetClient: ReplaySeenSetClient;
	refreshTokenFamilyClient: RefreshTokenFamilyClient;
	userSessionStoreClient: UserSessionStoreClient;
	sessionRPRegistryClient: SessionRPRegistryClient;
	sessionFamilyIndexClient: SessionSidSortedSetClient;
	sessionFederationIndexClient: SessionSidSortedSetClient;
	federationTokenStoreClient: FederationTokenStoreClient;
	rateLimiterClient: RateLimiterClient;
} {
	const challengeStoreClient: ChallengeStoreClient = {
		set: (k, v, _mode, ttl, _cond) => io.set(k, v, "PX", ttl, "NX") as Promise<"OK" | null>,
		pttl: (k) => io.pttl(k),
		del: (k) => io.del(k),
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
			const inner = buildRefreshClient(dup);
			const disposable: DisposableRefreshTokenFamilyClient = {
				...inner,
				[Symbol.asyncDispose]: async () => {
					await dup.quit();
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
			exec: async () => p.exec(),
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
			exec: async () => p.exec(),
		};
		return m;
	};

	const sessionRPRegistryClient: SessionRPRegistryClient = {
		del: (k) => io.del(k),
		hSet: (k, f, v) => io.hset(k, f, v) as Promise<number>,
		hVals: (k) => io.hvals(k),
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
			exec: async () => p.exec(),
		};
		return m;
	};

	const sortedSetClient: SessionSidSortedSetClient = {
		del: (k) => io.del(k),
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
		zRange: (k, s, e) => io.zrange(k, s, e),
		zRem: (k, m) => io.zrem(k, m) as Promise<number>,
	};

	const federationTokenStoreClient: FederationTokenStoreClient = {
		get: (k) => io.get(k),
		// Cast required for overloaded `set`; see UserSessionStoreClient above.
		set: ((k: string, v: string, _mode: "PX", ttl: number, cond?: "NX") =>
			cond === "NX"
				? io.set(k, v, "PX", ttl, "NX")
				: io.set(k, v, "PX", ttl)) as FederationTokenStoreClient["set"],
		del: (...keys) => io.del(...keys),
		scanIterator: ({ MATCH, COUNT }) =>
			(async function* () {
				const stream = io.scanStream({ match: MATCH, count: COUNT });
				for await (const batch of stream) {
					for (const key of batch as string[]) yield key;
				}
			})(),
		// D-9: atomic compare-and-delete via Lua. EVALSHA + cached SHA-1 on the
		// hot path; falls back to EVAL on NOSCRIPT (cold cache, SCRIPT FLUSH,
		// cluster failover) and re-loads the script for future calls.
		async compareAndDelete(key, expectedValue) {
			if (cachedLuaSha !== null) {
				try {
					const r = (await io.evalsha(cachedLuaSha, 1, key, expectedValue)) as number;
					return r === 1;
				} catch (err) {
					if (!(err instanceof Error) || !err.message.includes("NOSCRIPT")) throw err;
					cachedLuaSha = null;
					// Fall through to EVAL.
				}
			}
			const r = (await io.eval(LUA_COMPARE_AND_DELETE, 1, key, expectedValue)) as number;
			// Cache the SHA for the next call. `script("LOAD", ...)` returns
			// the SHA-1 digest; future EVALSHA hits the server-side cache.
			cachedLuaSha = (await io.script("LOAD", LUA_COMPARE_AND_DELETE)) as string;
			return r === 1;
		},
	};

	const rateLimiterClient: RateLimiterClient = {
		incr: (k) => io.incr(k),
		expire: (k, s) => io.expire(k, s),
	};

	return {
		challengeStoreClient,
		replaySeenSetClient,
		refreshTokenFamilyClient,
		userSessionStoreClient,
		sessionRPRegistryClient,
		sessionFamilyIndexClient: sortedSetClient,
		sessionFederationIndexClient: sortedSetClient,
		federationTokenStoreClient,
		rateLimiterClient,
	};
}
