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
	DeviceCodeRecordFields,
	DeviceCodeStoreClient,
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
	SubjectRevocationClient,
	SubjectSessionIndexClient,
	SubjectSessionIndexMultiClient,
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
 * Lua monotonic watermark write — the `SubjectRevocation` store's only mutation.
 *
 * `KEYS[1]` = the watermark key; `ARGV[1]` = the proposed `before` in epoch ms;
 * `ARGV[2]` = the proposed expiry in epoch ms. Returns the watermark in force
 * after the write.
 *
 * Both fields take the **larger** of proposed and stored. Moving the watermark
 * backwards would resurrect every token the earlier reset killed, and
 * shortening the expiry would retire the line while tokens it must refuse are
 * still presentable — so a plain `SET key value PX ttl` is the wrong primitive,
 * and a client-side read-compare-write loses the same race one round-trip
 * later.
 *
 * `PEXPIRETIME` (Redis 7.0+, and v0.5.1 pins the floor to 7.2 LTS) answers the
 * absolute expiry directly, so the comparison needs no clock reading of its
 * own. It answers `-1` for a key with no TTL and `-2` for one that does not
 * exist; both fall through to the proposed expiry, which is what makes an
 * expired watermark start fresh rather than being resurrected by the guard.
 */
const LUA_SET_WATERMARK_MONOTONIC = `
local before = tonumber(ARGV[1])
local expiresAt = tonumber(ARGV[2])
local current = redis.call("GET", KEYS[1])
if current then
  local currentBefore = tonumber(current)
  if currentBefore and currentBefore > before then
    before = currentBefore
  end
end
local currentExpiry = redis.call("PEXPIRETIME", KEYS[1])
if currentExpiry > 0 and currentExpiry > expiresAt then
  expiresAt = currentExpiry
end
redis.call("SET", KEYS[1], tostring(before), "PXAT", expiresAt)
return tostring(before)
`.trim();

/** See {@link LUA_COMPARE_AND_DELETE_SHA} for why the digest is precomputed. */
const LUA_SET_WATERMARK_MONOTONIC_SHA = createHash("sha1")
	.update(LUA_SET_WATERMARK_MONOTONIC)
	.digest("hex");

/** Script-cache residency flag for {@link LUA_SET_WATERMARK_MONOTONIC}. */
let watermarkScriptCached = false;

/**
 * Lua sweep-then-list for the subject session index — the read path of
 * `SubjectSessionIndex`.
 *
 * `KEYS[1]` = the subject's sorted set. Returns the members still live.
 *
 * The boundary is `TIME`, the **server's** clock, not the calling replica's
 * `Date.now()`. Scores are written by whichever replica handled the login and
 * read by whichever replica handles the next request; comparing two host
 * clocks would drop live sessions early or keep expired ones listed by exactly
 * the skew between them. The store is the one clock every replica shares,
 * which is the reason this index moved off in-process state at all.
 *
 * Sweeping and reading in one script also makes them one value and one moment
 * — as two commands they could disagree about the boundary member.
 *
 * `TIME` makes the script non-deterministic, which is fine: Redis has
 * replicated scripts by their effects since 5.0 and does so unconditionally in
 * 7.x, so replicas receive the resulting `ZREMRANGEBYSCORE`, not a re-run.
 */
const LUA_PRUNE_AND_LIST = `
local t = redis.call("TIME")
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
redis.call("ZREMRANGEBYSCORE", KEYS[1], "-inf", now)
return redis.call("ZRANGEBYSCORE", KEYS[1], now, "+inf")
`.trim();

/** See {@link LUA_COMPARE_AND_DELETE_SHA} for why the digest is precomputed. */
const LUA_PRUNE_AND_LIST_SHA = createHash("sha1").update(LUA_PRUNE_AND_LIST).digest("hex");

/** Script-cache residency flag for {@link LUA_PRUNE_AND_LIST}. */
let pruneAndListScriptCached = false;

/**
 * Whether `err` is Redis's `NOSCRIPT` — the cold-cache reply to `EVALSHA`
 * after a `SCRIPT FLUSH` or a cluster failover, and the signal to fall back to
 * `EVAL` (which implicitly reloads the script) rather than to fail the call.
 *
 * Shared by both EVALSHA call sites since #321 added the second one; a second
 * inline copy of the `instanceof` + `includes` pair is how the two would come
 * to disagree about what counts as a cache miss.
 */
function isNoScriptError(err: unknown): boolean {
	return err instanceof Error && err.message.includes("NOSCRIPT");
}

// --- Device authorization scripts (#433) -----------------------------------
//
// Five scripts, one per `DeviceCodeStoreClient` operation, because the port
// they back is written as atomic operations and a round trip cannot honour
// that. `KEYS` carries what the caller knows up front; the other key of the
// pair is derived inside the script — from the record's `userCode`, or from
// the index's device code — and reached through the shared `{devauth}` hash
// tag, which is what puts it in the slot the script was routed to. Redis 7
// lets a script touch an undeclared key in its own slot and refuses one in
// another, so the tag is load-bearing rather than cosmetic.
//
// Replies are small arrays headed by a kind string (`{'approved', flat}`)
// rather than integers, so a reply cannot be misread as another kind by an
// off-by-one. Numbers travel as strings both ways: Lua's `tostring` of an
// integral double is the integer, and epoch milliseconds are well inside the
// fourteen significant digits `%.14g` keeps.

/** Lua prelude: `HGETALL`'s flat `[field, value, …]` reply as a table. */
const LUA_DEVICE_CODE_RECORD_OF = `
local function record_of(flat)
  local r = {}
  for i = 1, #flat, 2 do r[flat[i]] = flat[i + 1] end
  return r
end
`.trim();

/**
 * `create` — both keys insert-only, both with the authorization's expiry.
 *
 * `KEYS[1]` = record key, `KEYS[2]` = user-code index key; `ARGV[1]` = the
 * device code (the index's value), `ARGV[2]` = expiry in epoch ms,
 * `ARGV[3…]` = the record's field/value pairs. Returns 1, or 0 — writing
 * nothing — when either key already exists.
 *
 * `PEXPIREAT` with the absolute deadline rather than `PX` with a lifetime
 * computed twice: the two keys must retire together. A deadline already in
 * the past reclaims the pair on the spot, as `PEXPIREAT` does for any key;
 * the port never issues one.
 */
const LUA_DEVICE_CODE_CREATE = `
if redis.call('EXISTS', KEYS[1], KEYS[2]) > 0 then
  return 0
end
redis.call('HSET', KEYS[1], unpack(ARGV, 3))
redis.call('SET', KEYS[2], ARGV[1])
redis.call('PEXPIREAT', KEYS[1], ARGV[2])
redis.call('PEXPIREAT', KEYS[2], ARGV[2])
return 1
`.trim();

/**
 * `findPending` — the record behind a user code, if it can still be approved.
 *
 * `KEYS[1]` = user-code index key; `ARGV[1]` = record key prefix, `ARGV[2]` =
 * now in epoch ms. Returns the record's `HGETALL` reply, or nil for absent,
 * expired, or already decided.
 *
 * Reads reclaim: an expired record is deleted by whoever finds it, as the
 * memory adapter does, rather than left for the TTL. An index whose record is
 * gone — the pair shares a deadline, but Redis retires keys one at a time —
 * is dropped on sight.
 */
const LUA_DEVICE_CODE_FIND_PENDING = `
${LUA_DEVICE_CODE_RECORD_OF}
local deviceCode = redis.call('GET', KEYS[1])
if not deviceCode then return false end
local codeKey = ARGV[1] .. deviceCode
local flat = redis.call('HGETALL', codeKey)
if #flat == 0 then
  redis.call('DEL', KEYS[1])
  return false
end
local r = record_of(flat)
if tonumber(r.expiresAtMs) <= tonumber(ARGV[2]) then
  redis.call('DEL', codeKey, KEYS[1])
  return false
end
if r.status ~= 'pending' then return false end
return flat
`.trim();

/**
 * `decide` — `pending` → `approved` | `denied`, refusing a second decision.
 *
 * `KEYS[1]` = user-code index key; `ARGV[1]` = record key prefix, `ARGV[2]` =
 * now in epoch ms, `ARGV[3]` = `approved` | `denied`, `ARGV[4]` = subject,
 * `ARGV[5]` = `requested` | `narrow`, `ARGV[6]` = the caller's grantedScope
 * as a JSON array (read only under `narrow`). Returns `{'ok', record}`,
 * `{'already_decided', status}`, `{'expired'}` or `{'not_found'}`.
 *
 * The check and the write are one script because the record is reached
 * through the index: `GET`, `HGETALL`, `HSET` from the client would let a
 * denial and an approval interleave, and whichever lands second overwrites
 * the first — the user who denied a phishing prompt talked into "just trying
 * again".
 *
 * The scope intersection happens here for the same reason. `requestedScope`
 * never changes after `create`, so it could be read separately — but that is
 * a second read between the lookup that showed the user a scope and the write
 * that grants one, which the port's docblock rules out. `narrow` filters the
 * caller's list against it in the caller's order; `requested` grants it
 * whole. An empty result is written as `[]` literally, because
 * `cjson.encode({})` is `{}` — an object, not an array.
 */
const LUA_DEVICE_CODE_DECIDE = `
${LUA_DEVICE_CODE_RECORD_OF}
local deviceCode = redis.call('GET', KEYS[1])
if not deviceCode then return {'not_found'} end
local codeKey = ARGV[1] .. deviceCode
local flat = redis.call('HGETALL', codeKey)
if #flat == 0 then
  redis.call('DEL', KEYS[1])
  return {'not_found'}
end
local r = record_of(flat)
if tonumber(r.expiresAtMs) <= tonumber(ARGV[2]) then
  redis.call('DEL', codeKey, KEYS[1])
  return {'expired'}
end
if r.status ~= 'pending' then return {'already_decided', r.status} end
if ARGV[3] == 'approved' then
  local requested = {}
  if r.requestedScope then requested = cjson.decode(r.requestedScope) end
  local granted = requested
  if ARGV[5] == 'narrow' then
    local allowed = {}
    for _, s in ipairs(requested) do allowed[s] = true end
    granted = {}
    for _, s in ipairs(cjson.decode(ARGV[6])) do
      if allowed[s] then granted[#granted + 1] = s end
    end
  end
  local encoded = '[]'
  if #granted > 0 then encoded = cjson.encode(granted) end
  redis.call('HSET', codeKey, 'status', 'approved', 'subject', ARGV[4], 'grantedScope', encoded)
else
  redis.call('HSET', codeKey, 'status', 'denied')
end
return {'ok', redis.call('HGETALL', codeKey)}
`.trim();

/**
 * `poll` — the interval gate, the status read, and the consumption of an
 * approval, in one script. This is the one the port's whole shape exists
 * for: as `HGETALL` then `DEL` from the client, two concurrent polls both
 * observe `approved`, and one human approval becomes two access tokens.
 *
 * `KEYS[1]` = record key; `ARGV[1]` = now in epoch ms, `ARGV[2]` = user-code
 * index key prefix, `ARGV[3]` = the `slow_down` increment in seconds.
 * Returns `{'not_found'}`, `{'expired'}`, `{'slow_down', interval}`,
 * `{'denied'}`, `{'pending'}` or `{'approved', record}`.
 *
 * `expired` is answered from `expiresAtMs` against the caller's `now`, not
 * from the key's TTL. The two are set from one value, but the port's contract
 * is the timestamp, and a record inside its TTL whose deadline has passed on
 * the caller's clock still answers `expired` — and is reclaimed here.
 *
 * The interval gate runs before the status read, as the memory adapter's
 * does: an over-eager poller is told to slow down whether or not its user
 * has answered. RFC 8628 §3.5 says the interval "MUST be increased by 5
 * seconds for this and all subsequent requests", and the increase is written
 * back so it is the interval the *next* gate measures against — a server
 * that says `slow_down` while still measuring against the original interval
 * tells a compliant client to slow down forever.
 *
 * `denied` and `approved` both delete the pair on the way out: the answer is
 * the record's last act, and a second poll must see `not_found`.
 */
const LUA_DEVICE_CODE_POLL = `
${LUA_DEVICE_CODE_RECORD_OF}
local flat = redis.call('HGETALL', KEYS[1])
if #flat == 0 then return {'not_found'} end
local r = record_of(flat)
local now = tonumber(ARGV[1])
local userKey = ARGV[2] .. r.userCode
if tonumber(r.expiresAtMs) <= now then
  redis.call('DEL', KEYS[1], userKey)
  return {'expired'}
end
local interval = tonumber(r.intervalSeconds)
local last = r.lastPolledAtMs and tonumber(r.lastPolledAtMs) or nil
if last and now - last < interval * 1000 then
  interval = interval + tonumber(ARGV[3])
  redis.call('HSET', KEYS[1], 'intervalSeconds', tostring(interval), 'lastPolledAtMs', ARGV[1])
  return {'slow_down', tostring(interval)}
end
redis.call('HSET', KEYS[1], 'lastPolledAtMs', ARGV[1])
if r.status == 'denied' then
  redis.call('DEL', KEYS[1], userKey)
  return {'denied'}
end
if r.status == 'pending' then return {'pending'} end
redis.call('DEL', KEYS[1], userKey)
return {'approved', flat}
`.trim();

/**
 * `remove` — the record and its index, together or not at all. `KEYS[1]` =
 * record key; `ARGV[1]` = user-code index key prefix. The index key is
 * derived from the record's `userCode` in the same script, so nothing can
 * consume the pair between reading one and deleting the other. Absence is
 * not an error.
 */
const LUA_DEVICE_CODE_REMOVE = `
local userCode = redis.call('HGET', KEYS[1], 'userCode')
if not userCode then return 0 end
return redis.call('DEL', KEYS[1], ARGV[1] .. userCode)
`.trim();

/**
 * A script, its digest, and its cache-residency flag — the EVALSHA-first call
 * path the three scripts above take by hand, packaged once for the five
 * device-authorization scripts (#433) so a sixth inline copy of the NOSCRIPT
 * dance cannot come to disagree with the others about what a cache miss is.
 *
 * The flag is module-scoped for the reason `scriptCached` gives: the script
 * is a constant, so every client in the process shares one view of whether
 * the server holds it.
 */
interface CachedScript {
	readonly source: string;
	/** See {@link LUA_COMPARE_AND_DELETE_SHA} for why the digest is precomputed. */
	readonly sha: string;
	cached: boolean;
}

const defineScript = (source: string): CachedScript => ({
	source,
	sha: createHash("sha1").update(source).digest("hex"),
	cached: false,
});

const DEVICE_CODE_CREATE = defineScript(LUA_DEVICE_CODE_CREATE);
const DEVICE_CODE_FIND_PENDING = defineScript(LUA_DEVICE_CODE_FIND_PENDING);
const DEVICE_CODE_DECIDE = defineScript(LUA_DEVICE_CODE_DECIDE);
const DEVICE_CODE_POLL = defineScript(LUA_DEVICE_CODE_POLL);
const DEVICE_CODE_REMOVE = defineScript(LUA_DEVICE_CODE_REMOVE);

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

/** `HGETALL`'s flat `[field, value, …]` reply as the record's fields. */
function deviceCodeRecordOf(flat: unknown): DeviceCodeRecordFields {
	const pairs = Array.isArray(flat) ? (flat as string[]) : [];
	const fields: Record<string, string> = {};
	for (let i = 0; i + 1 < pairs.length; i += 2) {
		fields[pairs[i] as string] = pairs[i + 1] as string;
	}
	return fields as unknown as DeviceCodeRecordFields;
}

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
 * Wrap a single ioredis connection into the 14 typed client wrappers
 * needed by `@o3co/auth-provider-redis` adapters. Production consumers
 * use this factory in their composition root and spread the result into
 * `bootstrapComponents`.
 *
 * Every returned client issues its commands against the one connection passed
 * in — this factory opens nothing of its own (the sole exception is
 * `refreshTokenFamilyClient.duplicate()`, which is per rotation, not per
 * purpose). Connection-level ioredis options are therefore shared by all
 * fourteen purposes, so a composition root that needs different failure timing
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
	subjectSessionIndexClient: SubjectSessionIndexClient;
	subjectRevocationClient: SubjectRevocationClient;
	federationTokenStoreClient: FederationTokenStoreClient;
	rateLimiterClient: RateLimiterClient;
	codeRepositoryClient: CodeRepositoryClient;
	deviceCodeStoreClient: DeviceCodeStoreClient;
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

	// --- subject-keyed clients (#321) ---------------------------------------

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
		async setWatermarkMonotonic(key, beforeMs, expiresAtMs) {
			// EVALSHA-first with a NOSCRIPT fallback to EVAL, matching
			// `compareAndDelete` above — see `scriptCached` for why the flag is
			// module-scoped and how a `SCRIPT FLUSH` or cluster failover is
			// recovered from.
			const args = [key, String(beforeMs), String(expiresAtMs)] as const;
			if (watermarkScriptCached) {
				try {
					const r = (await io.evalsha(LUA_SET_WATERMARK_MONOTONIC_SHA, 1, ...args)) as string;
					return Number(r);
				} catch (err) {
					if (!isNoScriptError(err)) throw err;
					watermarkScriptCached = false;
				}
			}
			const r = (await io.eval(LUA_SET_WATERMARK_MONOTONIC, 1, ...args)) as string;
			// EVAL implicitly loads the script into Redis's server-side cache.
			watermarkScriptCached = true;
			return Number(r);
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
					if (!isNoScriptError(err)) throw err;
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

	// #433: the device-code store's five operations, each one Lua script (see
	// the `LUA_DEVICE_CODE_*` docblocks for what each guarantees). The record
	// key and the index key share the `{devauth}` hash tag, so the key a script
	// derives from the other is in the slot it was routed to.
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
			return reply === 1;
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
	};
}
