/*
 * Copyright 2026 1o1 Co. Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 */
/*
 * ioredis bindings for the client ports in `./clients.mjs`: `makeIoredisClients` for the
 * single-connection set, separate factories for the federation grant, federation grant intent
 * and MFA stores, and the Lua scripts their atomic operations run. Published as the
 * `@o3co/auth-provider-redis/ioredis` subpath, so the main entry never pulls ioredis types into
 * a consumer's dependency closure.
 */
import { createHash } from "node:crypto";
import { consoleLogger, type EventLogger, loggableError } from "@o3co/auth-provider-core";
import type { Redis } from "ioredis";
import type {
	AccessTokenDenylistClient,
	ChallengeStoreClient,
	CodeRepositoryClient,
	ConsentRecordFields,
	ConsentStoreClient,
	DeviceCodeRecordFields,
	DeviceCodeStoreClient,
	DisposableRefreshTokenFamilyClient,
	FederationGrantConsentAnswered,
	FederationGrantHashFields,
	FederationGrantIntentAdmission,
	FederationGrantIntentStoreClient,
	FederationGrantStoreClient,
	FederationTokenStoreClient,
	MfaFactorStoreClient,
	MfaTransactionStoreClient,
	PendingConsentStoreClient,
	RateLimiterClient,
	RateLimitIncrement,
	RedisDurability,
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
 * Rate-limit counter increment, atomic with its expiry: `INCR` then a separate `EXPIRE` can
 * leave the key with no TTL, and a counter that never resets 429s its client forever.
 *
 * The expiry is set whenever the key has none (`TTL` < 0), not only on the first hit, so a key
 * left without a TTL is repaired. An existing expiry is left alone, so steady traffic cannot
 * hold the window open.
 *
 * Returns `{count, pttl}`, both read in the script so they describe one counter state. The
 * limiter turns `pttl` into `resetAt`, the 429's `Retry-After`.
 */
const LUA_INCREMENT_WITH_TTL = `
local count = redis.call('INCR', KEYS[1])
if redis.call('TTL', KEYS[1]) < 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return {count, redis.call('PTTL', KEYS[1])}
`.trim();

/**
 * Compare-and-replace for a session record, the MFA step-up write. `KEYS[1]` = the session
 * key; `ARGV[1]` = the value the caller read, `ARGV[2]` = its replacement. Replaces only while
 * the key still holds what was read, keeping its TTL (`KEEPTTL`): a second factor never changes
 * how long a session lives. Returns 1 when it replaced, 0 otherwise.
 */
const LUA_REPLACE_IF_UNCHANGED = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
  redis.call("SET", KEYS[1], ARGV[2], "KEEPTTL")
  return 1
end
return 0
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
 * SHA-1 of `LUA_COMPARE_AND_DELETE`. Redis keys its script cache by the SHA-1 of the source, so
 * the digest matches what `SCRIPT LOAD` would return, without that round trip.
 */
const LUA_COMPARE_AND_DELETE_SHA = createHash("sha1").update(LUA_COMPARE_AND_DELETE).digest("hex");

/**
 * The subject revocation record's only write: both boundaries (sessions, grants) in one key,
 * one atomic step. `KEYS[1]` = the record; `ARGV` = mode (`all` | `sessions`), `before` and the
 * proposed expiry (epoch ms), the grant retention (ms). Returns the value written; a stored value
 * it cannot read is refused with an error.
 *
 * Boundaries and expiry only move forward: a boundary moved back resurrects tokens an earlier
 * revocation killed, and a shorter expiry retires the record while tokens it must refuse are
 * still presentable. `PEXPIRETIME` gives the stored absolute expiry (-1: none, the key stays
 * persistent; -2: absent, the proposed one applies). A grants boundary keeps the record at least
 * until that boundary plus the retention.
 *
 * The value is not JSON (`cjson` writes 14 significant digits, too close to an epoch ms's 13):
 *   `<n>`         both boundaries are `n`
 *   `v1:<s>:<g>`  they differ
 *   `v1:<s>:-`    sessions only; no revocation has covered the subject's grants
 * Older releases read only `<n>`: rollback is safe until sessions-only stamps are used, and once
 * `v1:` records exist an old writer can move the sessions boundary backward, so drain old
 * writers first. See packages/core/docs/adr/2026-09-17-federation-grants-offline-delegation.md.
 */
const LUA_SET_REVOCATION_BOUNDARIES = `
local mode = ARGV[1]
-- What a Date can hold (ECMA-262). A stored value outside it is not a
-- boundary: the read path refuses it, and carrying it forward here would
-- write a record only this script can produce and nothing can read.
local MAX_DATE = 8640000000000000
local function readable(n)
  return n ~= nil and n == n and n >= -MAX_DATE and n <= MAX_DATE
end
local before = tonumber(ARGV[2])
local expiresAt = tonumber(ARGV[3])
local retention = tonumber(ARGV[4])
if before == nil or expiresAt == nil or retention == nil then
  return redis.error_reply("subject revocation: non-numeric argument")
end

local sessions = nil
local grants = nil
local current = redis.call("GET", KEYS[1])
if current then
  if string.match(current, "^%-?%d+$") then
    sessions = tonumber(current)
    grants = sessions
  else
    local s, g = string.match(current, "^v1:(%-?%d+):(%-?%d+)$")
    if s ~= nil then
      sessions = tonumber(s)
      grants = tonumber(g)
    else
      s = string.match(current, "^v1:(%-?%d+):%-$")
      if s == nil then
        return redis.error_reply("subject revocation: unreadable record")
      end
      sessions = tonumber(s)
    end
  end
  -- The shape matched; the numbers still have to be instants. tonumber of
  -- four hundred digits is infinity, which passes every pattern above and
  -- would be written back as "inf".
  if (not readable(sessions)) or (grants ~= nil and not readable(grants)) then
    return redis.error_reply("subject revocation: unreadable record")
  end
end

if sessions == nil or before > sessions then sessions = before end
if mode == "all" then
  if grants == nil or before > grants then grants = before end
end

local ttlAt = redis.call("PEXPIRETIME", KEYS[1])
local persistent = (ttlAt == -1)
if (not persistent) and ttlAt > 0 and ttlAt > expiresAt then expiresAt = ttlAt end
if grants ~= nil then
  local floor = grants + retention
  if floor > expiresAt then expiresAt = floor end
end

local value
if grants == nil then
  value = "v1:" .. string.format("%.0f", sessions) .. ":-"
elseif grants == sessions then
  value = string.format("%.0f", sessions)
else
  value = "v1:" .. string.format("%.0f", sessions) .. ":" .. string.format("%.0f", grants)
end

if persistent then
  redis.call("SET", KEYS[1], value)
else
  redis.call("SET", KEYS[1], value, "PXAT", expiresAt)
end
return value
`.trim();

/** See {@link LUA_COMPARE_AND_DELETE_SHA} for why the digest is precomputed. */
const LUA_SET_REVOCATION_BOUNDARIES_SHA = createHash("sha1")
	.update(LUA_SET_REVOCATION_BOUNDARIES)
	.digest("hex");

/** Script-cache residency flag for {@link LUA_SET_REVOCATION_BOUNDARIES}. */
let watermarkScriptCached = false;

/**
 * Sweep-then-list for the subject session index. `KEYS[1]` = the subject's sorted set; returns
 * the members still live.
 *
 * The boundary is the server's `TIME`, not the calling replica's clock: scores are written and
 * read by different replicas, and comparing two host clocks would misjudge sessions by the skew
 * between them. One script makes the sweep and the read agree on the boundary. A
 * non-deterministic `TIME` is fine: Redis 7 replicates scripts by their effects.
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
 * Whether `err` is Redis's `NOSCRIPT`, the cold-cache reply to `EVALSHA` after a `SCRIPT FLUSH`
 * or a failover: the signal to fall back to `EVAL` (which reloads the script), not to fail. It
 * reads the message because ioredis's `ReplyError` carries no code (ioredis's own `Script` does
 * the same); the text decides this boolean only and is never logged or thrown.
 */
function isNoScriptError(err: unknown): boolean {
	return err instanceof Error && err.message.includes("NOSCRIPT");
}

// --- Device authorization scripts --------------------------------------------
//
// One script per `DeviceCodeStoreClient` operation, because the port's operations are atomic.
// `KEYS` carries the key the caller knows; the other key of the pair is derived inside the
// script and shares the `{devauth}` hash tag, so it is in the slot the script was routed to
// (Redis refuses a script's access to an undeclared key in another slot).
//
// Replies are arrays headed by a kind string (`{'approved', flat}`), not integers, so one kind
// cannot be misread as another. Numbers travel as strings: epoch ms fit in the 14 significant
// digits Lua's `tostring` keeps.

/** Lua prelude: `HGETALL`'s flat `[field, value, …]` reply as a table. */
const LUA_DEVICE_CODE_RECORD_OF = `
local function record_of(flat)
  local r = {}
  for i = 1, #flat, 2 do r[flat[i]] = flat[i + 1] end
  return r
end
`.trim();

/**
 * `create`: both keys insert-only, both with the authorization's expiry. `KEYS[1]` = record,
 * `KEYS[2]` = user-code index; `ARGV[1]` = device code, `ARGV[2]` = expiry (epoch ms),
 * `ARGV[3…]` = the record's field/value pairs. Returns 1, or 0 (writing nothing) when either key
 * exists. One absolute `PEXPIREAT` deadline, so the two keys retire together.
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
 * `findPending`: the record behind a user code, if it can still be approved. `KEYS[1]` =
 * user-code index; `ARGV[1]` = record key prefix, `ARGV[2]` = now (epoch ms). Returns the
 * `HGETALL` reply, or nil for absent, expired or decided. Whoever finds an expired record, or an
 * index whose record is gone (Redis retires the pair's keys one at a time), deletes it.
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
 * `decide`: `pending` → `approved` | `denied`, refusing a second decision. `KEYS[1]` =
 * user-code index; `ARGV[1]` = record key prefix, `ARGV[2]` = now (epoch ms; an approval's
 * `approvedAtMs`), `ARGV[3]` = `approved` | `denied`, `ARGV[4]` = subject, `ARGV[5]` =
 * `requested` | `narrow`, `ARGV[6]` = the caller's grantedScope as a JSON array (`narrow` only).
 * Returns `{'ok', record}`, `{'already_decided', status}`, `{'expired'}` or `{'not_found'}`.
 *
 * Check and write are one step, so a denial and an approval cannot interleave with the second
 * overwriting the first. The scope intersection is inside it too, so no read sits between
 * showing the user a scope and granting one: `narrow` filters the caller's list by
 * `requestedScope` in the caller's order, `requested` grants it whole. An empty result is
 * written as `[]` literally, because `cjson.encode({})` is `{}`.
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
  redis.call('HSET', codeKey, 'status', 'approved', 'subject', ARGV[4], 'grantedScope', encoded, 'approvedAtMs', ARGV[2])
else
  redis.call('HSET', codeKey, 'status', 'denied')
end
return {'ok', redis.call('HGETALL', codeKey)}
`.trim();

/**
 * `poll`: the interval gate, the status read and the consumption of an approval in one step;
 * as `HGETALL` then `DEL`, two concurrent polls would turn one approval into two access tokens.
 * `KEYS[1]` = record; `ARGV[1]` = now (epoch ms), `ARGV[2]` = user-code index key prefix,
 * `ARGV[3]` = the `slow_down` increment (s). Returns `{'not_found'}`, `{'expired'}`,
 * `{'slow_down', interval}`, `{'denied'}`, `{'pending'}` or `{'approved', record}`.
 *
 * Expiry is judged by `expiresAtMs` against the caller's `now`, not by the key's TTL. The gate
 * runs before the status read, and the increased interval is written back: RFC 8628 §3.5
 * applies it to "this and all subsequent requests", so the next gate measures against it.
 * `denied` and `approved` delete the pair, so a second poll sees `not_found`.
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

// --- Consent scripts ---------------------------------------------------------
//
// One script per operation that must be indivisible (the pending store's read and consume
// share one). Expiry is judged by the record's `expiresAt` against the caller's clock (`ARGV`),
// never by the key's TTL, which is only a safety net for records nobody reads again; whoever
// finds a record past its `expiresAt` reclaims it.
//
// The safety net is a relative `PEXPIRE`, not `PEXPIREAT` at the caller's deadline: an absolute
// deadline is read on the server's clock and would shift by the writer-to-Redis skew, firing
// early when Redis runs ahead. The adapter adds slack for the writer-to-reader skew
// (`CONSENT_EXPIRY_SLACK_MS`).

/**
 * `ConsentStoreClient.find`: the record unless expired. `KEYS[1]` = record; `ARGV[1]` = now
 * (epoch ms). Returns `{scopes, grantedAt, expiresAt|nil}`, or nil for absent or expired. The
 * reclaim is in the script so it cannot delete a grant written after the read. An unparsable
 * `expiresAt` reads as expired (fail closed).
 */
const LUA_CONSENT_FIND = `
local r = redis.call('HMGET', KEYS[1], 'scopes', 'grantedAt', 'expiresAt')
if not r[1] or not r[2] then return false end
if r[3] then
  local expiresAt = tonumber(r[3])
  if not expiresAt or expiresAt <= tonumber(ARGV[1]) then
    redis.call('DEL', KEYS[1])
    return false
  end
end
return r
`.trim();

/**
 * `ConsentStoreClient.grant`: the union with what is recorded, as one write. `KEYS[1]` =
 * record; `ARGV[1]` = now (epoch ms), `ARGV[2]` = grantedAt, `ARGV[3]` = the granted scopes as
 * a JSON array, `ARGV[4]` = expiresAt, empty for until revoked, `ARGV[5]` = TTL (ms, with an
 * expiry only).
 *
 * Recorded scopes join (in order, new ones after) only while the recorded consent is live on
 * the caller's clock. A malformed record (`scopes` not a JSON array of strings, `grantedAt` not
 * a number) contributes nothing: `find` reports it absent, so the user was asked again. An
 * empty union is written as `[]` (`cjson.encode({})` is `{}`). Without an expiry the key is
 * `PERSIST`ed, or an earlier grant's TTL would delete it; a TTL that is not positive removes it.
 */
const LUA_CONSENT_GRANT = `
local now = tonumber(ARGV[1])
local merged, seen = {}, {}
local function add(list)
  for _, scope in ipairs(list) do
    if type(scope) == 'string' and not seen[scope] then
      seen[scope] = true
      merged[#merged + 1] = scope
    end
  end
end
local function string_array(json)
  local ok, list = pcall(cjson.decode, json)
  if not ok or type(list) ~= 'table' then return nil end
  local count = 0
  for _ in pairs(list) do count = count + 1 end
  if count ~= #list then return nil end
  for _, scope in ipairs(list) do
    if type(scope) ~= 'string' then return nil end
  end
  return list
end
local held = redis.call('HMGET', KEYS[1], 'scopes', 'grantedAt', 'expiresAt')
if held[1] and held[2] and tonumber(held[2]) then
  local live = true
  if held[3] then
    local expiresAt = tonumber(held[3])
    live = expiresAt ~= nil and expiresAt > now
  end
  local list = live and string_array(held[1])
  if list then add(list) end
end
add(cjson.decode(ARGV[3]))
local encoded = '[]'
if #merged > 0 then encoded = cjson.encode(merged) end
if ARGV[4] == '' then
  redis.call('HSET', KEYS[1], 'scopes', encoded, 'grantedAt', ARGV[2])
  redis.call('HDEL', KEYS[1], 'expiresAt')
  redis.call('PERSIST', KEYS[1])
  return 1
end
local ttl = tonumber(ARGV[5])
if not ttl or ttl <= 0 then
  redis.call('DEL', KEYS[1])
  return 0
end
redis.call('HSET', KEYS[1], 'scopes', encoded, 'grantedAt', ARGV[2], 'expiresAt', ARGV[4])
redis.call('PEXPIRE', KEYS[1], ttl)
return 1
`.trim();

/**
 * `PendingConsentStoreClient.set`: park a request and hold its session to the bound, in one
 * step. `KEYS[1]` = record, `KEYS[2]` = the session's index; `ARGV[1]` = now (epoch ms),
 * `ARGV[2]` = challenge, `ARGV[3]` = sessionId, `ARGV[4]` = expiresAt, `ARGV[5]` = record TTL
 * (ms), `ARGV[6]` = the serialised request, `ARGV[7]` = per-session bound, `ARGV[8]` = record
 * key prefix, `ARGV[9]` = session index key prefix.
 *
 * In the memory adapter's order: a request already parked under the challenge leaves its own
 * session's index; this session's expired or orphaned entries leave before the bound is judged,
 * so a dead request never costs a live one its place; then the first-parked go until there is
 * room. The index is scored by parking order (one past its highest score), not `createdAt`: a
 * total order no replica's clock takes part in. Its TTL only rises, so it outlives its records.
 */
const LUA_PENDING_CONSENT_SET = `
local now = tonumber(ARGV[1])
local challenge = ARGV[2]
local recordPrefix = ARGV[8]
local previous = redis.call('HGET', KEYS[1], 'sessionId')
if previous then
  redis.call('ZREM', ARGV[9] .. previous, challenge)
end
redis.call('DEL', KEYS[1])
for _, member in ipairs(redis.call('ZRANGE', KEYS[2], 0, -1)) do
  local expiresAt = tonumber(redis.call('HGET', recordPrefix .. member, 'expiresAt'))
  if not expiresAt or expiresAt <= now then
    redis.call('DEL', recordPrefix .. member)
    redis.call('ZREM', KEYS[2], member)
  end
end
local ttl = tonumber(ARGV[5])
if not ttl or ttl <= 0 then return 0 end
local limit = tonumber(ARGV[7])
while redis.call('ZCARD', KEYS[2]) >= limit do
  local oldest = redis.call('ZRANGE', KEYS[2], 0, 0)[1]
  if not oldest then break end
  redis.call('DEL', recordPrefix .. oldest)
  redis.call('ZREM', KEYS[2], oldest)
end
local last = redis.call('ZRANGE', KEYS[2], -1, -1, 'WITHSCORES')
local order = 1
if last[2] then order = tonumber(last[2]) + 1 end
redis.call('HSET', KEYS[1], 'record', ARGV[6], 'sessionId', ARGV[3], 'expiresAt', ARGV[4])
redis.call('PEXPIRE', KEYS[1], ttl)
redis.call('ZADD', KEYS[2], order, challenge)
if redis.call('PTTL', KEYS[2]) < ttl then
  redis.call('PEXPIRE', KEYS[2], ttl)
end
return 1
`.trim();

/**
 * `PendingConsentStoreClient.get` and `.consume`. `KEYS[1]` = record; `ARGV[1]` = now (epoch
 * ms), `ARGV[2]` = challenge, `ARGV[3]` = session index key prefix, `ARGV[4]` = `spend` |
 * `peek`. Returns the serialised request, or nil for absent or expired. `spend` removes the
 * record and its index entry in the same step, so of two answers in flight exactly one gets the
 * request. `peek` never spends a live request; either reclaims an expired one.
 */
const LUA_PENDING_CONSENT_TAKE = `
local r = redis.call('HMGET', KEYS[1], 'record', 'sessionId', 'expiresAt')
if not r[1] then return false end
local expiresAt = tonumber(r[3])
local live = expiresAt ~= nil and expiresAt > tonumber(ARGV[1])
if live and ARGV[4] ~= 'spend' then return r[1] end
redis.call('DEL', KEYS[1])
if r[2] then redis.call('ZREM', ARGV[3] .. r[2], ARGV[2]) end
if live then return r[1] end
return false
`.trim();

/**
 * `PendingConsentStoreClient.discard`: reclaim a request the adapter found corrupt, only while
 * it is still the value read. `KEYS[1]` = record; `ARGV[1]` = the serialised request as read,
 * `ARGV[2]` = challenge, `ARGV[3]` = session index key prefix. Returns 1 when removed, 0 when
 * the value changed or is gone. Compare-and-delete, so a valid request re-parked meanwhile is
 * not taken. The index is found through the record's `sessionId` field, not the possibly
 * corrupt JSON.
 */
const LUA_PENDING_CONSENT_DISCARD = `
local r = redis.call('HMGET', KEYS[1], 'record', 'sessionId')
if r[1] ~= ARGV[1] then return 0 end
redis.call('DEL', KEYS[1])
if r[2] then redis.call('ZREM', ARGV[3] .. r[2], ARGV[2]) end
return 1
`.trim();

/**
 * A script, its digest, and whether the server is expected to hold it, for
 * {@link runScript}'s EVALSHA-first path. Module-scoped, as `scriptCached` explains.
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

const REPLACE_IF_UNCHANGED = defineScript(LUA_REPLACE_IF_UNCHANGED);
const DEVICE_CODE_CREATE = defineScript(LUA_DEVICE_CODE_CREATE);
const DEVICE_CODE_FIND_PENDING = defineScript(LUA_DEVICE_CODE_FIND_PENDING);
const DEVICE_CODE_DECIDE = defineScript(LUA_DEVICE_CODE_DECIDE);
const DEVICE_CODE_POLL = defineScript(LUA_DEVICE_CODE_POLL);
const DEVICE_CODE_REMOVE = defineScript(LUA_DEVICE_CODE_REMOVE);
const CONSENT_FIND = defineScript(LUA_CONSENT_FIND);
const CONSENT_GRANT = defineScript(LUA_CONSENT_GRANT);
const PENDING_CONSENT_SET = defineScript(LUA_PENDING_CONSENT_SET);
const PENDING_CONSENT_TAKE = defineScript(LUA_PENDING_CONSENT_TAKE);
const PENDING_CONSENT_DISCARD = defineScript(LUA_PENDING_CONSENT_DISCARD);

// --- Federation grant scripts ------------------------------------------------
//
// One script per write, with every guard inside it. A grant's HASH, credential and lock share
// a hash tag, so one script may touch all three. The subject's index is its own key in its own
// slot, so grants spread across a Cluster, and no script touches it with a record: it is
// reserved before the record is written, at the horizon the record will have, and pruned by
// horizon alone. See the Redis layout in
// packages/core/docs/adr/2026-09-17-federation-grants-offline-delegation.md.
//
// Every script validates before it mutates: an error midway leaves what was already written.

/**
 * Shared prelude, concatenated into each script (each keeps its own SHA-1). `fg_horizon` is
 * the instant a record stops answering, the one arithmetic every guard and key deadline agrees
 * on: a `pending` grant lapses with its intent; an authorized one at its stored expiry plus its
 * retention; one revoked before it was authorized at the revocation plus the retention.
 */
const LUA_FG_PRELUDE = `
local function fg_num(v)
  if v == false or v == nil then return nil end
  return tonumber(v)
end
local function fg_fields(flat)
  local t = {}
  for i = 1, #flat, 2 do t[flat[i]] = flat[i + 1] end
  return t
end
local function fg_horizon(g)
  local retention = fg_num(g['retentionMs'])
  if retention == nil then return nil end
  if g['status'] == 'pending' then return fg_num(g['intentExpiresAt']) end
  local expiresAt = fg_num(g['expiresAtMs'])
  if expiresAt ~= nil then return expiresAt + retention end
  local revokedAt = fg_num(g['revokedAt'])
  if revokedAt ~= nil then return revokedAt + retention end
  return nil
end
-- The record as this caller may see it: resident, and not past its horizon.
-- A caller whose clock is wrong is told the wrong thing once; it never costs
-- anyone else the record, so nothing here deletes or expires anything.
local function fg_visible(key, now)
  local flat = redis.call('HGETALL', key)
  if #flat == 0 then return nil end
  local g = fg_fields(flat)
  local h = fg_horizon(g)
  if h == nil then return nil end
  if not (now < h) then return nil end
  return g
end
local function fg_renewable(g, now)
  if g['status'] ~= 'active' and g['status'] ~= 'reauthorization_required' then return false end
  return true
end
-- Compared byte by byte with no early exit: the handle is a capability the
-- browser carries, and the reference adapter compares it in constant time.
local function fg_same(a, b)
  if a == nil or b == nil then return false end
  if #a ~= #b then return false end
  local diff = 0
  for i = 1, #a do
    diff = bit.bor(diff, bit.bxor(string.byte(a, i), string.byte(b, i)))
  end
  return diff == 0
end
`;

/**
 * Creates a `pending` grant. `KEYS[1]` = record, `KEYS[2]` = credential; `ARGV` = the caller's
 * clock, the base fields, the intent's handle and expiry, the retention. The existence check is
 * on the key, not the horizon: a caller whose clock runs ahead must not lodge over a record
 * others still see. A leftover credential at `KEYS[2]` is deleted: unusable, but still a secret
 * at rest. The reply's fields are read before the deadline is applied, never from an expired key.
 */
const LUA_FG_CREATE = `${LUA_FG_PRELUDE}
local now = tonumber(ARGV[1])
local intentAt = tonumber(ARGV[4])
local retention = tonumber(ARGV[5])
if now == nil or intentAt == nil or retention == nil then return {0} end
if not (now < intentAt) then return {0} end
if redis.call('EXISTS', KEYS[1]) == 1 then return {0} end
redis.call('HSET', KEYS[1],
  'format', '1',
  'base', ARGV[2],
  'status', 'pending',
  'version', '1',
  'retentionMs', ARGV[5],
  'intentHandle', ARGV[3],
  'intentExpiresAt', ARGV[4])
redis.call('DEL', KEYS[2])
local fields = redis.call('HGETALL', KEYS[1])
redis.call('PEXPIREAT', KEYS[1], math.ceil(intentAt))
return {1, fields}
`;

/**
 * The record and its credential in one step, so an activation cannot replace both between two
 * reads. `KEYS[1]` = record, `KEYS[2]` = credential. A two-element reply means no credential,
 * three means one (possibly empty). No visibility guard: the caller judges visibility where it
 * decodes the record, against the authenticated text.
 */
const LUA_FG_SNAPSHOT = `
if redis.call('EXISTS', KEYS[1]) == 0 then return {0} end
local fields = redis.call('HGETALL', KEYS[1])
local credential = redis.call('GET', KEYS[2])
if credential == false then return {1, fields} end
return {1, fields, credential}
`;

/**
 * Names a reauthorization's intent as current. `KEYS[1]` = record; `ARGV` = the caller's clock,
 * the handle, the intent's expiry. Refuses a `pending` grant (a first intent makes a new grant)
 * and one past its stored expiry (a new consent cannot resurrect an ended lifetime). Moves no
 * deadline and bumps no version, so a refresh in flight does not lose its write to a renewal the
 * user may never finish.
 */
const LUA_FG_NAME_INTENT = `${LUA_FG_PRELUDE}
local now = tonumber(ARGV[1])
local intentAt = tonumber(ARGV[3])
if now == nil or intentAt == nil then return {0} end
if not (now < intentAt) then return {0} end
local g = fg_visible(KEYS[1], now)
if g == nil then return {0} end
if not fg_renewable(g, now) then return {0} end
local expiresAt = fg_num(g['expiresAtMs'])
if expiresAt == nil or not (now < expiresAt) then return {0} end
redis.call('HSET', KEYS[1], 'intentHandle', ARGV[2], 'intentExpiresAt', ARGV[3])
return {1, redis.call('HGETALL', KEYS[1])}
`;

/**
 * Retires the current intent. `KEYS[1]` = the record; `ARGV` = the caller's
 * clock, whether a handle was given, the handle.
 *
 * With a handle, only if that is the one there: a consent refused for a
 * superseded intent must not end the newer one. Without, whichever is
 * current. A `pending` grant is refused, whose first intent is its life.
 */
const LUA_FG_RETIRE_INTENT = `${LUA_FG_PRELUDE}
local now = tonumber(ARGV[1])
if now == nil then return {0} end
local g = fg_visible(KEYS[1], now)
if g == nil then return {0} end
if g['intentHandle'] == nil then return {0} end
if not fg_renewable(g, now) then return {0} end
if ARGV[2] == '1' and not fg_same(g['intentHandle'], ARGV[3]) then return {0} end
redis.call('HDEL', KEYS[1], 'intentHandle', 'intentExpiresAt')
return {1, redis.call('HGETALL', KEYS[1])}
`;

/**
 * Records a use. `KEYS[1]` = the record; `ARGV[1]` = the instant.
 *
 * Forward only, and on an `active` record only. A use never brings back a
 * record that has lapsed, and never creates one: an ID whose record is gone
 * is free, and a touch that wrote a field would take it.
 */
const LUA_FG_TOUCH = `${LUA_FG_PRELUDE}
local at = tonumber(ARGV[1])
if at == nil then return 0 end
local g = fg_visible(KEYS[1], at)
if g == nil or g['status'] ~= 'active' then return 0 end
local last = fg_num(g['lastUsedAt'])
if last ~= nil and not (last < at) then return 0 end
redis.call('HSET', KEYS[1], 'lastUsedAt', ARGV[1])
return 1
`;

/**
 * Reserves a grant in its subject's index. `KEYS[1]` = index; `ARGV` = member, its horizon, the
 * allowance. The score only moves forward (written out rather than `ZADD GT` so the index's
 * deadline is set in the same step). That deadline is the last horizon plus the allowance, so
 * the index outlives every record it points at even when its node's clock differs from theirs.
 */
const LUA_FG_RESERVE = `
local horizon = tonumber(ARGV[2])
local allowance = tonumber(ARGV[3])
if horizon == nil or allowance == nil then return 0 end
local current = redis.call('ZSCORE', KEYS[1], ARGV[1])
if current == false or tonumber(current) < horizon then
  redis.call('ZADD', KEYS[1], ARGV[2], ARGV[1])
end
local last = redis.call('ZRANGE', KEYS[1], -1, -1, 'WITHSCORES')
if #last == 2 then
  redis.call('PEXPIREAT', KEYS[1], math.ceil(tonumber(last[2]) + allowance))
end
return 1
`;

/**
 * Drops members whose horizon is past by the allowance. `KEYS[1]` = index; `ARGV` = the
 * adapter's clock, the allowance. Never by the record's absence: a member reserved for a record
 * still being written would be lost for good. The allowance keeps the prune later than any
 * answer a replica with a different clock could still give from the record.
 */
const LUA_FG_PRUNE = `
local clock = tonumber(ARGV[1])
local allowance = tonumber(ARGV[2])
if clock == nil or allowance == nil then return 0 end
return redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', '(' .. string.format('%.0f', clock - allowance))
`;

/**
 * Takes a grant from its current intent to `active`. `KEYS[1]` = record, `KEYS[2]` =
 * credential; `ARGV` = the caller's clock, the handle, the authorization text, its expiry, the
 * identity revision, upstream issuer and subject, the sealed credential.
 *
 * The current intent is compared here, not the version (naming and retiring an intent bump
 * none), so a renewal already superseded or retired by a subject-wide revocation can never be
 * activated. Unless `pending`, the stored expiry must not have passed, and the identity revision
 * and upstream account must match the recorded ones: a renewal never re-points a grant at
 * another account. The authorization is replaced whole, taking its marker and failure stamp with
 * it; a recorded use stays.
 */
const LUA_FG_ACTIVATE = `${LUA_FG_PRELUDE}
local now = tonumber(ARGV[1])
local expiresAt = tonumber(ARGV[4])
if now == nil or expiresAt == nil then return {0} end
local g = fg_visible(KEYS[1], now)
if g == nil then return {0} end
if g['status'] == 'revoked' then return {0} end
if g['status'] ~= 'pending' then
  local stored = fg_num(g['expiresAtMs'])
  if stored == nil or not (now < stored) then return {0} end
end
if not fg_same(g['intentHandle'], ARGV[2]) then return {0} end
local intentAt = fg_num(g['intentExpiresAt'])
if intentAt == nil or not (now < intentAt) then return {0} end
if g['authorization'] ~= nil then
  if g['identityRevision'] ~= ARGV[5] then return {0} end
  if g['upstreamIssuer'] ~= ARGV[6] then return {0} end
  if g['upstreamSubject'] ~= ARGV[7] then return {0} end
end
local version = fg_num(g['version'])
if version == nil then return {0} end
redis.call('HDEL', KEYS[1],
  'intentHandle', 'intentExpiresAt', 'ineligible',
  'failureAt', 'failureKind', 'failureCount',
  'failureRetryAfterSeconds', 'failureUpstreamCode')
redis.call('HSET', KEYS[1],
  'status', 'active',
  'version', string.format('%.0f', version + 1),
  'authorization', ARGV[3],
  'expiresAtMs', ARGV[4],
  'identityRevision', ARGV[5],
  'upstreamIssuer', ARGV[6],
  'upstreamSubject', ARGV[7])
redis.call('SET', KEYS[2], ARGV[8])
local fields = redis.call('HGETALL', KEYS[1])
local retention = fg_num(g['retentionMs']) or 0
redis.call('PEXPIREAT', KEYS[1], math.ceil(expiresAt + retention))
redis.call('PEXPIREAT', KEYS[2], math.ceil(expiresAt))
return {1, fields}
`;

/**
 * Replaces an `active` grant's credential. `KEYS[1]` = record, `KEYS[2]` = credential; `ARGV` =
 * the caller's clock, the expected version, the sealed credential, whether a marker was given,
 * the marker. The marker is replaced whole (none given: removed) and the failure stamp cleared.
 * No horizon moves: the credential keeps its expiry, so a rotation does not extend the consent.
 * A credential Redis has already reclaimed is not replaced; there is nothing to rotate.
 */
const LUA_FG_REPLACE = `${LUA_FG_PRELUDE}
local now = tonumber(ARGV[1])
local expected = tonumber(ARGV[2])
if now == nil or expected == nil then return {0} end
local g = fg_visible(KEYS[1], now)
if g == nil or g['status'] ~= 'active' then return {0} end
local version = fg_num(g['version'])
if version == nil or version ~= expected then return {0} end
local expiresAt = fg_num(g['expiresAtMs'])
if expiresAt == nil or not (now < expiresAt) then return {0} end
-- The credential it replaces must still be there (#631): its key's deadline
-- is the expiry on the server's clock, and once that has fired the refresh is
-- refused HERE, in the step that writes. The adapter's own read of the
-- credential is a round trip earlier, and the deadline can fire between the
-- two; written all the same, the new credential would take the same past
-- deadline and be gone at once, after a reply that said it was written
-- (Copilot).
if redis.call('EXISTS', KEYS[2]) == 0 then return {0} end
redis.call('HDEL', KEYS[1],
  'ineligible', 'failureAt', 'failureKind', 'failureCount',
  'failureRetryAfterSeconds', 'failureUpstreamCode')
redis.call('HSET', KEYS[1], 'version', string.format('%.0f', version + 1))
if ARGV[4] == '1' then
  redis.call('HSET', KEYS[1], 'ineligible', ARGV[5])
end
redis.call('SET', KEYS[2], ARGV[3])
local fields = redis.call('HGETALL', KEYS[1])
redis.call('PEXPIREAT', KEYS[2], math.ceil(expiresAt))
return {1, fields}
`;

/**
 * Asks for the user again. `KEYS[1]` = record, `KEYS[2]` = credential; `ARGV` = the caller's
 * clock, the expected version. No expiry guard: an upstream saying the credential is dead is
 * believed whenever it says so, and the credential goes. The marker stays (it describes what the
 * user is asked about) and the horizon does not move.
 */
const LUA_FG_REQUIRE_REAUTH = `${LUA_FG_PRELUDE}
local now = tonumber(ARGV[1])
local expected = tonumber(ARGV[2])
if now == nil or expected == nil then return {0} end
local g = fg_visible(KEYS[1], now)
if g == nil or g['status'] ~= 'active' then return {0} end
local version = fg_num(g['version'])
if version == nil or version ~= expected then return {0} end
redis.call('HDEL', KEYS[1],
  'failureAt', 'failureKind', 'failureCount',
  'failureRetryAfterSeconds', 'failureUpstreamCode')
redis.call('HSET', KEYS[1],
  'status', 'reauthorization_required',
  'version', string.format('%.0f', version + 1))
redis.call('DEL', KEYS[2])
return {1, redis.call('HGETALL', KEYS[1])}
`;

/**
 * Ends the grant. `KEYS[1]` = record, `KEYS[2]` = credential; `ARGV` = the instant, who revoked.
 * No version guard: in either order with a refresh the outcome is right (the revocation takes
 * the new credential, or the status refuses the refresh). What was authorized stays, so the
 * status route can say what ended. No horizon moves, except for a grant never authorized, which
 * has no expiry and is retained from the revocation.
 */
const LUA_FG_REVOKE = `${LUA_FG_PRELUDE}
-- The horizon as the read side computes it (#627): from the expiry in the
-- authenticated authorization text, and never from the expiresAtMs copy
-- beside it, which anyone able to write the keyspace can move. Moved into the
-- past, the copy made a live grant read as a tombstone HERE, and refused the
-- one write meant to end it, while the credential stayed at rest until the
-- key's own TTL. A pending grant has no text and runs from its intent; a text
-- that does not parse gives no horizon, which is the retention case below.
--
-- Every number is read as the TypeScript reader reads it — a string of digits
-- within the safe-integer range, and the retention not negative — and not
-- with tonumber, which takes "-1.5" and "1e21": a value the reader refuses
-- makes a record it answers nothing for, and a horizon computed from such a
-- value here would refuse to end exactly that record (Codex). No horizon
-- instead, and the revocation proceeds.
local function fg_int(v)
  if type(v) ~= 'string' or string.match(v, '^%-?%d+$') == nil then return nil end
  local n = tonumber(v)
  if n == nil or n > 9007199254740991 or n < -9007199254740991 then return nil end
  return n
end
local function fg_revoke_horizon(g)
  local retention = fg_int(g['retentionMs'])
  if retention == nil or retention < 0 then return nil end
  if g['status'] == 'pending' then return fg_int(g['intentExpiresAt']) end
  local text = g['authorization']
  if text == nil then return nil end
  local ok, parsed = pcall(cjson.decode, text)
  if not ok or type(parsed) ~= 'table' then return nil end
  -- The eleventh element of the canonical text, as the codec lays it out.
  local expiresAt = fg_int(parsed[11])
  if expiresAt == nil then return nil end
  return expiresAt + retention
end
local at = tonumber(ARGV[1])
if at == nil then return {0} end
local flat = redis.call('HGETALL', KEYS[1])
if #flat == 0 then return {0} end
local g = fg_fields(flat)
if g['status'] == 'revoked' then return {0} end
-- The one write that does not go through the visibility check, because it is
-- the one that must always win. A horizon that CAN be computed is still
-- honoured: a tombstone is not revoked again. One that cannot — a record
-- whose retention someone deleted, or whose text does not read — is not a
-- reason to leave a credential at rest with no way to end it, which is
-- exactly the state an operator reaches for this in (the reviewer, then
-- Copilot).
local horizon = fg_revoke_horizon(g)
if horizon ~= nil and not (at < horizon) then return {0} end
local version = fg_num(g['version'])
local wasPending = g['status'] == 'pending'
redis.call('HDEL', KEYS[1],
  'intentHandle', 'intentExpiresAt',
  'failureAt', 'failureKind', 'failureCount',
  'failureRetryAfterSeconds', 'failureUpstreamCode')
redis.call('HSET', KEYS[1],
  'status', 'revoked',
  'revokedBy', ARGV[2],
  'revokedAt', ARGV[1])
-- A version that is not a number is left as it is: it cannot be bumped, and
-- refusing over it would be refusing the revocation. The caller is told the
-- write could not be represented, and the credential is gone all the same.
if version ~= nil then
  redis.call('HSET', KEYS[1], 'version', string.format('%.0f', version + 1))
end
redis.call('DEL', KEYS[2])
local fields = redis.call('HGETALL', KEYS[1])
if wasPending then
  local retention = fg_num(g['retentionMs'])
  if retention ~= nil then
    redis.call('PEXPIREAT', KEYS[1], math.ceil(at + retention))
  end
end
return {1, fields}
`;

/**
 * Stamps a failed refresh. `KEYS[1]` = record; `ARGV` = the caller's clock, the expected
 * version, the failure's instant, its kind, the row window, and two optional fields with a flag
 * each. The version is compared although none is written: a failure that outlived its refresh
 * must not install a backoff over a credential written since. The row is measured from the
 * stamp it replaces by the failure's own instant, not the caller's clock; an earlier instant is
 * refused, so an out-of-order stamp never replaces a newer one. Only the stamp's fields are
 * touched, so a use or intent written meanwhile survives.
 */
const LUA_FG_NOTE_FAILURE = `${LUA_FG_PRELUDE}
local now = tonumber(ARGV[1])
local expected = tonumber(ARGV[2])
local failedAt = tonumber(ARGV[3])
local row = tonumber(ARGV[5])
if now == nil or expected == nil or failedAt == nil then return {0} end
local g = fg_visible(KEYS[1], now)
if g == nil or g['status'] ~= 'active' then return {0} end
local version = fg_num(g['version'])
if version == nil or version ~= expected then return {0} end
local expiresAt = fg_num(g['expiresAtMs'])
if expiresAt == nil or not (now < expiresAt) then return {0} end
local previous = fg_num(g['failureAt'])
local count = 1
if previous ~= nil then
  if failedAt < previous then return {0} end
  -- Never over the user (#616, D12): a refusal that says the user has to come
  -- back is read as reauthorization_required, and no later stamp replaces it.
  if g['failureKind'] == 'rejected' then
    local code = g['failureUpstreamCode']
    if code == 'interaction_required' or code == 'login_required'
      or code == 'consent_required' or code == 'account_selection_required' then
      return {0}
    end
  end
  local since = failedAt - previous
  if row ~= nil and since <= row then
    count = (fg_num(g['failureCount']) or 0) + 1
  end
end
redis.call('HDEL', KEYS[1], 'failureRetryAfterSeconds', 'failureUpstreamCode')
redis.call('HSET', KEYS[1],
  'failureAt', ARGV[3],
  'failureKind', ARGV[4],
  'failureCount', string.format('%.0f', count))
if ARGV[6] == '1' then redis.call('HSET', KEYS[1], 'failureRetryAfterSeconds', ARGV[7]) end
if ARGV[8] == '1' then redis.call('HSET', KEYS[1], 'failureUpstreamCode', ARGV[9]) end
return {1, redis.call('HGETALL', KEYS[1])}
`;

const FG_CREATE = defineScript(LUA_FG_CREATE);
const FG_SNAPSHOT = defineScript(LUA_FG_SNAPSHOT);
const FG_NAME_INTENT = defineScript(LUA_FG_NAME_INTENT);
const FG_RETIRE_INTENT = defineScript(LUA_FG_RETIRE_INTENT);
const FG_TOUCH = defineScript(LUA_FG_TOUCH);
const FG_RESERVE = defineScript(LUA_FG_RESERVE);
const FG_PRUNE = defineScript(LUA_FG_PRUNE);
/** The same source the session lock uses: a delete that only frees the value it was given. */
const FG_UNLOCK = defineScript(LUA_COMPARE_AND_DELETE);
const FG_ACTIVATE = defineScript(LUA_FG_ACTIVATE);
const FG_REPLACE = defineScript(LUA_FG_REPLACE);
const FG_REQUIRE_REAUTH = defineScript(LUA_FG_REQUIRE_REAUTH);
const FG_REVOKE = defineScript(LUA_FG_REVOKE);
const FG_NOTE_FAILURE = defineScript(LUA_FG_NOTE_FAILURE);

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
 * `HGETALL`'s flat `[field, value, …]` reply — as a script returns it — as
 * the hash's fields. Anything but a list is no fields. The one reading of
 * that reply, shared by every store here that has a script answer a hash.
 */
const hashFields = (flat: unknown): Record<string, string> => {
	const pairs = Array.isArray(flat) ? (flat as string[]) : [];
	const fields: Record<string, string> = {};
	for (let i = 0; i + 1 < pairs.length; i += 2) {
		fields[pairs[i] as string] = pairs[i + 1] as string;
	}
	return fields;
};

/** `HGETALL`'s flat `[field, value, …]` reply as the record's fields. */
const deviceCodeRecordOf = (flat: unknown): DeviceCodeRecordFields =>
	hashFields(flat) as unknown as DeviceCodeRecordFields;

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

/** A number as a Redis argument: never in exponent form, whatever its magnitude. */
const fgNumber = (value: number): string =>
	Number.isFinite(value) ? value.toFixed(0) : String(value);

/** `HGETALL`'s flat `[field, value, …]` reply as the record's fields. */
const fgFields = (flat: unknown): FederationGrantHashFields =>
	hashFields(flat) as unknown as FederationGrantHashFields;

/**
 * A write's reply: `[1, fields]` when it happened, `[0]` when it was refused.
 * Absence and a failed precondition are the same answer on purpose: the
 * record may change again before the caller looks, so the port re-reads.
 */
const fgWritten = (reply: unknown): FederationGrantHashFields | null => {
	if (!Array.isArray(reply) || reply[0] !== 1) return null;
	return fgFields(reply[1]);
};

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
//
// The five operations that read, decide and write across keys are scripts (the alternative,
// WATCH/MULTI, needs a connection of its own); the two reads are plain commands. Each script
// is routed by KEYS[1] and derives the other keys from ARGV[1], the `<prefix>{intents}:`
// namespace, so all share one hash tag and the operation stays one atomic step on a Cluster
// node. No script reaches a grant's keys (`<prefix>{<id>}:…`).
//
// A caller's `now` decides what it is told; only Redis reclaims (key TTLs, and the server time
// the admission script prunes the bound by). No script deletes a record on a caller's clock.

/**
 * Admission. KEYS[1] = the intent. ARGV: prefix, handle, record, expiresAtMs,
 * nowMs, pair, counts ("1"/"0"), limit, allowanceMs.
 *
 * Residency before visibility: a record that is THERE takes the handle, however
 * far ahead the caller's clock is. The same text again is the retry of a write
 * whose answer was lost, and changes nothing. The bound is pruned on the
 * server's clock, counted, and taken in the same step as the write.
 */
const LUA_FGI_ADMIT = `
local now = tonumber(ARGV[5])
local exp = tonumber(ARGV[4])
if now == nil or exp == nil then return {'refused', 'expired'} end
if redis.call('EXISTS', KEYS[1]) == 1 then
  if redis.call('HGET', KEYS[1], 'closed') == '1' then return {'refused', 'closed'} end
  if redis.call('HGET', KEYS[1], 'record') == ARGV[3] then return {'unchanged'} end
  return {'refused', 'collision'}
end
if not (now < exp) then return {'refused', 'expired'} end
if ARGV[7] == '1' then
  local rkey = ARGV[1] .. 'r:' .. ARGV[6]
  local t = redis.call('TIME')
  local serverMs = (tonumber(t[1]) * 1000) + math.floor(tonumber(t[2]) / 1000)
  redis.call('ZREMRANGEBYSCORE', rkey, '-inf', serverMs)
  if redis.call('ZCARD', rkey) >= tonumber(ARGV[8]) then return {'refused', 'limit'} end
  redis.call('ZADD', rkey, exp, ARGV[2])
  local last = redis.call('ZRANGE', rkey, -1, -1, 'WITHSCORES')
  redis.call('PEXPIREAT', rkey, math.ceil(tonumber(last[2]) + tonumber(ARGV[9])))
end
redis.call('HSET', KEYS[1],
  'format', '1',
  'record', ARGV[3],
  'expiresAt', ARGV[4],
  'pair', ARGV[6],
  'counts', ARGV[7])
redis.call('PEXPIREAT', KEYS[1], math.ceil(exp))
return {'created'}
`;

/**
 * KEYS[1] = the intent. ARGV: prefix, handle, challenge, record, binding,
 * expiresAtMs, nowMs.
 *
 * One challenge per intent: the browser that parked it gets the same one back,
 * any other browser gets nothing. A challenge another intent holds is never
 * taken.
 */
const LUA_FGI_PARK = `
local now = tonumber(ARGV[7])
if now == nil then return false end
if redis.call('EXISTS', KEYS[1]) == 0 then return false end
if redis.call('HGET', KEYS[1], 'closed') == '1' then return false end
local exp = tonumber(redis.call('HGET', KEYS[1], 'expiresAt'))
if exp == nil or not (now < exp) then return false end
local parked = redis.call('HGET', KEYS[1], 'challenge')
if parked then
  -- One challenge per intent, and the pointer says one was issued. A consent
  -- key that is gone (evicted, say) is not room for a new one: parking again
  -- would bind the flow to whichever browser asked next. The memory adapter
  -- refuses, and so does this.
  local pkey = ARGV[1] .. 'c:' .. parked
  if redis.call('EXISTS', pkey) == 0 then return false end
  if redis.call('HGET', pkey, 'binding') == ARGV[5] then
    return redis.call('HGET', pkey, 'record')
  end
  return false
end
local ckey = ARGV[1] .. 'c:' .. ARGV[3]
if redis.call('EXISTS', ckey) == 1 then return false end
redis.call('HSET', ckey,
  'format', '1',
  'record', ARGV[4],
  'binding', ARGV[5],
  'expiresAt', ARGV[6],
  'intent', ARGV[2])
redis.call('PEXPIREAT', ckey, math.ceil(exp))
redis.call('HSET', KEYS[1], 'challenge', ARGV[3])
return ARGV[4]
`;

/**
 * KEYS[1] = the consent. ARGV: prefix, nowMs, binding, decision, state, transaction,
 * transactionExpiresAtMs, connection.
 *
 * The whole answer in one step: the challenge goes, the intent is marked spent, and an approval
 * writes the transaction, or nothing happens. Both the consent's and the intent's deadline are
 * checked (one date, but two keys Redis may reclaim at different instants). A state already
 * held by a transaction refuses the approval and spends nothing.
 */
const LUA_FGI_ANSWER = `
local now = tonumber(ARGV[2])
if now == nil then return {'empty'} end
if redis.call('EXISTS', KEYS[1]) == 0 then return {'empty'} end
local exp = tonumber(redis.call('HGET', KEYS[1], 'expiresAt'))
if exp == nil or not (now < exp) then return {'empty'} end
if redis.call('HGET', KEYS[1], 'binding') ~= ARGV[3] then return {'empty'} end
local handle = redis.call('HGET', KEYS[1], 'intent')
if not handle then return {'empty'} end
local ikey = ARGV[1] .. 'i:' .. handle
if redis.call('EXISTS', ikey) == 0 then return {'empty'} end
if redis.call('HGET', ikey, 'closed') == '1' then return {'empty'} end
local iexp = tonumber(redis.call('HGET', ikey, 'expiresAt'))
if iexp == nil or not (now < iexp) then return {'empty'} end
if ARGV[4] == 'accept' then
  local txkey = ARGV[1] .. 'tx:' .. ARGV[5]
  if redis.call('EXISTS', txkey) == 1 then return {'state_collision'} end
  redis.call('DEL', KEYS[1])
  redis.call('HSET', ikey, 'closed', '1', 'state', ARGV[5])
  redis.call('HDEL', ikey, 'challenge')
  redis.call('HSET', txkey,
    'format', '1',
    'record', ARGV[6],
    'expiresAt', ARGV[7],
    'connection', ARGV[8],
    'intent', handle)
  redis.call('PEXPIREAT', txkey, math.ceil(tonumber(ARGV[7])))
  return {'accepted', ARGV[6]}
end
local record = redis.call('HGET', ikey, 'record')
redis.call('DEL', KEYS[1])
redis.call('HSET', ikey, 'closed', '1')
redis.call('HDEL', ikey, 'challenge')
if redis.call('HGET', ikey, 'counts') == '1' then
  local pair = redis.call('HGET', ikey, 'pair')
  if pair then redis.call('ZREM', ARGV[1] .. 'r:' .. pair, handle) end
end
return {'denied', record}
`;

/**
 * KEYS[1] = the transaction. ARGV: prefix, connection, nowMs. Read and removed
 * in one step, and only for the connection it belongs to: a callback on
 * another connection's path leaves it exactly where it is.
 */
const LUA_FGI_CONSUME = `
local now = tonumber(ARGV[3])
if now == nil then return false end
if redis.call('EXISTS', KEYS[1]) == 0 then return false end
local exp = tonumber(redis.call('HGET', KEYS[1], 'expiresAt'))
if exp == nil or not (now < exp) then return false end
local handle = redis.call('HGET', KEYS[1], 'intent')
if not handle then return false end
local ikey = ARGV[1] .. 'i:' .. handle
if redis.call('EXISTS', ikey) == 0 then return false end
if redis.call('HGET', KEYS[1], 'connection') ~= ARGV[2] then return false end
local record = redis.call('HGET', KEYS[1], 'record')
redis.call('DEL', KEYS[1])
redis.call('HDEL', ikey, 'state')
return record
`;

/**
 * KEYS[1] = the intent. ARGV: prefix, handle. Closes the handle, drops the
 * consent and transaction still under it, and releases its place — ZREM is
 * idempotent, so a second call releases nothing a second time.
 */
const LUA_FGI_FINISH = `
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
local challenge = redis.call('HGET', KEYS[1], 'challenge')
if challenge then redis.call('DEL', ARGV[1] .. 'c:' .. challenge) end
local state = redis.call('HGET', KEYS[1], 'state')
if state then redis.call('DEL', ARGV[1] .. 'tx:' .. state) end
if redis.call('HGET', KEYS[1], 'counts') == '1' then
  local pair = redis.call('HGET', KEYS[1], 'pair')
  if pair then redis.call('ZREM', ARGV[1] .. 'r:' .. pair, ARGV[2]) end
end
redis.call('HSET', KEYS[1], 'closed', '1')
redis.call('HDEL', KEYS[1], 'challenge', 'state')
return 1
`;

const FGI_ADMIT = defineScript(LUA_FGI_ADMIT);
const FGI_PARK = defineScript(LUA_FGI_PARK);
const FGI_ANSWER = defineScript(LUA_FGI_ANSWER);
const FGI_CONSUME = defineScript(LUA_FGI_CONSUME);
const FGI_FINISH = defineScript(LUA_FGI_FINISH);

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

const fgiText = (reply: unknown): string | null => (typeof reply === "string" ? reply : null);

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
 * `MfaFactorStoreClient.update`: the version compare-and-set. `KEYS[1]` = the subject's hash;
 * `ARGV[1]` = the factor's field, `ARGV[2]` = expected version, `ARGV[3]` = next version,
 * `ARGV[4]` = the new mutable part. Returns the value as written, or nil.
 *
 * The value is `<version>\n<fixed>\n<mutable>` (see `MfaFactorStoreClient`). The version is
 * compared as text and the fixed part copied byte for byte, never decoded: `cjson` would write
 * an empty array back as `{}`. A value with a fourth line, even an empty one, is not one this
 * adapter wrote and answers nil.
 */
const LUA_MFA_FACTOR_UPDATE = `
local current = redis.call('HGET', KEYS[1], ARGV[1])
if not current then return false end
local version, fixed = string.match(current, '^([^\\n]*)\\n([^\\n]*)\\n[^\\n]*$')
if version ~= ARGV[2] or fixed == nil then return false end
local written = ARGV[3] .. '\\n' .. fixed .. '\\n' .. ARGV[4]
redis.call('HSET', KEYS[1], ARGV[1], written)
return written
`.trim();

const MFA_FACTOR_UPDATE = defineScript(LUA_MFA_FACTOR_UPDATE);

/**
 * A reply that refuses the question — an unknown or renamed command, an
 * unknown subcommand, `NOPERM`, a command a managed service disabled — rather
 * than one that says the server cannot answer now (`BUSY`, `LOADING`,
 * `NOAUTH`, `READONLY`, anything else), which fails the boot as any store
 * outage at boot does.
 */
const REFUSED_QUESTION =
	/^(?:NOPERM\b|ERR unknown command\b|ERR unknown subcommand\b|ERR\b.*\b(?:disabled|not allowed|not permitted|not supported|not available)\b)/i;

const isRefusal = (err: unknown): boolean =>
	err instanceof Error && err.name === "ReplyError" && REFUSED_QUESTION.test(err.message);

/**
 * `CONFIG GET <name>`'s value: the reply is `[name, value]`, or empty for a name the server
 * does not know.
 */
const configValue = (reply: unknown, name: string): string | undefined =>
	Array.isArray(reply) && reply[0] === name && typeof reply[1] === "string" ? reply[1] : undefined;

/** An `INFO` section's `<name>:<value>` line's value. */
const infoValue = (section: unknown, name: string): string | undefined =>
	typeof section === "string"
		? new RegExp(`^${name}:([^\\r\\n]*)`, "m").exec(section)?.[1]
		: undefined;

/**
 * What `io`'s server says about keeping what it is written. The policy from `INFO memory`
 * (`CONFIG GET maxmemory-policy` only where INFO does not say, so a managed server that blocks
 * `CONFIG` still reports it); AOF from `INFO persistence`; `CONFIG GET save` only when AOF is
 * off, to tell RDB snapshots from none. A refused question leaves its part unread; any other
 * failure is the caller's.
 */
async function redisDurability(io: Redis): Promise<RedisDurability> {
	let refusal: unknown;
	const ask = async (question: () => Promise<unknown>): Promise<unknown> => {
		try {
			return await question();
		} catch (err) {
			if (!isRefusal(err)) throw err;
			refusal ??= err;
			return undefined;
		}
	};
	const maxmemoryPolicy =
		infoValue(await ask(() => io.info("memory")), "maxmemory_policy") ??
		configValue(await ask(() => io.config("GET", "maxmemory-policy")), "maxmemory-policy");
	const aof = infoValue(await ask(() => io.info("persistence")), "aof_enabled");
	const appendOnly = aof === "1" ? true : aof === "0" ? false : undefined;
	let snapshots: boolean | undefined;
	if (appendOnly === false) {
		const save = configValue(await ask(() => io.config("GET", "save")), "save");
		snapshots = save === undefined ? undefined : save.trim() !== "";
	}
	return { maxmemoryPolicy, appendOnly, snapshots, refusal };
}

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

// A transaction is one hash. Its deadline is set once, by `create`, and nothing moves it: an
// update, an attempt, a taken challenge each write fields and leave the key's expiry alone.

/**
 * `MfaTransactionStoreClient.create` — insert-only.
 *
 * `KEYS[1]` = the transaction; `ARGV[1]` = its deadline (epoch ms, whole),
 * then field, value, field, value, … Returns 1 when it wrote, 0 when a live
 * transaction holds the id. A deadline already past on the server's clock
 * removes the key as it is written: the transaction has expired on the
 * store's clock.
 */
const LUA_MFA_TX_CREATE = `
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
redis.call('HSET', KEYS[1], unpack(ARGV, 2))
redis.call('PEXPIREAT', KEYS[1], ARGV[1])
return 1
`.trim();

/**
 * `MfaTransactionStoreClient.update`: the version compare-and-set. `KEYS[1]` = the
 * transaction; `ARGV[1]` = expected version, `ARGV[2]` = incarnation, `ARGV[3]` = n, then n
 * field/value pairs, then the fields to remove. Returns every field as written, or nil.
 * `HINCRBY` moves the version, exact where Lua's 14-digit number text would not be; core's
 * `checkMfaVersionAdvances` refuses an update at `Number.MAX_SAFE_INTEGER` before this runs.
 */
const LUA_MFA_TX_UPDATE = `
local held = redis.call('HMGET', KEYS[1], 'version', 'incarnation')
if held[1] ~= ARGV[1] or held[2] ~= ARGV[2] then return false end
local n = tonumber(ARGV[3])
local set = {}
for i = 1, n * 2 do set[i] = ARGV[3 + i] end
if n > 0 then redis.call('HSET', KEYS[1], unpack(set)) end
for i = 4 + n * 2, #ARGV do redis.call('HDEL', KEYS[1], ARGV[i]) end
redis.call('HINCRBY', KEYS[1], 'version', 1)
return redis.call('HGETALL', KEYS[1])
`.trim();

/**
 * `mfa_tx_gone(key, now)`, for the scripts that decide on a live transaction with the caller's
 * clock (`reserveAttempt`, `takeChallenge`): gone at or past `expiresAtMs`, or when that field
 * is not a finite number, as `transactionOf` judges it (`tonumber` reads `String`'s text as the
 * same double). `record` is never decoded: `cjson` refuses lone surrogates and deep nesting that
 * `JSON.parse` reads. Nothing is deleted, so a caller whose clock runs ahead costs no other
 * caller the transaction (as `fg_visible` treats a federation grant).
 */
const LUA_MFA_TX_PRELUDE = `
local function mfa_tx_gone(key, now)
  local deadline = tonumber(redis.call('HGET', key, 'expiresAtMs'))
  if deadline == nil or deadline ~= deadline or deadline == math.huge or deadline == -math.huge then
    return true
  end
  return not (now < deadline)
end
`;

/**
 * `MfaTransactionStoreClient.reserveAttempt`.
 *
 * `KEYS[1]` = the transaction; `ARGV[1]` = max, `ARGV[2]` = the store's
 * clock. Returns `{ok, attempts}`: `{1, n}` for the nth attempt within max;
 * `{0, n}` — and the transaction gone — for the one past it, n being what it
 * had; `{0, 0}` for no transaction, for one gone at the store's clock (left
 * as it is), or for a count that is not a number (fails closed: deleted).
 */
const LUA_MFA_TX_RESERVE_ATTEMPT = `${LUA_MFA_TX_PRELUDE}
if redis.call('EXISTS', KEYS[1]) == 0 then return {0, 0} end
if mfa_tx_gone(KEYS[1], tonumber(ARGV[2])) then return {0, 0} end
local attempts = tonumber(redis.call('HGET', KEYS[1], 'attempts'))
if attempts == nil then
  redis.call('DEL', KEYS[1])
  return {0, 0}
end
if not (attempts + 1 <= tonumber(ARGV[1])) then
  redis.call('DEL', KEYS[1])
  return {0, attempts}
end
return {1, redis.call('HINCRBY', KEYS[1], 'attempts', 1)}
`.trim();

/**
 * `MfaTransactionStoreClient.takeChallenge`. `KEYS[1]` = the transaction;
 * `ARGV[1]` = the expected version, `ARGV[2]` = the store's clock. Nothing
 * is taken from a transaction gone at that clock.
 */
const LUA_MFA_TX_TAKE_CHALLENGE = `${LUA_MFA_TX_PRELUDE}
if redis.call('HGET', KEYS[1], 'version') ~= ARGV[1] then return false end
if mfa_tx_gone(KEYS[1], tonumber(ARGV[2])) then return false end
local challenge = redis.call('HGET', KEYS[1], 'challenge')
if not challenge then return false end
redis.call('HDEL', KEYS[1], 'challenge')
return challenge
`.trim();

/**
 * `MfaTransactionStoreClient.consume`. `KEYS[1]` = the transaction; `ARGV[1]` = the expected
 * version.
 */
const LUA_MFA_TX_CONSUME = `
if redis.call('HGET', KEYS[1], 'version') ~= ARGV[1] then return false end
local fields = redis.call('HGETALL', KEYS[1])
redis.call('DEL', KEYS[1])
return fields
`.trim();

// Subject lockout state: `KEYS[1]` the lock hash, `KEYS[2]` the week's sorted set (see
// `MfaSubjectKeys`), under one hash tag. The rules are core's in-process store's
// (`core/src/mfa/memoryTransactionStore.mts`), applied in the same floating-point operations
// on the same numbers: every instant travels as the caller's text or as `%.17g`, which reads
// back as the same double.
//
// Answers are judged on the caller's `now`; what a script forgets is judged no later than the
// server's clock less a day (MFA_CLOCK_SKEW_ALLOWANCE_MS), so a caller far ahead erases nothing.
// While a run is counted the keys have no TTL; otherwise they expire a day after the last
// failure stops counting. A stored value a script cannot read is an error (an outage), never
// read as an empty state; a lock-hash field of a kind the scripts do not read is ignored.

const LUA_MFA_SUBJECT_PRELUDE = `
local WEEK = 604800000
local SKEW = 86400000

local function corrupt()
  error({err = 'MFA subject state: a stored value is not one this store wrote; the operation is refused'})
end

local function num(text)
  local n = tonumber(text)
  if n == nil or n ~= n or n == math.huge or n == -math.huge then corrupt() end
  return n
end

local function fmt(n) return string.format('%.17g', n) end

local function server_ms()
  local t = redis.call('TIME')
  return tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
end

-- The state: the run, the reservations in flight, and the week in time
-- order. A field of any other kind is not read.
local function load()
  local run, pending, week = {}, {}, {}
  local flat = redis.call('HGETALL', KEYS[1])
  for i = 1, #flat, 2 do
    local field, value = flat[i], flat[i + 1]
    local kind, id = string.sub(field, 1, 2), string.sub(field, 3)
    if kind == 'r:' then
      local seq, at = string.match(value, '^(%d+)|(.+)$')
      if seq == nil then corrupt() end
      run[#run + 1] = {id = id, seq = num(seq), at = num(at)}
    elseif kind == 'p:' then
      if string.match(value, '^%d+$') == nil then corrupt() end
      pending[id] = num(value)
    end
  end
  local z = redis.call('ZRANGE', KEYS[2], 0, -1, 'WITHSCORES')
  for i = 1, #z, 2 do week[#week + 1] = {id = z[i], at = num(z[i + 1])} end
  return run, pending, week
end

-- Forgets what no longer counts at horizon: the week's failures that ended
-- before it, and the reservations nothing counts any more. Answers what is
-- kept, and whether anything was forgotten.
local function prune(run, pending, week, horizon)
  local forgot = false
  local kept_week, in_week = {}, {}
  for _, a in ipairs(week) do
    if a.at + WEEK > horizon then
      kept_week[#kept_week + 1] = a
      in_week[a.id] = true
    else
      redis.call('ZREM', KEYS[2], a.id)
      forgot = true
    end
  end
  local in_run = {}
  for _, a in ipairs(run) do in_run[a.id] = true end
  for id in pairs(pending) do
    if not in_run[id] and not in_week[id] then
      redis.call('HDEL', KEYS[1], 'p:' .. id)
      pending[id] = nil
      forgot = true
    end
  end
  return kept_week, forgot
end

-- Sets what Redis reclaims: no TTL while a run is counted; else a day past
-- the last failure to stop counting; nothing left, both keys go.
local function keep()
  local flat = redis.call('HGETALL', KEYS[1])
  local running, deadline = false, nil
  for i = 1, #flat, 2 do
    if string.sub(flat[i], 1, 2) == 'r:' then running = true end
  end
  if running then
    redis.call('PERSIST', KEYS[1])
    redis.call('PERSIST', KEYS[2])
    return
  end
  local last = redis.call('ZRANGE', KEYS[2], -1, -1, 'WITHSCORES')
  if last[2] then
    local e = num(last[2]) + WEEK
    if deadline == nil or e > deadline then deadline = e end
  end
  if deadline == nil then
    redis.call('DEL', KEYS[1], KEYS[2])
    return
  end
  local at = string.format('%.0f', math.ceil(deadline + SKEW))
  redis.call('PEXPIREAT', KEYS[1], at)
  redis.call('PEXPIREAT', KEYS[2], at)
end
`;

/**
 * `MfaTransactionStoreClient.reserveSubjectAttempt`.
 *
 * `ARGV`: now, threshold, baseSeconds, maxSeconds, memorySeconds,
 * weeklyBudget, hardLimit, the reservation's id. Returns `{'ok'}`, or
 * `{'held', hold, retryAfterMs, first}` with an empty retry for the hard
 * hold and `first` `1` for the refusal that begins an episode, `0` after.
 */
const LUA_MFA_SUBJECT_RESERVE = `${LUA_MFA_SUBJECT_PRELUDE}
local now = num(ARGV[1])
local threshold, base, max_s, memory_s = num(ARGV[2]), num(ARGV[3]), num(ARGV[4]), num(ARGV[5])
local budget, hard = num(ARGV[6]), num(ARGV[7])
local id = ARGV[8]
local run, pending, week = load()
local forgot
week, forgot = prune(run, pending, week, math.min(now, server_ms()) - SKEW)

-- A refusal writes only the mark that its episode began, once: the deadlines
-- are set again only then or when the prune forgot something, so a held
-- subject hammered is no write load.
local function refuse(hold, retry)
  local first = redis.call('HSETNX', KEYS[1], 'held', '1') == 1
  if forgot or first then keep() end
  local mark = '0'
  if first then mark = '1' end
  return {'held', hold, retry, mark}
end

if #run >= hard then
  return refuse('hard', '')
end

-- The short backoff: the run replayed in time order. A failure memorySeconds
-- after the last lock ended — or, before any lock, after the previous
-- failure — starts it again; from the threshold-th, each locks for
-- baseSeconds doubled per further failure, at most maxSeconds.
table.sort(run, function(a, b)
  if a.at ~= b.at then return a.at < b.at end
  return a.seq < b.seq
end)
local memory_ms = memory_s * 1000
local count, lock_until, last_at = 0, nil, nil
for _, a in ipairs(run) do
  local anchor = lock_until or last_at
  if anchor ~= nil and a.at >= anchor + memory_ms then
    count = 0
    lock_until = nil
  end
  count = count + 1
  last_at = a.at
  if count >= threshold then
    local doublings = math.min(count - threshold, 64)
    lock_until = a.at + math.min(base * 2 ^ doublings, max_s) * 1000
  end
end
local backoff = nil
if lock_until ~= nil and now < lock_until then backoff = lock_until end

-- The weekly budget: when the week will count fewer than weeklyBudget
-- failures again.
local weekly = nil
local counted = {}
for _, a in ipairs(week) do
  if a.at + WEEK > now then counted[#counted + 1] = a end
end
if #counted >= budget then weekly = counted[#counted - budget + 1].at + WEEK end

if backoff ~= nil or weekly ~= nil then
  -- The hold that ends later decides when to come back.
  if (weekly or -math.huge) >= (backoff or -math.huge) then
    return refuse('weekly', fmt(weekly - now))
  end
  return refuse('backoff', fmt(backoff - now))
end

local seq = redis.call('HINCRBY', KEYS[1], 'seq', 1)
redis.call('HSET', KEYS[1], 'r:' .. id, seq .. '|' .. ARGV[1], 'p:' .. id, seq)
redis.call('HDEL', KEYS[1], 'held')
redis.call('ZADD', KEYS[2], ARGV[1], id)
keep()
return {'ok'}
`;

/**
 * `MfaTransactionStoreClient.settleSubjectAttempt`.
 *
 * `ARGV`: the reservation, the outcome. `void` removes the attempt; `success`
 * ends the run up to and including it, and takes it out of the week;
 * `failure` leaves it standing. A reservation not in flight changes nothing.
 * The whole state is read and validated before anything is written.
 */
const LUA_MFA_SUBJECT_SETTLE = `${LUA_MFA_SUBJECT_PRELUDE}
local id, outcome = ARGV[1], ARGV[2]
-- Read and validate the whole state before anything is written: a corrupt
-- field is the refusal, with nothing half-settled.
local run, pending = load()
local seq = pending[id]
if seq == nil then return 0 end
redis.call('HDEL', KEYS[1], 'p:' .. id)
if outcome == 'void' then
  redis.call('HDEL', KEYS[1], 'r:' .. id)
  redis.call('ZREM', KEYS[2], id)
elseif outcome == 'success' then
  for _, a in ipairs(run) do
    if a.seq <= seq then redis.call('HDEL', KEYS[1], 'r:' .. a.id) end
  end
  redis.call('ZREM', KEYS[2], id)
end
keep()
return 1
`;

/**
 * `MfaTransactionStoreClient.noteExemptSuccess`.
 *
 * `ARGV`: now. Ends the run up to now; the week stands.
 */
const LUA_MFA_SUBJECT_EXEMPT = `${LUA_MFA_SUBJECT_PRELUDE}
local now = num(ARGV[1])
local run, pending, week = load()
prune(run, pending, week, math.min(now, server_ms()) - SKEW)
for _, a in ipairs(run) do
  if a.at <= now then redis.call('HDEL', KEYS[1], 'r:' .. a.id) end
end
keep()
return 1
`;

const MFA_TX_CREATE = defineScript(LUA_MFA_TX_CREATE);
const MFA_TX_UPDATE = defineScript(LUA_MFA_TX_UPDATE);
const MFA_TX_RESERVE_ATTEMPT = defineScript(LUA_MFA_TX_RESERVE_ATTEMPT);
const MFA_TX_TAKE_CHALLENGE = defineScript(LUA_MFA_TX_TAKE_CHALLENGE);
const MFA_TX_CONSUME = defineScript(LUA_MFA_TX_CONSUME);
const MFA_SUBJECT_RESERVE = defineScript(LUA_MFA_SUBJECT_RESERVE);
const MFA_SUBJECT_SETTLE = defineScript(LUA_MFA_SUBJECT_SETTLE);
const MFA_SUBJECT_EXEMPT = defineScript(LUA_MFA_SUBJECT_EXEMPT);

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
