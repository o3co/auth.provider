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
	ConsentRecordFields,
	ConsentStoreClient,
	DeviceCodeRecordFields,
	DeviceCodeStoreClient,
	DisposableRefreshTokenFamilyClient,
	FederationGrantHashFields,
	FederationGrantStoreClient,
	FederationTokenStoreClient,
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
 *
 * Returns `{count, pttl}` — the post-increment count and the key's remaining
 * window in milliseconds (#458). The PTTL is read inside the script, after
 * the increment, so the pair describes one counter state; a separate PTTL
 * round-trip could observe a key the window had already expired out from
 * under. The limiter turns it into `resetAt`, which is what the guard needs
 * to put a `Retry-After` on the 429 — behind Redis it had none.
 */
const LUA_INCREMENT_WITH_TTL = `
local count = redis.call('INCR', KEYS[1])
if redis.call('TTL', KEYS[1]) < 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return {count, redis.call('PTTL', KEYS[1])}
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
/**
 * Both revocation boundaries, one key, one atomic write (#593, D13).
 *
 * The value is deliberately **not** JSON. `cjson.encode` writes numbers at
 * fourteen significant digits by default and an epoch millisecond is thirteen
 * — too close to a silent truncation for a value that decides whether a token
 * is refused — and the common case here is a single number, which a delimited
 * form keeps as a single number.
 *
 * That encoding is the other half of the rollback argument:
 *
 *   `<n>`          both boundaries are `n`. What `revokeBefore` always writes,
 *                  so what every caller written before #593, and the whole
 *                  `"revoke"` path, writes.
 *   `v1:<s>:<g>`   they differ.
 *   `v1:<s>:-`     the sessions boundary alone; no revocation has covered this
 *                  subject's grants.
 *
 * A previous release reads the first form and only the first form. So a
 * deployment that never makes a sessions-only stamp never writes anything an
 * older reader would refuse and can roll back freely; one that does has the
 * richer form only for the subjects it was used on, where an older reader
 * fails closed — the safe direction, and the smallest set available.
 *
 * What is unsafe in BOTH directions, and has to be said out loud: a
 * mixed-version writer. An old writer stamping over a `v1:` record reads it
 * with `tonumber`, gets nil, and writes its own scalar — moving the grants
 * boundary forward (safe) and the sessions boundary possibly backward (not).
 * Drain old writers before allowing sessions-only stamps.
 */
const LUA_SET_REVOCATION_BOUNDARIES = `
local mode = ARGV[1]
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

// --- Consent scripts (#561) -------------------------------------------------
//
// Five scripts — one per operation that must be indivisible, the pending
// store's read and consume sharing one — for the reason the device scripts
// above give. Expiry is judged by the record's own `expiresAt`
// against the caller's clock, passed in `ARGV`, and never by a key's TTL:
// the TTL a write sets is a safety net for records nobody reads again, the
// same split `LUA_DEVICE_CODE_POLL` makes between the TTL and `expiresAtMs`.
// A record inside its TTL whose timestamp has passed on the caller's clock is
// gone, and is reclaimed by whoever finds it.
//
// Expiries are set with a relative `PEXPIRE` rather than `PEXPIREAT` the
// caller's deadline. An absolute deadline is read on the server's clock, so
// the skew between the writing replica and Redis would move the safety net
// by exactly that much — before the logical expiry when Redis runs ahead. A
// lifetime measured from the write is independent of that skew; the adapter
// adds slack for the one it cannot remove, between the writer and a later
// reader (see `CONSENT_EXPIRY_SLACK_MS`).

/**
 * `ConsentStoreClient.find` — the record, unless it has expired.
 *
 * `KEYS[1]` = record key; `ARGV[1]` = now in epoch ms. Returns
 * `{scopes, grantedAt, expiresAt|nil}`, or nil for absent or expired.
 *
 * The reclaim is in the script because a `DEL` sent after the read could
 * remove a grant another browser wrote in between. An `expiresAt` that does
 * not parse reads as expired: the fail-closed direction for a consent.
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
 * `ConsentStoreClient.grant` — the union with what is recorded, as one write.
 *
 * `KEYS[1]` = record key; `ARGV[1]` = now in epoch ms, `ARGV[2]` = grantedAt,
 * `ARGV[3]` = the granted scopes as a JSON array, `ARGV[4]` = expiresAt or
 * empty for until revoked, `ARGV[5]` = the TTL in ms (read only with an
 * expiry).
 *
 * The recorded scopes join the union only while the recorded consent is live
 * on the caller's clock: a lapsed consent is not something the user still
 * agrees to. They keep their order and the new ones follow, as the memory
 * adapter's `Set` does. A recorded consent that is not well-formed — `scopes`
 * not a JSON array of strings, `grantedAt` not a number — contributes nothing
 * rather than failing the grant or lending it the strings it does hold: the
 * adapter's `find` reports such a record absent, so the user was asked again,
 * and their answer is the whole record. An empty union is written as `[]`
 * literally, because `cjson.encode({})` is `{}`.
 *
 * Without an expiry the record is until revoked, so the stale `expiresAt`
 * field goes and so does the key's TTL — `PERSIST`, explicitly: an earlier
 * expiring grant's TTL left in place would delete this consent when it fired,
 * on no request at all. With one whose TTL is not positive the new record is
 * dead on arrival, and the key is removed, as the memory adapter's record
 * would read.
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
 * `PendingConsentStoreClient.set` — park a request and hold its session to
 * the bound, in one script.
 *
 * `KEYS[1]` = record key, `KEYS[2]` = the session's index; `ARGV[1]` = now in
 * epoch ms, `ARGV[2]` = challenge, `ARGV[3]` = sessionId, `ARGV[4]` =
 * expiresAt, `ARGV[5]` = the record's TTL in ms, `ARGV[6]` = the serialised
 * request, `ARGV[7]` = the per-session bound, `ARGV[8]` = record key prefix,
 * `ARGV[9]` = session index key prefix.
 *
 * In the memory adapter's order: a request already parked under the
 * challenge leaves its own session's index (possibly another session's,
 * reached through the record); this session's expired requests — and index
 * entries whose record is already gone — leave before the bound is judged, so
 * a dead request never costs a live one its place; then the first-parked go
 * until there is room.
 *
 * The index is a sorted set scored by the order requests were parked in —
 * one past the highest score it holds — not by `createdAt`. That is the
 * memory adapter's insertion order exactly, and it is a total order no
 * replica's clock takes part in: `createdAt` is written by whichever replica
 * served the request, and two within a millisecond would tie and fall back to
 * comparing challenges, which are random.
 *
 * The index is kept alive at least as long as its longest-lived request —
 * its TTL is only ever raised — so it cannot vanish under a record it still
 * has to bound.
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
 * `PendingConsentStoreClient.get` and `.consume` — the read, and the read
 * that spends.
 *
 * `KEYS[1]` = record key; `ARGV[1]` = now in epoch ms, `ARGV[2]` = challenge,
 * `ARGV[3]` = session index key prefix, `ARGV[4]` = `spend` | `peek`.
 * Returns the serialised request, or nil for absent or expired.
 *
 * `spend` is the port's one step: the record, its removal and its index
 * entry's removal in one script, so of two answers in flight exactly one is
 * handed the request. `GETDEL` alone would be atomic for the record but
 * leave the index entry to a second command — a consumed request still
 * counting toward the bound until it did. `peek` never spends a live request;
 * an expired one is reclaimed by either.
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
 * `PendingConsentStoreClient.discard` — reclaim a request the adapter read and
 * found corrupt, only if it is still the value that was read.
 *
 * `KEYS[1]` = record key; `ARGV[1]` = the serialised request as read,
 * `ARGV[2]` = challenge, `ARGV[3]` = session index key prefix. Returns 1 when
 * the record and its index entry were removed, 0 when the stored value is no
 * longer that one (or is gone).
 *
 * A compare-and-delete rather than a plain delete because it runs after the
 * read, as a second command: a valid request re-parked under the challenge in
 * between must not be taken with the corrupt one it replaced. The index is
 * reached through the record's own `sessionId` field, which the park script
 * writes beside the serialisation — the JSON's copy is exactly what may be
 * corrupt.
 */
const LUA_PENDING_CONSENT_DISCARD = `
local r = redis.call('HMGET', KEYS[1], 'record', 'sessionId')
if r[1] ~= ARGV[1] then return 0 end
redis.call('DEL', KEYS[1])
if r[2] then redis.call('ZREM', ARGV[3] .. r[2], ARGV[2]) end
return 1
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
const CONSENT_FIND = defineScript(LUA_CONSENT_FIND);
const CONSENT_GRANT = defineScript(LUA_CONSENT_GRANT);
const PENDING_CONSENT_SET = defineScript(LUA_PENDING_CONSENT_SET);
const PENDING_CONSENT_TAKE = defineScript(LUA_PENDING_CONSENT_TAKE);
const PENDING_CONSENT_DISCARD = defineScript(LUA_PENDING_CONSENT_DISCARD);

// --- Federation grant scripts (#593) ---------------------------------------
//
// One script per write, and every guard inside it. What the layout makes
// possible, and what it does not: a grant's HASH, its credential and its lock
// share a hash tag, so one script may touch all three; the subject's index is
// its own key, in its own slot, and no script touches it together with a
// record. That is the price of letting a deployment's grants spread across a
// Cluster rather than pile onto the one node a shared tag would name — and it
// is why the index is reserved before the record is written, at the horizon
// the record will have, and pruned by that horizon alone (D16).
//
// Every script validates before it mutates. Lua's isolation is not a
// transaction: an error halfway through leaves what it already wrote.

/**
 * Shared prelude. Concatenated into each script's source, so each still has
 * its own SHA-1 and its own cache entry.
 *
 * `horizon` is the instant the record stops answering, and it is the one
 * arithmetic every guard and every key deadline agrees on: a `pending` grant
 * lapses with its intent and keeps no retention; anything ever authorized runs
 * from the stored expiry plus the retention it was created with; one revoked
 * before it was ever authorized has no expiry, so it runs from the revocation.
 * A revocation moves no horizon.
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
 * Creates a `pending` grant. `KEYS[1]` = the record, `KEYS[2]` = its
 * credential; `ARGV` = the caller's clock, the base fields, the intent's
 * handle and expiry, the retention.
 *
 * The existence check is on the key, not on the horizon: an ID is taken for
 * as long as a record is there under it, and a caller whose clock is ahead
 * must not lodge over a record everyone else can still see.
 *
 * A credential already at `KEYS[2]` goes with it. It could never authenticate
 * under the new authorization — the record it was sealed for is gone — but a
 * secret at rest that nothing can use is still a secret at rest, and a
 * mismatched restore or a reused ID can leave one. The record's fields are
 * read for the reply *before* the deadline is applied, so that a reply is
 * never built from a key the same script expired.
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
 * The record and its credential, in one step. `KEYS[1]` = the record,
 * `KEYS[2]` = its credential.
 *
 * One step because the two are read together or not at all: between a
 * `HGETALL` and a `GET` an activation can replace both, and the caller would
 * evaluate one authorization against the other's credential. A reply of two
 * elements says there is no credential; three says there is one, which an
 * empty string also is.
 *
 * No visibility guard: what the caller may see is judged where the record is
 * decoded, against the authenticated text rather than the arithmetic field.
 */
const LUA_FG_SNAPSHOT = `
if redis.call('EXISTS', KEYS[1]) == 0 then return {0} end
local fields = redis.call('HGETALL', KEYS[1])
local credential = redis.call('GET', KEYS[2])
if credential == false then return {1, fields} end
return {1, fields, credential}
`;

/**
 * Names a reauthorization's intent as current. `KEYS[1]` = the record;
 * `ARGV` = the caller's clock, the handle, the intent's expiry.
 *
 * Refuses a `pending` grant — a first-time intent makes a new grant and never
 * takes over another one's — and a grant past its stored expiry, so that a
 * new consent cannot resurrect a lifetime that has ended. Moves no deadline
 * and bumps no version: a refresh in flight must not lose its write to a
 * renewal the user may never finish.
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
 * Reserves a grant in its subject's index. `KEYS[1]` = the index; `ARGV` =
 * the member, its horizon, the allowance.
 *
 * The score moves forward only, and `ZADD GT` would do it in one command —
 * it is written out here so that the comparison and the index's own deadline
 * are one step, and so that the reply says what the horizon became. The
 * deadline is the last horizon the index holds plus the allowance, so the
 * index outlives every record it points at even when its node's clock differs
 * from theirs.
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
 * Drops members whose horizon is past by the allowance. `KEYS[1]` = the
 * index; `ARGV` = the adapter's clock, the allowance.
 *
 * By horizon and never by whether the record is there: the two are different
 * keys, so a member reserved for a record still being written would be
 * dropped by that rule and nothing would put it back. The allowance is what
 * keeps the prune later than any answer a replica whose clock differs could
 * still give from the record itself.
 */
const LUA_FG_PRUNE = `
local clock = tonumber(ARGV[1])
local allowance = tonumber(ARGV[2])
if clock == nil or allowance == nil then return 0 end
return redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', '(' .. string.format('%.0f', clock - allowance))
`;

/**
 * Takes a grant from its current intent to `active`. `KEYS[1]` = the record,
 * `KEYS[2]` = its credential; `ARGV` = the caller's clock, the handle, the
 * authorization text, its expiry, the three guard fields, the sealed
 * credential.
 *
 * The current intent is compared here and not by version, because naming and
 * retiring an intent bump none: a caller that read a pointer and activated on
 * it would otherwise activate a renewal the user had already superseded, or
 * one a subject-wide revocation had retired. That is the mistake this script
 * exists to make impossible.
 *
 * The stored expiry is checked unless the grant is `pending` — a new consent
 * must not resurrect a lifetime that has ended — and the identity revision
 * and upstream account must be the ones recorded, so that a renewal never
 * re-points a grant at another account (D4, D7).
 *
 * The authorization is replaced as a whole, so the marker and the stamp of a
 * failed refresh go with the one they were about. A use recorded before it
 * stays: it says nothing about what the grant allows.
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
 * Replaces the credential of an `active` grant. `KEYS[1]` = the record,
 * `KEYS[2]` = its credential; `ARGV` = the caller's clock, the expected
 * version, the sealed credential, whether a marker was given, the marker.
 *
 * The marker is replaced as a whole, including being removed: a refresh that
 * found the token eligible says so by handing over none. The stamp of a
 * failed refresh is forgotten, because this refresh succeeded. Neither
 * horizon moves — the credential's deadline is set to the same expiry it
 * already had, so a rotation does not extend what the user consented to.
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
 * Asks for the user again. `KEYS[1]` = the record, `KEYS[2]` = its
 * credential; `ARGV` = the caller's clock, the expected version.
 *
 * The one transition with no expiry guard: an upstream that says the
 * credential is dead is believed whenever it says it, and a record whose
 * expiry passed while the answer was in flight must still lose its
 * credential. The marker stays — it describes the tokens this authorization
 * yields, which is exactly what the user is being asked about — and the
 * horizon does not move, because what was consented to has not changed.
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
 * Ends the grant. `KEYS[1]` = the record, `KEYS[2]` = its credential; `ARGV`
 * = the instant, who revoked it.
 *
 * No version guard: a revocation does not lose to a refresh in flight, and
 * whichever runs second is still correct — a revocation after a refresh takes
 * the credential the refresh wrote, and a refresh after a revocation is
 * refused by the status.
 *
 * What the grant was authorized for stays, so the status route can say what
 * ended. A revocation moves no horizon — an authorized grant is retained from
 * its expiry whenever it was revoked — except for one that was never
 * authorized, which has no expiry to be retained from and runs from here.
 */
const LUA_FG_REVOKE = `${LUA_FG_PRELUDE}
local at = tonumber(ARGV[1])
if at == nil then return {0} end
local flat = redis.call('HGETALL', KEYS[1])
if #flat == 0 then return {0} end
local g = fg_fields(flat)
if g['status'] == 'revoked' then return {0} end
-- The one write that does not go through the visibility check, because it is
-- the one that must always win. A horizon that CAN be computed is still
-- honoured: a tombstone is not revoked again. One that cannot — a record
-- whose retention someone deleted — is not a reason to leave a credential at
-- rest with no way to end it, which is exactly the state an operator reaches
-- for this in (the reviewer, then Copilot).
local horizon = fg_horizon(g)
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
 * Stamps a failed refresh. `KEYS[1]` = the record; `ARGV` = the caller's
 * clock, the expected version, when the failure happened, its kind, the row,
 * and the two optional fields with a flag each.
 *
 * The version is compared although none is written: a failure that outlived
 * its own refresh must not install a backoff over a credential written since
 * (D12). The row is measured from the stamp it replaces and against the
 * failure's own instant, not the caller's clock — a stamp that took a second
 * to arrive is still one failure after the last. An equal instant counts
 * onward; an earlier one is refused, so a stamp that arrives out of order
 * never replaces a newer one.
 *
 * Only the stamp's fields are touched, so a use or a pointer written
 * meanwhile survives — which is the reason this is a script and not a
 * read, a count and a write.
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
 * Wrap a single ioredis connection into the 16 typed client wrappers
 * needed by `@o3co/auth-provider-redis` adapters. Production consumers
 * use this factory in their composition root and spread the result into
 * `bootstrapComponents`.
 *
 * Every returned client issues its commands against the one connection passed
 * in — this factory opens nothing of its own (the sole exception is
 * `refreshTokenFamilyClient.duplicate()`, which is per rotation, not per
 * purpose). Connection-level ioredis options are therefore shared by all
 * sixteen purposes, so a composition root that needs different failure timing
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
	consentStoreClient: ConsentStoreClient;
	pendingConsentStoreClient: PendingConsentStoreClient;
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
		async setRevocationBoundaries(key, mode, beforeMs, expiresAtMs, grantRetentionMs) {
			// EVALSHA-first with a NOSCRIPT fallback to EVAL, matching
			// `compareAndDelete` above — see `scriptCached` for why the flag is
			// module-scoped and how a `SCRIPT FLUSH` or cluster failover is
			// recovered from.
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
		// One script for both: the count-only method is the original contract,
		// kept for callers that hold this client directly (#458).
		incrementWithTtl: async (k, ttlSeconds) => (await incrementWithTtlAndPttl(k, ttlSeconds)).count,
		incrementWithTtlAndPttl,
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

	// #561: the consent store and the parked-request store, each operation that
	// must be indivisible one Lua script (see the `LUA_CONSENT_*` and
	// `LUA_PENDING_CONSENT_*` docblocks). A consent record is one key; a parked
	// request and its session's index share the `{pending}` hash tag, so the
	// keys a script derives from the other are in the slot it was routed to.
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
				...(expiresAt === null || expiresAt === undefined ? {} : { expiresAt }),
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
	};
}

/**
 * The commands a federation grant store needs from its connection (#593).
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
const fgFields = (flat: unknown): FederationGrantHashFields => {
	const pairs = Array.isArray(flat) ? (flat as string[]) : [];
	const fields: Record<string, string> = {};
	for (let i = 0; i + 1 < pairs.length; i += 2) {
		fields[pairs[i] as string] = pairs[i + 1] as string;
	}
	return fields as unknown as FederationGrantHashFields;
};

/**
 * A write's reply: `[1, fields]` when it happened, `[0]` when it was refused.
 * Absence and a failed precondition are the same answer on purpose — the
 * record may change again before the caller looks, so the port re-reads (D2).
 */
const fgWritten = (reply: unknown): FederationGrantHashFields | null => {
	if (!Array.isArray(reply) || reply[0] !== 1) return null;
	return fgFields(reply[1]);
};

/**
 * The federation grant store's connection (#593, D16), separate from
 * {@link makeIoredisClients} so that a Cluster deployment can have one.
 */
export function makeIoredisFederationGrantStoreClient(
	io: FederationGrantRedisCommands,
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
			return await io.zrange(indexKey, 0, -1);
		},

		async prune(indexKey, clockMs, allowanceMs) {
			await runScript(connection, FG_PRUNE, [indexKey], [fgNumber(clockMs), fgNumber(allowanceMs)]);
		},
	};
}
