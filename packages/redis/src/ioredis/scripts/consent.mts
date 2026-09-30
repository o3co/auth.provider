/*
 * Copyright 2026 1o1 Co. Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The consent stores' scripts: a recorded consent's read and union, and a parked request's
 * park, take and discard, each one indivisible step.
 */

import { defineScript } from "./define.mjs";

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

export const CONSENT_FIND = defineScript(LUA_CONSENT_FIND);
export const CONSENT_GRANT = defineScript(LUA_CONSENT_GRANT);
export const PENDING_CONSENT_SET = defineScript(LUA_PENDING_CONSENT_SET);
export const PENDING_CONSENT_TAKE = defineScript(LUA_PENDING_CONSENT_TAKE);
export const PENDING_CONSENT_DISCARD = defineScript(LUA_PENDING_CONSENT_DISCARD);
