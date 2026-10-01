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
 * The federation grant store's scripts: one per write, with every guard inside it, and the
 * subject index's reservation and prune.
 */

import { defineScript } from "./define.mjs";
import { COMPARE_AND_DELETE } from "./lock.mjs";

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
 * identity revision, upstream issuer and subject, the sealed credential, whether an extension
 * was given, the extension. The extension is written or removed with the credential.
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
if ARGV[9] == '1' then
  redis.call('HSET', KEYS[1], 'ext', ARGV[10])
else
  redis.call('HDEL', KEYS[1], 'ext')
end
local fields = redis.call('HGETALL', KEYS[1])
local retention = fg_num(g['retentionMs']) or 0
redis.call('PEXPIREAT', KEYS[1], math.ceil(expiresAt + retention))
redis.call('PEXPIREAT', KEYS[2], math.ceil(expiresAt))
return {1, fields}
`;

/**
 * Replaces an `active` grant's credential. `KEYS[1]` = record, `KEYS[2]` = credential; `ARGV` =
 * the caller's clock, the expected version, the sealed credential, whether a marker was given,
 * the marker, whether an extension was given, the extension. The marker and the extension are
 * replaced whole (none given: removed) and the failure stamp cleared.
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
-- The credential it replaces must still be there, checked in the step that
-- writes: its key's deadline is the expiry on the server's clock, and the
-- adapter's own read is a round trip earlier. A credential written after that
-- deadline fired would take the same past deadline and be gone at once, after
-- a reply that said it was written.
if redis.call('EXISTS', KEYS[2]) == 0 then return {0} end
redis.call('HDEL', KEYS[1],
  'ineligible', 'failureAt', 'failureKind', 'failureCount',
  'failureRetryAfterSeconds', 'failureUpstreamCode')
redis.call('HSET', KEYS[1], 'version', string.format('%.0f', version + 1))
if ARGV[4] == '1' then
  redis.call('HSET', KEYS[1], 'ineligible', ARGV[5])
end
redis.call('SET', KEYS[2], ARGV[3])
if ARGV[6] == '1' then
  redis.call('HSET', KEYS[1], 'ext', ARGV[7])
else
  redis.call('HDEL', KEYS[1], 'ext')
end
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
  'ext', 'failureAt', 'failureKind', 'failureCount',
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
-- The horizon as the read side computes it: from the expiry in the
-- authenticated authorization text, and never from the expiresAtMs copy
-- beside it, which anyone able to write the keyspace can move. A copy moved
-- into the past would make a live grant read as a tombstone here and refuse
-- the one write meant to end it. A pending grant has no text and runs from its
-- intent; a text that does not parse gives no horizon, which is the retention
-- case below.
--
-- Every number is read as the TypeScript reader reads it — a string of digits
-- within the safe-integer range, and the retention not negative — and not
-- with tonumber, which takes "-1.5" and "1e21": the reader answers nothing for
-- a record holding such a value, and a horizon computed from it here would
-- refuse to end exactly that record. Such a value gives no horizon, and the
-- revocation proceeds.
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
-- reason to leave a credential at rest with no way to end it: that is exactly
-- the state an operator reaches for this in.
local horizon = fg_revoke_horizon(g)
if horizon ~= nil and not (at < horizon) then return {0} end
local version = fg_num(g['version'])
local wasPending = g['status'] == 'pending'
redis.call('HDEL', KEYS[1],
  'intentHandle', 'intentExpiresAt', 'ext',
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
  -- Never over the user: a refusal that says the user has to come back is
  -- read as reauthorization_required, and no later stamp replaces it.
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

export const FG_CREATE = defineScript(LUA_FG_CREATE);
export const FG_SNAPSHOT = defineScript(LUA_FG_SNAPSHOT);
export const FG_NAME_INTENT = defineScript(LUA_FG_NAME_INTENT);
export const FG_RETIRE_INTENT = defineScript(LUA_FG_RETIRE_INTENT);
export const FG_TOUCH = defineScript(LUA_FG_TOUCH);
export const FG_RESERVE = defineScript(LUA_FG_RESERVE);
export const FG_PRUNE = defineScript(LUA_FG_PRUNE);
/** The federation token lock's release, shared: a delete that frees only the value it was given. */
export const FG_UNLOCK = COMPARE_AND_DELETE;
export const FG_ACTIVATE = defineScript(LUA_FG_ACTIVATE);
export const FG_REPLACE = defineScript(LUA_FG_REPLACE);
export const FG_REQUIRE_REAUTH = defineScript(LUA_FG_REQUIRE_REAUTH);
export const FG_REVOKE = defineScript(LUA_FG_REVOKE);
export const FG_NOTE_FAILURE = defineScript(LUA_FG_NOTE_FAILURE);
