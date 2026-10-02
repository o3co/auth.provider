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
 * The MFA stores' scripts: a factor's version compare-and-set, a transaction's operations, the
 * subject lock state's reserve, settle and exempt success, and a subject's first-binding mark. See
 * packages/core/docs/adr/2026-09-25-multi-factor-authentication.md.
 */

import { defineScript } from "./define.mjs";

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

export const MFA_FACTOR_UPDATE = defineScript(LUA_MFA_FACTOR_UPDATE);

// A subject's factor set: the factor fields and `~g`, the set's generation, in one hash. Each
// script below is one membership write or the versioned read, and starts with `#!lua` and no
// `no-writes` flag, so a read-only replica refuses it outright: none ever answers from a
// replica (Redis 7.0+).
//
// A membership write is `apply`, a function each script defines, run by one shared step
// (`LUA_MFA_FACTOR_SET_STEP`): a copy of a write already applied answers that write's answer and
// writes nothing; a write the server takes at or past the deadline the adapter set at issue
// writes nothing and answers `late`; otherwise `apply` checks and writes the fields, `~g` = the
// generation it was handed and the key's expiry (none while the set holds a factor, the
// tombstone's while it holds `~g` alone), and its answer is kept until the declared clock skew
// past the deadline, so a server whose clock lags the one that kept it (after a failover or a
// slot migration) still finds it. A key holding factors but no `~g` was written before the set
// had a generation: a conditional write against it is a `conflict`.
//
// The removal, the reset and the versioned read declare `allow-oom`: under `noeviction` a full
// server still runs them, since they write only `~g`, the replay key and an expiry, and a factor
// must stay removable, and the reset must run, when nothing more can be enrolled. The create
// declares no flag, so a full server refuses it (`OOM`).
//
// Membership writes: `KEYS[1]` = the subject's hash, `KEYS[2]` = the write's replay key (same
// hash tag); `ARGV[1]` = the next generation, `ARGV[2]` = the deadline (epoch ms), `ARGV[3]` =
// the declared clock skew (ms), then each script's own arguments from `ARGV[4]`.

/**
 * What every membership script starts with. `mfa_factor_late()`: whether the server's clock, to
 * the millisecond, is at or past the deadline. `mfa_factor_settle(tombstone)`: the key's expiry
 * for what the write left — the tombstone's `PEXPIRE` when `~g` is all it holds, none otherwise.
 */
const LUA_MFA_FACTOR_SET_PRELUDE = `
local function mfa_factor_late()
  local t = redis.call('TIME')
  return tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000) >= tonumber(ARGV[2])
end

local function mfa_factor_settle(tombstone)
  if redis.call('HLEN', KEYS[1]) == 1 then
    redis.call('PEXPIRE', KEYS[1], tombstone)
  else
    redis.call('PERSIST', KEYS[1])
  end
end
`;

/**
 * What every membership script ends with: the replay key's answer for a copy, `late` past the
 * deadline, or `apply()`'s answer, kept under the replay key until the declared clock skew past
 * the deadline.
 */
const LUA_MFA_FACTOR_SET_STEP = `
local applied = redis.call('GET', KEYS[2])
if applied then return applied end
if mfa_factor_late() then return 'late' end
local outcome = apply()
redis.call('SET', KEYS[2], outcome, 'PXAT', tonumber(ARGV[2]) + tonumber(ARGV[3]) + 1)
return outcome
`;

/** The first line of a script that runs on a full server: the removal, the reset, the versioned read. */
const ALLOW_OOM = "#!lua flags=allow-oom";

/** The first line of a script a full server refuses: the create. */
const REFUSED_WHEN_FULL = "#!lua";

/** A membership script: its first line, the prelude, its `apply`, and the shared step. */
const membershipScript = (shebang: string, apply: string): string =>
	`${shebang}${LUA_MFA_FACTOR_SET_PRELUDE}\nlocal function apply()\n${apply.replace(/^\n+|\s+$/g, "")}\nend\n${LUA_MFA_FACTOR_SET_STEP}`;

/**
 * `MfaFactorStoreClient.listVersioned`. `KEYS[1]` = the subject's hash; `ARGV[1]` = the
 * generation a hash without `~g` is given. Returns every field and value, `~g` among them, or an
 * empty array for no key. `HSETNX` keeps a generation held, and leaves the key's expiry.
 */
const LUA_MFA_FACTOR_LIST_VERSIONED = `${ALLOW_OOM}
if redis.call('EXISTS', KEYS[1]) == 0 then return {} end
redis.call('HSETNX', KEYS[1], '~g', ARGV[1])
return redis.call('HGETALL', KEYS[1])
`;

/**
 * `MfaFactorStoreClient.createIf`. `ARGV[4]` = the expected generation (empty: the key must be
 * absent), `ARGV[5]` = the factor's field, `ARGV[6]` = its value. Answers `created`,
 * `conflict` or `late`.
 */
const LUA_MFA_FACTOR_CREATE_IF = membershipScript(
	REFUSED_WHEN_FULL,
	`
  if ARGV[4] == '' then
    if redis.call('EXISTS', KEYS[1]) == 1 then return 'conflict' end
  elseif redis.call('HGET', KEYS[1], '~g') ~= ARGV[4] then
    return 'conflict'
  end
  if redis.call('HEXISTS', KEYS[1], ARGV[5]) == 1 then return 'conflict' end
  redis.call('HSET', KEYS[1], ARGV[5], ARGV[6], '~g', ARGV[1])
  redis.call('PERSIST', KEYS[1])
  return 'created'
`,
);

/**
 * `MfaFactorStoreClient.removeIf`. `ARGV[4]` = the tombstone's lifetime (ms), `ARGV[5]` = the
 * expected generation, `ARGV[6]` = the factor's field. Answers `removed`, `missing`,
 * `conflict` or `late`; the generation is checked before the field.
 */
const LUA_MFA_FACTOR_REMOVE_IF = membershipScript(
	ALLOW_OOM,
	`
  if redis.call('EXISTS', KEYS[1]) == 0 then return 'missing' end
  if redis.call('HGET', KEYS[1], '~g') ~= ARGV[5] then return 'conflict' end
  if redis.call('HDEL', KEYS[1], ARGV[6]) == 0 then return 'missing' end
  redis.call('HSET', KEYS[1], '~g', ARGV[1])
  mfa_factor_settle(ARGV[4])
  return 'removed'
`,
);

/**
 * `MfaFactorStoreClient.removeAll`: the reset, unconditional, serialised with the writes above
 * as one script. `ARGV[4]` = the tombstone's lifetime (ms). Answers `removed` or `late`. The
 * tombstone is made when there was no key, and its expiry starts again when there was one.
 */
const LUA_MFA_FACTOR_REMOVE_ALL = membershipScript(
	ALLOW_OOM,
	`
  redis.call('DEL', KEYS[1])
  redis.call('HSET', KEYS[1], '~g', ARGV[1])
  redis.call('PEXPIRE', KEYS[1], ARGV[4])
  return 'removed'
`,
);

export const MFA_FACTOR_LIST_VERSIONED = defineScript(LUA_MFA_FACTOR_LIST_VERSIONED);
export const MFA_FACTOR_CREATE_IF = defineScript(LUA_MFA_FACTOR_CREATE_IF);
export const MFA_FACTOR_REMOVE_IF = defineScript(LUA_MFA_FACTOR_REMOVE_IF);
export const MFA_FACTOR_REMOVE_ALL = defineScript(LUA_MFA_FACTOR_REMOVE_ALL);

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
 * `{0, n, index, incarnation}` — and the transaction gone — for the one past
 * it, n being what it had and the two its `index` and `incarnation` fields
 * (nil when absent), for its binding's index; `{0, 0}` for no transaction or
 * for one gone at the store's clock (left as it is); `{0, 0, index,
 * incarnation}` for a count that is not a number (fails closed: deleted).
 */
const LUA_MFA_TX_RESERVE_ATTEMPT = `${LUA_MFA_TX_PRELUDE}
if redis.call('EXISTS', KEYS[1]) == 0 then return {0, 0} end
if mfa_tx_gone(KEYS[1], tonumber(ARGV[2])) then return {0, 0} end
local attempts = tonumber(redis.call('HGET', KEYS[1], 'attempts'))
local function removed(n)
  local held = redis.call('HMGET', KEYS[1], 'index', 'incarnation')
  redis.call('DEL', KEYS[1])
  return {0, n, held[1], held[2]}
end
if attempts == nil then return removed(0) end
if not (attempts + 1 <= tonumber(ARGV[1])) then return removed(attempts) end
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

// A binding's index: a sorted set under a hash tag of its own, one member per transaction —
// `<incarnation>:<id key part>` — scored by the transaction's `expiresAtMs`. The transactions sit on
// slots of their own, so no script reaches both: the index script decides which go, and the
// client ends each through `MFA_TX_EVICT`, which deletes a transaction only while it still holds
// the incarnation its member names.

/**
 * `MfaTransactionStoreClient.indexTransaction`. `KEYS[1]` = the binding's index; `ARGV[1]` = the
 * new member, `ARGV[2]` = its transaction's `expiresAtMs` (epoch ms, as the caller's text),
 * `ARGV[3]` = the most members held. While the index holds that many or more, removes the
 * lowest-scored (the soonest to expire; between equal scores, the lower member) until one fewer
 * remain, then adds the new member — so it is never among those removed — and sets the key to
 * expire at the highest score it holds, rounded up, as the transactions' keys are. Returns the
 * members removed.
 */
const LUA_MFA_BINDING_INDEX = `
local max = tonumber(ARGV[3])
local held = redis.call('ZCARD', KEYS[1])
local ended = {}
if held >= max then
  ended = redis.call('ZRANGE', KEYS[1], 0, held - max)
  redis.call('ZREM', KEYS[1], unpack(ended))
end
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[1])
local latest = redis.call('ZRANGE', KEYS[1], -1, -1, 'WITHSCORES')
redis.call('PEXPIREAT', KEYS[1], string.format('%.0f', math.ceil(tonumber(latest[2]))))
return ended
`.trim();

/**
 * `MfaTransactionStoreClient.unindexTransaction`. `KEYS[1]` = the binding's index; `ARGV[1]` = the
 * member to remove. Removes it and sets the key to expire at the highest score left, rounded up,
 * so the index never outlives the transactions it still names; the last member gone, the key is
 * gone with it.
 */
const LUA_MFA_BINDING_UNINDEX = `
redis.call('ZREM', KEYS[1], ARGV[1])
local latest = redis.call('ZRANGE', KEYS[1], -1, -1, 'WITHSCORES')
if latest[2] then
  redis.call('PEXPIREAT', KEYS[1], string.format('%.0f', math.ceil(tonumber(latest[2]))))
end
return 1
`.trim();

/**
 * `MfaTransactionStoreClient.evictTransaction`. `KEYS[1]` = the transaction; `ARGV[1]` = the
 * incarnation its index member names. Deletes it only while its `incarnation` field holds that
 * one: a transaction created again under the id, for this binding or another, is left alone.
 * Returns 1 when it deleted.
 */
const LUA_MFA_TX_EVICT = `
if redis.call('HGET', KEYS[1], 'incarnation') ~= ARGV[1] then return 0 end
return redis.call('DEL', KEYS[1])
`.trim();

// Subject lockout state: `KEYS[1]` the lock hash, `KEYS[2]` the week's sorted set (see
// `MfaSubjectKeys`), under one hash tag. The rules are core's in-process store's
// (`core/src/mfa/memoryTransactionStore.mts`), applied in the same floating-point operations
// on the same numbers: every instant travels as the caller's text or as `%.17g`, which reads
// back as the same double.
//
// Answers are judged on the caller's `now`; what a script forgets is judged no later than the
// server's clock less a day (MFA_CLOCK_SKEW_ALLOWANCE_MS), so a caller far ahead erases nothing.
// The lock hash's `hard` field is the hard hold, fixed (`HSETNX`) by the script that finds the
// run at the hard limit and removed by nothing but an applied recovery. It holds the later of
// that script's `now` and the run's newest attempt, so no attempt of the run is dated after it.
// While a run is counted or the hold stands the keys have no TTL; otherwise they expire a day
// after the last failure stops counting. A stored value a script cannot read is an error (an outage), never read as an
// empty state; a lock-hash field of a kind the scripts do not read is ignored.

const LUA_MFA_SUBJECT_PRELUDE = `
local WEEK = 604800000
local ALLOWANCE = 86400000

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

-- The state: the run, the reservations in flight, the week in time order,
-- and when the hard hold was fixed (nil while it is not). A field of any
-- other kind is not read.
local function load()
  local run, pending, week, held_hard = {}, {}, {}, nil
  local flat = redis.call('HGETALL', KEYS[1])
  for i = 1, #flat, 2 do
    local field, value = flat[i], flat[i + 1]
    local kind, id = string.sub(field, 1, 2), string.sub(field, 3)
    if field == 'hard' then
      held_hard = num(value)
    elseif kind == 'r:' then
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
  return run, pending, week, held_hard
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

-- The time a hold fixed at now records: never before the run's newest attempt.
local function fixed_at(run, now)
  local latest = now
  for _, a in ipairs(run) do
    if a.at > latest then latest = a.at end
  end
  return fmt(latest)
end

-- Sets what Redis reclaims: no TTL while a run is counted or the hard hold
-- stands; else a day past the last failure to stop counting; nothing left,
-- both keys go.
local function keep()
  local flat = redis.call('HGETALL', KEYS[1])
  for i = 1, #flat, 2 do
    if flat[i] == 'hard' or string.sub(flat[i], 1, 2) == 'r:' then
      redis.call('PERSIST', KEYS[1])
      redis.call('PERSIST', KEYS[2])
      return
    end
  end
  local last = redis.call('ZRANGE', KEYS[2], -1, -1, 'WITHSCORES')
  if not last[2] then
    redis.call('DEL', KEYS[1], KEYS[2])
    return
  end
  local at = string.format('%.0f', math.ceil(num(last[2]) + WEEK + ALLOWANCE))
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
 * The reservation that brings the run to hardLimit, or a call that finds it
 * there, fixes the hard hold in the same step, at the later of now and the
 * run's newest attempt; once fixed, every reservation is refused `hard`,
 * whatever hardLimit it is handed, and a refusal takes off a deadline the
 * lock hash carries.
 */
const LUA_MFA_SUBJECT_RESERVE = `${LUA_MFA_SUBJECT_PRELUDE}
local now = num(ARGV[1])
local threshold, base, max_s, memory_s = num(ARGV[2]), num(ARGV[3]), num(ARGV[4]), num(ARGV[5])
local budget, hard = num(ARGV[6]), num(ARGV[7])
local id = ARGV[8]
local run, pending, week, held_hard = load()
local forgot
week, forgot = prune(run, pending, week, math.min(now, server_ms()) - ALLOWANCE)

-- A refusal writes only the mark that its episode began, once, and the hard
-- hold when it fixes it: the deadlines are set again only then, when the
-- prune forgot something, or when a held hash carries a deadline, so a held
-- subject hammered is no write load.
local rekeep = false
local function refuse(hold, retry)
  local first = redis.call('HSETNX', KEYS[1], 'held', '1') == 1
  if forgot or first or rekeep then keep() end
  local mark = '0'
  if first then mark = '1' end
  return {'held', hold, retry, mark}
end

if held_hard == nil and #run >= hard then
  redis.call('HSETNX', KEYS[1], 'hard', fixed_at(run, now))
  rekeep = true
elseif held_hard ~= nil and redis.call('PTTL', KEYS[1]) >= 0 then
  -- A deadline set by a script that does not keep the hold: taken off here.
  rekeep = true
end
if held_hard ~= nil or #run >= hard then
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
-- The attempt that brings the run to the limit fixes the hold in this step.
if #run + 1 >= hard then redis.call('HSETNX', KEYS[1], 'hard', fixed_at(run, now)) end
keep()
return {'ok'}
`;

/**
 * `MfaTransactionStoreClient.settleSubjectAttempt`.
 *
 * `ARGV`: the reservation, the outcome. `void` removes the attempt; `success`
 * ends the run up to and including it, and takes it out of the week;
 * `failure` leaves it standing. None touches the hard hold. A reservation
 * not in flight changes nothing. The whole state is read and validated
 * before anything is written.
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
 * `ARGV`: now, hardLimit. Before the hard hold is fixed, ends the run up to
 * now; a run already at hardLimit or past it fixes the hold instead, at the
 * later of now and its newest attempt.
 * Once fixed, nothing ends. An attempt after now stays, and the week stands.
 * A hardLimit that is missing or not a number is refused before anything is
 * read.
 */
const LUA_MFA_SUBJECT_EXEMPT = `${LUA_MFA_SUBJECT_PRELUDE}
local hard = tonumber(ARGV[2])
if hard == nil or hard ~= hard or hard == math.huge or hard == -math.huge then
  error({err = 'MFA subject state: the hardLimit argument is missing or not a number'})
end
local now = num(ARGV[1])
local run, pending, week, held_hard = load()
prune(run, pending, week, math.min(now, server_ms()) - ALLOWANCE)
if held_hard == nil and #run >= hard then
  redis.call('HSETNX', KEYS[1], 'hard', fixed_at(run, now))
elseif held_hard == nil then
  for _, a in ipairs(run) do
    if a.at <= now then redis.call('HDEL', KEYS[1], 'r:' .. a.id) end
  end
end
keep()
return 1
`;

// A subject's recovery hash, under the subject's hash tag: `g`, its generation, `floor`, its
// recovery-set floor (a recovery-code set's generation, not the subject's), and one field per
// authorization, `a:<operation>:<sid>` → `p|<expiresAtMs>|<recoveryId>` while pending, or
// `a|<generation>|<expiresAtMs>|<recoveryId>` once applied. An authorization ends on the
// server's clock. The hash has no TTL while it holds a generation or a floor; before that it
// expires a day (ALLOWANCE) after its latest authorization ends. Every script reads and
// validates the whole hash before its first write: a value it cannot read is an error with
// nothing written, never a write half made.

const LUA_MFA_RECOVERY_PRELUDE = `
local MAX_COUNT = 9007199254740991

-- A count the recovery hash keeps: canonical decimal text of a safe whole number.
local function count_of(text)
  if text == '0' or string.match(text, '^[1-9]%d*$') ~= nil then
    local n = tonumber(text)
    if n <= MAX_COUNT then return n end
  end
  corrupt()
end

-- An authorization's end: whole epoch milliseconds within the Date range.
local MAX_INSTANT = 8640000000000000
local function ends_of(text)
  local n = num(text)
  if n > MAX_INSTANT then corrupt() end
  return n
end

local function slot_of(value)
  local ends, id = string.match(value, '^p|(%d+)|(.+)$')
  if ends ~= nil then return {ends = ends_of(ends), id = id} end
  local gen, applied_ends, applied_id = string.match(value, '^a|([1-9]%d*)|(%d+)|(.+)$')
  if gen == nil then corrupt() end
  count_of(gen)
  return {applied = gen, ends = ends_of(applied_ends), id = applied_id}
end

-- The recovery hash, read and validated whole: its generation and floor (nil when absent) and
-- its authorizations by field.
local function recovery_load(key)
  local g, floor, slots = nil, nil, {}
  local flat = redis.call('HGETALL', key)
  for i = 1, #flat, 2 do
    local field, value = flat[i], flat[i + 1]
    if field == 'g' then
      g = count_of(value)
    elseif field == 'floor' then
      floor = count_of(value)
    elseif string.sub(field, 1, 2) == 'a:' then
      slots[field] = slot_of(value)
    end
  end
  return g, floor, slots
end

-- Sets the hash's deadline from what it holds, as validated: none while it holds a generation or
-- a floor; else the latest authorization's end and a day; nothing left, it goes.
local function recovery_keep(key, counted, slots)
  if counted then
    redis.call('PERSIST', key)
    return
  end
  local latest = nil
  for _, slot in pairs(slots) do
    if latest == nil or slot.ends > latest then latest = slot.ends end
  end
  if latest == nil then
    redis.call('DEL', key)
    return
  end
  redis.call('PEXPIREAT', key, string.format('%.0f', latest + ALLOWANCE))
end

-- Whether the lease holds token and stands: one at its last millisecond (PTTL 0) has lapsed, and
-- one with no deadline (PTTL -1) is not one this store wrote; neither is held.
local function lease_held(key, token)
  return redis.call('GET', key) == token and redis.call('PTTL', key) > 0
end

local function argument(text)
  local n = tonumber(text)
  if n == nil or n ~= n or n == math.huge or n == -math.huge then
    error({err = 'MFA subject recovery: an argument is not a number'})
  end
  return n
end
`;

/**
 * `MfaTransactionStoreClient.authorizeSubjectRecovery`. `KEYS[1]` = the recovery hash;
 * `ARGV[1]` = the authorization's field, `ARGV[2]` = its recoveryId, `ARGV[3]` = its end,
 * `ARGV[4]` = how far ahead of the server's clock an end may lie. Refuses, writing nothing, an
 * end not after the server's clock or further ahead than `ARGV[4]`: `{0, now}`. Otherwise, the
 * hash read whole first, drops the authorizations ended on that clock, writes this one pending
 * over whatever its field held, and answers `{1, now}`.
 */
const LUA_MFA_SUBJECT_RECOVERY_AUTHORIZE = `${LUA_MFA_SUBJECT_PRELUDE}${LUA_MFA_RECOVERY_PRELUDE}
local now = server_ms()
local stamp = string.format('%.0f', now)
local ends = argument(ARGV[3])
if not (ends > now) or ends > now + argument(ARGV[4]) then return {0, stamp} end
local g, floor, slots = recovery_load(KEYS[1])
for field, slot in pairs(slots) do
  if slot.ends <= now then
    redis.call('HDEL', KEYS[1], field)
    slots[field] = nil
  end
end
redis.call('HSET', KEYS[1], ARGV[1], 'p|' .. ARGV[3] .. '|' .. ARGV[2])
slots[ARGV[1]] = {ends = ends}
recovery_keep(KEYS[1], g ~= nil or floor ~= nil, slots)
return {1, stamp}
`;

/**
 * `MfaTransactionStoreClient.applySubjectRecovery`. `KEYS`: the lock hash, the week, the
 * recovery hash, the lease. `ARGV`: the operation, the authorization's field, now, the lease
 * token, the sessions boundary or empty, the earliest guessable record's time or `none` when no
 * guessable record remains (empty for a reset), and the clock skew (`DEFAULT_CLOCK_SKEW_MS`).
 * The recovery hash, and for a recover the lock state, are read and validated whole before the
 * first write. Refuses, in the port's order, with `{'refused', reason, hard}`; answers
 * `{'already', recoveryId, generation, hard}` for an authorization applied, and
 * `{'applied', recoveryId, generation, week, run, liftedHard, hard}` once it applies, each flag
 * `1` or `0`, `hard` read after the apply.
 */
const LUA_MFA_SUBJECT_RECOVERY_APPLY = `${LUA_MFA_SUBJECT_PRELUDE}${LUA_MFA_RECOVERY_PRELUDE}
local operation, field, token = ARGV[1], ARGV[2], ARGV[4]
local now, clock_skew = argument(ARGV[3]), argument(ARGV[7])
local boundary, since = nil, nil
if operation == 'recover' then
  if ARGV[5] ~= '' then boundary = argument(ARGV[5]) end
  -- A recover names its rebind: the earliest guessable record's time, or 'none' when none remains.
  if ARGV[6] ~= 'none' then since = argument(ARGV[6]) end
end

-- Everything read and validated before the first write.
local g, floor, slots = recovery_load(KEYS[3])
local next_generation = (g or 0) + 1
if next_generation > MAX_COUNT then corrupt() end
local run, pending, week, held_hard = nil, nil, nil, nil
if operation == 'recover' then run, pending, week, held_hard = load() end

local function hard_flag()
  if redis.call('HEXISTS', KEYS[1], 'hard') == 1 then return '1' end
  return '0'
end
local function refused(reason) return {'refused', reason, hard_flag()} end

if not lease_held(KEYS[4], token) then return refused('lease_not_held') end
local slot = slots[field]
if slot == nil then return refused('unauthorized') end
if slot.ends <= server_ms() then
  redis.call('HDEL', KEYS[3], field)
  slots[field] = nil
  recovery_keep(KEYS[3], g ~= nil or floor ~= nil, slots)
  return refused('unauthorized')
end
if slot.applied ~= nil then return {'already', slot.id, slot.applied, hard_flag()} end
if slot.ends <= now then return refused('expired') end

-- Applied: the slot is marked at the generation this moves to.
local function applied(ended_week, ended_run, lifted)
  local gen = string.format('%.0f', next_generation)
  redis.call('HSET', KEYS[3], 'g', gen, field, 'a|' .. gen .. '|' .. string.format('%.0f', slot.ends) .. '|' .. slot.id)
  redis.call('PERSIST', KEYS[3])
  return {'applied', slot.id, gen, ended_week, ended_run, lifted, hard_flag()}
end

if operation == 'reset' then
  -- The lock state whole, unread, and every other authorization of the subject.
  redis.call('DEL', KEYS[1], KEYS[2])
  for other in pairs(slots) do
    if other ~= field then redis.call('HDEL', KEYS[3], other) end
  end
  return applied('1', '1', '1')
end

if boundary ~= nil and boundary > now + clock_skew then return refused('boundary_ahead') end

-- The earliest failure the week counts up to now must come before the boundary by more than the skew.
local earliest = nil
for _, a in ipairs(week) do
  if a.at <= now and a.at + WEEK > now and (earliest == nil or a.at < earliest) then earliest = a.at end
end
local revoked = earliest == nil or (boundary ~= nil and boundary > earliest + clock_skew)
-- The hard hold lifts on a rebind alone: no guessable record from before it, by more than the skew.
local rebound = held_hard ~= nil and (since == nil or since > held_hard + clock_skew)
if not revoked and not rebound then return refused('not_revoked_since') end

local ended_week, ended_run, lifted = '0', '0', '0'
if rebound then
  -- The run the hold counted ends with it, its backoff included.
  redis.call('HDEL', KEYS[1], 'hard')
  for _, a in ipairs(run) do redis.call('HDEL', KEYS[1], 'r:' .. a.id) end
  run, held_hard = {}, nil
  ended_run, lifted = '1', '1'
end
if revoked then
  -- The attempts up to now end: the week's, and the run's unless the hard hold keeps it.
  local week_left = {}
  for _, a in ipairs(week) do
    if a.at <= now then redis.call('ZREM', KEYS[2], a.id) else week_left[#week_left + 1] = a end
  end
  week, ended_week = week_left, '1'
  if held_hard == nil then
    local run_left = {}
    for _, a in ipairs(run) do
      if a.at <= now then redis.call('HDEL', KEYS[1], 'r:' .. a.id) else run_left[#run_left + 1] = a end
    end
    run, ended_run = run_left, '1'
  end
end
if held_hard == nil then redis.call('HDEL', KEYS[1], 'held') end
local kept = {}
for _, a in ipairs(run) do kept[a.id] = true end
for _, a in ipairs(week) do kept[a.id] = true end
for id in pairs(pending) do
  if not kept[id] then redis.call('HDEL', KEYS[1], 'p:' .. id) end
end
keep()
return applied(ended_week, ended_run, lifted)
`;

/**
 * `MfaTransactionStoreClient.raiseRecoverySetFloor`. `KEYS[1]` = the recovery hash, `KEYS[2]` =
 * the subject's lease; `ARGV[1]` = a recovery-code set's generation (not the subject's), as
 * decimal text, `ARGV[2]` = the lease token. Answers `{0}` when the lease is not held under the
 * token, writing nothing. Otherwise writes the set generation as `floor` when it is higher than
 * the floor held, compared as numbers, takes off the hash's deadline, and answers `{1, floor}`.
 * A `floor` that is not canonical decimal text is an error.
 */
const LUA_MFA_RECOVERY_SET_FLOOR_RAISE = `${LUA_MFA_SUBJECT_PRELUDE}${LUA_MFA_RECOVERY_PRELUDE}
if not lease_held(KEYS[2], ARGV[2]) then return {0} end
local held = redis.call('HGET', KEYS[1], 'floor')
local raise = count_of(ARGV[1])
local floor = held
if not held or raise > count_of(held) then
  redis.call('HSET', KEYS[1], 'floor', ARGV[1])
  floor = ARGV[1]
end
redis.call('PERSIST', KEYS[1])
return {1, floor}
`;

// A subject's first-binding mark is judged on one clock, the server's (`TIME`): its end, which
// mark a note keeps, and the key's deadline. A replica's clock decides none of them.

/**
 * `MfaTransactionStoreClient.noteFirstBinding`. `KEYS[1]` = the subject's mark; `ARGV[1]` =
 * its `atMs`, `ARGV[2]` = its `untilMs` (whole, the shape already checked), `ARGV[3]` = the
 * clock skew allowed, `ARGV[4]` = the longest a mark may stand. Refuses, writing nothing, a
 * mark whose end is not after the server's clock or whose time lies further from it than
 * the skew: `{0, now}`. Otherwise keeps the later time and the later end of the mark held,
 * while it stands, and this one, as core's `laterFirstBindingMark` does, written to expire at
 * that end (`PXAT`): `{1, now}`.
 *
 * A held mark is judged on its shape alone: `atMs` and `untilMs` and no other field, as the
 * adapter's read-back requires, a time whole and from the epoch, an end after it by no more
 * than `ARGV[4]`, within the Date range. One that has it is merged, however its
 * time sits on the server's clock, since a clock stepped back makes a sound mark look ahead.
 * A value without it, or a key of another type, is replaced: what does not read back is never
 * kept over a mark that does, and a key nothing can read is healed.
 */
const LUA_MFA_FIRST_BINDING_NOTE = `
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
local at, untl, skew, longest = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3]), tonumber(ARGV[4])
local stamp = string.format('%.0f', now)
if not (untl > now) or at > now + skew or at < now - skew then return {0, stamp} end
local MAX = 8640000000000000
local function mark_of(text)
  local ok, mark = pcall(cjson.decode, text)
  if not ok or type(mark) ~= 'table' then return nil end
  for key in pairs(mark) do
    if key ~= 'atMs' and key ~= 'untilMs' then return nil end
  end
  local h_at, h_until = mark.atMs, mark.untilMs
  if type(h_at) ~= 'number' or type(h_until) ~= 'number' then return nil end
  if h_at ~= h_at or h_at < 0 or math.floor(h_at) ~= h_at or math.floor(h_until) ~= h_until then
    return nil
  end
  if not (h_until > h_at) or h_until > MAX or h_until - h_at > longest then return nil end
  return h_at, h_until
end
local read, held = pcall(redis.call, 'GET', KEYS[1])
if read and held then
  local h_at, h_until = mark_of(held)
  if h_at ~= nil and h_until > now then
    if h_at > at then at = h_at end
    if h_until > untl then untl = h_until end
  end
end
local until_text = string.format('%.0f', untl)
local value = '{"atMs":' .. string.format('%.0f', at) .. ',"untilMs":' .. until_text .. '}'
redis.call('SET', KEYS[1], value, 'PXAT', until_text)
return {1, stamp}
`.trim();

/**
 * `MfaTransactionStoreClient.releaseSubjectLease`. `KEYS[1]` = the subject's lease; `ARGV[1]` =
 * the holder's token. Deletes the lease while it holds the token and answers `1`; `0` when it
 * holds another or none, or is at its last millisecond (`PTTL` 0: it has lapsed, and goes
 * within that millisecond). A lease holding the token with no deadline (`PTTL` -1) is none
 * this store wrote: an error, nothing deleted.
 */
const LUA_MFA_SUBJECT_LEASE_RELEASE = `
if redis.call('GET', KEYS[1]) ~= ARGV[1] then return 0 end
local left = redis.call('PTTL', KEYS[1])
if left == -1 then
  error({err = 'MFA subject lease: a lease with no deadline is not one this store wrote; the operation is refused'})
end
if left <= 0 then return 0 end
return redis.call('DEL', KEYS[1])
`.trim();

/**
 * `MfaTransactionStoreClient.acquireSubjectLease`. `KEYS[1]` = the subject's lease, `KEYS[2]` =
 * its recovery hash; `ARGV[1]` = the new holder's token, `ARGV[2]` = the lease's length in ms,
 * `ARGV[3]` = the generation the writer captured, as decimal text. Returns
 * `{'stale'}` when that is not the hash's `g` (absent is `0`), compared as numbers, else
 * `{'busy', pttl}` while another holder's lease stands, else `{'acquired'}` with the lease
 * written (`SET NX PX`, on the server's clock). A `g` that is not canonical decimal text is an
 * error.
 */
const LUA_MFA_SUBJECT_LEASE_ACQUIRE = `${LUA_MFA_SUBJECT_PRELUDE}${LUA_MFA_RECOVERY_PRELUDE}
local g = redis.call('HGET', KEYS[2], 'g')
local current = 0
if g then current = count_of(g) end
if current ~= argument(ARGV[3]) then return {'stale'} end
if redis.call('SET', KEYS[1], ARGV[1], 'NX', 'PX', ARGV[2]) then return {'acquired'} end
return {'busy', redis.call('PTTL', KEYS[1])}
`.trim();

/**
 * `MfaTransactionStoreClient.firstBindingMark`: `KEYS[1]` = the subject's mark. Returns the
 * server's clock and the key's value (nil when there is none), read in one step.
 */
const LUA_MFA_FIRST_BINDING_READ = `
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
return {string.format('%.0f', now), redis.call('GET', KEYS[1])}
`.trim();

export const MFA_TX_CREATE = defineScript(LUA_MFA_TX_CREATE);
export const MFA_TX_UPDATE = defineScript(LUA_MFA_TX_UPDATE);
export const MFA_TX_RESERVE_ATTEMPT = defineScript(LUA_MFA_TX_RESERVE_ATTEMPT);
export const MFA_TX_TAKE_CHALLENGE = defineScript(LUA_MFA_TX_TAKE_CHALLENGE);
export const MFA_TX_CONSUME = defineScript(LUA_MFA_TX_CONSUME);
export const MFA_TX_EVICT = defineScript(LUA_MFA_TX_EVICT);
export const MFA_BINDING_INDEX = defineScript(LUA_MFA_BINDING_INDEX);
export const MFA_BINDING_UNINDEX = defineScript(LUA_MFA_BINDING_UNINDEX);
export const MFA_SUBJECT_RESERVE = defineScript(LUA_MFA_SUBJECT_RESERVE);
export const MFA_SUBJECT_SETTLE = defineScript(LUA_MFA_SUBJECT_SETTLE);
export const MFA_SUBJECT_EXEMPT = defineScript(LUA_MFA_SUBJECT_EXEMPT);
export const MFA_FIRST_BINDING_NOTE = defineScript(LUA_MFA_FIRST_BINDING_NOTE);
export const MFA_FIRST_BINDING_READ = defineScript(LUA_MFA_FIRST_BINDING_READ);
export const MFA_SUBJECT_LEASE_ACQUIRE = defineScript(LUA_MFA_SUBJECT_LEASE_ACQUIRE);
export const MFA_SUBJECT_LEASE_RELEASE = defineScript(LUA_MFA_SUBJECT_LEASE_RELEASE);
export const MFA_SUBJECT_RECOVERY_AUTHORIZE = defineScript(LUA_MFA_SUBJECT_RECOVERY_AUTHORIZE);
export const MFA_SUBJECT_RECOVERY_APPLY = defineScript(LUA_MFA_SUBJECT_RECOVERY_APPLY);
export const MFA_RECOVERY_SET_FLOOR_RAISE = defineScript(LUA_MFA_RECOVERY_SET_FLOOR_RAISE);
