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
 * The MFA stores' scripts: a factor's version compare-and-set, a transaction's operations, and
 * the subject lock state's reserve, settle and exempt success. See
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
  for i = 1, #flat, 2 do
    if string.sub(flat[i], 1, 2) == 'r:' then
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
  local at = string.format('%.0f', math.ceil(num(last[2]) + WEEK + SKEW))
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
 * `ARGV`: now, hardLimit. Ends the run up to now while it is shorter than
 * hardLimit; at or past it the run, and the hard hold, stand. The week stands.
 */
const LUA_MFA_SUBJECT_EXEMPT = `${LUA_MFA_SUBJECT_PRELUDE}
local now, hard = num(ARGV[1]), num(ARGV[2])
local run, pending, week = load()
prune(run, pending, week, math.min(now, server_ms()) - SKEW)
if #run < hard then
  for _, a in ipairs(run) do
    if a.at <= now then redis.call('HDEL', KEYS[1], 'r:' .. a.id) end
  end
end
keep()
return 1
`;

export const MFA_TX_CREATE = defineScript(LUA_MFA_TX_CREATE);
export const MFA_TX_UPDATE = defineScript(LUA_MFA_TX_UPDATE);
export const MFA_TX_RESERVE_ATTEMPT = defineScript(LUA_MFA_TX_RESERVE_ATTEMPT);
export const MFA_TX_TAKE_CHALLENGE = defineScript(LUA_MFA_TX_TAKE_CHALLENGE);
export const MFA_TX_CONSUME = defineScript(LUA_MFA_TX_CONSUME);
export const MFA_SUBJECT_RESERVE = defineScript(LUA_MFA_SUBJECT_RESERVE);
export const MFA_SUBJECT_SETTLE = defineScript(LUA_MFA_SUBJECT_SETTLE);
export const MFA_SUBJECT_EXEMPT = defineScript(LUA_MFA_SUBJECT_EXEMPT);
