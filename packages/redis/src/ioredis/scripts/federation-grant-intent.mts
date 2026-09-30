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
 * The federation grant intent store's scripts: admission, parking, answering, consuming and
 * finishing, each one step under the `{intents}` hash tag.
 */

import { defineScript } from "./define.mjs";

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

export const FGI_ADMIT = defineScript(LUA_FGI_ADMIT);
export const FGI_PARK = defineScript(LUA_FGI_PARK);
export const FGI_ANSWER = defineScript(LUA_FGI_ANSWER);
export const FGI_CONSUME = defineScript(LUA_FGI_CONSUME);
export const FGI_FINISH = defineScript(LUA_FGI_FINISH);
