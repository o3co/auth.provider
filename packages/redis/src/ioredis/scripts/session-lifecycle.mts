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
 * The session lifecycle store's scripts. Each write to a session is one
 * script over the session's one hash and, for a write that keeps its answer,
 * its replay key and its shard's closing index, all on one Cluster slot; the
 * hash's layout is `clients/session-lifecycle.mts`'s. A closing record joins
 * the index, and a closed one leaves it, in the step that writes the record.
 * Every write is refused at or after its deadline on the server's clock, and
 * checks the record before it writes, so a record it cannot read fails the
 * script with nothing written. The reads are scripts too, so they run on the
 * primary. The scripts make no generation: the adapter hands each one in.
 */

import { defineScript } from "./define.mjs";

/**
 * `lc_now()`: the server's clock, epoch ms. `lc_keep(replay, answer, untilMs)`:
 * `answer` kept under the replay key until `untilMs`. `lc_state(key)`: the
 * record's state, `nil` for no key, an error for a hash holding no known
 * state. `lc_int(key, field)`: an integer field, an error when it is none.
 * `lc_ms(n)`: an epoch ms as decimal digits.
 */
const PRELUDE = `
local function lc_now()
  local t = redis.call('TIME')
  return tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
end
local function lc_keep(replay, answer, untilMs)
  redis.call('SET', replay, answer, 'PXAT', untilMs)
  return answer
end
local function lc_state(key)
  local state = redis.call('HGET', key, 'state')
  if not state then
    if redis.call('EXISTS', key) == 1 then error('session lifecycle record holds no state') end
    return nil
  end
  if state ~= 'active' and state ~= 'closing' and state ~= 'closed' then
    error('session lifecycle record holds an unknown state')
  end
  return state
end
local function lc_int(key, field)
  local raw = redis.call('HGET', key, field)
  local value = raw and string.match(raw, '^%-?%d+$') and tonumber(raw)
  if not value then error('session lifecycle record holds a malformed ' .. field) end
  return value
end
local function lc_ms(n)
  return string.format('%d', n)
end
`;

/**
 * The open. `KEYS[1]` = the record, `KEYS[2]` = the write's replay key;
 * `ARGV[1]` = the deadline, `ARGV[2]` = when the replay key expires,
 * `ARGV[3]` = sub, `ARGV[4]` = expiresAt, `ARGV[5]` = when the record expires,
 * `ARGV[6]` = the generation. Returns `late`, a kept answer, or `opened` /
 * `refused`, kept until `ARGV[2]`.
 */
const LUA_OPEN = `${PRELUDE}
if lc_now() >= tonumber(ARGV[1]) then return 'late' end
local kept = redis.call('GET', KEYS[2])
if kept then return kept end
if tonumber(ARGV[4]) <= lc_now() then return lc_keep(KEYS[2], 'refused', ARGV[2]) end
local state = lc_state(KEYS[1])
if state then
  if state == 'active' and redis.call('HGET', KEYS[1], 'sub') == ARGV[3]
    and redis.call('HGET', KEYS[1], 'exp') == ARGV[4] then
    return lc_keep(KEYS[2], 'opened', ARGV[2])
  end
  return lc_keep(KEYS[2], 'refused', ARGV[2])
end
redis.call('HSET', KEYS[1], 'sub', ARGV[3], 'state', 'active', 'exp', ARGV[4],
  'until', ARGV[5], 'gen', ARGV[6], 'np', '0')
redis.call('PEXPIREAT', KEYS[1], ARGV[5])
return lc_keep(KEYS[2], 'opened', ARGV[2])
`.trim();

/**
 * The join. `KEYS[1]` = the record, `KEYS[2]` = the write's replay key;
 * `ARGV[1]` = the deadline, `ARGV[2]` = when the replay key expires,
 * `ARGV[3]` = the participant's item, `ARGV[4]` = its data, `ARGV[5]` = the
 * generation, `ARGV[6]` = the most participants. Returns `late`, a kept
 * answer, `full` (nothing written or kept), or `missing` / `closed` /
 * `joined`, kept until `ARGV[2]`.
 */
const LUA_JOIN = `${PRELUDE}
if lc_now() >= tonumber(ARGV[1]) then return 'late' end
local kept = redis.call('GET', KEYS[2])
if kept then return kept end
local state = lc_state(KEYS[1])
if not state then return lc_keep(KEYS[2], 'missing', ARGV[2]) end
if state ~= 'active' or lc_int(KEYS[1], 'exp') <= lc_now() then
  return lc_keep(KEYS[2], 'closed', ARGV[2])
end
local field = 'p:' .. ARGV[3]
if redis.call('HEXISTS', KEYS[1], field) == 0 then
  local count = lc_int(KEYS[1], 'np')
  if count >= tonumber(ARGV[6]) then return 'full' end
  redis.call('HSET', KEYS[1], 'np', lc_ms(count + 1))
end
redis.call('HSET', KEYS[1], field, ARGV[4], 'gen', ARGV[5])
return lc_keep(KEYS[2], 'joined', ARGV[2])
`.trim();

/**
 * The closing commit. `KEYS[1]` = the record, `KEYS[2]` = its shard's closing
 * index; `ARGV[1]` = the deadline, `ARGV[2]` = the generation, `ARGV[3]` = the
 * cause, `ARGV[4]` = retainMs, `ARGV[5]` = the step names, comma-separated,
 * `ARGV[6]` = the participant kinds that make an item each, comma-separated,
 * `ARGV[7]` = the sid. Returns `late`, `missing`, or the record's fields after
 * the step. Only an active record is written: it turns closing, and its sid
 * joins the index, in this step (the index first, so a failure writes
 * nothing). A copy that lands again finds it closing or closed and writes
 * nothing.
 */
const LUA_BEGIN_CLOSE = `${PRELUDE}
if lc_now() >= tonumber(ARGV[1]) then return 'late' end
local state = lc_state(KEYS[1])
if not state then return 'missing' end
if state == 'active' then
  local now = lc_now()
  local untilMs = math.max(lc_int(KEYS[1], 'until'), now + tonumber(ARGV[4]))
  local kinds = {}
  for kind in string.gmatch(ARGV[6], '[^,]+') do kinds[kind] = true end
  local items = {}
  for step in string.gmatch(ARGV[5], '[^,]+') do items[#items + 1] = step end
  for _, field in ipairs(redis.call('HKEYS', KEYS[1])) do
    if string.sub(field, 1, 2) == 'p:' then
      local item = string.sub(field, 3)
      local colon = string.find(item, ':', 1, true)
      if colon and kinds[string.sub(item, 1, colon - 1)] then items[#items + 1] = item end
    end
  end
  if #items > 0 then redis.call('ZADD', KEYS[2], 0, ARGV[7]) end
  for _, item in ipairs(items) do redis.call('HSET', KEYS[1], 'w:' .. item, '1') end
  redis.call('HSET', KEYS[1], 'state', (#items > 0) and 'closing' or 'closed', 'cause', ARGV[3],
    'at', lc_ms(now), 'nw', lc_ms(#items), 'gen', ARGV[2], 'until', lc_ms(untilMs))
  redis.call('PEXPIREAT', KEYS[1], lc_ms(untilMs))
end
return redis.call('HGETALL', KEYS[1])
`.trim();

/**
 * The completion. `KEYS[1]` = the record, `KEYS[2]` = the write's replay key,
 * `KEYS[3]` = its shard's closing index; `ARGV[1]` = the deadline, `ARGV[2]` =
 * when the replay key expires, `ARGV[3]` = the expected generation, `ARGV[4]`
 * = the item, `ARGV[5]` = the new generation, `ARGV[6]` = the sid. Returns
 * `late`, a kept answer, `not_pending` (nothing written or kept), or
 * `missing` / `conflict` / `updated` / `closed` (the last item: the record is
 * closed and its sid leaves the index in this step), kept until `ARGV[2]`. A
 * record whose pending count disagrees with its pending fields fails the
 * script before any write.
 */
const LUA_COMPLETE = `${PRELUDE}
if lc_now() >= tonumber(ARGV[1]) then return 'late' end
local kept = redis.call('GET', KEYS[2])
if kept then return kept end
local state = lc_state(KEYS[1])
if not state then return lc_keep(KEYS[2], 'missing', ARGV[2]) end
if redis.call('HGET', KEYS[1], 'gen') ~= ARGV[3] then return lc_keep(KEYS[2], 'conflict', ARGV[2]) end
local field = 'w:' .. ARGV[4]
if redis.call('HEXISTS', KEYS[1], field) == 0 then return 'not_pending' end
local left = lc_int(KEYS[1], 'nw') - 1
if left <= 0 then
  for _, other in ipairs(redis.call('HKEYS', KEYS[1])) do
    if string.sub(other, 1, 2) == 'w:' and other ~= field then
      error('session lifecycle record holds more pending items than its count')
    end
  end
  redis.call('ZREM', KEYS[3], ARGV[6])
  redis.call('HDEL', KEYS[1], field)
  redis.call('HSET', KEYS[1], 'state', 'closed', 'nw', '0', 'gen', ARGV[5])
  return lc_keep(KEYS[2], 'closed', ARGV[2])
end
redis.call('HDEL', KEYS[1], field)
redis.call('HSET', KEYS[1], 'nw', lc_ms(left), 'gen', ARGV[5])
return lc_keep(KEYS[2], 'updated', ARGV[2])
`.trim();

/** The read. `KEYS[1]` = the record. A script, so it runs on the primary. */
const LUA_READ = `return redis.call('HGETALL', KEYS[1])`;

/**
 * One page of a shard's closing index. `KEYS[1]` = the index; `ARGV[1]` = the
 * lex range's start (`-` or `(<sid>`), `ARGV[2]` = the page size. A script,
 * so it runs on the primary.
 */
const LUA_INDEX_PAGE = `return redis.call('ZRANGEBYLEX', KEYS[1], ARGV[1], '+', 'LIMIT', 0, ARGV[2])`;

/**
 * The listing's check. `KEYS[1]` = a shard's closing index, `KEYS[2..]` = the
 * records of the sids in `ARGV`, in order, on the same slot. Returns the sids
 * whose record is closing; every other one leaves the index in this step. A
 * record it cannot read fails the script before any write.
 */
const LUA_INDEX_CONFIRM = `${PRELUDE}
local states = {}
for i = 1, #ARGV do states[i] = lc_state(KEYS[i + 1]) end
local closing = {}
for i = 1, #ARGV do
  if states[i] == 'closing' then closing[#closing + 1] = ARGV[i]
  else redis.call('ZREM', KEYS[1], ARGV[i]) end
end
return closing
`.trim();

export const LC_OPEN = defineScript(LUA_OPEN);
export const LC_JOIN = defineScript(LUA_JOIN);
export const LC_BEGIN_CLOSE = defineScript(LUA_BEGIN_CLOSE);
export const LC_COMPLETE = defineScript(LUA_COMPLETE);
export const LC_READ = defineScript(LUA_READ);
export const LC_INDEX_PAGE = defineScript(LUA_INDEX_PAGE);
export const LC_INDEX_CONFIRM = defineScript(LUA_INDEX_CONFIRM);
