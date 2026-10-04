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
 * its replay key on the same Cluster slot; the hash's layout is
 * `clients/session-lifecycle.mts`'s. Every write is refused at or after its
 * deadline on the server's clock, and checks the record before it writes, so
 * a record it cannot read fails the script with nothing written. The closing
 * index's scripts touch only the index's two keys, on a slot of their own.
 * The scripts make no generation: the adapter hands each one in.
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
 * The closing commit. `KEYS[1]` = the record; `ARGV[1]` = the deadline,
 * `ARGV[2]` = the generation, `ARGV[3]` = the cause, `ARGV[4]` = retainMs,
 * `ARGV[5]` = the step names, comma-separated, `ARGV[6]` = the participant
 * kinds that make an item each, comma-separated. Returns `late`, `missing`,
 * or the record's fields after the step. Only an active record is written;
 * a copy that lands again finds it closing or closed and writes nothing.
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
  for _, item in ipairs(items) do redis.call('HSET', KEYS[1], 'w:' .. item, '1') end
  redis.call('HSET', KEYS[1], 'state', (#items > 0) and 'closing' or 'closed', 'cause', ARGV[3],
    'at', lc_ms(now), 'nw', lc_ms(#items), 'gen', ARGV[2], 'until', lc_ms(untilMs))
  redis.call('PEXPIREAT', KEYS[1], lc_ms(untilMs))
end
return redis.call('HGETALL', KEYS[1])
`.trim();

/**
 * The completion. `KEYS[1]` = the record, `KEYS[2]` = the write's replay key;
 * `ARGV[1]` = the deadline, `ARGV[2]` = when the replay key expires,
 * `ARGV[3]` = the expected generation, `ARGV[4]` = the item, `ARGV[5]` = the
 * new generation. Returns `late`, a kept answer, `not_pending` (nothing
 * written or kept), or `missing` / `conflict` / `updated` /
 * `closed:<until>` (the last item: the record is closed, its key expiring at
 * `<until>`), kept until `ARGV[2]`.
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
local untilMs = lc_int(KEYS[1], 'until')
redis.call('HDEL', KEYS[1], field)
if left <= 0 then
  redis.call('HSET', KEYS[1], 'state', 'closed', 'nw', '0', 'gen', ARGV[5])
  return lc_keep(KEYS[2], 'closed:' .. lc_ms(untilMs), ARGV[2])
end
redis.call('HSET', KEYS[1], 'nw', lc_ms(left), 'gen', ARGV[5])
return lc_keep(KEYS[2], 'updated', ARGV[2])
`.trim();

/**
 * The index's add. `KEYS[1]` = the index's sids, `KEYS[2]` = its deadlines;
 * `ARGV[1]` = the sid, `ARGV[2]` = the close's deadline. Returns `late` at or
 * after the deadline (nothing written), else `added`: the sid is in the
 * index, its stored deadline the later of the one there and `ARGV[2]`.
 */
const LUA_INDEX_ADD = `${PRELUDE}
if lc_now() >= tonumber(ARGV[2]) then return 'late' end
redis.call('ZADD', KEYS[1], 0, ARGV[1])
local stored = tonumber(redis.call('HGET', KEYS[2], ARGV[1]) or '')
if not stored or stored < tonumber(ARGV[2]) then redis.call('HSET', KEYS[2], ARGV[1], ARGV[2]) end
return 'added'
`.trim();

/**
 * One page of the index. `KEYS` as for the add; `ARGV[1]` = the lex range's
 * start (`-` or `(<sid>`), `ARGV[2]` = the page size. Returns the server's
 * clock, then each sid and its stored deadline (`''` for none), in order.
 */
const LUA_INDEX_PAGE = `${PRELUDE}
local sids = redis.call('ZRANGEBYLEX', KEYS[1], ARGV[1], '+', 'LIMIT', 0, ARGV[2])
local out = { lc_ms(lc_now()) }
for _, sid in ipairs(sids) do
  out[#out + 1] = sid
  out[#out + 1] = redis.call('HGET', KEYS[2], sid) or ''
end
return out
`.trim();

/**
 * The listing's removal. `KEYS` as for the add; `ARGV[1]` = the sid,
 * `ARGV[2]` = the stored deadline the listing read. Removes the sid only
 * while that is still its stored deadline; returns 1 when it did.
 */
const LUA_INDEX_PRUNE_IF = `
if (redis.call('HGET', KEYS[2], ARGV[1]) or '') ~= ARGV[2] then return 0 end
redis.call('ZREM', KEYS[1], ARGV[1])
redis.call('HDEL', KEYS[2], ARGV[1])
return 1
`.trim();

/**
 * A closed record's removal. `KEYS` as for the add; `ARGV[1]` = the sid,
 * `ARGV[2]` = when the closed record's key expires, `ARGV[3]` = the clock
 * skew. Removes the sid only while its stored deadline plus the skew is no
 * later than `ARGV[2]`; returns 1 when it did.
 */
const LUA_INDEX_PRUNE_OUTLIVED = `
local stored = tonumber(redis.call('HGET', KEYS[2], ARGV[1]) or '')
if stored and stored + tonumber(ARGV[3]) > tonumber(ARGV[2]) then return 0 end
redis.call('ZREM', KEYS[1], ARGV[1])
redis.call('HDEL', KEYS[2], ARGV[1])
return 1
`.trim();

export const LC_OPEN = defineScript(LUA_OPEN);
export const LC_JOIN = defineScript(LUA_JOIN);
export const LC_BEGIN_CLOSE = defineScript(LUA_BEGIN_CLOSE);
export const LC_COMPLETE = defineScript(LUA_COMPLETE);
export const LC_INDEX_ADD = defineScript(LUA_INDEX_ADD);
export const LC_INDEX_PAGE = defineScript(LUA_INDEX_PAGE);
export const LC_INDEX_PRUNE_IF = defineScript(LUA_INDEX_PRUNE_IF);
export const LC_INDEX_PRUNE_OUTLIVED = defineScript(LUA_INDEX_PRUNE_OUTLIVED);
