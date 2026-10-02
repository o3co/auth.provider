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
 * The device authorization store's scripts, one per operation, each indivisible over a record
 * and its user-code index.
 */

import { defineScript } from "./define.mjs";

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
 * `requested` | `narrow`, `ARGV[6]` = the caller's grantedScope as a JSON array (`narrow` only),
 * `ARGV[7]` = the approving session's `amr` as a JSON array, `ARGV[8]` = its authentication
 * instant (epoch ms); an empty or missing `ARGV[7]` or `ARGV[8]` is not written. Returns
 * `{'ok', record}`, `{'already_decided', status}`, `{'expired'}` or `{'not_found'}`.
 *
 * Check and write are one step, so a denial and an approval cannot interleave with the second
 * overwriting the first. The scope intersection is inside it too, so no read sits between
 * showing the user a scope and granting one: `narrow` filters the caller's list by
 * `requestedScope` in the caller's order, `requested` grants it whole. An empty result is
 * written as `[]` literally, because `cjson.encode({})` is `{}`. The `amr` is stored as handed,
 * never decoded or re-encoded, in the same `HSET` as the approval.
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
  local fields = {'status', 'approved', 'subject', ARGV[4], 'grantedScope', encoded, 'approvedAtMs', ARGV[2]}
  if ARGV[7] and ARGV[7] ~= '' then
    fields[#fields + 1] = 'amr'
    fields[#fields + 1] = ARGV[7]
  end
  if ARGV[8] and ARGV[8] ~= '' then
    fields[#fields + 1] = 'authTimeMs'
    fields[#fields + 1] = ARGV[8]
  end
  redis.call('HSET', codeKey, unpack(fields))
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

export const DEVICE_CODE_CREATE = defineScript(LUA_DEVICE_CODE_CREATE);
export const DEVICE_CODE_FIND_PENDING = defineScript(LUA_DEVICE_CODE_FIND_PENDING);
export const DEVICE_CODE_DECIDE = defineScript(LUA_DEVICE_CODE_DECIDE);
export const DEVICE_CODE_POLL = defineScript(LUA_DEVICE_CODE_POLL);
export const DEVICE_CODE_REMOVE = defineScript(LUA_DEVICE_CODE_REMOVE);
