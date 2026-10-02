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
 * The federation token store's conditional members, one script each over the
 * record's one key (no other key is touched, so each runs on one Cluster
 * slot). A record's generation is its wrapper's `g`, outside the ciphertext.
 * The scripts make no generation: the adapter hands each one in.
 */

import { defineScript } from "./define.mjs";

/**
 * `ft_generation(raw)`: the generation the stored value carries, or `nil` when
 * it carries none (or is no JSON object). `ft_late(deadline)`: whether the
 * server's clock is past `deadline`, in epoch milliseconds.
 */
const PRELUDE = `
local function ft_generation(raw)
  local ok, rec = pcall(cjson.decode, raw)
  if not ok or type(rec) ~= 'table' then return nil end
  local g = rec['g']
  if type(g) ~= 'string' then return nil end
  return g
end
local function ft_late(deadline)
  local t = redis.call('TIME')
  return tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000) > tonumber(deadline)
end
`;

/**
 * The versioned read. `KEYS[1]` = the record; `ARGV[1]` = a fresh generation.
 * Returns `false` for no key, else `{ value, generation }`. A record the
 * store's format wrote without `g` (`{"v":2,` first, as `JSON.stringify`
 * writes it) is given `ARGV[1]`, its TTL kept, and answered with it. Any
 * other value is answered with the generation `""`: unreadable.
 */
const LUA_READ_VERSIONED = `${PRELUDE}
local raw = redis.call('GET', KEYS[1])
if not raw then return false end
local g = ft_generation(raw)
if g then return {raw, g} end
local ok, rec = pcall(cjson.decode, raw)
if ok and type(rec) == 'table' and rec['g'] == nil and string.sub(raw, 1, 7) == '{"v":2,' then
  local minted = '{"g":' .. cjson.encode(ARGV[1]) .. ',' .. string.sub(raw, 2)
  redis.call('SET', KEYS[1], minted, 'KEEPTTL')
  return {minted, ARGV[1]}
end
return {raw, ''}
`.trim();

/**
 * The conditional replace. `KEYS[1]` = the record; `ARGV[1]` = the deadline
 * (epoch ms), `ARGV[2]` = the expected generation, `ARGV[3]` = the new value
 * (carrying its new generation), `ARGV[4]` = the store TTL (ms). Returns
 * `late` (past the deadline on the server's clock: nothing read or written),
 * `missing` (no key, or past its `PX`), `conflict` (another generation, or
 * none) or `updated`.
 */
const LUA_REPLACE_IF = `${PRELUDE}
if ft_late(ARGV[1]) then return 'late' end
local raw = redis.call('GET', KEYS[1])
if not raw then return 'missing' end
if ft_generation(raw) ~= ARGV[2] then return 'conflict' end
redis.call('SET', KEYS[1], ARGV[3], 'PX', ARGV[4])
return 'updated'
`.trim();

/**
 * The conditional delete. `KEYS[1]` = the record; `ARGV[1]` = the deadline
 * (epoch ms), `ARGV[2]` = the expected generation. Returns `late`, `missing`,
 * `conflict` or `removed`, as the replace does.
 */
const LUA_REMOVE_IF = `${PRELUDE}
if ft_late(ARGV[1]) then return 'late' end
local raw = redis.call('GET', KEYS[1])
if not raw then return 'missing' end
if ft_generation(raw) ~= ARGV[2] then return 'conflict' end
redis.call('DEL', KEYS[1])
return 'removed'
`.trim();

export const FT_READ_VERSIONED = defineScript(LUA_READ_VERSIONED);
export const FT_REPLACE_IF = defineScript(LUA_REPLACE_IF);
export const FT_REMOVE_IF = defineScript(LUA_REMOVE_IF);
