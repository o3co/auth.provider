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
 * record's key and, for a write, its replay key on the same Cluster slot. A
 * record's generation is its wrapper's `g`, outside the ciphertext. The
 * scripts make no generation: the adapter hands each one in.
 *
 * The removal declares `allow-oom`: under `noeviction` a full server still
 * runs it, since a record must stay removable when nothing more can be
 * written. Besides the delete, it writes only its answer: one small replay key
 * per call, living about 2 s, and on `missing` or `conflict` that key is all
 * it writes. The replace and the versioned read declare no flags.
 */

import { defineScript } from "./define.mjs";

/** The first line of a script a full `noeviction` server still runs (Redis 7.0+). */
const ALLOW_OOM = "#!lua flags=allow-oom";

/**
 * `ft_generation(raw)`: the generation the stored value carries, or `nil` when
 * it carries none (or is no JSON object). `ft_late(deadline)`: whether the
 * server's clock is at or after `deadline`, in epoch milliseconds.
 * `ft_keep(replay, answer, untilMs)`: `answer` kept under the replay key
 * until `untilMs` (epoch ms), for a copy of the write that arrives before then.
 * Exported for the tests that pin these helpers on a real Redis.
 */
export const FT_PRELUDE = `
local function ft_generation(raw)
  local ok, rec = pcall(cjson.decode, raw)
  if not ok or type(rec) ~= 'table' then return nil end
  local g = rec['g']
  if type(g) ~= 'string' then return nil end
  return g
end
local function ft_late(deadline)
  local t = redis.call('TIME')
  return tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000) >= tonumber(deadline)
end
local function ft_keep(replay, answer, untilMs)
  redis.call('SET', replay, answer, 'PXAT', untilMs)
  return answer
end
`;

/**
 * The versioned read. `KEYS[1]` = the record; `ARGV[1]` = a fresh generation.
 * Returns `false` for no key, else `{ value, generation }`. A record the
 * store's format wrote without `g` (it decodes to an object with `v` 2 and no
 * `g`, and its first byte is `{`) is given `ARGV[1]`, its TTL kept, and
 * answered with it. The mint splices `"g"` in after that first byte rather
 * than re-encoding the object, which could change its numbers. Any other
 * value without a generation is answered with the generation `""`.
 */
const LUA_READ_VERSIONED = `${FT_PRELUDE}
local raw = redis.call('GET', KEYS[1])
if not raw then return false end
local g = ft_generation(raw)
if g then return {raw, g} end
local ok, rec = pcall(cjson.decode, raw)
if ok and type(rec) == 'table' and rec['v'] == 2 and rec['g'] == nil and string.sub(raw, 1, 1) == '{' then
  local minted = '{"g":' .. cjson.encode(ARGV[1]) .. ',' .. string.sub(raw, 2)
  redis.call('SET', KEYS[1], minted, 'KEEPTTL')
  return {minted, ARGV[1]}
end
return {raw, ''}
`.trim();

/**
 * The conditional replace. `KEYS[1]` = the record, `KEYS[2]` = the write's
 * replay key; `ARGV[1]` = the deadline (epoch ms), `ARGV[2]` = when the
 * replay key expires (epoch ms: the declared clock skew and a millisecond past
 * the deadline), `ARGV[3]` = the expected generation, `ARGV[4]` = the new
 * value (carrying its new generation), `ARGV[5]` = the store TTL (ms). Returns
 * `late` (at or after the deadline on the server's clock: nothing read or
 * written by this copy),
 * the answer the replay key holds (a copy of a write already taken: nothing
 * written), or the answer kept there until `ARGV[2]`: `missing` (no key, or
 * past its `PX`), `conflict` (another generation, or none) or `updated`.
 */
const LUA_REPLACE_IF = `${FT_PRELUDE}
if ft_late(ARGV[1]) then return 'late' end
local kept = redis.call('GET', KEYS[2])
if kept then return kept end
local raw = redis.call('GET', KEYS[1])
if not raw then return ft_keep(KEYS[2], 'missing', ARGV[2]) end
if ft_generation(raw) ~= ARGV[3] then return ft_keep(KEYS[2], 'conflict', ARGV[2]) end
redis.call('SET', KEYS[1], ARGV[4], 'PX', ARGV[5])
return ft_keep(KEYS[2], 'updated', ARGV[2])
`.trim();

/**
 * The conditional delete. `KEYS[1]` = the record, `KEYS[2]` = the write's
 * replay key; `ARGV[1]` = the deadline (epoch ms), `ARGV[2]` = when the
 * replay key expires, `ARGV[3]` = the expected generation. Returns `late`, a
 * kept answer, `missing`, `conflict` or `removed`, as the replace does. Its
 * first line declares `allow-oom`, so it must stay the script's first line.
 */
const LUA_REMOVE_IF = `${ALLOW_OOM}${FT_PRELUDE}
if ft_late(ARGV[1]) then return 'late' end
local kept = redis.call('GET', KEYS[2])
if kept then return kept end
local raw = redis.call('GET', KEYS[1])
if not raw then return ft_keep(KEYS[2], 'missing', ARGV[2]) end
if ft_generation(raw) ~= ARGV[3] then return ft_keep(KEYS[2], 'conflict', ARGV[2]) end
redis.call('DEL', KEYS[1])
return ft_keep(KEYS[2], 'removed', ARGV[2])
`.trim();

export const FT_READ_VERSIONED = defineScript(LUA_READ_VERSIONED);
export const FT_REPLACE_IF = defineScript(LUA_REPLACE_IF);
export const FT_REMOVE_IF = defineScript(LUA_REMOVE_IF);
