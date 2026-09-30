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
 * The session stores' scripts: the step-up's compare-and-replace, the subject index's sweep on
 * the server's clock, and the subject revocation record's forward-only write.
 */

import { createHash } from "node:crypto";
import { defineScript } from "./define.mjs";

/**
 * Compare-and-replace for a session record, the MFA step-up write. `KEYS[1]` = the session
 * key; `ARGV[1]` = the value the caller read, `ARGV[2]` = its replacement. Replaces only while
 * the key still holds what was read, keeping its TTL (`KEEPTTL`): a second factor never changes
 * how long a session lives. Returns 1 when it replaced, 0 otherwise.
 */
const LUA_REPLACE_IF_UNCHANGED = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
  redis.call("SET", KEYS[1], ARGV[2], "KEEPTTL")
  return 1
end
return 0
`.trim();

/**
 * The subject revocation record's only write: both boundaries (sessions, grants) in one key,
 * one atomic step. `KEYS[1]` = the record; `ARGV` = mode (`all` | `sessions`), `before` and the
 * proposed expiry (epoch ms), the grant retention (ms). Returns the value written; a stored value
 * it cannot read is refused with an error.
 *
 * Boundaries and expiry only move forward: a boundary moved back resurrects tokens an earlier
 * revocation killed, and a shorter expiry retires the record while tokens it must refuse are
 * still presentable. `PEXPIRETIME` gives the stored absolute expiry (-1: none, the key stays
 * persistent; -2: absent, the proposed one applies). A grants boundary keeps the record at least
 * until that boundary plus the retention.
 *
 * The value is not JSON (`cjson` writes 14 significant digits, too close to an epoch ms's 13):
 *   `<n>`         both boundaries are `n`
 *   `v1:<s>:<g>`  they differ
 *   `v1:<s>:-`    sessions only; no revocation has covered the subject's grants
 * Older releases read only `<n>`: rollback is safe until sessions-only stamps are used, and once
 * `v1:` records exist an old writer can move the sessions boundary backward, so drain old
 * writers first. See packages/core/docs/adr/2026-09-17-federation-grants-offline-delegation.md.
 */
export const LUA_SET_REVOCATION_BOUNDARIES = `
local mode = ARGV[1]
-- What a Date can hold (ECMA-262). A stored value outside it is not a
-- boundary: the read path refuses it, and carrying it forward here would
-- write a record only this script can produce and nothing can read.
local MAX_DATE = 8640000000000000
local function readable(n)
  return n ~= nil and n == n and n >= -MAX_DATE and n <= MAX_DATE
end
local before = tonumber(ARGV[2])
local expiresAt = tonumber(ARGV[3])
local retention = tonumber(ARGV[4])
if before == nil or expiresAt == nil or retention == nil then
  return redis.error_reply("subject revocation: non-numeric argument")
end

local sessions = nil
local grants = nil
local current = redis.call("GET", KEYS[1])
if current then
  if string.match(current, "^%-?%d+$") then
    sessions = tonumber(current)
    grants = sessions
  else
    local s, g = string.match(current, "^v1:(%-?%d+):(%-?%d+)$")
    if s ~= nil then
      sessions = tonumber(s)
      grants = tonumber(g)
    else
      s = string.match(current, "^v1:(%-?%d+):%-$")
      if s == nil then
        return redis.error_reply("subject revocation: unreadable record")
      end
      sessions = tonumber(s)
    end
  end
  -- The shape matched; the numbers still have to be instants. tonumber of
  -- four hundred digits is infinity, which passes every pattern above and
  -- would be written back as "inf".
  if (not readable(sessions)) or (grants ~= nil and not readable(grants)) then
    return redis.error_reply("subject revocation: unreadable record")
  end
end

if sessions == nil or before > sessions then sessions = before end
if mode == "all" then
  if grants == nil or before > grants then grants = before end
end

local ttlAt = redis.call("PEXPIRETIME", KEYS[1])
local persistent = (ttlAt == -1)
if (not persistent) and ttlAt > 0 and ttlAt > expiresAt then expiresAt = ttlAt end
if grants ~= nil then
  local floor = grants + retention
  if floor > expiresAt then expiresAt = floor end
end

local value
if grants == nil then
  value = "v1:" .. string.format("%.0f", sessions) .. ":-"
elseif grants == sessions then
  value = string.format("%.0f", sessions)
else
  value = "v1:" .. string.format("%.0f", sessions) .. ":" .. string.format("%.0f", grants)
end

if persistent then
  redis.call("SET", KEYS[1], value)
else
  redis.call("SET", KEYS[1], value, "PXAT", expiresAt)
end
return value
`.trim();

/** See {@link LUA_COMPARE_AND_DELETE_SHA} for why the digest is precomputed. */
export const LUA_SET_REVOCATION_BOUNDARIES_SHA = createHash("sha1")
	.update(LUA_SET_REVOCATION_BOUNDARIES)
	.digest("hex");

/**
 * Sweep-then-list for the subject session index. `KEYS[1]` = the subject's sorted set; returns
 * the members still live.
 *
 * The boundary is the server's `TIME`, not the calling replica's clock: scores are written and
 * read by different replicas, and comparing two host clocks would misjudge sessions by the skew
 * between them. One script makes the sweep and the read agree on the boundary. A
 * non-deterministic `TIME` is fine: Redis 7 replicates scripts by their effects.
 */
export const LUA_PRUNE_AND_LIST = `
local t = redis.call("TIME")
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
redis.call("ZREMRANGEBYSCORE", KEYS[1], "-inf", now)
return redis.call("ZRANGEBYSCORE", KEYS[1], now, "+inf")
`.trim();

/** See {@link LUA_COMPARE_AND_DELETE_SHA} for why the digest is precomputed. */
export const LUA_PRUNE_AND_LIST_SHA = createHash("sha1").update(LUA_PRUNE_AND_LIST).digest("hex");

export const REPLACE_IF_UNCHANGED = defineScript(LUA_REPLACE_IF_UNCHANGED);
