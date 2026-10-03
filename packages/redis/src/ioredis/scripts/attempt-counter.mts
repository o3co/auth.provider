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
 * The attempt counter's script: one attempt counted against a fixed window in one step.
 */

import { defineScript } from "./define.mjs";

/**
 * `KEYS[1]` = the window's hash (`count`, `resetAt`); `ARGV` = the caller's clock, the limit,
 * the end of a window this attempt opens, the clock allowance. A window opens with its end
 * (`ARGV[3]`) and a relative TTL, the window's length on the caller's clock plus the allowance.
 * It is running while its end is after the caller's clock, or while its TTL is above the
 * allowance: the server's countdown, which no caller's clock moves, so a caller whose clock runs
 * ahead never reopens a window the server still runs, and is answered its end. Running, below the
 * limit the attempt is counted; at it the attempt is refused and nothing is written. Replies
 * `{allowed (0|1), count, resetAt}`.
 */
export const ATTEMPT_COUNTER_CONSUME = defineScript(
	`
local now = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
local opensUntil = tonumber(ARGV[3])
local allowance = tonumber(ARGV[4])
if now == nil or limit == nil or opensUntil == nil or allowance == nil or not (now < opensUntil) then
  return redis.error_reply('ERR attempt counter: malformed arguments')
end
local count = tonumber(redis.call('HGET', KEYS[1], 'count'))
local resetAt = tonumber(redis.call('HGET', KEYS[1], 'resetAt'))
if count ~= nil and resetAt ~= nil and (now < resetAt or redis.call('PTTL', KEYS[1]) > allowance) then
  if count >= limit then return {0, count, resetAt} end
  return {1, redis.call('HINCRBY', KEYS[1], 'count', 1), resetAt}
end
redis.call('HSET', KEYS[1], 'count', 1, 'resetAt', ARGV[3])
redis.call('PEXPIRE', KEYS[1], opensUntil - now + allowance)
return {1, 1, opensUntil}
`.trim(),
);
