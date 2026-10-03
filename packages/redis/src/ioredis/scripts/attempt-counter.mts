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
 * the end of a window this attempt opens, the key's deadline. A window is running while its end
 * is after the caller's clock: below the limit the attempt is counted, at it the attempt is
 * refused and nothing is written. Otherwise a window opens, ending at `ARGV[3]`, its key
 * expiring at `ARGV[4]`. Replies `{allowed (0|1), count, resetAt}`.
 */
export const ATTEMPT_COUNTER_CONSUME = defineScript(
	`
local now = tonumber(ARGV[1])
local limit = tonumber(ARGV[2])
if now == nil or limit == nil or tonumber(ARGV[3]) == nil or tonumber(ARGV[4]) == nil then
  return redis.error_reply('ERR attempt counter: malformed arguments')
end
local count = tonumber(redis.call('HGET', KEYS[1], 'count'))
local resetAt = tonumber(redis.call('HGET', KEYS[1], 'resetAt'))
if count ~= nil and resetAt ~= nil and now < resetAt then
  if count >= limit then return {0, count, resetAt} end
  return {1, redis.call('HINCRBY', KEYS[1], 'count', 1), resetAt}
end
redis.call('HSET', KEYS[1], 'count', 1, 'resetAt', ARGV[3])
redis.call('PEXPIREAT', KEYS[1], ARGV[4])
return {1, 1, tonumber(ARGV[3])}
`.trim(),
);
