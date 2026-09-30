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
 * The rate limiter's script: a counter's increment and its expiry in one step.
 */

/**
 * Rate-limit counter increment, atomic with its expiry: `INCR` then a separate `EXPIRE` can
 * leave the key with no TTL, and a counter that never resets 429s its client forever.
 *
 * The expiry is set whenever the key has none (`TTL` < 0), not only on the first hit, so a key
 * left without a TTL is repaired. An existing expiry is left alone, so steady traffic cannot
 * hold the window open.
 *
 * Returns `{count, pttl}`, both read in the script so they describe one counter state. The
 * limiter turns `pttl` into `resetAt`, the 429's `Retry-After`.
 */
export const LUA_INCREMENT_WITH_TTL = `
local count = redis.call('INCR', KEYS[1])
if redis.call('TTL', KEYS[1]) < 0 then
  redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return {count, redis.call('PTTL', KEYS[1])}
`.trim();
