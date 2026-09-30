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
 * The advisory lock's release, shared by the federation token and federation grant stores: a
 * delete that frees only the value the caller was given.
 */

import { createHash } from "node:crypto";

/**
 * Lua compare-and-delete script — atomic alternative to GET+DEL.
 * Returns 1 when the key was deleted (caller's token matched), 0 otherwise.
 * `KEYS[1]` = the lock key; `ARGV[1]` = the caller's acquire token.
 */
export const LUA_COMPARE_AND_DELETE = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
  return redis.call("DEL", KEYS[1])
else
  return 0
end
`.trim();

/**
 * SHA-1 of `LUA_COMPARE_AND_DELETE`. Redis keys its script cache by the SHA-1 of the source, so
 * the digest matches what `SCRIPT LOAD` would return, without that round trip.
 */
export const LUA_COMPARE_AND_DELETE_SHA = createHash("sha1")
	.update(LUA_COMPARE_AND_DELETE)
	.digest("hex");
