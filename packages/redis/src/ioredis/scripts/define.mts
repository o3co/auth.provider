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
 * A Lua script as the server caches it: its source, its SHA-1 (what `EVALSHA` names it by) and
 * whether the server is expected to hold it. Each is defined once, at module scope: the script
 * is constant, so every client in a process shares the server's cache state.
 */

import { createHash } from "node:crypto";

/**
 * A script, its digest, and whether the server is expected to hold it, for `runScript`'s
 * EVALSHA-first path.
 */
export interface CachedScript {
	readonly source: string;
	/**
	 * SHA-1 of `source`: Redis keys its script cache by it, so the digest is what `SCRIPT LOAD`
	 * would return, without that round trip.
	 */
	readonly sha: string;
	/** `true` lets the next run use `EVALSHA`; a `NOSCRIPT` clears it and `EVAL` sets it again. */
	cached: boolean;
}

export const defineScript = (source: string): CachedScript => ({
	source,
	sha: createHash("sha1").update(source).digest("hex"),
	cached: false,
});
