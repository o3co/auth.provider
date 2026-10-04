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
 * The attempt counter's client: one attempt counted against a fixed window as one indivisible
 * step, and what its server says about evicting keys.
 */

import type { RedisDurability } from "./durability.mjs";

// --- AttemptCounterClient --------------------------------------------------

/** What {@link AttemptCounterClient.consume} is handed besides the key. */
export interface AttemptCounterConsumeInput {
	/** The caller's clock, whole epoch milliseconds: a window is running while its end is after it. */
	readonly nowMs: number;
	/** The most attempts a window allows, judged on this attempt. */
	readonly limit: number;
	/** Where a window this attempt opens ends, whole epoch milliseconds. */
	readonly resetAtMs: number;
	/**
	 * How long past its end, in milliseconds, the key of a window this attempt opens lives. The
	 * key's TTL is relative (`PEXPIRE` of `resetAtMs − nowMs` plus this), so the server's clock
	 * never decides when a running window is freed.
	 */
	readonly expiryAllowanceMs: number;
}

/** What {@link AttemptCounterClient.consume} answers. */
export interface AttemptCounterConsumeReply {
	/** The attempt was counted. */
	readonly allowed: boolean;
	/** Attempts counted in the window, this one included when allowed. */
	readonly count: number;
	/** Where the window the attempt fell in ends, epoch milliseconds. */
	readonly resetAtMs: number;
}

/**
 * Backing client for the Redis `AttemptCounter`. One method, because reading
 * the window, counting the attempt and setting the key's deadline must be one
 * indivisible step, or concurrent attempts are counted past the limit.
 */
export interface AttemptCounterClient {
	/**
	 * Count one attempt under `key`, **atomically**:
	 *
	 *   - a window is running when the key holds a count and an end, and
	 *     either the end is after `nowMs` or the key's remaining TTL is above
	 *     `expiryAllowanceMs` (the server's countdown, which a caller's clock
	 *     running ahead cannot end early: such a caller is answered the running
	 *     window's end, never a fresh window); then the attempt is allowed and
	 *     counted while the count is below `limit`, and refused otherwise,
	 *     writing nothing
	 *   - with no window running, open one: count 1, ending at `resetAtMs`,
	 *     the key's TTL `resetAtMs − nowMs + expiryAllowanceMs`
	 *   - a running window's end and TTL are never moved
	 */
	consume(key: string, input: AttemptCounterConsumeInput): Promise<AttemptCounterConsumeReply>;

	/** What the server says about evicting and keeping keys, read once at boot by the module. */
	durability(): Promise<RedisDurability>;
}
