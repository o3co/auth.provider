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
 * A subject's first-binding mark as this package notes and reads it (the
 * MFA ADR's D12; core's `MfaTransactionStore.noteFirstBinding` and
 * `firstBindingAt`): how long a noted mark stands, how a store's answer is
 * read, and which authentication a mark distrusts.
 *
 * - A mark stands `max(mfa.manage.maxAgeSeconds, 2 × mfa.transactionTtlSeconds)`
 *   and twice `DEFAULT_CLOCK_SKEW_MS`: the longest a session (its recent
 *   primary) or a continuation (one reopen) it distrusts can still bind,
 *   with the skew once for the clock that dated the authentication and once
 *   for the store's clock that ends the mark.
 * - An authentication at or before the mark plus `DEFAULT_CLOCK_SKEW_MS` is
 *   distrusted, and so is one whose time cannot be read.
 * - An answer the port does not promise is an outage, never "no mark".
 */

import { DEFAULT_CLOCK_SKEW_MS, readFirstBindingAt } from "@o3co/auth-provider-core";

/** The settings a mark's lifetime is read from: `mfa.manage.maxAgeSeconds` and `mfa.transactionTtlSeconds`. */
export interface FirstBindingMarkSettings {
	readonly manageMaxAgeSeconds: number;
	readonly transactionTtlSeconds: number;
}

/** How long a mark noted now stands, in whole milliseconds (see this file's header). */
export function firstBindingMarkLifetimeMs(settings: FirstBindingMarkSettings): number {
	const windowSeconds = Math.max(settings.manageMaxAgeSeconds, 2 * settings.transactionTtlSeconds);
	return windowSeconds * 1000 + 2 * DEFAULT_CLOCK_SKEW_MS;
}

/**
 * What `firstBindingAt(subject, nowMs)` answered, read through core's
 * `readFirstBindingAt`: the mark's time, or `null` for none. Throws a
 * `TypeError` for anything else.
 */
export function readFirstBindingMark(answer: unknown, nowMs: number): number | null {
	const read = readFirstBindingAt(answer, nowMs);
	if (read === undefined) {
		throw new TypeError(
			"MfaTransactionStore.firstBindingAt answered something that is not a time or null",
		);
	}
	return read;
}

/**
 * Whether a mark at `markAtMs` distrusts an authentication at
 * `authTimeMs`: one not later than the mark by more than
 * `DEFAULT_CLOCK_SKEW_MS`, or one that is not a number. None, with no mark.
 */
export function distrustedByFirstBinding(
	authTimeMs: number | undefined,
	markAtMs: number | null,
): boolean {
	if (markAtMs === null) return false;
	return !(typeof authTimeMs === "number" && authTimeMs > markAtMs + DEFAULT_CLOCK_SKEW_MS);
}
