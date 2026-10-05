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
 * - A mark stands `max(mfa.manage.maxAgeSeconds, 2 × mfa.transactionTtlSeconds)`,
 *   twice `DEFAULT_CLOCK_SKEW_MS` and one factor-set lease: the longest a
 *   session (its recent primary) or a continuation (one reopen) it distrusts
 *   can still bind, with the skew once for the clock that dated the
 *   authentication and once for the store's clock that ends the mark, and the
 *   lease a write it marks may still be landing in.
 * - An authentication at or before the mark plus `DEFAULT_CLOCK_SKEW_MS` and
 *   one factor-set lease is distrusted — a sign-in made while the marked write
 *   may still have been landing, on a clock up to the skew ahead — and so is
 *   one whose time cannot be read; a fresh one is not until that has passed
 *   (`retryAfterMs`). Every reader judges by the same mark
 *   (`createFirstBindingMark`), which holds the lease: none passes it.
 * - An answer the port does not promise is an outage, never "no mark".
 */

import { DEFAULT_CLOCK_SKEW_MS, readFirstBindingAt } from "@o3co/auth-provider-core";

/** The settings a mark's lifetime is read from: `mfa.manage.maxAgeSeconds`, `mfa.transactionTtlSeconds` and a factor-set write's lease. */
export interface FirstBindingMarkSettings {
	readonly manageMaxAgeSeconds: number;
	readonly transactionTtlSeconds: number;
	/** How long a factor-set write's lease stands, in milliseconds (`leaseMsFor`). */
	readonly leaseMs: number;
}

/** How long a mark noted now stands, in whole milliseconds (see this file's header). */
export function firstBindingMarkLifetimeMs(settings: FirstBindingMarkSettings): number {
	const windowSeconds = Math.max(settings.manageMaxAgeSeconds, 2 * settings.transactionTtlSeconds);
	return windowSeconds * 1000 + 2 * DEFAULT_CLOCK_SKEW_MS + settings.leaseMs;
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

/** One subject's first-binding mark as every reader judges it, over the settings it was built with. */
export interface FirstBindingMark {
	/** How long a mark noted now stands, in whole milliseconds. */
	readonly lifetimeMs: number;
	/**
	 * How long after a read finds no mark that read still covers a binding: a
	 * mark noted since stands its lifetime, less the skew and the lease it may
	 * be noted ahead of its write.
	 */
	readonly readCoversMs: number;
	/**
	 * Whether a mark at `markAtMs` distrusts an authentication at
	 * `authTimeMs`: one not later than the mark by more than
	 * `DEFAULT_CLOCK_SKEW_MS` and one lease, or one that is not a number.
	 * None, with no mark.
	 */
	distrusts(authTimeMs: number | undefined, markAtMs: number | null): boolean;
	/**
	 * How long from `nowMs` until an authentication is no longer distrusted by
	 * a mark at `markAtMs`, on this clock. Another replica's clock may put it
	 * up to the skew later.
	 */
	retryAfterMs(markAtMs: number, nowMs: number): number;
}

/** The mark over `settings` (see this file's header). */
export function createFirstBindingMark(settings: FirstBindingMarkSettings): FirstBindingMark {
	const lifetimeMs = firstBindingMarkLifetimeMs(settings);
	const { leaseMs } = settings;
	/** The latest authentication a mark at `markAtMs` distrusts. */
	const distrustedUntil = (markAtMs: number): number => markAtMs + DEFAULT_CLOCK_SKEW_MS + leaseMs;
	return Object.freeze({
		lifetimeMs,
		readCoversMs: lifetimeMs - DEFAULT_CLOCK_SKEW_MS - leaseMs,
		distrusts: (authTimeMs: number | undefined, markAtMs: number | null): boolean =>
			markAtMs !== null &&
			!(typeof authTimeMs === "number" && authTimeMs > distrustedUntil(markAtMs)),
		retryAfterMs: (markAtMs: number, nowMs: number): number =>
			Math.max(0, distrustedUntil(markAtMs) + 1 - nowMs),
	});
}
