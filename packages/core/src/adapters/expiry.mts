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
 * The expiries and lifetimes a store may be handed — one rule, for every
 * adapter, in-process or shared.
 *
 * An expiry is an instant in epoch milliseconds, and a store keeps something
 * until it. So it has to be a finite number (NaN is never `<= now`, so it
 * slipped past every "already expired" check and was kept for ever) inside
 * ECMAScript's Date range, ±8.64e15 ms: past that a number is no instant a
 * `Date` can hold, and no deadline Redis can take — `1e21` is sent as `1e+21`,
 * and a whole but enormous value overflows the server's expiry. A script that
 * writes its record before it sets the deadline then leaves the record with
 * no TTL at all, which is the failure this rule exists to make impossible.
 *
 * A lifetime (a TTL, a wait, a code's `expiresIn`) is measured from now, so
 * its end has to be such an instant too.
 */

/** The last instant a store keeps anything until: the end of ECMAScript's Date range. */
export const MAX_STORABLE_EXPIRY_MS = 8_640_000_000_000_000;

/**
 * Whether `expiresAtMs` is an instant a store can keep something until:
 * finite, and within ±{@link MAX_STORABLE_EXPIRY_MS} once rounded up to a
 * whole millisecond, as every Redis adapter rounds it.
 */
export const isStorableExpiry = (expiresAtMs: number): boolean =>
	Number.isFinite(expiresAtMs) && Math.abs(Math.ceil(expiresAtMs)) <= MAX_STORABLE_EXPIRY_MS;

/**
 * Whether a lifetime of `lifetimeMs` from `nowMs` ends at an instant a store
 * can hold. It must also be positive, or — for a wait, where `allowZero` —
 * not negative.
 */
export const isStorableLifetime = (
	lifetimeMs: number,
	options: { readonly allowZero?: boolean; readonly nowMs?: number } = {},
): boolean =>
	Number.isFinite(lifetimeMs) &&
	(options.allowZero === true ? lifetimeMs >= 0 : lifetimeMs > 0) &&
	isStorableExpiry((options.nowMs ?? Date.now()) + lifetimeMs);
