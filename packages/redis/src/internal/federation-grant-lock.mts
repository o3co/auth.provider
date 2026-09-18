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

import { randomBytes } from "node:crypto";
import type { FederationGrantLockResult } from "@o3co/auth-provider-core";

/** What the lock needs from a connection: take it if nobody holds it, and free the one this caller holds. */
export interface FederationGrantLockClient {
	/** `SET key token NX PX ttl`: whether this caller now holds it. */
	tryLock(lockKey: string, token: string, ttlMs: number): Promise<boolean>;
	/** Deletes the key only while its value is still `token`. */
	unlock(lockKey: string, token: string): Promise<void>;
}

export interface FederationGrantLockOptions {
	readonly client: FederationGrantLockClient;
	readonly lockKey: (grantId: string) => string;
	/** How long to leave between attempts. Default 25 ms. */
	readonly pollIntervalMs?: number;
	/**
	 * The monotonic clock, in milliseconds. Default `performance.now`.
	 *
	 * A seam, and only for tests: what `waitedMs` rounds to, and which side of
	 * the deadline an attempt falls on, are differences of one millisecond that
	 * no test can produce on a real clock reliably — and the direction of the
	 * rounding is the difference between a lease that is understated and one
	 * that is overstated.
	 */
	readonly now?: () => number;
}

const DEFAULT_POLL_INTERVAL_MS = 25;
/** 256 bits, base64url: what a release is compared against, and not guessable from the key. */
const TOKEN_BYTES = 32;

const sleep = (ms: number): Promise<void> => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * The lock a refresh holds (#593, D12), over a connection.
 *
 * ## What `waitedMs` is, and why it is measured where it is
 *
 * The lease is spent from the moment the store took the lock, and the
 * acknowledgement's own travel is spent too: core dates the lease at
 * `askedAt + waitedMs` and measures the rest itself. So `waitedMs` is the
 * elapsed time recorded **immediately before the attempt that succeeded was
 * sent** — a conservative lower bound on when the lease began. Including the
 * answer's travel would put the lease later than it started, which is the one
 * direction that is unsafe: two refreshes would present one refresh token.
 *
 * It is measured on `performance.now()` and not on `Date.now()`, which steps
 * when the host's clock is set — a wait reported as negative, or as hours,
 * and core refusing the lease of a lock that was in fact taken at once.
 *
 * ## What it does not do
 *
 * It does not give back a lock it took because the answer was late. That
 * would say `timeout`, which means another holder has it, and core turns that
 * into "serve what is stored, come back later" — so a grant nothing was
 * competing for would go unrefreshed. Core already measures the
 * acknowledgement and refuses to start upstream work once the budget is
 * spent; that decision belongs there, with the whole call in view.
 *
 * It does not retry an attempt whose answer never came. A lock that may or
 * may not have been taken must not be taken again: the TTL is what frees it.
 */
export function createFederationGrantLock(options: FederationGrantLockOptions): {
	acquire(
		grantId: string,
		bounds: { readonly ttlMs: number; readonly waitForMs: number },
	): Promise<FederationGrantLockResult>;
} {
	const { client, lockKey } = options;
	const pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
	const now = options.now ?? (() => performance.now());

	return {
		async acquire(grantId, { ttlMs, waitForMs }) {
			// A TTL of NaN compares as already expired: exclusion would be
			// silently off, and two refreshes would present one refresh token
			// (D12). An infinite one is not a lease.
			if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
				throw new RangeError("acquireRefreshLock: ttlMs must be a positive finite number");
			}
			if (!Number.isFinite(waitForMs) || waitForMs < 0) {
				throw new RangeError("acquireRefreshLock: waitForMs must be a non-negative finite number");
			}
			const key = lockKey(grantId);
			// Rounded up: a fractional millisecond would be a TTL of nothing.
			const ttl = Math.ceil(ttlMs);
			const startedAt = now();
			const deadline = startedAt + waitForMs;
			for (;;) {
				const token = randomBytes(TOKEN_BYTES).toString("base64url");
				// Rounded DOWN to a whole millisecond, as the reference adapter's
				// clock difference already is. Down, because this is a lower bound:
				// rounding up would date the lease later than it began.
				const waitedMs = Math.floor(now() - startedAt);
				if (await client.tryLock(key, token, ttl)) {
					let releasing: Promise<void> | undefined;
					return {
						acquired: true,
						waitedMs,
						release: () => {
							// One request, however many times it is asked for, and its
							// failure is the answer every caller gets: a release that
							// could not be sent is a connection problem, and a second
							// attempt at it could delete a lock the TTL had meanwhile
							// handed to somebody else.
							releasing ??= client.unlock(key, token);
							return releasing;
						},
					};
				}
				// The deadline is looked at before every further attempt is SENT: a
				// lock released between the deadline and the next attempt is not
				// taken, since the caller has given up by then. One check, after
				// the wait — a second one in front of it could only refuse what
				// this one refuses a turn of the event loop later.
				const remaining = deadline - now();
				await sleep(Math.max(0, Math.min(pollIntervalMs, remaining)));
				if (now() >= deadline) return { acquired: false, reason: "timeout" };
			}
		},
	};
}
