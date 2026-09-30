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
 * Keeps work that outlives an answer until a shutdown has waited for it.
 *
 * `retrieveFederationGrantToken` hands its `background(work)` seam what it does
 * not make a caller wait for: the refresh-lock release, the audit event, the use
 * record and, when the caller was answered at the soft deadline, the refresh
 * itself. Each is a write the upstream already accepted; a process that exits
 * before it lands loses the rotated refresh token, and the next request presents
 * a credential the IdP has retired.
 *
 * One registry per application: `register` tracks tails, `admit` tracks requests
 * let in but not yet answered (their tails are not registered yet), and `drain`
 * refuses new operations and waits until both are empty. The drain rechecks
 * because settling work registers more work (a release, then its audit).
 *
 * Not durable, no delivery guarantee, no SIGKILL protection, and it bounds
 * nothing: the host's cleanup budget does. An enabled deployment registers the
 * drain's tail with the lifecycle registrar ({@link federationGrantsCleanupTailMs}),
 * which `AppHandle.cleanupAllowanceMs` reports to the host.
 *
 * A lock wait the call gave up on is kept out, because it may never settle; core
 * registers only the release, if the lock arrives. If it arrives after the drain
 * has finished, the lock stands for `refreshLockTtlMs` and every replica's
 * `/token` for that grant answers `503 temporarily_unavailable/lock_timeout`
 * meanwhile. Only a store whose lock acquisition is bounded avoids that.
 */

import type { FederationGrantRetrievalLimits } from "@o3co/auth-provider-core";

/**
 * The per-application registry. Exported so a composition root that mounts the
 * handlers by hand gets the same shutdown contract the module wires up.
 */
export interface FederationGrantBackground {
	/**
	 * Track `work` that may outlive its answer: the `background` seam of
	 * `RetrieveFederationGrantTokenDeps`. Accepted while closing (awaited work
	 * registers the next piece) and after the drain (tracked, not awaited), so a
	 * late-arriving abandoned lock is still released.
	 */
	register(work: Promise<void>): void;
	/**
	 * Admit one handler operation, returning the release to run when it has
	 * answered — or `undefined` once the drain has begun, which is the caller's
	 * signal to answer 503 rather than start something a shutdown will not
	 * wait for.
	 */
	admit(): (() => void) | undefined;
	/** Whether the drain has begun. Nothing new is admitted after this is true. */
	readonly closing: boolean;
	/**
	 * Refuse new operations and wait for every admitted operation and
	 * registered promise, including the ones they register while being waited
	 * for. Idempotent: a second call is the first one.
	 */
	drain(): Promise<void>;
}

declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		/**
		 * Work that outlives an answer, kept until a shutdown has waited for it.
		 * One per application. A component, because `AppHandle.dispose()` runs
		 * component cleanups before `lifecycleRegistrar` callbacks, so the drain
		 * finishes before an adapter closes the client a pending write needs.
		 */
		readonly federationGrantBackground: FederationGrantBackground;
	}
}

/** Whatever happened, it happened; see `drain`'s contract below. */
const swallow = (): undefined => undefined;

export function createFederationGrantBackground(): FederationGrantBackground {
	/** Registered work plus one promise per admitted operation, resolved by its release. */
	const pending = new Set<Promise<void>>();
	let closing = false;
	let draining: Promise<void> | undefined;

	const track = (work: Promise<void>): void => {
		// Outcomes are ignored: core reports its own failures, and a rejection from a
		// hand-mounted handler must not fail a shutdown over an answer already sent.
		const entry = work.then(swallow, swallow);
		pending.add(entry);
		// Without this a long-running process leaks one entry per refresh. The drain
		// does not rely on it.
		void entry.then(() => {
			pending.delete(entry);
		});
	};

	return {
		register: track,
		admit: () => {
			if (closing) return undefined;
			let release!: () => void;
			// The executor runs synchronously, so `release` is assigned before
			// `track` — and before this returns.
			track(
				new Promise<void>((resolve) => {
					release = () => resolve();
				}),
			);
			// Resolving twice is resolving once, so a handler whose `finally`
			// and whose error path both release does not free a sibling.
			return release;
		},
		get closing() {
			return closing;
		},
		drain: () => {
			if (draining !== undefined) return draining;
			closing = true;
			draining = (async () => {
				// Repeat until no new work arrived. The drain deletes what it awaited
				// itself: re-reading a set nothing removes from would spin on the
				// microtask queue for ever and hang the shutdown.
				for (let batch = [...pending]; batch.length > 0; batch = [...pending]) {
					await Promise.all(batch);
					for (const entry of batch) pending.delete(entry);
				}
			})();
			return draining;
		},
	};
}

/** The least tail the drain registers: the shipped budgets' tail plus the margin. */
const CLEANUP_FLOOR_MS = 45_000;

/** What the tail adds to one refresh's: room for the cleanups after the drain, and the exit. */
const CLEANUP_MARGIN_MS = 12_000;

/** The longest delay a timer takes; a larger one fires after about a millisecond. */
const MAX_TIMER_MS = 2_147_483_647;

/**
 * The `tailMs` the drain is registered with: one refresh's longest tail (the
 * upstream hard timeout, the persist budget and the wait for the grant's lock,
 * back to back) plus the margin, never below 45 seconds, never past what a
 * timer can wait.
 */
export function federationGrantsCleanupTailMs(
	limits: Pick<
		FederationGrantRetrievalLimits,
		"upstreamHardTimeoutMs" | "persistRetryBudgetMs" | "lockWaitMs"
	>,
): number {
	const tail =
		limits.upstreamHardTimeoutMs +
		limits.persistRetryBudgetMs +
		limits.lockWaitMs +
		CLEANUP_MARGIN_MS;
	return Math.min(Math.max(CLEANUP_FLOOR_MS, tail), MAX_TIMER_MS);
}
