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
 * Where work that outlives an answer is kept until a shutdown has waited for
 * it (#593, D12).
 *
 * `retrieveFederationGrantToken` takes a `background(work)` seam and hands it
 * everything it deliberately does not make a caller wait for: letting go of
 * the refresh lock, telling the audit sink what happened, recording a use, and
 * — when the caller was answered at the soft deadline — the refresh itself,
 * which goes on holding the lock until its result is persisted. Every one of
 * those is a write the upstream has already accepted. A process that exits
 * when the last HTTP response is flushed drops the rotated refresh token on
 * the floor, and the next request presents a credential the IdP has retired.
 *
 * So this is one object per application, with three jobs:
 *
 *  - **register** what may outlive an answer, which is core's seam;
 *  - **admit** the requests that have been let in but not answered, because
 *    core has not had the chance to register their tails yet, and an empty
 *    registry does not mean there is nothing to wait for;
 *  - **drain** — refuse new operations, then wait until both are empty.
 *
 * The drain rechecks rather than awaiting one snapshot: finishing work
 * registers further work (a release, then the audit of what it released), so
 * a single `Promise.all` over the set as it stood returns while the tail of a
 * tail is still outstanding.
 *
 * What this is NOT: durable job execution, guaranteed audit delivery, or any
 * protection against SIGKILL. It bounds nothing by itself either — core bounds
 * its own waits, and an adapter whose read can hang needs its own I/O timeout.
 * The host's cleanup budget is what stops a pathological tail from holding a
 * shutdown open; a deployment mounting this package wants at least 45 seconds
 * of it, against a standalone default of ten.
 *
 * ### The one thing a drain cannot wait for
 *
 * Core deliberately keeps ONE thing out of this registry (D12): the wait for a
 * refresh lock that the call gave up on. That wait may never end, and what is
 * handed over here has to settle — so core watches it separately and hands
 * over the RELEASE only if the lock later arrives. When a store is slow enough
 * that the lock arrives after the drain has finished, the release is registered
 * into a registry nobody is waiting for any more.
 *
 * Measured by review, and worth being exact about: the answer was already sent
 * and nothing is lost. What is left behind is a refresh lock nobody released,
 * which stands for its `refreshLockTtlMs` (thirty seconds by default) — and
 * during that window every other replica's `/token` for that grant waits
 * `lockWaitMs` and answers `503 temporarily_unavailable/lock_timeout`. A
 * larger host cleanup allowance does not help, because the drain has already
 * returned. What helps is a store whose lock acquisition is bounded.
 */

/**
 * The per-application registry. Exported so a composition root that mounts the
 * handlers by hand gets the same shutdown contract the module wires up.
 */
export interface FederationGrantBackground {
	/**
	 * Track `work` that may outlive the answer it belongs to. This is the
	 * `background` seam of `RetrieveFederationGrantTokenDeps`.
	 *
	 * Accepted while closing, deliberately: the work a drain is waiting for is
	 * exactly what registers the next piece of it. Accepted AFTER the drain has
	 * finished too, where it is tracked and simply not waited for — an
	 * abandoned lock that arrives late is the case, and refusing it there would
	 * turn "not waited for" into "not released at all".
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
		 * Where work that outlives an answer is kept until a shutdown has
		 * waited for it. One per application; see this file's header for why
		 * it is a component rather than a `lifecycleRegistrar` callback.
		 */
		readonly federationGrantBackground: FederationGrantBackground;
	}
}

/** Whatever happened, it happened; see `drain`'s contract below. */
const swallow = (): undefined => undefined;

export function createFederationGrantBackground(): FederationGrantBackground {
	/**
	 * Both kinds of outstanding thing, as promises: registered work, and one
	 * promise per admitted operation that its release resolves. Holding them
	 * in one set is what lets the drain treat "a request that has not answered"
	 * and "a write that has not landed" as the same question.
	 */
	const pending = new Set<Promise<void>>();
	let closing = false;
	let draining: Promise<void> | undefined;

	const track = (work: Promise<void>): void => {
		// Neither outcome is this registry's to have an opinion about. Core
		// promises what it hands over never rejects and reports its own
		// failures through `report`; a hand-mounted handler has no such
		// discipline, and the answer the tail belongs to was sent long ago, so
		// failing the shutdown over it would be an AggregateError for something
		// nobody is waiting for.
		const entry = work.then(swallow, swallow);
		pending.add(entry);
		// For the process that never shuts down: a provider serving traffic
		// registers a tail per refresh, and a set nothing is ever removed from
		// is a leak. The drain does not depend on this — it forgets what it has
		// awaited itself, for the reason given there.
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
				// Take a batch, wait for it, forget it, and go again while
				// anything new has arrived: see the file header for why one
				// snapshot is not enough.
				//
				// The drain removes what it awaited rather than leaving that to
				// `track`, so that it terminates on its own terms. A loop that
				// re-reads a set nothing removes from would spin on the
				// microtask queue for ever without ever yielding to a timer —
				// a shutdown that hangs rather than fails, which is the worse
				// of the two and the harder one to diagnose.
				for (let batch = [...pending]; batch.length > 0; batch = [...pending]) {
					await Promise.all(batch);
					for (const entry of batch) pending.delete(entry);
				}
			})();
			return draining;
		},
	};
}
