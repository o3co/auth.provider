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
 * The background registry on its own (#593, D12).
 *
 * Core's retrieval hands this everything that may outlive the answer a caller
 * is waiting for: letting go of the refresh lock, telling the audit sink, the
 * record of a use, and — when the caller stopped waiting at the soft deadline
 * — the refresh itself, which goes on holding the lock until its result is
 * persisted. A shutdown that does not wait for those discards a rotated
 * refresh credential that the upstream has already accepted, and the next
 * request presents one the IdP has retired.
 *
 * What this file pins is the registry's own promises. What makes them reach
 * the store's cleanup in the right order is the component wiring, in
 * `lifecycle.test.mts`.
 */

import { describe, expect, it } from "vitest";
import { createFederationGrantBackground } from "#/background.mjs";

/** A promise with its resolver, for holding work open across an assertion. */
function deferred(): { readonly promise: Promise<void>; resolve: () => void } {
	let resolve!: () => void;
	const promise = new Promise<void>((r) => {
		resolve = () => r();
	});
	return { promise, resolve };
}

/** One turn of the event loop — enough for every queued microtask to have run. */
const tick = (): Promise<void> => new Promise((r) => setTimeout(r, 0));

describe("createFederationGrantBackground", () => {
	it("drains work registered before the drain started", async () => {
		const background = createFederationGrantBackground();
		const work = deferred();
		let finished = false;
		background.register(
			work.promise.then(() => {
				finished = true;
			}),
		);

		const drained = background.drain();
		let settled = false;
		void drained.then(() => {
			settled = true;
		});

		await tick();
		expect(settled).toBe(false);
		expect(finished).toBe(false);

		work.resolve();
		await drained;
		expect(finished).toBe(true);
	});

	it("waits for work that finishing work registers, not only for the set it started with", async () => {
		// The shape core actually produces: a refresh's tail lets go of the
		// lock, and only then hands over the audit of what it did. A drain that
		// snapshots the set once and awaits that snapshot returns while the
		// second promise is still outstanding.
		const background = createFederationGrantBackground();
		const first = deferred();
		const second = deferred();
		let tailFinished = false;

		background.register(
			first.promise.then(() => {
				background.register(
					second.promise.then(() => {
						tailFinished = true;
					}),
				);
			}),
		);

		const drained = background.drain();
		first.resolve();
		await tick();
		expect(tailFinished).toBe(false);

		let settled = false;
		void drained.then(() => {
			settled = true;
		});
		await tick();
		expect(settled).toBe(false);

		second.resolve();
		await drained;
		expect(tailFinished).toBe(true);
	});

	it("waits for an admitted operation, which is not a promise it was handed", async () => {
		// A request that has been let in but has not answered yet is work too:
		// core has not had the chance to register its tails, so an empty
		// registry does not mean there is nothing to wait for.
		const background = createFederationGrantBackground();
		const release = background.admit();
		expect(release).toBeTypeOf("function");

		const drained = background.drain();
		let settled = false;
		void drained.then(() => {
			settled = true;
		});
		await tick();
		expect(settled).toBe(false);

		release?.();
		await drained;
		expect(settled).toBe(true);
	});

	it("refuses to admit once closing, and says so rather than throwing", async () => {
		const background = createFederationGrantBackground();
		expect(background.closing).toBe(false);

		const drained = background.drain();
		expect(background.closing).toBe(true);
		expect(background.admit()).toBeUndefined();

		await drained;
		expect(background.admit()).toBeUndefined();
	});

	it("releases an operation once however often the release is called", async () => {
		// The handler's `finally` and an error path can both run it. A release
		// that decremented twice would let the drain return while a sibling
		// operation is still open.
		const background = createFederationGrantBackground();
		const first = background.admit();
		const second = background.admit();

		first?.();
		first?.();

		const drained = background.drain();
		let settled = false;
		void drained.then(() => {
			settled = true;
		});
		await tick();
		expect(settled).toBe(false);

		second?.();
		await drained;
		expect(settled).toBe(true);
	});

	it("is idempotent: a second drain is the first one, not a second wait", async () => {
		const background = createFederationGrantBackground();
		const work = deferred();
		background.register(work.promise);

		const first = background.drain();
		const second = background.drain();
		expect(second).toBe(first);

		work.resolve();
		await first;
		// A disposal that runs twice must not reopen anything, and must not
		// wait a second time for work that has already finished.
		await expect(background.drain()).resolves.toBeUndefined();
	});

	it("does not fail a shutdown because a registered tail rejected", async () => {
		// Core promises the work it hands over never rejects, and reports its
		// own failures through `report`. A hand-mounted handler has no such
		// discipline, and the answer that tail belongs to was sent long ago:
		// failing `dispose()` over it would turn a graceful shutdown into an
		// AggregateError for something no caller is waiting for.
		const background = createFederationGrantBackground();
		background.register(Promise.reject(new Error("tail failed")));

		await expect(background.drain()).resolves.toBeUndefined();
	});
});
