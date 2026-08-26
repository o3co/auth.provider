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

import { describe, expect, it, vi } from "vitest";
import { createReadinessRegistrar } from "#/readiness/registrar.mjs";
import { runReadinessProbes } from "#/readiness/run.mjs";

describe("createReadinessRegistrar", () => {
	it("returns registered probes in registration order", () => {
		const registrar = createReadinessRegistrar();
		registrar.register({ name: "redis", check: async () => "PONG" });
		registrar.register({ name: "session-store", check: async () => "PONG" });

		expect(registrar._probes().map((p) => p.name)).toEqual(["redis", "session-store"]);
	});
});

describe("runReadinessProbes", () => {
	it("reports ready with no probes registered", async () => {
		const report = await runReadinessProbes([], { timeoutMs: 100 });

		expect(report.ready).toBe(true);
		expect(report.checks).toEqual([]);
	});

	it("reports ready when every probe resolves", async () => {
		const report = await runReadinessProbes(
			[
				{ name: "redis", check: async () => "PONG" },
				{ name: "session-store", check: async () => "PONG" },
			],
			{ timeoutMs: 100 },
		);

		expect(report.ready).toBe(true);
		expect(report.checks.map((c) => c.ok)).toEqual([true, true]);
	});

	it("reports not-ready and names the failing dependency", async () => {
		const report = await runReadinessProbes(
			[
				{ name: "redis", check: async () => "PONG" },
				{
					name: "session-store",
					check: async () => {
						throw new Error("ECONNREFUSED");
					},
				},
			],
			{ timeoutMs: 100 },
		);

		expect(report.ready).toBe(false);
		expect(report.checks.find((c) => c.name === "redis")?.ok).toBe(true);
		const failed = report.checks.find((c) => c.name === "session-store");
		expect(failed?.ok).toBe(false);
		expect(failed?.error).toContain("ECONNREFUSED");
	});

	it("fails a probe that hangs past the timeout instead of hanging with it", async () => {
		// A partitioned Redis does not refuse the connection — it accepts the
		// command and never answers. Without a deadline the probe inherits that
		// silence and the readiness endpoint stops responding, which reads to an
		// orchestrator as a slow pod rather than an unready one.
		const report = await runReadinessProbes(
			[{ name: "redis", check: () => new Promise(() => {}) }],
			{ timeoutMs: 20 },
		);

		expect(report.ready).toBe(false);
		expect(report.checks[0]?.ok).toBe(false);
		expect(report.checks[0]?.error).toContain("timed out");
	});

	it("runs probes concurrently rather than one after another", async () => {
		// Asserted by overlap, not by wall-clock: all three probes must be
		// in flight at the same moment. A duration bound would be a coin flip
		// under CI load.
		let inFlight = 0;
		let peak = 0;
		const release: Array<() => void> = [];
		const probe = (name: string) => ({
			name,
			check: () =>
				new Promise<void>((resolve) => {
					inFlight++;
					peak = Math.max(peak, inFlight);
					release.push(() => {
						inFlight--;
						resolve();
					});
				}),
		});

		const pending = runReadinessProbes([probe("a"), probe("b"), probe("c")], {
			timeoutMs: 500,
		});
		await Promise.resolve();
		expect(peak).toBe(3);

		for (const r of release) r();
		expect((await pending).ready).toBe(true);
	});

	it("keeps one failing probe from masking the others", async () => {
		const report = await runReadinessProbes(
			[
				{
					name: "a",
					check: async () => {
						throw new Error("down");
					},
				},
				{ name: "b", check: async () => "PONG" },
			],
			{ timeoutMs: 100 },
		);

		expect(report.checks.map((c) => `${c.name}:${c.ok}`)).toEqual(["a:false", "b:true"]);
	});

	it("joins an in-flight check instead of issuing a second one", async () => {
		// Abandoning a check at the deadline does not cancel it: against a
		// partitioned Redis the driver holds the PING in its offline queue until
		// reconnect, so an un-coalesced endpoint accumulates one pending command
		// per scrape and releases them as a burst on recovery.
		const check = vi.fn(() => new Promise(() => {}));
		const inFlight = new Map<string, Promise<unknown>>();
		const probes = [{ name: "redis", check }];

		await runReadinessProbes(probes, { timeoutMs: 10, inFlight });
		await runReadinessProbes(probes, { timeoutMs: 10, inFlight });
		await runReadinessProbes(probes, { timeoutMs: 10, inFlight });

		expect(check).toHaveBeenCalledTimes(1);
		expect(inFlight.size).toBe(1);
	});

	it("starts a fresh check once the previous one settles", async () => {
		// The join must not turn into a cached verdict — readiness is a question
		// about now.
		const check = vi.fn(async () => "PONG");
		const inFlight = new Map<string, Promise<unknown>>();
		const probes = [{ name: "redis", check }];

		await runReadinessProbes(probes, { timeoutMs: 100, inFlight });
		await runReadinessProbes(probes, { timeoutMs: 100, inFlight });

		expect(check).toHaveBeenCalledTimes(2);
		expect(inFlight.size).toBe(0);
	});

	it("does not surface an unhandled rejection when every waiter has timed out", async () => {
		// The shared promise outlives its waiters; whoever rejects last must not
		// take the process down.
		const unhandled: unknown[] = [];
		const onUnhandled = (reason: unknown) => unhandled.push(reason);
		process.on("unhandledRejection", onUnhandled);
		try {
			const inFlight = new Map<string, Promise<unknown>>();
			const probes = [
				{
					name: "redis",
					check: () =>
						new Promise((_resolve, reject) =>
							setTimeout(() => reject(new Error("late ECONNRESET")), 30),
						),
				},
			];

			const report = await runReadinessProbes(probes, { timeoutMs: 5, inFlight });
			expect(report.ready).toBe(false);

			await new Promise((resolve) => setTimeout(resolve, 60));
			expect(unhandled).toEqual([]);
		} finally {
			process.off("unhandledRejection", onUnhandled);
		}
	});

	it("describes a non-Error rejection without losing it", async () => {
		// Drivers do not always reject with an Error — a string or a plain object
		// is common enough, and the endpoint must still name the failure.
		const report = await runReadinessProbes(
			[{ name: "redis", check: () => Promise.reject("CONNECTION_BROKEN") }],
			{ timeoutMs: 100 },
		);

		expect(report.ready).toBe(false);
		expect(report.checks[0]?.error).toBe("CONNECTION_BROKEN");
	});

	it("does not evict a newer check when a slower predecessor settles", async () => {
		// The in-flight entry is keyed by probe name, so a late settle must clear
		// only its own entry — otherwise it would drop the check a subsequent
		// scrape had already started, and that scrape's successor would issue a
		// duplicate command.
		let release: (() => void) | undefined;
		const slow = new Promise<void>((resolve) => {
			release = resolve;
		});
		const inFlight = new Map<string, Promise<unknown>>();
		const probes = [{ name: "redis", check: () => slow }];

		// First scrape times out; `slow` stays in the map.
		await runReadinessProbes(probes, { timeoutMs: 5, inFlight });
		expect(inFlight.get("redis")).toBe(slow);

		// A newer entry lands under the same name.
		const newer = Promise.resolve("PONG");
		inFlight.set("redis", newer);

		release?.();
		await slow;
		await Promise.resolve();

		expect(inFlight.get("redis")).toBe(newer);
	});

	it("leaves no armed timer behind after a probe resolves", async () => {
		// A timer left armed keeps the event loop alive; on an endpoint scraped
		// every few seconds that is a leak proportional to probe rate, and it
		// delays process exit at shutdown. Asserted on the timer count rather
		// than on clearTimeout being called, so an implementation that avoids
		// the timer entirely also passes.
		vi.useFakeTimers();
		try {
			const before = vi.getTimerCount();
			await runReadinessProbes([{ name: "redis", check: async () => "PONG" }], {
				timeoutMs: 100,
			});
			expect(vi.getTimerCount()).toBe(before);
		} finally {
			vi.useRealTimers();
		}
	});
});
