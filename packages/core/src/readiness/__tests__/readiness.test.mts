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

	it("runs probes concurrently so total latency is bounded by the slowest", async () => {
		const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
		const started = Date.now();

		const report = await runReadinessProbes(
			[
				{ name: "a", check: () => delay(40) },
				{ name: "b", check: () => delay(40) },
				{ name: "c", check: () => delay(40) },
			],
			{ timeoutMs: 500 },
		);

		expect(report.ready).toBe(true);
		// Sequential execution would need ~120ms; allow generous headroom.
		expect(Date.now() - started).toBeLessThan(110);
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

	it("does not leave a pending timer behind after a probe resolves", async () => {
		// A timer left armed keeps the event loop alive; on a probe running per
		// scrape that is a leak proportional to probe rate.
		const clearSpy = vi.spyOn(globalThis, "clearTimeout");
		const before = clearSpy.mock.calls.length;

		await runReadinessProbes([{ name: "redis", check: async () => "PONG" }], { timeoutMs: 100 });

		expect(clearSpy.mock.calls.length).toBeGreaterThan(before);
		clearSpy.mockRestore();
	});
});
