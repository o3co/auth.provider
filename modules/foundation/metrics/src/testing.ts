import { defineModule } from "@mod/kernel";
import { describe, expect, it, vi } from "vitest";
import { metricsBy } from "./build.ts";
import { counter, gauge, type Instrument, type Metrics, metrics } from "./contract.ts";

/** A composition holding the instruments a scene made, as one implementation of the contract does. */
export interface MetricsComposition {
	readonly metrics: Metrics;
	/** The warn lines so far, as event and fields. */
	warned(): readonly (readonly [string, unknown])[];
	/** How long a sample waits on a gauge's read. */
	readonly boundMs: number;
}

/** What every implementation of metrics must do with gauges, as an emitter and a reader see it. */
export function metricsContract(
	name: string,
	open: (made: () => readonly Instrument[]) => Promise<MetricsComposition>,
): void {
	describe(`metrics' contract: ${name}`, () => {
		const up = (read: () => unknown) =>
			gauge({ name: "up", help: "Up.", labels: { part: ["a", "b"] } }, read as never);

		it("reads a gauge only when sampled, giving read none of its series", async () => {
			let reads = 0;
			const c = counter({ name: "c_total", help: "C.", labels: {} });
			const { metrics } = await open(() => [
				c,
				up(() => {
					reads += 1;
					return [
						{ labels: { part: "a" }, value: 1 },
						{ labels: { part: "b" }, value: -0.5 },
					];
				}),
			]);
			c.add({});
			expect(metrics.read()[1]).toEqual({
				kind: "gauge",
				name: "up",
				help: "Up.",
				labels: ["part"],
				series: [],
			});
			expect(reads).toBe(0);
			const sampled = await metrics.sample();
			expect(reads).toBe(1);
			expect(sampled[0]).toEqual(metrics.read()[0]);
			expect(sampled[1]?.series).toEqual([
				{ labels: { part: "a" }, value: 1 },
				{ labels: { part: "b" }, value: -0.5 },
			]);
			expect(Object.isFrozen(sampled[1]?.series[0])).toBe(true);
		});

		it("gives a gauge no series, warning by name, when its read fails or is unfit", async () => {
			const fails: (() => unknown)[] = [
				() => {
					throw new Error("zq9 secret");
				},
				async () => Promise.reject(new Error("zq9 secret")),
				() => "zq9",
				() => [{ labels: { part: "zq9" }, value: 1 }],
				() => [{ labels: { part: "a", extra: "zq9" }, value: 1 }],
				() => [{ labels: { part: "a" }, value: Number.NaN }],
				() => [{ labels: { part: "a" }, value: "1" }],
				() => [
					{ labels: { part: "a" }, value: 1 },
					{ labels: { part: "a" }, value: 0 },
				],
			];
			for (const read of fails) {
				const opened = await open(() => [up(read)]);
				expect((await opened.metrics.sample())[0]?.series).toEqual([]);
				expect(opened.warned()).toHaveLength(1);
				expect(opened.warned()[0]?.[0]).toBe("metrics.unread");
				expect(JSON.stringify(opened.warned())).not.toContain("zq9");
			}
		});

		it("warns why: failed, unfit, or late after its bound, each time it reads", async () => {
			const opened = await open(() => [
				up(() => {
					throw new Error("no");
				}),
				gauge({ name: "odd", help: "", labels: {} }, (() => [
					{ labels: { x: "1" }, value: 1 },
				]) as never),
				gauge({ name: "slow", help: "", labels: {} }, () => new Promise(() => {})),
				gauge({ name: "fine", help: "", labels: {} }, () => [{ labels: {}, value: 3 }]),
			]);
			vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
			try {
				for (let i = 0; i < 2; i++) {
					const sampling = opened.metrics.sample();
					await vi.advanceTimersByTimeAsync(opened.boundMs);
					const sampled = await sampling;
					expect(sampled.map((r) => r.series.length)).toEqual([0, 0, 0, 1]);
				}
			} finally {
				vi.useRealTimers();
			}
			const once = [
				["metrics.unread", { instrument: "up", why: "failed" }],
				["metrics.unread", { instrument: "odd", why: "unfit" }],
				["metrics.unread", { instrument: "slow", why: "late" }],
			];
			expect(opened.warned()).toEqual([...once, ...once]);
		});
	});
}

/**
 * Metrics decided by the same rules as the module, reading each gauge within `boundMs`, so a test
 * sees a late read without waiting for the module's bound.
 */
export function metricsStandIn(boundMs: number) {
	return defineModule({ name: "metrics", replicaSafe: true }, (m) => [
		m.provide(metrics).by(metricsBy(boundMs)),
	]);
}
