import { assemble, BootRefused, defineModule, kernelConfig } from "@mod/kernel";
import { quietRuntime, recordingLog, takesUnused } from "@mod/kernel/testing";
import { describe, expect, it } from "vitest";
import {
	counter,
	gauge,
	histogram,
	type Instrument,
	instruments,
	type Metrics,
	metrics,
} from "../src/contract.ts";
import metricsModule from "../src/module.ts";
import { metricsStandIn } from "../src/testing.ts";

function runtime() {
	const recorded = recordingLog();
	const quiet = quietRuntime({
		clock: { now: () => 0 },
		random: { bytes: (n) => new Uint8Array(n) },
		log: recorded.log,
	});
	/** The warn lines so far, as event and fields. */
	const warned = () =>
		recorded
			.lines()
			.filter((line) => line.level === "warn")
			.map((line) => [line.event, line.fields]);
	return { quiet, warned };
}

const emitter = (made: () => readonly Instrument[]) =>
	defineModule({ name: "emitter", takes: [] }, (m) =>
		made().map((i) => m.contribute(instruments).by(() => i)),
	);

async function boot(made: () => readonly Instrument[], quiet = runtime().quiet): Promise<Metrics> {
	const app = await assemble({
		modules: [metricsModule, emitter(made)],
		config: kernelConfig(),
		runtime: quiet,
	});
	return app.get(metrics);
}

async function refusals(made: () => readonly Instrument[]): Promise<string[]> {
	const error = await boot(made).catch((e: unknown) => e);
	expect(error).toBeInstanceOf(BootRefused);
	return (error as BootRefused).refusals.map((r) => `${r.where}: ${r.reason}`);
}

const requests = () =>
	counter({ name: "requests_total", help: "Requests.", labels: { outcome: ["ok", "failed"] } });
const durations = () =>
	histogram({
		name: "duration_seconds",
		help: "Durations.",
		labels: { route: ["/a", "/b"] },
		buckets: [0.1, 1],
	});

describe("recording", () => {
	it("adds to a counter by series, and freezes what it read", async () => {
		const c = requests();
		const m = await boot(() => [c]);
		c.add({ outcome: "ok" });
		c.add({ outcome: "ok" }, 2);
		c.add({ outcome: "failed" }, 0);
		const read = m.read();
		c.add({ outcome: "ok" });
		expect(read).toEqual([
			{
				kind: "counter",
				name: "requests_total",
				help: "Requests.",
				labels: ["outcome"],
				series: [
					{ labels: { outcome: "ok" }, value: 3 },
					{ labels: { outcome: "failed" }, value: 0 },
				],
			},
		]);
		expect(Object.isFrozen(read[0])).toBe(true);
		expect(m.read()[0]?.series[0]).toEqual({ labels: { outcome: "ok" }, value: 4 });
	});

	it("keeps a histogram's counts cumulative per bucket, with the last for all", async () => {
		const h = durations();
		const m = await boot(() => [h]);
		for (const value of [0.05, 0.1, 0.5, 3]) h.observe({ route: "/a" }, value);
		const read = m.read();
		h.observe({ route: "/a" }, 0.05);
		expect(read).toEqual([
			{
				kind: "histogram",
				name: "duration_seconds",
				help: "Durations.",
				labels: ["route"],
				buckets: [0.1, 1],
				series: [{ labels: { route: "/a" }, counts: [2, 3, 4], sum: 3.65, count: 4 }],
			},
		]);
	});

	it("drops a value outside the declared set, a missing or extra label, and a bad number", async () => {
		const { quiet, warned } = runtime();
		const c = requests();
		const h = durations();
		const bare = counter({ name: "bare_total", help: "", labels: {} });
		const m = await boot(() => [c, h, bare], quiet);
		c.add({ outcome: "/some/request/path" } as never);
		c.add(Object.assign(Object.create({ outcome: "ok" }), { other: "ok" }));
		bare.add("" as never);
		bare.add(5 as never);
		c.add({} as never);
		c.add({ outcome: "ok", extra: "x" } as never);
		c.add(null as never);
		c.add({ outcome: "ok" }, -1);
		c.add({ outcome: "ok" }, Number.NaN);
		c.add({ outcome: "ok" }, Number.POSITIVE_INFINITY);
		h.observe({ route: "/a" }, Number.NaN);
		h.observe({ route: "/c" } as never, 1);
		expect(m.read().map((r) => r.series)).toEqual([[], [], []]);
		// Once per instrument, naming it only, never the value dropped.
		expect(warned()).toEqual([
			["metrics.dropped", { instrument: "requests_total" }],
			["metrics.dropped", { instrument: "bare_total" }],
			["metrics.dropped", { instrument: "duration_seconds" }],
		]);
	});

	it("keeps the label values and buckets as made, whatever the emitter changes after", async () => {
		const outcomes = ["ok"];
		const buckets = [1];
		const c = counter({ name: "a_total", help: "", labels: { outcome: outcomes } });
		const h = histogram({ name: "b", help: "", labels: {}, buckets });
		outcomes.push("other");
		buckets.unshift(0.5);
		const m = await boot(() => [c, h]);
		c.add({ outcome: "other" } as never);
		h.observe({}, 0.1);
		expect(m.read()).toMatchObject([
			{ series: [] },
			{ buckets: [1], series: [{ counts: [1, 1] }] },
		]);
	});

	it("throws nothing without metrics, and keeps nothing recorded before metrics collects", async () => {
		const c = requests();
		c.add({ outcome: "ok" });
		await assemble({
			modules: [emitter(() => [c])],
			config: kernelConfig(),
			runtime: runtime().quiet,
		});
		c.add({ outcome: "ok" });
		const later = requests();
		later.add({ outcome: "ok" });
		const m = await boot(() => [later]);
		expect(m.read()[0]?.series).toEqual([]);
	});

	it("keeps each assembly's counts apart", async () => {
		const first = await boot(() => [requests()]);
		const mine = requests();
		const second = await boot(() => [mine]);
		mine.add({ outcome: "ok" });
		expect(first.read()[0]?.series).toEqual([]);
		expect(second.read()[0]?.series).toEqual([{ labels: { outcome: "ok" }, value: 1 }]);
	});
});

describe("sampling", () => {
	it("finds a gauge's read that gives no list unfit, not failed", async () => {
		const { quiet, warned } = runtime();
		const up = gauge({ name: "up", help: "", labels: {} }, (() => 5) as never);
		const m = await boot(() => [up], quiet);
		expect((await m.sample())[0]?.series).toEqual([]);
		expect(warned()).toEqual([["metrics.unread", { instrument: "up", why: "unfit" }]]);
	});
});

describe("refusals at boot", () => {
	it("refuses a name or a label name outside [a-z][a-z0-9_]*, naming the instrument", async () => {
		expect(await refusals(() => [counter({ name: "Requests", help: "", labels: {} })])).toEqual([
			"metrics.instruments:Requests: the name is not [a-z][a-z0-9_]*",
		]);
		expect(
			await refusals(() => [counter({ name: "a", help: "", labels: { "bad-name": ["x"] } })]),
		).toEqual(["metrics.instruments:a: a label name is not [a-z][a-z0-9_]*"]);
	});

	it("refuses a name that is not a string", async () => {
		expect(
			await refusals(() => [counter({ name: undefined as never, help: "", labels: {} })]),
		).toEqual(["metrics.instruments:undefined: the name is not [a-z][a-z0-9_]*"]);
	});

	it("refuses help that is not a string, naming the instrument", async () => {
		expect(
			await refusals(() => [
				counter({ name: "a", help: undefined as never, labels: {} }),
				histogram({ name: "b", help: 1 as never, labels: {}, buckets: [1] }),
				gauge({ name: "c", help: null as never, labels: {} }, () => []),
			]),
		).toEqual(["a", "b", "c"].map((n) => `metrics.instruments:${n}: the help is not a string`));
	});

	it("refuses label values that are not a list of distinct strings, at least one", async () => {
		expect(
			await refusals(() => [
				counter({ name: "a", help: "", labels: { x: [] } }),
				counter({ name: "b", help: "", labels: { y: ["1", "1"] } }),
				counter({ name: "c", help: "", labels: { z: "ok" as never } }),
				counter({ name: "d", help: "", labels: { w: [1 as never] } }),
			]),
		).toEqual([
			"metrics.instruments:a: the label x needs distinct string values, at least one",
			"metrics.instruments:b: the label y needs distinct string values, at least one",
			"metrics.instruments:c: the label z needs distinct string values, at least one",
			"metrics.instruments:d: the label w needs distinct string values, at least one",
		]);
	});

	it("refuses buckets that are none, not increasing, or not finite", async () => {
		const made = (name: string, buckets: unknown) =>
			histogram({ name, help: "", labels: {}, buckets: buckets as number[] });
		expect(
			await refusals(() => [
				made("a", []),
				made("b", [1, 1]),
				made("c", [2, 1]),
				made("d", [1, Number.POSITIVE_INFINITY]),
				made("e", undefined),
			]),
		).toEqual(
			["a", "b", "c", "d", "e"].map(
				(n) => `metrics.instruments:${n}: the buckets are not finite and strictly increasing`,
			),
		);
	});

	it("refuses two instruments of one name", async () => {
		expect(await refusals(() => [requests(), requests()])).toEqual([
			"metrics.instruments:requests_total: more than one contribution for the same key",
		]);
	});

	it("refuses an instrument another assembly has, and one not made by counter or histogram", async () => {
		const shared = requests();
		await boot(() => [shared]);
		const reason = "not made by counter, histogram or gauge, or made for another assembly";
		expect(await refusals(() => [shared])).toEqual([
			`metrics.instruments:requests_total: ${reason}`,
		]);
		const handMade: Instrument = { kind: "counter", spec: requests().spec, add: () => {} };
		expect(await refusals(() => [handMade])).toEqual([
			`metrics.instruments:requests_total: ${reason}`,
		]);
	});

	it("refuses a gauge another assembly has, or one whose name is outside [a-z][a-z0-9_]*", async () => {
		const up = gauge({ name: "up", help: "", labels: {} }, () => []);
		await boot(() => [up]);
		expect(
			await refusals(() => [up, gauge({ name: "Up", help: "", labels: {} }, () => [])]),
		).toEqual(["metrics.instruments:Up: the name is not [a-z][a-z0-9_]*"]);
		expect(await refusals(() => [up])).toEqual([
			"metrics.instruments:up: not made by counter, histogram or gauge, or made for another assembly",
		]);
	});
});

it("takes every handle its takes name, the module and its stand-in alike", async () => {
	for (const module of [metricsModule, metricsStandIn(10)]) {
		expect(await takesUnused({ modules: [module], config: kernelConfig() })).toEqual({});
	}
});
