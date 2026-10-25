import { afterEach, describe, expect, it, vi } from "vitest";
import { refusalsOf } from "../../../test/refusals.ts";
import {
	assemble,
	type BuildContext,
	contract,
	defineModule,
	kernelConfig,
	type Probe,
	probes,
} from "../../contract.ts";
import { quietRuntime, recordingLog } from "../../testing.ts";

const single = kernelConfig();

function setUp(list: readonly Probe[]) {
	const recorded = recordingLog();
	let now = 0;
	const runtime = quietRuntime({ clock: { now: () => now }, log: recorded.log });
	let context: BuildContext<unknown> | undefined;
	const asker = defineModule({ name: "asker", takes: [] }, (m) => [
		m.provide(contract<object>("asker")).by((c) => {
			context = c;
			return {};
		}),
	]);
	const contributors = list.map((probe, i) =>
		defineModule({ name: `c${i}`, takes: [] }, (m) => [m.contribute(probes).by(() => probe)]),
	);
	return {
		/** The fields of each warn line so far. */
		get warned() {
			return recorded
				.lines()
				.filter((line) => line.level === "warn")
				.map((line) => line.fields);
		},
		tick: (ms: number) => {
			now += ms;
		},
		app: assemble({ modules: [asker, ...contributors], config: single, runtime }),
		ask: (deadlineMs: number) => {
			if (!context) throw new Error("not built");
			return context.readinessReport(deadlineMs).then((report) => report.answer);
		},
		report: (deadlineMs: number) => {
			if (!context) throw new Error("not built");
			return context.readinessReport(deadlineMs);
		},
	};
}

const passing = (name: string): Probe => ({ name, check: async () => {} });
const never = (name: string, seen: AbortSignal[] = []): Probe => ({
	name,
	check: (signal) =>
		new Promise<void>((_, reject) => {
			seen.push(signal);
			signal.addEventListener("abort", () => reject(new Error("aborted at 10.0.0.1")));
		}),
});

afterEach(() => {
	vi.useRealTimers();
});

describe("readiness", () => {
	it("answers ready with no probes, and when every probe passes", async () => {
		const none = setUp([]);
		await none.app;
		expect(await none.ask(1000)).toBe("ready");
		const two = setUp([passing("a"), passing("b")]);
		await two.app;
		expect(await two.ask(1000)).toBe("ready");
	});

	it("answers unready on one failure, having started every check", async () => {
		const started: string[] = [];
		const s = setUp([
			{
				name: "down",
				check: async () => {
					started.push("down");
					throw new Error("refused by db.internal:6379");
				},
			},
			{ name: "up", check: async () => void started.push("up") },
		]);
		await s.app;
		expect(await s.ask(1000)).toBe("unready");
		expect(started.sort()).toEqual(["down", "up"]);
		expect(s.warned).toEqual([{ probe: "down", outcome: "failed", kind: "Error", ms: 0 }]);
		expect(JSON.stringify(s.warned)).not.toContain("db.internal");
	});

	it("counts a check that throws before it returns a promise as failed", async () => {
		const s = setUp([
			{
				name: "sync",
				check: () => {
					throw new TypeError("at once");
				},
			},
		]);
		await s.app;
		expect(await s.ask(1000)).toBe("unready");
		expect(s.warned).toEqual([{ probe: "sync", outcome: "failed", kind: "TypeError", ms: 0 }]);
	});

	it("answers unready at the deadline, aborts the late check and leaves no timer", async () => {
		vi.useFakeTimers();
		const signals: AbortSignal[] = [];
		const s = setUp([never("slow", signals), passing("fast")]);
		await s.app;
		const answer = s.ask(500);
		s.tick(500);
		await vi.advanceTimersByTimeAsync(499);
		expect(signals[0]?.aborted).toBe(false);
		await vi.advanceTimersByTimeAsync(1);
		expect(await answer).toBe("unready");
		expect(signals[0]?.aborted).toBe(true);
		expect(s.warned).toEqual([{ probe: "slow", outcome: "late", ms: 500 }]);
		expect(vi.getTimerCount()).toBe(0);
		const quick = setUp([passing("a")]);
		await quick.app;
		expect(await quick.ask(500)).toBe("ready");
		expect(vi.getTimerCount()).toBe(0);
	});

	it("does not hold the process open while it waits", async () => {
		const timers = () =>
			process.getActiveResourcesInfo().filter((kind) => kind === "Timeout").length;
		const s = setUp([never("slow")]);
		await s.app;
		const before = timers();
		const answer = s.ask(50);
		expect(timers()).toBe(before);
		expect(await answer).toBe("unready");
	});

	it("joins a check still running instead of starting another, and starts anew once it settles", async () => {
		let runs = 0;
		let release = () => {};
		const s = setUp([
			{
				name: "once",
				check: () => {
					runs++;
					return new Promise<void>((resolve) => (release = resolve));
				},
			},
		]);
		await s.app;
		const first = s.ask(1000);
		const second = s.ask(1000);
		await Promise.resolve();
		release();
		expect([await first, await second, runs]).toEqual(["ready", "ready", 1]);
		const third = s.ask(1000);
		await Promise.resolve();
		release();
		expect([await third, runs]).toEqual(["ready", 2]);
	});

	it("answers each caller by its own deadline, the shared check running on for a later one", async () => {
		vi.useFakeTimers();
		const signals: AbortSignal[] = [];
		const s = setUp([
			{
				name: "slow",
				check: (signal) =>
					new Promise<void>((resolve, reject) => {
						signals.push(signal);
						signal.addEventListener("abort", () => reject(new Error("aborted")));
						setTimeout(resolve, 200);
					}),
			},
		]);
		await s.app;
		const short = s.ask(100);
		const long = s.ask(5000);
		await vi.advanceTimersByTimeAsync(100);
		expect([await short, signals.length, signals[0]?.aborted]).toEqual(["unready", 1, false]);
		await vi.advanceTimersByTimeAsync(100);
		expect(await long).toBe("ready");
	});

	it("aborts a shared check only once no caller waits for it", async () => {
		vi.useFakeTimers();
		const signals: AbortSignal[] = [];
		const s = setUp([never("slow", signals)]);
		await s.app;
		const first = s.ask(100);
		const second = s.ask(300);
		await vi.advanceTimersByTimeAsync(100);
		expect([await first, signals[0]?.aborted]).toEqual(["unready", false]);
		await vi.advanceTimersByTimeAsync(200);
		expect([await second, signals[0]?.aborted]).toEqual(["unready", true]);
	});

	it("leaves no unhandled rejection from a check that fails after everyone stopped waiting", async () => {
		let fail = () => {};
		const s = setUp([
			{
				name: "later",
				check: () => new Promise<void>((_, reject) => (fail = () => reject(new Error("late")))),
			},
		]);
		await s.app;
		expect(await s.ask(1)).toBe("unready");
		const unhandled: unknown[] = [];
		const listener = (reason: unknown) => unhandled.push(reason);
		process.on("unhandledRejection", listener);
		try {
			fail();
			await new Promise((resolve) => setTimeout(resolve, 10));
			expect(unhandled).toEqual([]);
		} finally {
			process.off("unhandledRejection", listener);
		}
	});

	it("answers unready without checking once stop begins", async () => {
		let runs = 0;
		const s = setUp([{ name: "a", check: async () => void runs++ }]);
		const app = await s.app;
		await app.stop(1000);
		expect([await s.ask(1000), runs]).toEqual(["unready", 0]);
	});

	it("reports each probe by name, in contribution order, from the run it joins", async () => {
		let runs = 0;
		let release = () => {};
		const s = setUp([
			{
				name: "store",
				check: () => {
					runs++;
					return new Promise<void>((resolve) => (release = resolve));
				},
			},
			{
				name: "cache",
				check: async () => {
					throw new Error("down");
				},
			},
		]);
		await s.app;
		const answer = s.ask(1000);
		const report = s.report(1000);
		await Promise.resolve();
		release();
		expect([await answer, await report, runs]).toEqual([
			"unready",
			{
				answer: "unready",
				probes: [
					{ name: "store", up: true },
					{ name: "cache", up: false },
				],
			},
			1,
		]);
		expect(Object.isFrozen(await s.report(1000))).toBe(true);
	});

	it("reports a late probe down, and with no probes, ready and none", async () => {
		const s = setUp([never("slow"), passing("fast")]);
		await s.app;
		expect(await s.report(10)).toEqual({
			answer: "unready",
			probes: [
				{ name: "slow", up: false },
				{ name: "fast", up: true },
			],
		});
		const none = setUp([]);
		await none.app;
		expect(await none.report(10)).toEqual({ answer: "ready", probes: [] });
	});

	it("reports every probe down without checking once stop begins", async () => {
		let runs = 0;
		const s = setUp([
			{ name: "a", check: async () => void runs++ },
			{ name: "b", check: async () => void runs++ },
		]);
		const app = await s.app;
		await app.stop(1000);
		expect([await s.report(1000), runs]).toEqual([
			{
				answer: "unready",
				probes: [
					{ name: "a", up: false },
					{ name: "b", up: false },
				],
			},
			0,
		]);
	});

	it("refuses a deadline that is no whole number from 1 to 2^31-1", async () => {
		const s = setUp([]);
		await s.app;
		for (const bad of [0, -1, 1.5, Number.NaN, 2 ** 31]) {
			const asked = s.ask(bad);
			await expect(asked).rejects.toThrow(TypeError);
		}
		expect(await s.ask(2 ** 31 - 1)).toBe("ready");
	});

	it("refuses two probes with the same name at boot", async () => {
		const refusals = await refusalsOf(setUp([passing("redis"), passing("redis")]).app);
		expect(refusals.map((r) => r.where)).toEqual(["probes:redis"]);
	});

	it("rejects when asked during assembly, and after a refused assembly", async () => {
		const early = defineModule({ name: "early", takes: [] }, (m) => [
			m.provide(contract<object>("early")).by((c) => c.readinessReport(1000)),
		]);
		expect(await refusalsOf(assemble({ modules: [early], config: single }))).toEqual([
			{ where: "early", reason: "failed during assembly" },
		]);
		let held: BuildContext<unknown> | undefined;
		const holder = defineModule({ name: "holder", takes: [] }, (m) => [
			m.provide(contract<object>("holder")).by((c) => {
				held = c;
				return {};
			}),
		]);
		await refusalsOf(assemble({ modules: [holder, early], config: single }));
		const asked = held?.readinessReport(1000);
		await expect(asked).rejects.toThrow("before assembly is done");
	});
});
