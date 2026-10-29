import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { refusalsOf } from "../../../test/refusals.ts";
import { assemble, contract, defineModule, kernelConfig } from "../../contract.ts";
import { quietRuntime, recordingLog } from "../../testing.ts";

const single = kernelConfig();

describe("every", () => {
	const probe = contract<object>("probe");
	const recorded = recordingLog();
	let from = 0;
	/** The events warned since this test began. */
	const warned = () =>
		recorded
			.lines()
			.slice(from)
			.filter((line) => line.level === "warn")
			.map((line) => line.event);
	const runtime = quietRuntime({ log: recorded.log });
	const withTask = (intervalMs: number, task: (signal: AbortSignal) => Promise<void>) =>
		defineModule({ name: "p", replicaSafe: false, takes: [] }, (m) => [
			m.provide(probe).by((c) => {
				c.every(intervalMs, task);
				return {};
			}),
		]);

	beforeEach(() => {
		from = recorded.lines().length;
		vi.useFakeTimers();
	});
	afterEach(() => {
		vi.useRealTimers();
	});

	it("logs a task that throws before it returns a promise, as one that rejects, and runs it again", async () => {
		let runs = 0;
		const app = await assemble({
			modules: [
				withTask(100, () => {
					runs++;
					throw new Error("at once");
				}),
			],
			config: single,
			runtime,
		});
		await app.start();
		await vi.advanceTimersByTimeAsync(200);
		expect([runs, warned()]).toEqual([2, ["kernel.every_failed", "kernel.every_failed"]]);
		await app.stop(1000);
	});

	it("runs a task on its interval only once started, never two runs at once, and on after a failure", async () => {
		let runs = 0;
		let release = () => {};
		const app = await assemble({
			modules: [
				withTask(100, async () => {
					runs++;
					if (runs === 1) throw new Error("once");
					if (runs === 2) await new Promise<void>((resolve) => (release = resolve));
				}),
			],
			config: single,
			runtime,
		});
		await vi.advanceTimersByTimeAsync(500);
		expect(runs).toBe(0);
		await app.start();
		await vi.advanceTimersByTimeAsync(100);
		expect([runs, warned()]).toEqual([1, ["kernel.every_failed"]]);
		await vi.advanceTimersByTimeAsync(500);
		expect(runs).toBe(2);
		release();
		await vi.advanceTimersByTimeAsync(100);
		expect(runs).toBe(3);
		await app.stop(1000);
	});

	it("aborts the running run on stop and waits for it", async () => {
		const seen: string[] = [];
		const app = await assemble({
			modules: [
				withTask(
					100,
					(signal) =>
						new Promise<void>((resolve) => {
							seen.push("running");
							// The run takes a while to wind down once aborted, so stop has to wait for it.
							signal.addEventListener("abort", () => {
								seen.push("aborted");
								setTimeout(() => {
									seen.push("ended");
									resolve();
								}, 50);
							});
						}),
				),
			],
			config: single,
			runtime,
		});
		await app.start();
		await vi.advanceTimersByTimeAsync(100);
		const stopped = app.stop(1000).then(() => seen.push("stopped"));
		await vi.advanceTimersByTimeAsync(10);
		expect(seen).toEqual(["running", "aborted"]);
		await vi.advanceTimersByTimeAsync(50);
		await stopped;
		expect(seen).toEqual(["running", "aborted", "ended", "stopped"]);
		await vi.advanceTimersByTimeAsync(1000);
		expect(seen).toEqual(["running", "aborted", "ended", "stopped"]);
	});

	it.each([0, -1, 1.5, 2 ** 31])(
		"refuses the interval %s, no whole number of ms from 1 to 2^31-1",
		async (bad) => {
			const refusals = await refusalsOf(
				assemble({ modules: [withTask(bad, async () => {})], config: single, runtime }),
			);
			expect(refusals.map((r) => r.where)).toContain("p");
		},
	);

	it("takes the longest interval a timer holds", async () => {
		await expect(
			assemble({ modules: [withTask(2 ** 31 - 1, async () => {})], config: single, runtime }),
		).resolves.toBeDefined();
	});
});
