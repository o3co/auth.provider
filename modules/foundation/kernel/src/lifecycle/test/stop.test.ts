import { afterEach, describe, expect, it, vi } from "vitest";
import { refusalsOf } from "../../../test/refusals.ts";
import { assemble, contract, defineModule, kernelConfig } from "../../contract.ts";
import { quietRuntime, recordingLog } from "../../testing.ts";

const single = kernelConfig();

describe("stop", () => {
	afterEach(() => {
		vi.useRealTimers();
	});
	/** A module whose stop hook does what `hook` does, after noting its name in `order`. */
	const stopping = (
		name: string,
		order: string[],
		hook: (signal: AbortSignal) => Promise<void> | void = () => {},
	) =>
		defineModule({ name, takes: [] }, (m) => [
			m.provide(contract<object>(name)).by((c) => {
				c.onStop((signal) => {
					order.push(name);
					return hook(signal);
				});
				return {};
			}),
		]);

	it("runs the earlier stop hooks when one fails, logging the failure", async () => {
		const order: string[] = [];
		const recorded = recordingLog();
		const app = await assemble({
			modules: [
				stopping("store", order),
				stopping("broken", order, () => {
					throw new Error("at db.internal");
				}),
			],
			config: single,
			runtime: quietRuntime({ log: recorded.log }),
		});
		await app.stop(1000);
		expect(order).toEqual(["broken", "store"]);
		expect(recorded.lines()).toEqual([
			{
				level: "warn",
				event: "kernel.stop_failed",
				fields: { module: "broken", outcome: "failed", kind: "Error" },
			},
		]);
	});

	it("refuses a deadline that is no whole number from 1 to 2^31-1, stopping nothing", async () => {
		const order: string[] = [];
		const app = await assemble({ modules: [stopping("store", order)], config: single });
		for (const bad of [0, -1, 1.5, Number.NaN, 2 ** 31]) {
			await expect(app.stop(bad)).rejects.toThrow(TypeError);
		}
		expect(order).toEqual([]);
		await app.stop(2 ** 31 - 1);
		expect(order).toEqual(["store"]);
	});

	it("stops by kernel.stop-deadline when given no deadline, 30s unless set", async () => {
		vi.useFakeTimers();
		const hung = (signals: AbortSignal[]) =>
			stopping("hung", [], (signal) => {
				signals.push(signal);
				return new Promise<void>(() => {});
			});
		const at = async (config: object, ms: number) => {
			const signals: AbortSignal[] = [];
			const app = await assemble({ modules: [hung(signals)], config });
			const stop = app.stop();
			await vi.advanceTimersByTimeAsync(ms - 1);
			const before = signals[0]?.aborted;
			await vi.advanceTimersByTimeAsync(1);
			await stop;
			return [before, signals[0]?.aborted];
		};
		expect(await at(single, 30_000)).toEqual([false, true]);
		expect(await at(kernelConfig({ "stop-deadline": "5s" }), 5_000)).toEqual([false, true]);
		expect(await at({ kernel: { deployment: "single", "stop-deadline": "7s" } }, 7_000)).toEqual([
			false,
			true,
		]);
	});

	it("refuses a stop-deadline without its unit, or not whole seconds from 1s to 1h", async () => {
		for (const bad of ["0s", "3601s", "1500ms", 30, "30", "x", true]) {
			const refusals = await refusalsOf(
				assemble({
					modules: [],
					config: { kernel: { deployment: "single", "stop-deadline": bad } },
				}),
			);
			expect(refusals.map((r) => r.where)).toEqual(["kernel.stop-deadline"]);
		}
	});

	it("calls the hooks left at the deadline with the aborted signal, without waiting for them", async () => {
		vi.useFakeTimers();
		const order: string[] = [];
		const signals: AbortSignal[] = [];
		const hang = (signal: AbortSignal) => {
			signals.push(signal);
			return new Promise<void>(() => {});
		};
		const app = await assemble({
			modules: [stopping("first", order, hang), stopping("last", order, hang)],
			config: single,
			runtime: quietRuntime(),
		});
		let stopped = false;
		const stop = app.stop(500).then(() => {
			stopped = true;
		});
		await vi.advanceTimersByTimeAsync(500);
		await stop;
		expect([stopped, order]).toEqual([true, ["last", "first"]]);
		expect(signals.map((signal) => signal.aborted)).toEqual([true, true]);
	});

	it("runs the stop hooks only once the periodic tasks have ended", async () => {
		vi.useFakeTimers();
		const seen: string[] = [];
		const app = await assemble({
			modules: [
				defineModule({ name: "p", takes: [] }, (m) => [
					m.provide(contract<object>("p")).by((c) => {
						c.every(100, (signal) => {
							return new Promise<void>((resolve) => {
								signal.addEventListener("abort", () =>
									setTimeout(() => {
										seen.push("task ended");
										resolve();
									}, 50),
								);
							});
						});
						c.onStop(() => void seen.push("hook"));
						return {};
					}),
				]),
			],
			config: single,
			runtime: quietRuntime(),
		});
		await app.start();
		await vi.advanceTimersByTimeAsync(100);
		const stop = app.stop(1000);
		await vi.advanceTimersByTimeAsync(50);
		await stop;
		expect(seen).toEqual(["task ended", "hook"]);
	});

	it("aborts a hung stop hook at the deadline, and still calls the earlier ones", async () => {
		vi.useFakeTimers();
		const order: string[] = [];
		const signals: AbortSignal[] = [];
		const recorded = recordingLog();
		const app = await assemble({
			modules: [
				stopping("store", order, (signal) => void signals.push(signal)),
				stopping("hung", order, (signal) => {
					signals.push(signal);
					return new Promise<void>(() => {});
				}),
			],
			config: single,
			runtime: quietRuntime({ log: recorded.log }),
		});
		let stopped = false;
		const stop = app.stop(500).then(() => {
			stopped = true;
		});
		await vi.advanceTimersByTimeAsync(499);
		expect([stopped, order, signals[0]?.aborted]).toEqual([false, ["hung"], false]);
		await vi.advanceTimersByTimeAsync(1);
		await stop;
		expect(order).toEqual(["hung", "store"]);
		expect(signals.map((signal) => signal.aborted)).toEqual([true, true]);
		expect(recorded.lines().map((line) => line.fields)).toEqual([
			{ module: "hung", outcome: "late" },
		]);
	});
});
