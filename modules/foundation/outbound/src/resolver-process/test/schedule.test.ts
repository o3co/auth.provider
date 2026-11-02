import { describe, expect, it } from "vitest";
import { restartSchedule } from "../schedule.ts";

const limits = {
	windowMs: 60_000,
	faultRestarts: 2,
	abandonRestarts: 2,
	backoffMs: 100,
	maxBackoffMs: 300,
};

describe("a pool's restart schedule", () => {
	it("backs off after each fault, doubling to its most, and back to its start once one answers", () => {
		const schedule = restartSchedule(() => 0, { ...limits, faultRestarts: 10 });
		expect([1, 2, 3].map(() => schedule.faulted())).toEqual([
			{ delayMs: 100 },
			{ delayMs: 200 },
			{ delayMs: 300 },
		]);
		expect(schedule.recovered()).toBe(true);
		expect(schedule.recovered()).toBe(false);
		expect(schedule.faulted()).toEqual({ delayMs: 100 });
	});

	it("refuses past the window's fault restarts, until the window frees", () => {
		let at = 1_000;
		const schedule = restartSchedule(() => at, limits);
		schedule.faulted();
		schedule.faulted();
		expect(schedule.refusing()).toBe(false);
		expect(schedule.faulted()).toEqual({ refusingUntil: 61_000, restarts: 3 });
		expect(schedule.refusing()).toBe(true);
		at = 61_000;
		expect(schedule.refusing()).toBe(false);
	});

	it("lets an abandoned helper go within the window, and tells when to look again past it", () => {
		let at = 1_000;
		const schedule = restartSchedule(() => at, limits);
		expect(schedule.abandonable()).toBe(true);
		schedule.abandoned();
		schedule.abandoned();
		expect(schedule.abandonable()).toEqual({ recheckAt: 61_000 });
		at = 61_000;
		expect(schedule.abandonable()).toBe(true);
	});
});
