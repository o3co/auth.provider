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
 * The periodic sweep that resumes pending closes: one sweep at a time, a
 * failed sweep logged and the next one run, and a stop that waits for the
 * sweep in flight.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SessionResumeReport } from "#/index.mjs";
import { startSessionLifecycleSweeper } from "#/user-sessions/lifecycle/sweeper.mjs";

const REPORT: SessionResumeReport = { done: 0, pending: 0, unavailable: 0 };

const logger = () => {
	const lines: { level: string; message: string; fields: Record<string, unknown> }[] = [];
	return {
		lines,
		warn: (fields: object, message: string) =>
			lines.push({ level: "warn", message, fields: fields as Record<string, unknown> }),
		error: (fields: object, message: string) =>
			lines.push({ level: "error", message, fields: fields as Record<string, unknown> }),
	};
};

beforeEach(() => {
	vi.useFakeTimers({ toFake: ["setInterval", "clearInterval"] });
});

afterEach(() => {
	vi.useRealTimers();
});

describe("startSessionLifecycleSweeper", () => {
	it("resumes pending closes once per interval", async () => {
		const resumePending = vi.fn(async () => REPORT);
		const sweeper = startSessionLifecycleSweeper({ resumePending }, 1_000, logger());
		await vi.advanceTimersByTimeAsync(999);
		expect(resumePending).toHaveBeenCalledTimes(0);
		await vi.advanceTimersByTimeAsync(2_001);
		expect(resumePending).toHaveBeenCalledTimes(3);
		await sweeper.stop();
	});

	it("starts no sweep while the last one is still running", async () => {
		let finish: (report: SessionResumeReport) => void = () => undefined;
		const resumePending = vi.fn(
			() =>
				new Promise<SessionResumeReport>((resolve) => {
					finish = resolve;
				}),
		);
		const sweeper = startSessionLifecycleSweeper({ resumePending }, 1_000, logger());
		await vi.advanceTimersByTimeAsync(5_000);
		expect(resumePending).toHaveBeenCalledTimes(1);
		finish(REPORT);
		await vi.advanceTimersByTimeAsync(1_000);
		expect(resumePending).toHaveBeenCalledTimes(2);
		finish(REPORT);
		await sweeper.stop();
	});

	it("logs a sweep that rejects, and sweeps again at the next interval", async () => {
		const log = logger();
		const resumePending = vi
			.fn<() => Promise<SessionResumeReport>>()
			.mockRejectedValueOnce(new Error("lifecycle store down"))
			.mockResolvedValue(REPORT);
		const sweeper = startSessionLifecycleSweeper({ resumePending }, 1_000, log);
		await vi.advanceTimersByTimeAsync(2_000);
		expect(resumePending).toHaveBeenCalledTimes(2);
		expect(log.lines.map((line) => [line.level, line.message])).toEqual([
			["error", "session_lifecycle_sweep_failed"],
		]);
		await sweeper.stop();
	});

	it("logs a sweep that left closes pending or unreadable", async () => {
		const log = logger();
		const resumePending = vi.fn(async () => ({ done: 2, pending: 1, unavailable: 1 }));
		const sweeper = startSessionLifecycleSweeper({ resumePending }, 1_000, log);
		await vi.advanceTimersByTimeAsync(1_000);
		expect(log.lines).toEqual([
			{
				level: "warn",
				message: "session_lifecycle_sweep_pending",
				fields: { done: 2, pending: 1, unavailable: 1 },
			},
		]);
		await sweeper.stop();
	});

	it("stops sweeping on stop, and waits for the sweep in flight", async () => {
		let finish: (report: SessionResumeReport) => void = () => undefined;
		const resumePending = vi.fn(
			() =>
				new Promise<SessionResumeReport>((resolve) => {
					finish = resolve;
				}),
		);
		const sweeper = startSessionLifecycleSweeper({ resumePending }, 1_000, logger());
		await vi.advanceTimersByTimeAsync(1_000);
		let stopped = false;
		const stopping = sweeper.stop().then(() => {
			stopped = true;
		});
		await Promise.resolve();
		expect(stopped).toBe(false);
		finish(REPORT);
		await stopping;
		expect(stopped).toBe(true);
		await vi.advanceTimersByTimeAsync(10_000);
		expect(resumePending).toHaveBeenCalledTimes(1);
	});
});
