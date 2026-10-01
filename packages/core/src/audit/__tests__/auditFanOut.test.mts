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
 * `createAuditFanOut`: the one sink core fills the `auditSink` slot with when
 * a module contributes `auditHooks`. Each event goes to the slot's own sink
 * and every hook, in that order, each call isolated, and the fan-out never
 * fails its caller.
 */

import { describe, expect, it, vi } from "vitest";
import { createAuditFanOut } from "#/audit/factory.mjs";
import type { AuditEvent, AuditSink } from "#/audit/types.mjs";
import type { Logger } from "#/logging/Logger.mjs";
import { createRecordingAuditSink } from "#/testing/index.mjs";

const event = (): AuditEvent => ({
	timestamp: new Date(0),
	type: "test.event",
	subject: "user-1",
	details: { error: "secret-detail", nested: { list: [1, { deep: true }] } },
});

const spyLogger = () => {
	const error = vi.fn();
	return { logger: { error } as unknown as Logger, error };
};

const rejecting = (calls?: string[], name = "rejecting"): AuditSink => ({
	kind: name,
	record: async (e) => {
		calls?.push(name);
		throw new Error(`down while writing ${e.subject}`);
	},
});

describe("createAuditFanOut", () => {
	it("hands an event to the slot's sink and to every hook", async () => {
		const primary = createRecordingAuditSink();
		const first = createRecordingAuditSink();
		const second = createRecordingAuditSink();
		const fanOut = createAuditFanOut({
			sink: primary,
			hooks: () => [first, second],
			logger: () => undefined,
		});

		await fanOut.record(event());

		expect([primary, first, second].map((s) => s.events.map((e) => e.type))).toEqual([
			["test.event"],
			["test.event"],
			["test.event"],
		]);
	});

	it("delivers to the hooks alone when the slot has no sink of its own", async () => {
		const hook = createRecordingAuditSink();
		const fanOut = createAuditFanOut({ hooks: () => [hook], logger: () => undefined });

		await fanOut.record(event());

		expect(hook.events).toHaveLength(1);
	});

	it("calls the slot's sink first, then the hooks in their order, each before any has settled", () => {
		const calls: string[] = [];
		const pending = (name: string): AuditSink => ({
			kind: name,
			record: () => {
				calls.push(name);
				return new Promise<void>(() => {});
			},
		});

		void createAuditFanOut({
			sink: pending("slot"),
			hooks: () => [pending("hook-a"), pending("hook-b")],
			logger: () => undefined,
		}).record(event());

		expect(calls).toEqual(["slot", "hook-a", "hook-b"]);
	});

	it.each([
		["rejects", (): AuditSink => rejecting()],
		[
			"throws synchronously",
			(): AuditSink => ({
				kind: "throwing",
				record: () => {
					throw new Error("sync");
				},
			}),
		],
		[
			"answers something that is not a promise",
			(): AuditSink => ({ kind: "non-promise", record: (() => undefined) as never }),
		],
	])("still delivers to the others when one sink %s, and resolves", async (_, failing) => {
		const before = createRecordingAuditSink();
		const after = createRecordingAuditSink();
		const { logger } = spyLogger();
		const fanOut = createAuditFanOut({
			sink: before,
			hooks: () => [failing(), after],
			logger: () => logger,
		});

		await expect(fanOut.record(event())).resolves.toBeUndefined();

		expect([before.events.length, after.events.length]).toEqual([1, 1]);
	});

	it("resolves when every sink fails", async () => {
		const { logger } = spyLogger();
		const fanOut = createAuditFanOut({
			sink: rejecting(),
			hooks: () => [rejecting(), rejecting()],
			logger: () => logger,
		});

		await expect(fanOut.record(event())).resolves.toBeUndefined();
	});

	it("resolves only once the slowest sink has settled", async () => {
		let settle!: () => void;
		const slow: AuditSink = {
			kind: "slow",
			record: () =>
				new Promise<void>((resolve) => {
					settle = resolve;
				}),
		};
		const fanOut = createAuditFanOut({
			sink: createRecordingAuditSink(),
			hooks: () => [slow],
			logger: () => undefined,
		});

		let done = false;
		const recorded = fanOut.record(event()).then(() => {
			done = true;
		});
		await new Promise((r) => setTimeout(r, 0));
		expect(done).toBe(false);
		settle();
		await recorded;
		expect(done).toBe(true);
	});

	it("hands every sink one deeply frozen event, the same object, and leaves the emitter's event unfrozen", async () => {
		const primary = createRecordingAuditSink();
		const hook = createRecordingAuditSink();
		const emitted = event();
		const fanOut = createAuditFanOut({
			sink: primary,
			hooks: () => [hook],
			logger: () => undefined,
		});

		await fanOut.record(emitted);

		const [handed] = primary.events;
		const nested = handed?.details?.nested as { list: [number, { deep: boolean }] };
		expect({
			same: hook.events[0] === handed,
			frozen: [
				Object.isFrozen(handed),
				Object.isFrozen(handed?.details),
				Object.isFrozen(nested),
				Object.isFrozen(nested.list),
				Object.isFrozen(nested.list[1]),
				Object.isFrozen(handed?.timestamp),
			],
			emitterFrozen: [Object.isFrozen(emitted), Object.isFrozen(emitted.details)],
			copied: handed === emitted,
		}).toEqual({
			same: true,
			frozen: [true, true, true, true, true, true],
			emitterFrozen: [false, false],
			copied: false,
		});
		expect(handed).toEqual(emitted);
	});

	it("logs a failing sink as audit_sink_failed with its position and the event's type, and nothing of the event", async () => {
		const { logger, error } = spyLogger();
		const fanOut = createAuditFanOut({
			sink: createRecordingAuditSink(),
			hooks: () => [createRecordingAuditSink(), rejecting()],
			logger: () => logger,
		});

		await fanOut.record(event());

		expect(error.mock.calls).toEqual([[{ sink: 2, type: "test.event" }, "audit_sink_failed"]]);
	});

	it("resolves when the logger itself throws", async () => {
		const fanOut = createAuditFanOut({
			sink: rejecting(),
			hooks: () => [],
			logger: () =>
				({
					error: () => {
						throw new Error("logger down");
					},
				}) as unknown as Logger,
		});

		await expect(fanOut.record(event())).resolves.toBeUndefined();
	});

	it("reads the hooks at each event", async () => {
		const hooks: AuditSink[] = [];
		const late = createRecordingAuditSink();
		const fanOut = createAuditFanOut({ hooks: () => hooks, logger: () => undefined });

		await fanOut.record(event());
		hooks.push(late);
		await fanOut.record(event());

		expect(late.events).toHaveLength(1);
	});

	it("carries the slot's sink's kind", () => {
		const fanOut = createAuditFanOut({
			sink: createRecordingAuditSink(),
			hooks: () => [],
			logger: () => undefined,
		});

		expect(fanOut.kind).toBe("recording");
	});
});
