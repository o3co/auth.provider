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
 * `recordAuditEvent`: the one way a built-in event reaches its sink. It hands
 * the sink the event with its request fields bounded, and — unlike
 * `emitAuditEvent`, which detaches — answers the sink's own promise, for the
 * emitters that bound and drain their audit waits (federation grants).
 */

import { describe, expect, it, vi } from "vitest";
import { recordAuditEvent } from "#/audit/factory.mjs";
import type { AuditSink } from "#/audit/types.mjs";

describe("recordAuditEvent", () => {
	it("answers the sink's own promise", async () => {
		let settle!: () => void;
		const pending = new Promise<void>((resolve) => {
			settle = resolve;
		});
		const sink = { kind: "slow", record: () => pending } as AuditSink;

		let done = false;
		const answered = recordAuditEvent(sink, { timestamp: new Date(), type: "test" }).then(() => {
			done = true;
		});
		await new Promise((r) => setTimeout(r, 0));
		expect(done).toBe(false);
		settle();
		await answered;
		expect(done).toBe(true);
	});

	it("passes the sink's rejection on", async () => {
		const sink = { kind: "down", record: async () => Promise.reject(new Error("sink down")) };
		await expect(
			recordAuditEvent(sink as AuditSink, { timestamp: new Date(), type: "test" }),
		).rejects.toThrow("sink down");
	});

	it("hands the sink the event with its userAgent sanitised and capped, and an ip only if it is an address", async () => {
		const record = vi.fn(async () => undefined);
		await recordAuditEvent({ kind: "spy", record } as AuditSink, {
			timestamp: new Date(),
			type: "test",
			ip: `x\r\n${"i".repeat(10_000)}`,
			userAgent: `x\u0085${"u".repeat(10_000)}`,
		});
		const event = (record.mock.calls[0] as unknown[])[0] as { ip?: string; userAgent: string };
		expect({
			hasIp: "ip" in event,
			userAgent: [event.userAgent.slice(0, 3), event.userAgent.length <= 200],
		}).toEqual({ hasIp: false, userAgent: ["x?u", true] });
	});

	it("turns a sink's synchronous throw into a rejection", async () => {
		const sink = {
			kind: "sync-throw",
			record: () => {
				throw new Error("sink down");
			},
		} as unknown as AuditSink;
		let answered: Promise<void> | undefined;
		expect(() => {
			answered = recordAuditEvent(sink, { timestamp: new Date(), type: "test" });
		}).not.toThrow();
		await expect(answered).rejects.toThrow("sink down");
	});
});
