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
 * The audit doubles on the testing entry: a sink that keeps what it is
 * handed, and a module that contributes sinks as `auditHooks`.
 */

import { describe, expect, it } from "vitest";
import type { AuditEvent } from "#/audit/types.mjs";
import { auditHooksModule, createRecordingAuditSink } from "#/testing/index.mjs";

const event: AuditEvent = { timestamp: new Date(0), type: "test.event" };

describe("createRecordingAuditSink", () => {
	it("keeps every event it is handed, oldest first, as it was handed", async () => {
		const sink = createRecordingAuditSink();
		const second: AuditEvent = { ...event, type: "test.second" };

		await sink.record(event);
		await sink.record(second);

		expect(sink.events[0]).toBe(event);
		expect(sink.events[1]).toBe(second);
		expect(sink.events).toHaveLength(2);
	});

	it("rejects with the error it is told to fail with and keeps nothing, until it recovers", async () => {
		const sink = createRecordingAuditSink();
		const down = new Error("sink down");

		sink.failWith(down);
		await expect(sink.record(event)).rejects.toBe(down);
		sink.recover();
		await sink.record(event);

		expect(sink.events).toHaveLength(1);
	});
});

describe("auditHooksModule", () => {
	it("contributes each sink as an auditHooks entry, in order, under its name", () => {
		const first = createRecordingAuditSink();
		const second = createRecordingAuditSink();

		const module = auditHooksModule("test:hooks", first, second);

		expect(module.name).toBe("test:hooks");
		expect(module.contributes?.auditHooks?.map((factory) => factory({} as never))).toEqual([
			first,
			second,
		]);
	});
});
