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

import { describe, expect, it, vi } from "vitest";
import { createAuditSinkFactory, registerBuiltinAuditSinks } from "#/audit/factory.mjs";

describe("createAuditSinkFactory", () => {
	it("creates an adapter factory and resolves registered sinks", async () => {
		const factory = createAuditSinkFactory();
		factory.register("testsink", () => ({
			kind: "testsink",
			async record() {},
		}));
		const sink = await factory.create({ type: "testsink" });
		expect(sink.kind).toBe("testsink");
	});
});

describe("registerBuiltinAuditSinks", () => {
	it("registers console sink that writes one JSON line per event to stdout", async () => {
		const factory = createAuditSinkFactory();
		registerBuiltinAuditSinks(factory);
		const sink = await factory.create({ type: "console" });
		expect(sink.kind).toBe("console");

		const writeSpy = vi.spyOn(process.stdout, "write").mockReturnValue(true);
		try {
			await sink.record({
				timestamp: new Date("2026-04-21T00:00:00Z"),
				type: "login.success",
				subject: "user-1",
				details: { ip: "1.2.3.4" },
			});
			expect(writeSpy).toHaveBeenCalledTimes(1);
			const written = writeSpy.mock.calls[0][0] as string;
			expect(written.trimEnd()).toMatch(/^\{.*\}$/);
			const parsed = JSON.parse(written);
			expect(parsed.type).toBe("login.success");
			expect(parsed.subject).toBe("user-1");
			expect(parsed.timestamp).toBe("2026-04-21T00:00:00.000Z");
			expect(written.endsWith("\n")).toBe(true);
		} finally {
			writeSpy.mockRestore();
		}
	});
});
