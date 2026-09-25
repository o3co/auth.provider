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
import {
	createAuditSinkFactory,
	emitAuditEvent,
	registerBuiltinAuditSinks,
} from "#/audit/factory.mjs";
import type { AuditSink } from "#/audit/types.mjs";

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

describe("emitAuditEvent", () => {
	it("resolves, and throws nothing into the route, when a sink throws synchronously", async () => {
		const sink = {
			kind: "sync-throw",
			record: () => {
				throw new Error("sink down");
			},
		} as unknown as AuditSink;
		let answered: Promise<void> | undefined;
		expect(() => {
			answered = emitAuditEvent(sink, { timestamp: new Date(), type: "test" });
		}).not.toThrow();
		await expect(answered).resolves.toBeUndefined();
	});

	it("resolves, and throws nothing into the route, when a sink returns undefined", async () => {
		const sink = { kind: "sync", record: () => undefined } as unknown as AuditSink;
		let answered: Promise<void> | undefined;
		expect(() => {
			answered = emitAuditEvent(sink, { timestamp: new Date(), type: "test" });
		}).not.toThrow();
		await expect(answered).resolves.toBeUndefined();
	});

	it("swallows thrown errors from sink.record", async () => {
		const throwingSink: AuditSink = {
			kind: "boom",
			async record() {
				throw new Error("sink down");
			},
		};
		await expect(
			emitAuditEvent(throwingSink, {
				timestamp: new Date(),
				type: "test",
			}),
		).resolves.toBeUndefined();
	});

	it("is a no-op when sink is undefined", async () => {
		await expect(
			emitAuditEvent(undefined, {
				timestamp: new Date(),
				type: "test",
			}),
		).resolves.toBeUndefined();
	});

	it("does not block the caller on a slow sink (fire-and-forget)", async () => {
		// Resolve-later promise — never settles during this test.
		let release: (() => void) | undefined;
		const slowSink: AuditSink = {
			kind: "slow",
			async record() {
				await new Promise<void>((resolve) => {
					release = resolve;
				});
			},
		};

		const started = Date.now();
		await emitAuditEvent(slowSink, { timestamp: new Date(), type: "test" });
		const elapsed = Date.now() - started;
		expect(elapsed).toBeLessThan(50);
		// Release the dangling promise so vitest doesn't see an unhandled async op
		release?.();
	});

	it("swallows rejections from detached sink.record without emitting unhandled-rejection", async () => {
		const rejectingSink: AuditSink = {
			kind: "reject",
			record() {
				return Promise.reject(new Error("sink failed"));
			},
		};
		// If the .catch weren't attached, process would log
		// an unhandledRejection warning. We assert the emit returns cleanly.
		await expect(
			emitAuditEvent(rejectingSink, { timestamp: new Date(), type: "test" }),
		).resolves.toBeUndefined();
		// Yield the microtask queue so the detached promise settles
		await new Promise((r) => setImmediate(r));
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

describe("emitAuditEvent — the request's own fields", () => {
	// A route copies `ip` (behind `trust proxy`, the caller's X-Forwarded-For)
	// and `userAgent` from the request: the caller's text. A composition may
	// hand in anything; a real request can carry a tab, the C1 controls
	// (U+0085 NEL, U+009B CSI) and up to Node's header-size limit.
	// biome-ignore lint/suspicious/noControlCharactersInRegex: a control character is what must not be audited.
	const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;
	/** What an assertion needs of an audited value: a failure prints this, not the value. */
	const shapeOf = (value: unknown) => ({
		string: typeof value === "string",
		control: CONTROL.test(String(value)),
		within200: String(value).length <= 200,
		head: String(value).slice(0, 9),
	});
	const BOUNDED = { string: true, control: false, within200: true, head: "x??FORGED" };
	const HOSTILE = `x\r\nFORGED audit\u0085\u009b31m\u0000\t${"h".repeat(10_000)}`;

	const recorded = async (event: Parameters<typeof emitAuditEvent>[1]) => {
		const record = vi.fn(async () => undefined);
		await emitAuditEvent({ kind: "spy", record } as AuditSink, event);
		expect(record).toHaveBeenCalledTimes(1);
		return (record.mock.calls[0] as unknown[])[0] as Record<string, unknown>;
	};

	it("hands the sink a userAgent sanitised and capped, and no ip that is not an address", async () => {
		const event = await recorded({
			timestamp: new Date(),
			type: "test",
			ip: HOSTILE,
			userAgent: HOSTILE,
		});
		expect({ ip: event.ip, hasIp: "ip" in event, userAgent: shapeOf(event.userAgent) }).toEqual({
			ip: undefined,
			hasIp: false,
			userAgent: BOUNDED,
		});
	});

	// An `ip` is an address or nothing: an SIEM that maps the field as an IP
	// type rejects the whole event over a value that is not one, and a spoofed
	// `X-Forwarded-For: x` would otherwise make it.
	it.each([
		["an IPv4 address", "203.0.113.7", "203.0.113.7"],
		["an IPv6 address", "2001:db8::1", "2001:db8::1"],
		["an IPv4-mapped IPv6 address", "::ffff:127.0.0.1", "::ffff:127.0.0.1"],
		["a link-local address, its zone stripped", "fe80::1%eth0", "fe80::1"],
		["a zone that is anything, stripped", "fe80::1%<script>", "fe80::1"],
		["a name", "x", undefined],
		["an IPv4 address with a zone", "203.0.113.7%eth0", undefined],
		["an address in brackets", "[::1]", undefined],
		["an address with a port", "203.0.113.7:8080", undefined],
		["an empty string", "", undefined],
	])("hands the sink %s, %j, as %j", async (_label, ip, expected) => {
		const event = await recorded({ timestamp: new Date(), type: "test", ip });
		expect({ ip: event.ip, hasIp: "ip" in event }).toEqual({
			ip: expected,
			hasIp: expected !== undefined,
		});
	});

	it("keeps the event's own key order", async () => {
		const event = await recorded({
			timestamp: new Date(),
			type: "test",
			subject: "u1",
			ip: "203.0.113.7",
			userAgent: "ua/1",
			clientId: "c1",
			details: { reason: "x" },
		});
		expect(Object.keys(event)).toEqual([
			"timestamp",
			"type",
			"subject",
			"ip",
			"userAgent",
			"clientId",
			"details",
		]);
	});

	it("hands the sink an ordinary ip and userAgent unchanged, and everything else as it was", async () => {
		const timestamp = new Date();
		const details = { reason: "x" };
		const event = await recorded({
			timestamp,
			type: "test",
			subject: "u1",
			clientId: "c1",
			ip: "2001:db8::1",
			userAgent:
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			details,
		});
		expect(event).toEqual({
			timestamp,
			type: "test",
			subject: "u1",
			clientId: "c1",
			ip: "2001:db8::1",
			userAgent:
				"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			details,
		});
	});

	it("adds neither field to an event that has none", async () => {
		const event = await recorded({ timestamp: new Date(), type: "test" });
		expect(Object.keys(event).sort()).toEqual(["timestamp", "type"]);
	});

	it("drops an ip or userAgent that is not a string rather than coercing it", async () => {
		const event = await recorded({
			timestamp: new Date(),
			type: "test",
			ip: { toString: () => "1.2.3.4" } as unknown as string,
			userAgent: 7 as unknown as string,
		});
		expect(event.ip).toBeUndefined();
		expect(event.userAgent).toBeUndefined();
	});
});
