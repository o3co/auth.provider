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

import type { Logger } from "@o3co/auth-provider-core";
import { describe, expect, it, vi } from "vitest";
import type { SessionRPRegistryClient, SessionRPRegistryMultiClient } from "../src/clients.mjs";
import {
	createRedisSessionRPRegistry,
	redisSessionRPRegistryBuilder,
} from "../src/sessionRPRegistry.mjs";

function createMockLogger(): Logger {
	const logger = {
		trace: vi.fn(),
		debug: vi.fn(),
		info: vi.fn(),
		warn: vi.fn(),
		error: vi.fn(),
		fatal: vi.fn(),
		child: vi.fn(),
	} as unknown as Logger;
	(logger.child as unknown as ReturnType<typeof vi.fn>).mockReturnValue(logger);
	return logger;
}

function createMockClient(values: string[]): SessionRPRegistryClient {
	const multi: SessionRPRegistryMultiClient = {
		hSet: vi.fn(() => multi),
		pExpireAt: vi.fn(() => multi),
		pExpireGT: vi.fn(() => multi),
		exec: vi.fn(async () => []),
	};
	return {
		unlink: vi.fn(async () => 0),
		hSet: vi.fn(async () => 1),
		hScanIterator: vi.fn(() =>
			(async function* () {
				for (const [i, value] of values.entries()) yield [`field-${i}`, value] as const;
			})(),
		),
		multi: vi.fn(() => multi),
		pExpireAt: vi.fn(async () => 1),
		pExpireGT: vi.fn(async () => 1),
	};
}

describe("RedisSessionRPRegistry corrupt envelope handling", () => {
	it("filters corrupt envelopes instead of returning Invalid Date records", async () => {
		const registeredAtMs = Date.now();
		const logger = createMockLogger();
		const registry = createRedisSessionRPRegistry({
			client: createMockClient([
				JSON.stringify({ clientId: "rp-valid", registeredAtMs }),
				JSON.stringify({ clientId: "rp-missing-date" }),
				JSON.stringify({ clientId: "rp-string-date", registeredAtMs: "not-a-number" }),
				JSON.stringify({ clientId: "rp-nan-date", registeredAtMs: Number.NaN }),
				JSON.stringify({ registeredAtMs }),
				"{not-json",
			]),
			keyPrefix: "test:rp:",
			logger,
		});

		const rps = await registry.listRPs("sid-1");

		expect(rps).toHaveLength(1);
		expect(rps[0]?.clientId).toBe("rp-valid");
		expect(rps[0]?.registeredAt.getTime()).toBe(registeredAtMs);
		expect(logger.warn).toHaveBeenCalledTimes(5);
	});

	it("rejects array-shaped JSON payloads via the !Array.isArray envelope guard", async () => {
		// Regression: previously isRecord accepted arrays (typeof [] === "object"
		// && [] !== null). Without an explicit array guard, a payload like
		// `["client-1", ...]` would only fail by accident when subsequent field
		// accesses returned undefined — fail-closed at the shape-check layer
		// instead, matching the userSessionStore envelope guard pattern.
		const logger = createMockLogger();
		const registry = createRedisSessionRPRegistry({
			client: createMockClient([JSON.stringify(["client-array", 12345])]),
			keyPrefix: "test:rp:",
			logger,
		});

		const rps = await registry.listRPs("sid-array");

		expect(rps).toHaveLength(0);
		expect(logger.warn).toHaveBeenCalledWith(
			{ sid: "sid-array", reason: "shape_invalid" },
			expect.stringContaining("session_rp_registry_corrupt_envelope"),
		);
	});

	it("emits structured corrupt-envelope warns with sid + reason + cause (no raw JSON)", async () => {
		// Mirror the userSessionStore corrupt-envelope warn shape so operators
		// see consistent fields across sibling adapters and the raw JSON
		// payload — which may contain attacker-controlled or sensitive data
		// — never reaches log sinks.
		const logger = createMockLogger();
		const registry = createRedisSessionRPRegistry({
			client: createMockClient(["{not-json", JSON.stringify({ clientId: "rp-no-date" })]),
			keyPrefix: "test:rp:",
			logger,
		});

		await registry.listRPs("sid-corrupt");

		expect(logger.warn).toHaveBeenCalledWith(
			{ sid: "sid-corrupt", reason: "json_parse", cause: expect.any(SyntaxError) },
			expect.stringContaining("JSON.parse failed"),
		);
		expect(logger.warn).toHaveBeenCalledWith(
			{ sid: "sid-corrupt", reason: "shape_invalid" },
			expect.stringContaining("shape invalid"),
		);
		// The raw payload snippet must NOT appear in any warn invocation —
		// previously the implementation logged `{ json: json.slice(0, 100) }`
		// which risked leaking sensitive data.
		const allWarnCalls = (logger.warn as ReturnType<typeof vi.fn>).mock.calls;
		for (const [payload] of allWarnCalls) {
			expect(payload).not.toHaveProperty("json");
		}
	});
});

describe("redisSessionRPRegistryBuilder", () => {
	it("forwards config.logger to the adapter so corrupt-envelope warns can fire", async () => {
		const logger = createMockLogger();
		const client = createMockClient(["{not-json"]);
		const registry = redisSessionRPRegistryBuilder(
			{ client, logger },
			{} as Parameters<typeof redisSessionRPRegistryBuilder>[1],
		);

		await registry.listRPs("sid-builder");

		expect(logger.warn).toHaveBeenCalledWith(
			{ sid: "sid-builder", reason: "json_parse", cause: expect.any(SyntaxError) },
			expect.stringContaining("session_rp_registry_corrupt_envelope"),
		);
	});

	it("omits logger field when caller does not supply one (exactOptionalPropertyTypes)", () => {
		// Builder must not pass an explicit `logger: undefined` to the adapter;
		// the spread idiom drops the field entirely so the adapter sees
		// `opts.logger === undefined` via "absent" rather than "explicit".
		const client = createMockClient([]);
		expect(() =>
			redisSessionRPRegistryBuilder(
				{ client },
				{} as Parameters<typeof redisSessionRPRegistryBuilder>[1],
			),
		).not.toThrow();
	});

	it("throws at boot when client option is missing", () => {
		expect(() =>
			redisSessionRPRegistryBuilder({}, {} as Parameters<typeof redisSessionRPRegistryBuilder>[1]),
		).toThrow(/client.+required/i);
	});
});
