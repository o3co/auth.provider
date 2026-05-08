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
import { createRedisSessionRPRegistry } from "../src/sessionRPRegistry.mjs";

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
		del: vi.fn(async () => 0),
		hSet: vi.fn(async () => 1),
		hVals: vi.fn(async () => values),
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
});
