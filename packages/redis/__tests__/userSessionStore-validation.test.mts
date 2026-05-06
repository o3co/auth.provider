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
import type { UserSessionStoreClient } from "../src/clients.mjs";
import { createRedisUserSessionStore } from "../src/userSessionStore.mjs";

// Lightweight in-memory mock with a `seed()` helper to inject corrupt
// payloads directly into the Redis store. Matches the exactly-what-we-test
// surface: only `get` is exercised by these tests.
const makeMockClient = (): UserSessionStoreClient & {
	seed: (key: string, raw: string) => void;
} => {
	const store = new Map<string, string>();
	const set = ((..._args: unknown[]) => Promise.resolve("OK" as const)) as never;
	return {
		set,
		get: async (k: string) => store.get(k) ?? null,
		del: async (k: string) => (store.delete(k) ? 1 : 0),
		seed: (key, raw) => store.set(key, raw),
	};
};

const validEnvelope = {
	sid: "sid-1",
	sub: "user-1",
	authTimeMs: Date.now(),
	createdAtMs: Date.now(),
	expiresAtMs: Date.now() + 60_000,
	claims: { iss: "https://auth.example" },
};

describe("TS-3: RedisUserSessionStore.get — corrupt envelope validation", () => {
	const keyPrefix = "sess:";

	it("returns the session for a valid envelope (regression guard)", async () => {
		const client = makeMockClient();
		const store = createRedisUserSessionStore({ client, keyPrefix });
		client.seed(`${keyPrefix}sid-1`, JSON.stringify(validEnvelope));
		const result = await store.get("sid-1");
		expect(result).not.toBeNull();
		expect(result?.sid).toBe("sid-1");
		expect(result?.sub).toBe("user-1");
	});

	it("returns null and logs json_parse warn on malformed JSON", async () => {
		const logger = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
		const client = makeMockClient();
		const store = createRedisUserSessionStore({ client, keyPrefix, logger });
		client.seed(`${keyPrefix}sid-bad`, "{not-valid-json}}");

		const result = await store.get("sid-bad");
		expect(result).toBeNull();
		expect(logger.warn).toHaveBeenCalledWith(
			expect.any(String),
			expect.objectContaining({ sid: "sid-bad", reason: "json_parse" }),
		);
	});

	// Parametric coverage: each missing/invalid field individually causes
	// `get()` to return null and emit a `shape_invalid` warn. An
	// implementation that only validated `expiresAtMs` would still fail
	// these — preventing the regression where `expiresAtMs: undefined`
	// silently bypassed the expiry filter.
	it.each([
		["sid missing", { ...validEnvelope, sid: undefined as unknown as string }],
		["sub missing", { ...validEnvelope, sub: undefined as unknown as string }],
		["authTimeMs missing", { ...validEnvelope, authTimeMs: undefined as unknown as number }],
		["createdAtMs missing", { ...validEnvelope, createdAtMs: undefined as unknown as number }],
		["expiresAtMs missing", { ...validEnvelope, expiresAtMs: undefined as unknown as number }],
		[
			"expiresAtMs non-numeric",
			{ ...validEnvelope, expiresAtMs: "not-a-number" as unknown as number },
		],
		["expiresAtMs null", { ...validEnvelope, expiresAtMs: null as unknown as number }],
		["claims null", { ...validEnvelope, claims: null as unknown as Record<string, unknown> }],
		[
			"claims is array (not object)",
			{ ...validEnvelope, claims: [] as unknown as Record<string, unknown> },
		],
	])("returns null and logs shape_invalid warn for %s", async (_label, corrupt) => {
		const logger = { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
		const client = makeMockClient();
		const store = createRedisUserSessionStore({ client, keyPrefix, logger });
		client.seed(`${keyPrefix}sid-corrupt`, JSON.stringify(corrupt));

		const result = await store.get("sid-corrupt");
		expect(result).toBeNull();
		expect(logger.warn).toHaveBeenCalledWith(
			expect.any(String),
			expect.objectContaining({ sid: "sid-corrupt", reason: "shape_invalid" }),
		);
	});

	it("returns null without logger when no logger is injected (optional-chain semantics)", async () => {
		const client = makeMockClient();
		const store = createRedisUserSessionStore({ client, keyPrefix });
		client.seed(`${keyPrefix}sid-corrupt`, "{not-valid-json}");
		const result = await store.get("sid-corrupt");
		expect(result).toBeNull();
		// No assertion on logger — simply not crashing without one is the
		// success criterion.
	});
});
