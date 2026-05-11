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

import Redis from "ioredis";
import { GenericContainer, type StartedTestContainer } from "testcontainers";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const KEY_PREFIX = "oauth:code:";

// In-memory store simulating Redis
const store = new Map<string, string>();

import type { CodeRepositoryClient } from "../src/clients.mjs";
import { RedisCodeRepository } from "../src/code-repository.mjs";
import { makeIoredisClients } from "../src/ioredis.mjs";

// OR-9: the public `RedisCodeRepository` constructor accepts a typed
// `CodeRepositoryClient` wrapper, not a node-redis client. The mock satisfies
// only that interface — `set/get/getDel/del` — and ignores the `mode`/`ttlMs`
// arguments which the in-memory store doesn't honor.
const createMockClient = (): CodeRepositoryClient => ({
	set: vi.fn().mockImplementation((key: string, value: string) => {
		store.set(key, value);
		return Promise.resolve("OK" as const);
	}),
	get: vi.fn().mockImplementation((key: string) => {
		return Promise.resolve(store.get(key) ?? null);
	}),
	getDel: vi.fn().mockImplementation((key: string) => {
		const value = store.get(key) ?? null;
		store.delete(key);
		return Promise.resolve(value);
	}),
	del: vi.fn().mockImplementation((key: string) => {
		store.delete(key);
		return Promise.resolve(1);
	}),
});

describe("RedisCodeRepository", () => {
	let repo: RedisCodeRepository;
	let client: CodeRepositoryClient;

	// Minimal valid params for v0.5.1+ (D-1: client_id and redirect_uri required).
	const minimalParams = {
		client_id: "test-client",
		redirect_uri: "https://rp.example/cb",
	};

	beforeEach(() => {
		store.clear();
		client = createMockClient();
		repo = new RedisCodeRepository(client);
	});

	describe("createCode", () => {
		it("generates a code string and stores it", async () => {
			const result = await repo.createCode(minimalParams);

			expect(typeof result.code).toBe("string");
			expect(result.code.length).toBeGreaterThan(0);
			// Verify it was stored with namespace prefix
			expect(store.has(`${KEY_PREFIX}${result.code}`)).toBe(true);
		});

		it("returns code with code_challenge and code_challenge_method", async () => {
			const result = await repo.createCode({
				...minimalParams,
				code_challenge: "abc123",
				code_challenge_method: "S256",
			});

			expect(result.code_challenge).toBe("abc123");
			expect(result.code_challenge_method).toBe("S256");
		});

		it("stores code_challenge and code_challenge_method in Redis", async () => {
			const result = await repo.createCode({
				...minimalParams,
				code_challenge: "challenge-value",
				code_challenge_method: "S256",
			});

			const stored = store.get(`${KEY_PREFIX}${result.code}`);
			expect(stored).toBeDefined();
			const parsed = JSON.parse(stored as string);
			expect(parsed.code_challenge).toBe("challenge-value");
			expect(parsed.code_challenge_method).toBe("S256");
		});

		it("uses default expiresIn when not provided", async () => {
			const result = await repo.createCode(minimalParams);
			expect(result.expiresIn).toBe(600);
		});

		it("uses provided expiresIn", async () => {
			const result = await repo.createCode({ ...minimalParams, expiresIn: 300 });
			expect(result.expiresIn).toBe(300);
		});
	});

	describe("findByCode", () => {
		it("returns stored code data", async () => {
			const created = await repo.createCode({
				...minimalParams,
				code_challenge: "test-challenge",
				code_challenge_method: "S256",
			});

			const found = await repo.findByCode(created.code);

			expect(found).not.toBeNull();
			expect(found?.code).toBe(created.code);
			expect(found?.code_challenge).toBe("test-challenge");
			expect(found?.code_challenge_method).toBe("S256");
		});

		it("returns null for unknown code", async () => {
			const result = await repo.findByCode("nonexistent-code");
			expect(result).toBeNull();
		});

		it("returns null for corrupted data", async () => {
			store.set(`${KEY_PREFIX}corrupted`, "not-valid-json{{{");
			const result = await repo.findByCode("corrupted");
			expect(result).toBeNull();
		});

		// D-1: pre-v0.5.1 records persisted via the old createCode path lacked
		// `client_id` / `redirect_uri` because RedisCodeRepository.createCode
		// silently dropped both. parseCodeValue treats such records as corrupt
		// (returns null + structured error log) so the strict identity gates
		// in /token never see `client_id: undefined` or `redirect_uri: undefined`.
		it("treats pre-v0.5.1 records lacking client_id and redirect_uri as corrupt", async () => {
			store.set(`${KEY_PREFIX}legacy-1`, JSON.stringify({ code_challenge: "x" }));
			expect(await repo.findByCode("legacy-1")).toBeNull();
		});

		it("treats records with non-string client_id as corrupt", async () => {
			store.set(
				`${KEY_PREFIX}legacy-2`,
				JSON.stringify({ client_id: 123, redirect_uri: "https://rp/cb" }),
			);
			expect(await repo.findByCode("legacy-2")).toBeNull();
		});

		it("treats records with missing redirect_uri as corrupt even if client_id is present", async () => {
			store.set(`${KEY_PREFIX}legacy-3`, JSON.stringify({ client_id: "client-1" }));
			expect(await repo.findByCode("legacy-3")).toBeNull();
		});
	});

	describe("consumeByCode", () => {
		it("returns code data and removes it atomically", async () => {
			const created = await repo.createCode({
				...minimalParams,
				code_challenge: "consume-test",
				code_challenge_method: "S256",
			});

			const consumed = await repo.consumeByCode(created.code);
			expect(consumed).not.toBeNull();
			expect(consumed?.code).toBe(created.code);
			expect(consumed?.code_challenge).toBe("consume-test");

			// Should be gone from store
			expect(store.has(`${KEY_PREFIX}${created.code}`)).toBe(false);
		});

		it("returns null for unknown code", async () => {
			expect(await repo.consumeByCode("nonexistent")).toBeNull();
		});

		it("second consume returns null (replay prevention)", async () => {
			const created = await repo.createCode(minimalParams);
			const first = await repo.consumeByCode(created.code);
			expect(first).not.toBeNull();

			const second = await repo.consumeByCode(created.code);
			expect(second).toBeNull();
		});
	});

	describe("removeByCode", () => {
		it("removes a stored code", async () => {
			const created = await repo.createCode({ ...minimalParams, code_challenge: "c" });
			expect(store.has(`${KEY_PREFIX}${created.code}`)).toBe(true);

			await repo.removeByCode(created.code);
			expect(store.has(`${KEY_PREFIX}${created.code}`)).toBe(false);
		});

		it("does not throw for unknown code", async () => {
			await expect(repo.removeByCode("nonexistent")).resolves.toBeUndefined();
		});
	});

	// OR-9 (Wave 5d): external client + ioredis migration. The constructor
	// accepts a `CodeRepositoryClient` typed wrapper instead of constructing
	// its own node-redis client. PX expiry is in milliseconds; keyPrefix and
	// defaultExpiresIn flow through the options object.
	describe("OR-9 external client", () => {
		it("calls client.set with PX mode and ttlMs = expiresIn * 1000", async () => {
			await repo.createCode({ ...minimalParams, expiresIn: 300 });
			expect(client.set).toHaveBeenCalledWith(
				expect.stringMatching(/^oauth:code:/),
				expect.any(String),
				"PX",
				300_000,
			);
		});

		it("uses the default expiry (600s = 600000ms) when expiresIn is omitted", async () => {
			await repo.createCode(minimalParams);
			expect(client.set).toHaveBeenCalledWith(
				expect.any(String),
				expect.any(String),
				"PX",
				600_000,
			);
		});

		it("honors a custom keyPrefix option", async () => {
			const customClient = createMockClient();
			const customRepo = new RedisCodeRepository(customClient, { keyPrefix: "tenant-a:code:" });
			const result = await customRepo.createCode(minimalParams);
			expect(customClient.set).toHaveBeenCalledWith(
				`tenant-a:code:${result.code}`,
				expect.any(String),
				"PX",
				expect.any(Number),
			);
		});

		it("honors a custom defaultExpiresIn option", async () => {
			const customClient = createMockClient();
			const customRepo = new RedisCodeRepository(customClient, { defaultExpiresIn: 120 });
			const result = await customRepo.createCode(minimalParams);
			expect(result.expiresIn).toBe(120);
			expect(customClient.set).toHaveBeenCalledWith(
				expect.any(String),
				expect.any(String),
				"PX",
				120_000,
			);
		});

		it("has no dispose / [Symbol.asyncDispose] method (consumer manages client lifecycle, D-5 v2)", () => {
			// Regression guard: the consumer (composition root) owns the
			// ioredis socket via `standaloneRedisClientsModule` and registers
			// its own `lifecycleRegistrar.register(io.quit)`. The repository
			// is purely a typed wrapper; introducing a dispose() here would
			// double-quit the shared socket.
			const r = repo as unknown as Record<string, unknown>;
			expect(r.dispose).toBeUndefined();
			expect(r[Symbol.asyncDispose as unknown as string]).toBeUndefined();
		});

		// Defense-in-depth: the module configSchema rejects non-positive
		// integers at boot, but direct constructor callers must also fail
		// loudly so the failure mode is identical regardless of wiring path.
		// Per Copilot review on PR #122.
		it.each([
			["zero", 0],
			["negative", -1],
			["fractional", 1.5],
			["NaN", Number.NaN],
			["Infinity", Number.POSITIVE_INFINITY],
		])("constructor throws RangeError when defaultExpiresIn is %s", (_label, badValue) => {
			const c = createMockClient();
			expect(() => new RedisCodeRepository(c, { defaultExpiresIn: badValue })).toThrow(RangeError);
		});

		it("constructor accepts undefined defaultExpiresIn (falls back to 600s default)", async () => {
			const c = createMockClient();
			const r = new RedisCodeRepository(c, {});
			const result = await r.createCode(minimalParams);
			expect(result.expiresIn).toBe(600);
		});
	});

	// D-1 / TD-1 / IH-2 / TS-1: extended-fields round-trip
	// Pre-fix RedisCodeRepository.createCode silently drops every field except
	// code_challenge / code_challenge_method / expiresIn (sid / nonce / redirect_uri /
	// grantedScope / grantedAudience). Production deployments using Redis +
	// userSessionStore could not complete a single authorization-code exchange
	// because codeData.sid was always undefined.
	describe("D-1 extended fields round-trip", () => {
		it("persists and returns client_id, redirect_uri via consumeByCode", async () => {
			const result = await repo.createCode({
				client_id: "client-abc",
				redirect_uri: "https://rp.example/cb",
			});
			const consumed = await repo.consumeByCode(result.code);
			expect(consumed?.client_id).toBe("client-abc");
			expect(consumed?.redirect_uri).toBe("https://rp.example/cb");
		});

		it("persists and returns sid, nonce, grantedScope, grantedAudience via consumeByCode", async () => {
			const result = await repo.createCode({
				client_id: "client-abc",
				redirect_uri: "https://rp.example/cb",
				sid: "sid-xyz",
				nonce: "nonce-abc",
				grantedScope: ["openid", "profile"],
				grantedAudience: ["api.example"],
			});
			const consumed = await repo.consumeByCode(result.code);
			expect(consumed?.sid).toBe("sid-xyz");
			expect(consumed?.nonce).toBe("nonce-abc");
			expect(consumed?.grantedScope).toEqual(["openid", "profile"]);
			expect(consumed?.grantedAudience).toEqual(["api.example"]);
		});

		it("persists all fields in the Redis JSON payload (storage-level assertion)", async () => {
			const result = await repo.createCode({
				client_id: "client-abc",
				redirect_uri: "https://rp.example/cb",
				sid: "sid-xyz",
				nonce: "nonce-abc",
				grantedScope: ["openid"],
			});
			const raw = store.get(`${KEY_PREFIX}${result.code}`) as string;
			expect(raw).toBeDefined();
			const parsed = JSON.parse(raw);
			expect(parsed.client_id).toBe("client-abc");
			expect(parsed.redirect_uri).toBe("https://rp.example/cb");
			expect(parsed.sid).toBe("sid-xyz");
			expect(parsed.nonce).toBe("nonce-abc");
			expect(parsed.grantedScope).toEqual(["openid"]);
		});

		it("findByCode also returns all extended fields", async () => {
			const result = await repo.createCode({
				client_id: "client-abc",
				redirect_uri: "https://rp.example/cb",
				sid: "sid-xyz",
				nonce: "nonce-abc",
			});
			const found = await repo.findByCode(result.code);
			expect(found?.client_id).toBe("client-abc");
			expect(found?.redirect_uri).toBe("https://rp.example/cb");
			expect(found?.sid).toBe("sid-xyz");
			expect(found?.nonce).toBe("nonce-abc");
		});
	});
});

const describeWithRedis = process.env.REDIS_TESTCONTAINERS === "true" ? describe : describe.skip;

describeWithRedis("RedisCodeRepository with real Redis", () => {
	let container: StartedTestContainer | undefined;
	let raw: Redis | undefined;

	beforeAll(async () => {
		container = await new GenericContainer("redis:7.2-alpine").withExposedPorts(6379).start();
		raw = new Redis({ host: container.getHost(), port: container.getMappedPort(6379) });
	}, 60_000);

	afterAll(async () => {
		if (raw) {
			await raw.quit().catch(() => {
				raw?.disconnect();
			});
		}
		await container?.stop();
	});

	it("expires authorization codes according to the Redis PX TTL", async () => {
		if (!raw) throw new Error("Redis test container did not start");
		const keyPrefix = `td4:ttl:${Date.now()}:`;
		const { codeRepositoryClient } = makeIoredisClients(raw);
		const repo = new RedisCodeRepository(codeRepositoryClient, {
			keyPrefix,
			defaultExpiresIn: 1,
		});

		const created = await repo.createCode({
			client_id: "test-client",
			redirect_uri: "https://rp.example/cb",
		});
		const ttl = await raw.pttl(`${keyPrefix}${created.code}`);
		expect(ttl).toBeGreaterThan(0);
		expect(ttl).toBeLessThanOrEqual(1000);

		await new Promise((resolve) => setTimeout(resolve, 1100));
		expect(await repo.findByCode(created.code)).toBeNull();
	});

	it("round-trips sid, nonce, redirect_uri, grantedScope, and grantedAudience through Redis", async () => {
		if (!raw) throw new Error("Redis test container did not start");
		const keyPrefix = `td4:fields:${Date.now()}:`;
		const { codeRepositoryClient } = makeIoredisClients(raw);
		const repo = new RedisCodeRepository(codeRepositoryClient, { keyPrefix });

		const created = await repo.createCode({
			client_id: "client-real",
			redirect_uri: "https://rp.example/callback",
			sid: "sid-real",
			nonce: "nonce-real",
			grantedScope: ["openid", "profile"],
			grantedAudience: ["https://api.example"],
		});
		const consumed = await repo.consumeByCode(created.code);

		expect(consumed?.client_id).toBe("client-real");
		expect(consumed?.redirect_uri).toBe("https://rp.example/callback");
		expect(consumed?.sid).toBe("sid-real");
		expect(consumed?.nonce).toBe("nonce-real");
		expect(consumed?.grantedScope).toEqual(["openid", "profile"]);
		expect(consumed?.grantedAudience).toEqual(["https://api.example"]);
	});
});
