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
import { afterEach, describe, expect, it, vi } from "vitest";
import type { CodeRepository, CreateCodeInput } from "#/repositories/CodeRepository.mjs";
import { InMemoryCodeRepository } from "#/repositories/InMemoryCodeRepository.mjs";

describe("InMemoryCodeRepository", () => {
	let repo: InMemoryCodeRepository;

	// Minimal valid params for v0.5.1+ (D-1: client_id and redirect_uri
	// required); every other field named, unset (#626).
	const minimalParams: CreateCodeInput = {
		client_id: "test-client",
		redirect_uri: "https://rp.example/cb",
		code_challenge: undefined,
		code_challenge_method: undefined,
		nonce: undefined,
		sid: undefined,
		acr: undefined,
		grantedScope: undefined,
		grantedAudience: undefined,
	};

	afterEach(() => {
		repo?.dispose();
	});

	describe("createCode", () => {
		it("creates a code with random string", async () => {
			repo = new InMemoryCodeRepository();
			const code = await repo.createCode(minimalParams);

			expect(code.code).toBeDefined();
			expect(typeof code.code).toBe("string");
			expect(code.code.length).toBeGreaterThan(0);
		});

		it("stores code_challenge and code_challenge_method", async () => {
			repo = new InMemoryCodeRepository();
			const code = await repo.createCode({
				...minimalParams,
				code_challenge: "challenge123",
				code_challenge_method: "S256",
			});

			expect(code.code_challenge).toBe("challenge123");
			expect(code.code_challenge_method).toBe("S256");
		});

		it("generates unique codes", async () => {
			repo = new InMemoryCodeRepository();
			const codes = await Promise.all(
				Array.from({ length: 10 }, () => repo.createCode(minimalParams)),
			);
			const unique = new Set(codes.map((c) => c.code));
			expect(unique.size).toBe(10);
		});
	});

	describe("findByCode", () => {
		it("returns stored code", async () => {
			repo = new InMemoryCodeRepository();
			const created = await repo.createCode({ ...minimalParams, code_challenge: "ch" });
			const found = await repo.findByCode(created.code);

			expect(found).not.toBeNull();
			expect(found?.code).toBe(created.code);
			expect(found?.code_challenge).toBe("ch");
		});

		it("returns null for unknown code", async () => {
			repo = new InMemoryCodeRepository();
			const found = await repo.findByCode("nonexistent");

			expect(found).toBeNull();
		});
	});

	describe("consumeByCode", () => {
		it("returns and removes the code atomically", async () => {
			repo = new InMemoryCodeRepository();
			const created = await repo.createCode(minimalParams);
			const consumed = await repo.consumeByCode(created.code);

			expect(consumed).not.toBeNull();
			expect(consumed?.code).toBe(created.code);

			// Second consume returns null (replay prevention)
			const again = await repo.consumeByCode(created.code);
			expect(again).toBeNull();
		});

		it("returns null for unknown code", async () => {
			repo = new InMemoryCodeRepository();
			const consumed = await repo.consumeByCode("nonexistent");

			expect(consumed).toBeNull();
		});
	});

	describe("removeByCode", () => {
		it("removes a stored code", async () => {
			repo = new InMemoryCodeRepository();
			const created = await repo.createCode(minimalParams);
			await repo.removeByCode(created.code);

			const found = await repo.findByCode(created.code);
			expect(found).toBeNull();
		});

		it("does not throw for unknown code", async () => {
			repo = new InMemoryCodeRepository();
			await expect(repo.removeByCode("nonexistent")).resolves.toBeUndefined();
		});
	});

	describe("grantedScope / grantedAudience round-trip", () => {
		it("round-trips grantedScope and grantedAudience", async () => {
			const repo = new InMemoryCodeRepository();
			const created = await repo.createCode({
				...minimalParams,
				grantedScope: ["read"],
				grantedAudience: ["https://api.example"],
			});
			const found = await repo.findByCode(created.code);
			expect(found?.grantedScope).toEqual(["read"]);
			expect(found?.grantedAudience).toEqual(["https://api.example"]);
			repo.dispose();
		});
	});

	describe("expiration", () => {
		it("expires codes after defaultExpiresIn", async () => {
			repo = new InMemoryCodeRepository({ defaultExpiresIn: 0.05 }); // 50ms
			const created = await repo.createCode(minimalParams);

			await new Promise((r) => setTimeout(r, 100));

			const found = await repo.findByCode(created.code);
			expect(found).toBeNull();
		});

		it("respects per-code expiresIn override", async () => {
			repo = new InMemoryCodeRepository({ defaultExpiresIn: 10 });
			const created = await repo.createCode({ ...minimalParams, expiresIn: 0.05 }); // 50ms

			await new Promise((r) => setTimeout(r, 100));

			const found = await repo.findByCode(created.code);
			expect(found).toBeNull();
		});

		it("refuses a lifetime that is not a positive number of seconds, and stores nothing", async () => {
			// NaN is never `>= now`: a code minted with a NaN lifetime was
			// redeemable for ever, and no sweep ever reclaimed it. An infinite
			// one is no lifetime either, and zero or less is a code that is dead
			// on arrival — which the Redis repository cannot store at all.
			repo = new InMemoryCodeRepository();
			for (const expiresIn of [
				Number.NaN,
				Number.POSITIVE_INFINITY,
				Number.NEGATIVE_INFINITY,
				0,
				-1,
			]) {
				await expect(repo.createCode({ ...minimalParams, expiresIn })).rejects.toThrow(RangeError);
			}
			expect((repo as unknown as { codes: Map<string, unknown> }).codes.size).toBe(0);
		});

		it("refuses a default lifetime that is not a positive number of seconds, when it is built", () => {
			for (const defaultExpiresIn of [Number.NaN, Number.POSITIVE_INFINITY, 0, -1]) {
				expect(() => new InMemoryCodeRepository({ defaultExpiresIn })).toThrow(RangeError);
			}
		});

		it("consumeByCode refuses an expired code, and burns it on the way out", async () => {
			// The expiry checks on `findByCode` and `consumeByCode` are separate
			// guards and only the former was pinned — but `consumeByCode` is the
			// one `/token` calls, so it is the one that decides whether an
			// expired authorization code is still redeemable. A code past its
			// TTL must not be exchangeable for tokens no matter how it is
			// presented.
			repo = new InMemoryCodeRepository({ defaultExpiresIn: 0.05 }); // 50ms
			const created = await repo.createCode(minimalParams);

			await new Promise((r) => setTimeout(r, 100));

			expect(await repo.consumeByCode(created.code)).toBeNull();
			// Deleted before the expiry verdict, so a replay of an expired code
			// is indistinguishable from a replay of a consumed one.
			expect(await repo.consumeByCode(created.code)).toBeNull();
		});

		it("sweeps expired codes that were never presented", async () => {
			// Codes that are minted and then abandoned — the user closes the tab
			// — are never read again, so neither read-path guard ever runs on
			// them and only the periodic sweep reclaims them. Without it the map
			// grows for the life of the process, which is why this asserts on
			// the map itself: "findByCode returns null" would pass whether or
			// not the sweep exists, since that path filters by expiry anyway.
			vi.useFakeTimers();
			try {
				repo = new InMemoryCodeRepository({ defaultExpiresIn: 1 });
				await repo.createCode(minimalParams);
				const stored = (repo as unknown as { codes: Map<string, unknown> }).codes;
				expect(stored.size).toBe(1);

				await vi.advanceTimersByTimeAsync(10_000);

				expect(stored.size).toBe(0);
			} finally {
				vi.useRealTimers();
			}
		});
	});

	// D-1 / TS-1: client_id and redirect_uri are required fields on CodeData and
	// must be required on CodeRepository.createCode params, so omitting either
	// is a TS error at every call site (including consumer custom impls).
	//
	// Each probe is the full input with that one field taken out. Since #626
	// every other field is a required key too, so a probe that named only the
	// other identity field would be refused for the keys it leaves out, and its
	// directive consumed whether or not the field under test were required.
	//
	// Type-only assertions: the directives are attached to typed-variable
	// declarations rather than runtime call sites, so vitest's typecheck pass
	// validates the contract without storing invalid records in the repository.
	describe("D-1 / TS-1: createCode requires client_id and redirect_uri at compile time", () => {
		it("compile-time guard: omitting client_id is a type error", () => {
			const { client_id: _omitted, ...withoutClientId } = minimalParams;
			// @ts-expect-error client_id is required on CodeData (D-1)
			const _params: Parameters<CodeRepository["createCode"]>[0] = withoutClientId;
		});

		it("compile-time guard: omitting redirect_uri is a type error", () => {
			const { redirect_uri: _omitted, ...withoutRedirectUri } = minimalParams;
			// @ts-expect-error redirect_uri is required on CodeData (D-1)
			const _params: Parameters<CodeRepository["createCode"]>[0] = withoutRedirectUri;
		});

		it("populated client_id and redirect_uri round-trip via findByCode", async () => {
			const repo = new InMemoryCodeRepository();
			const created = await repo.createCode({
				...minimalParams,
				client_id: "client-abc",
				redirect_uri: "https://rp.example/cb",
			});
			const found = await repo.findByCode(created.code);
			expect(found?.client_id).toBe("client-abc");
			expect(found?.redirect_uri).toBe("https://rp.example/cb");
			repo.dispose();
		});
	});

	describe("TODO-F-3 extended fields (nonce / sid)", () => {
		it("roundtrips nonce + sid + grantedScope via createCode → findByCode", async () => {
			repo = new InMemoryCodeRepository();
			const { code } = await repo.createCode({
				...minimalParams,
				code_challenge: "cc",
				code_challenge_method: "S256",
				nonce: "n-abc",
				sid: "sid-123",
				grantedScope: ["openid", "profile"],
				expiresIn: 60,
			});
			const r = await repo.findByCode(code);
			expect(r?.nonce).toBe("n-abc");
			expect(r?.sid).toBe("sid-123");
			expect(r?.grantedScope).toEqual(["openid", "profile"]);
		});

		it("consumeByCode returns the fields exactly once then removes them", async () => {
			repo = new InMemoryCodeRepository();
			const { code } = await repo.createCode({
				...minimalParams,
				sid: "sid-1",
				nonce: "n-1",
			});
			const first = await repo.consumeByCode(code);
			expect(first?.sid).toBe("sid-1");
			expect(first?.nonce).toBe("n-1");
			const second = await repo.consumeByCode(code);
			expect(second).toBeNull();
		});

		it("round-trips every field with its own value, through both reads (#626)", async () => {
			// The types catch a field forgotten by a copy, not two fields of the
			// same type swapped: `nonce`, `sid`, `acr` and the challenge are all
			// strings. Every value is distinct here, and the whole record is
			// compared.
			repo = new InMemoryCodeRepository();
			const params: CreateCodeInput = {
				client_id: "client-rt",
				redirect_uri: "https://rp.example/rt",
				code_challenge: "challenge-rt",
				code_challenge_method: "S256",
				nonce: "nonce-rt",
				sid: "sid-rt",
				acr: "urn:example:acr:mfa",
				expiresIn: 90,
				grantedScope: ["openid", "read"],
				grantedAudience: ["https://api.example"],
			};
			const created = await repo.createCode(params);
			const expected = { ...params, code: created.code };
			expect(created).toStrictEqual(expected);
			expect(await repo.findByCode(created.code)).toStrictEqual(expected);
			expect(await repo.consumeByCode(created.code)).toStrictEqual(expected);
		});

		it("names every field it has no value for as undefined, rather than leaving it out (#626)", async () => {
			repo = new InMemoryCodeRepository();
			const created = await repo.createCode(minimalParams);
			const found = await repo.findByCode(created.code);
			// The read `/token` makes, which builds its record separately from
			// `findByCode`'s.
			const consumed = await repo.consumeByCode(created.code);
			for (const key of [
				"code_challenge",
				"code_challenge_method",
				"nonce",
				"sid",
				"acr",
				"grantedScope",
				"grantedAudience",
			]) {
				// `toHaveProperty(key, undefined)` fails on a missing key as well as
				// on a value.
				expect(created, key).toHaveProperty(key, undefined);
				expect(found, key).toHaveProperty(key, undefined);
				expect(consumed, key).toHaveProperty(key, undefined);
			}
		});

		it("createCode without nonce/sid leaves them undefined (backward compat)", async () => {
			repo = new InMemoryCodeRepository();
			const { code } = await repo.createCode(minimalParams);
			const r = await repo.findByCode(code);
			expect(r?.nonce).toBeUndefined();
			expect(r?.sid).toBeUndefined();
		});
	});
});
