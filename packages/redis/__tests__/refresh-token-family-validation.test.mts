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
import { RefreshTokenStorageError } from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";
import type {
	DisposableRefreshTokenFamilyClient,
	RefreshTokenFamilyClient,
	RefreshTokenFamilyMultiClient,
} from "../src/clients.mjs";
import {
	createRedisRefreshTokenFamilyStore,
	redisRefreshTokenFamilyStoreBuilder,
} from "../src/refresh-token-family.mjs";

// Lightweight in-memory mock — only `get` / `pttl` are exercised by the
// `findFamily` corrupt-data tests below. The other methods are stubs that
// return shapes wide enough for the type contract; tests do not invoke
// them.
const makeMockClient = (
	store: Map<string, string>,
	pttls: Map<string, number>,
): RefreshTokenFamilyClient => {
	const noopMulti: RefreshTokenFamilyMultiClient = {
		set: () => noopMulti,
		exec: async () => [],
	};
	const self: RefreshTokenFamilyClient = {
		set: async () => "OK",
		get: async (k) => store.get(k) ?? null,
		pttl: async (k) => pttls.get(k) ?? -2,
		watch: async () => "OK",
		unwatch: async () => "OK",
		multi: () => noopMulti,
		duplicate: (): DisposableRefreshTokenFamilyClient =>
			Object.assign(
				{ ...self },
				{
					[Symbol.asyncDispose]: async () => {},
				},
			),
	};
	return self;
};

describe("TS-M1: RedisRefreshTokenFamilyStore.findFamily — corrupt-data validation", () => {
	const keyPrefix = "rtfam:";

	it("throws RefreshTokenStorageError({reason:'corrupt-data'}) for truncated JSON in Redis", async () => {
		const store = new Map<string, string>([[`${keyPrefix}fam-1`, "{truncated"]]);
		const pttls = new Map<string, number>([[`${keyPrefix}fam-1`, 60_000]]);
		const repo = createRedisRefreshTokenFamilyStore({
			client: makeMockClient(store, pttls),
			keyPrefix,
		});

		await expect(repo.findFamily("fam-1")).rejects.toBeInstanceOf(RefreshTokenStorageError);
		const err = await repo.findFamily("fam-1").catch((e: unknown) => e);
		expect((err as RefreshTokenStorageError).reason).toBe("corrupt-data");
	});

	it("throws corrupt-data for envelope missing required fields", async () => {
		const store = new Map<string, string>([
			// activeJti, revoked, expiresAtMs all absent
			[`${keyPrefix}fam-2`, JSON.stringify({ familyId: "fam-2" })],
		]);
		const pttls = new Map<string, number>([[`${keyPrefix}fam-2`, 60_000]]);
		const repo = createRedisRefreshTokenFamilyStore({
			client: makeMockClient(store, pttls),
			keyPrefix,
		});

		const err = await repo.findFamily("fam-2").catch((e: unknown) => e);
		expect(err).toBeInstanceOf(RefreshTokenStorageError);
		expect((err as RefreshTokenStorageError).reason).toBe("corrupt-data");
	});

	it("throws corrupt-data for wrong field type (revoked: 'yes' instead of boolean)", async () => {
		const store = new Map<string, string>([
			[
				`${keyPrefix}fam-3`,
				JSON.stringify({
					familyId: "fam-3",
					activeJti: "j1",
					revoked: "yes",
					expiresAtMs: Date.now() + 60_000,
				}),
			],
		]);
		const pttls = new Map<string, number>([[`${keyPrefix}fam-3`, 60_000]]);
		const repo = createRedisRefreshTokenFamilyStore({
			client: makeMockClient(store, pttls),
			keyPrefix,
		});

		const err = await repo.findFamily("fam-3").catch((e: unknown) => e);
		expect((err as RefreshTokenStorageError).reason).toBe("corrupt-data");
	});

	it("throws corrupt-data for unknown extra field (.strict() rejects schema drift)", async () => {
		const store = new Map<string, string>([
			[
				`${keyPrefix}fam-4`,
				JSON.stringify({
					familyId: "fam-4",
					activeJti: "j1",
					revoked: false,
					expiresAtMs: Date.now() + 60_000,
					unknownFutureField: "value",
				}),
			],
		]);
		const pttls = new Map<string, number>([[`${keyPrefix}fam-4`, 60_000]]);
		const repo = createRedisRefreshTokenFamilyStore({
			client: makeMockClient(store, pttls),
			keyPrefix,
		});

		const err = await repo.findFamily("fam-4").catch((e: unknown) => e);
		expect((err as RefreshTokenStorageError).reason).toBe("corrupt-data");
	});

	it("returns the family normally for a valid envelope (regression guard)", async () => {
		const expiresAtMs = Date.now() + 60_000;
		const store = new Map<string, string>([
			[
				`${keyPrefix}fam-ok`,
				JSON.stringify({
					familyId: "fam-ok",
					activeJti: "j1",
					revoked: false,
					expiresAtMs,
				}),
			],
		]);
		const pttls = new Map<string, number>([[`${keyPrefix}fam-ok`, 60_000]]);
		const repo = createRedisRefreshTokenFamilyStore({
			client: makeMockClient(store, pttls),
			keyPrefix,
		});

		const fam = await repo.findFamily("fam-ok");
		expect(fam).not.toBeNull();
		expect(fam?.familyId).toBe("fam-ok");
		expect(fam?.activeJti).toBe("j1");
		expect(fam?.revoked).toBe(false);
	});
});

describe("TS-6: redisRefreshTokenFamilyStoreBuilder — client guard", () => {
	it("throws when 'client' option is missing (config = {})", () => {
		expect(() =>
			redisRefreshTokenFamilyStoreBuilder({} as never, { lifecycle: undefined } as never),
		).toThrow("redisRefreshTokenFamilyStoreBuilder: 'client' option is required");
	});

	it("succeeds when 'client' is present", () => {
		const client = makeMockClient(new Map(), new Map());
		const store = redisRefreshTokenFamilyStoreBuilder(
			{ client } as never,
			{ lifecycle: undefined } as never,
		);
		expect(store).toBeDefined();
		expect(store.kind).toBe("redis");
	});
});
