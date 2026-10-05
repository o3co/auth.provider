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
 * `foundationMfaFactorStoreModule` through `createApp`: it provides the
 * Store-backed factor store over its section's four URLs, built at boot, on
 * the Store transport settings the composition root must hand it — the user
 * repository's HTTP settings, whose `bearerToken`, `timeout` and
 * `maxResponseBytes` are read as the user repository's builder reads them,
 * and refused where that repository refuses them. It requires no slot, reads
 * no configuration beyond its own section, and declares no replica-unsafe
 * state.
 */

import {
	BootError,
	createApp,
	type MfaFactorRecord,
	type MfaFactorStore,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig } from "@o3co/auth-provider-core/testing";
import { type FakeStore, startFakeStore } from "@o3co/auth-provider-test-kit";
import { afterEach, beforeEach, describe, expect, expectTypeOf, it } from "vitest";
import {
	type FoundationMfaFactorStoreModuleOptions,
	foundationMfaFactorStoreModule,
	HttpMfaFactorStore,
	HttpUserRepository,
} from "#/index.mjs";
import {
	FOUNDATION_MFA_FACTOR_STORE_SECTION,
	foundationMfaFactorStoreLifecycle,
} from "#/mfa/section.mjs";
import {
	foundationMfaFactorStoreConfig,
	foundationUserRepositoryHttpConfig,
} from "#/testing/index.mjs";
import { consumer } from "./consumer.mjs";

const TOKEN = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

const RECORD: MfaFactorRecord = {
	id: "u1PIlRkb_cy7UmjYUKaL_A",
	subject: "user-1",
	kind: "totp",
	label: undefined,
	binding: "password",
	createdAt: new Date("2026-09-01T00:00:00.000Z"),
	lastUsedAt: undefined,
	version: 1,
	data: "v2.opaque-sealed-data",
};

let fake: FakeStore;
let disposable: { dispose(): Promise<void> } | undefined;
beforeEach(async () => {
	fake = await startFakeStore({ bearerToken: TOKEN });
});
afterEach(async () => {
	await disposable?.dispose();
	disposable = undefined;
	await fake.close();
});

/** The configuration: the section on `store`'s URLs. */
const configOver = (store = fake) => ({
	...makeValidAppConfig(),
	...foundationMfaFactorStoreConfig(store.urls),
});

/** Boots the module with `storeTransport` and a consumer, over `config`, and answers the store it provides. */
async function bootWith(storeTransport: unknown, config: object): Promise<MfaFactorStore> {
	const seen: { store?: MfaFactorStore } = {};
	disposable = await createApp({
		modules: [foundationMfaFactorStoreModule({ storeTransport }), consumer(seen)],
		bootstrapComponents: { config, pathResolver: (p: string) => p } as never,
	});
	if (seen.store === undefined) throw new Error("no store was provided");
	return seen.store;
}

/** Boots the module as a composition root does: handed the user repository's HTTP settings, `http` over `store`'s URLs. */
function provided(http: Readonly<Record<string, unknown>>, store = fake): Promise<MfaFactorStore> {
	return bootWith(foundationUserRepositoryHttpConfig(store.urls, http), configOver(store));
}

async function refusal(boot: () => Promise<unknown>): Promise<BootError> {
	try {
		await boot();
	} catch (error) {
		expect(error).toBeInstanceOf(BootError);
		return error as BootError;
	}
	throw new Error("expected the boot to be refused");
}

describe("foundationMfaFactorStoreModule", () => {
	it("is the section's module, provides mfaFactorStore at boot, requires no slot, and declares no replica-unsafe state", () => {
		const module = foundationMfaFactorStoreModule({
			storeTransport: foundationUserRepositoryHttpConfig({}),
		});
		expect(module.name).toBe(FOUNDATION_MFA_FACTOR_STORE_SECTION);
		expect(module.lifecycle).toEqual(foundationMfaFactorStoreLifecycle);
		expect(module.replicaSafety).toBeUndefined();
		expect(module.requires ?? []).toEqual([]);
		expect(module.optional ?? []).toEqual([]);
	});

	it("takes the Store transport settings as a required option", () => {
		expectTypeOf(foundationMfaFactorStoreModule).parameters.toEqualTypeOf<
			[FoundationMfaFactorStoreModuleOptions]
		>();
		expectTypeOf<FoundationMfaFactorStoreModuleOptions>().toEqualTypeOf<{
			readonly storeTransport: unknown;
		}>();
	});

	it("provides the Store-backed factor store over the section's URLs, with nothing else installed", async () => {
		const store = await provided({ bearerToken: TOKEN });
		expect(store).toBeInstanceOf(HttpMfaFactorStore);
		expect(store.kind).toBe("store");
		expect((await store.createIf(RECORD, null)).outcome).toBe("created");
		expect(await store.list("user-1")).toStrictEqual([RECORD]);
		expect(fake.requests.map((request) => request.endpoint)).toEqual(["create", "list"]);
	});

	it("sends the user repository's bearer token", async () => {
		await (await provided({ bearerToken: TOKEN })).list("user-1");
		expect(fake.requests.map((request) => request.headers.authorization)).toEqual([
			`Bearer ${TOKEN}`,
		]);
	});

	it("sends no Authorization header when the settings it is handed hold no bearer token", async () => {
		const open = await startFakeStore();
		try {
			await (await provided({}, open)).list("user-1");
			expect(open.requests.map((request) => request.headers.authorization)).toEqual([undefined]);
		} finally {
			await disposable?.dispose();
			disposable = undefined;
			await open.close();
		}
	});

	it("keeps to the user repository's deadline and response cap, read from text as an environment variable gives them", async () => {
		const store = await provided({ bearerToken: TOKEN, timeout: "300", maxResponseBytes: "256" });
		fake.answer("list", () => new Promise(() => {}));
		await expect(store.list("user-1")).rejects.toThrow("timed out after 300ms");
		fake.answer("list", () => ({
			status: 200,
			body: JSON.stringify({ factors: [], pad: "x".repeat(512) }),
		}));
		await expect(store.list("user-1")).rejects.toThrow("256-byte cap");
	});

	it("refuses the boot for a bearer token, a deadline or a cap the user repository refuses", async () => {
		const numberOf = (value: unknown) =>
			typeof value === "string" ? Number(value.trim()) : (value as number);
		for (const http of [
			{ bearerToken: "short" },
			{ bearerToken: "" },
			{ timeout: "" },
			{ timeout: 0 },
			{ maxResponseBytes: "" },
			{ maxResponseBytes: -1 },
		]) {
			const refused = await refusal(() => provided(http));
			expect(refused.reason, JSON.stringify(http)).toBe("provides-factory-failed");
			expect(refused.message, JSON.stringify(http)).toContain("HttpMfaFactorStore");
			// The user repository refuses the same value.
			expect(
				() =>
					new HttpUserRepository({
						authenticateUrl: "https://store.example/authenticate",
						authenticateByTokenUrl: "https://store.example/authenticate-by-token",
						timeout: "timeout" in http ? numberOf(http.timeout) : 5000,
						...("maxResponseBytes" in http
							? { maxResponseBytes: numberOf(http.maxResponseBytes) }
							: {}),
						...("bearerToken" in http ? { bearerToken: http.bearerToken } : {}),
					}),
				JSON.stringify(http),
			).toThrow();
		}
	});

	it("refuses the boot when the settings it is handed are absent or not a section of keys, rather than sending no credential", async () => {
		for (const storeTransport of [undefined, "https://store.example", 5000, null, ["x"]]) {
			const refused = await refusal(() => bootWith(storeTransport, configOver()));
			expect(refused.reason, JSON.stringify(storeTransport)).toBe("provides-factory-failed");
			expect(refused.message, JSON.stringify(storeTransport)).toContain(
				"storeTransport, the Store transport settings, must be a section of keys ({} for none)",
			);
		}
	});
});
