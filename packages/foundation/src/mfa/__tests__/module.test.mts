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
 * the user repository's transport settings (`repositories.user.http`'s
 * `bearerToken`, `timeout` and `maxResponseBytes`, read as the user
 * repository's builder reads them), with its version floor in the
 * `replaySeenSet` slot. It declares no replica-unsafe state.
 */

import {
	BootError,
	createApp,
	createMemoryReplaySeenSet,
	defineModule,
	type MfaFactorRecord,
	type MfaFactorStore,
	memoryReplaySeenSetModule,
	type ReplaySeenSet,
} from "@o3co/auth-provider-core";
import { makeValidAppConfig, withUserRepositoryHttp } from "@o3co/auth-provider-core/testing";
import { type FakeStore, startFakeStore } from "@o3co/auth-provider-test-kit";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { foundationMfaFactorStoreModule, HttpMfaFactorStore } from "#/index.mjs";
import {
	FOUNDATION_MFA_FACTOR_STORE_SECTION,
	foundationMfaFactorStoreLifecycle,
} from "#/mfa/section.mjs";
import { foundationMfaFactorStoreConfig } from "#/testing/index.mjs";
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

/** The configuration with the section on `store`'s URLs and the user repository's `http` block as given. */
const configOver = (http: Readonly<Record<string, unknown>> | undefined, store = fake) => {
	const base = makeValidAppConfig();
	return {
		...(http === undefined ? base : withUserRepositoryHttp(base, http)),
		...foundationMfaFactorStoreConfig(store.urls),
	};
};

/** A module providing `seen` as the seen-set. */
const seenSetModule = (seen: ReplaySeenSet) =>
	defineModule({ name: "test-replay-seen-set", provides: { replaySeenSet: () => seen } });

/** Boots the module with a consumer and answers the store it provides. */
async function provided(
	http: Readonly<Record<string, unknown>> | undefined,
	seenSet = seenSetModule(createMemoryReplaySeenSet()),
	store = fake,
): Promise<MfaFactorStore> {
	const seen: { store?: MfaFactorStore } = {};
	disposable = await createApp({
		modules: [foundationMfaFactorStoreModule, seenSet, consumer(seen)],
		bootstrapComponents: {
			config: configOver(http, store),
			pathResolver: (p: string) => p,
		} as never,
	});
	if (seen.store === undefined) throw new Error("no store was provided");
	return seen.store;
}

async function refusal(http: Readonly<Record<string, unknown>>): Promise<BootError> {
	try {
		await provided(http);
	} catch (error) {
		expect(error).toBeInstanceOf(BootError);
		return error as BootError;
	}
	throw new Error("expected the boot to be refused");
}

describe("foundationMfaFactorStoreModule", () => {
	it("is the section's module, provides mfaFactorStore at boot, and declares no replica-unsafe state", () => {
		expect(foundationMfaFactorStoreModule.name).toBe(FOUNDATION_MFA_FACTOR_STORE_SECTION);
		expect(foundationMfaFactorStoreModule.lifecycle).toEqual(foundationMfaFactorStoreLifecycle);
		expect(foundationMfaFactorStoreModule.replicaSafety).toBeUndefined();
		expect(foundationMfaFactorStoreModule.requires).toEqual(["config", "replaySeenSet"]);
	});

	it("provides the Store-backed factor store over the section's URLs", async () => {
		const store = await provided({ bearerToken: TOKEN });
		expect(store).toBeInstanceOf(HttpMfaFactorStore);
		expect(store.kind).toBe("store");
		await store.create(RECORD);
		expect(await store.list("user-1")).toStrictEqual([RECORD]);
		expect(fake.requests.map((request) => request.endpoint)).toEqual(["create", "list"]);
	});

	it("sends the user repository's bearer token", async () => {
		await (await provided({ bearerToken: TOKEN })).list("user-1");
		expect(fake.requests.map((request) => request.headers.authorization)).toEqual([
			`Bearer ${TOKEN}`,
		]);
	});

	it("sends no Authorization header when the user repository has no bearer token", async () => {
		const open = await startFakeStore();
		try {
			await (await provided(undefined, undefined, open)).list("user-1");
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
		for (const http of [
			{ bearerToken: "short" },
			{ bearerToken: "" },
			{ timeout: "" },
			{ timeout: 0 },
			{ maxResponseBytes: "" },
			{ maxResponseBytes: -1 },
		]) {
			const refused = await refusal(http);
			expect(refused.reason, JSON.stringify(http)).toBe("provides-factory-failed");
			expect(refused.message, JSON.stringify(http)).toContain("HttpMfaFactorStore");
		}
	});

	it("keeps its version floor in the replaySeenSet slot", async () => {
		const scopes: string[] = [];
		const inner = createMemoryReplaySeenSet();
		const recording: ReplaySeenSet = {
			kind: "recording",
			markSeen: (scope, key, expiresAtMs) => {
				scopes.push(scope);
				return inner.markSeen(scope, key, expiresAtMs);
			},
			contains: (scope, key) => inner.contains(scope, key),
		};
		const store = await provided({ bearerToken: TOKEN }, seenSetModule(recording));
		await store.create(RECORD);
		await store.update("user-1", RECORD.id, 1, {
			data: "v2.x",
			label: undefined,
			lastUsedAt: undefined,
		});
		expect(new Set(scopes)).toEqual(new Set(["mfa-factor-version-floor"]));
	});

	it("boots beside core's in-process seen-set", async () => {
		const seen: { store?: MfaFactorStore } = {};
		disposable = await createApp({
			modules: [foundationMfaFactorStoreModule, memoryReplaySeenSetModule, consumer(seen)],
			bootstrapComponents: {
				config: configOver(undefined),
				pathResolver: (p: string) => p,
			} as never,
		});
		expect(seen.store?.kind).toBe("store");
	});
});
