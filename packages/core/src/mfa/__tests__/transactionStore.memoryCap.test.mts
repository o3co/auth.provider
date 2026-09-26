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

/*
 * The in-process MFA transaction store holds at most `maxEntries`
 * transactions. A transaction is opened at every password login that needs a
 * second factor and at every step-up or enrollment a session starts, and one
 * the user abandons is never presented again, so only its expiry reclaims it:
 * the sweep bounds the store by time, and the login rate — anyone's, where
 * the Store lets anyone sign up — decides its size. At the cap it reclaims
 * what has expired, then refuses a new transaction as a store fault (the MFA
 * routes answer 503), the way the challenge store and the replay seen-set do.
 * It never evicts a live transaction: that would end the ceremony of a user
 * already typing a code.
 */

import { describe, expect, it } from "vitest";
import { createApp } from "#/boot/create-app.mjs";
import { BootError, type BootstrapMap } from "#/boot/types.mjs";
import { AppConfigSchema } from "#/config/application.schema.mjs";
import {
	createMfaTransactionStoreFactory,
	registerBuiltinMfaTransactionStores,
} from "#/mfa/factory.mjs";
import {
	createMemoryMfaTransactionStore,
	DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MAX_ENTRIES,
	type MemoryMfaTransactionStore,
	MfaTransactionStoreFullError,
} from "#/mfa/memoryTransactionStore.mjs";
import { memoryMfaTransactionStoreModule } from "#/mfa/module.mjs";
import type { MfaTransaction } from "#/mfa/transactionStore.mjs";
import { defineModule } from "#/modules/manifest/index.mjs";
import { makeValidAppConfig, makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

const T0 = Date.UTC(2026, 8, 1);

const TX = (id: string, expiresAtMs = T0 + 600_000): MfaTransaction => ({
	id,
	purpose: "login",
	sessionId: `express-session-${id}`,
	subject: "user-1",
	sid: undefined,
	primary: { method: "pwd", authTimeMs: T0 },
	user: { id: "user-1" },
	redirectTo: undefined,
	enrollment: "none",
	emailProof: "not_required",
	acrValues: undefined,
	challenge: undefined,
	pendingEnrollment: undefined,
	attempts: 0,
	sends: 0,
	lastSentAtMs: undefined,
	createdAtMs: T0,
	expiresAtMs,
	version: 1,
});

const refusalOf = (promise: Promise<unknown>): Promise<unknown> =>
	promise.then(
		() => undefined,
		(err: unknown) => err,
	);

describe("createMemoryMfaTransactionStore — a cap on the transactions it holds", () => {
	it("holds at most a hundred thousand transactions by default, and says what its cap is", () => {
		expect(DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MAX_ENTRIES).toBe(100_000);
		expect(createMemoryMfaTransactionStore().maxEntries).toBe(
			DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MAX_ENTRIES,
		);
		expect(createMemoryMfaTransactionStore({ maxEntries: 5 }).maxEntries).toBe(5);
	});

	it("refuses a new transaction at its cap as a store fault, recording nothing and evicting nothing", async () => {
		const store = createMemoryMfaTransactionStore({ now: () => T0, maxEntries: 2 });
		await store.create(TX("tx-1"));
		await store.create(TX("tx-2"));

		const refusal = await refusalOf(store.create(TX("tx-3")));
		expect(refusal).toBeInstanceOf(MfaTransactionStoreFullError);
		// Not the port's own refusal of a bad expiry, which a caller reads as
		// something it did.
		expect(refusal).not.toBeInstanceOf(RangeError);
		expect(refusal).toMatchObject({ name: "MfaTransactionStoreFullError", reason: "full" });
		expect((refusal as Error).message).toBe(
			"memory MfaTransactionStore is at its cap of 2 live transactions; refusing a new one rather than evicting one",
		);

		expect(store.transactions).toBe(2);
		expect(await store.get("tx-3")).toBeNull();
		expect(await store.get("tx-1")).not.toBeNull();
		expect(await store.get("tx-2")).not.toBeNull();
	});

	it("still answers a duplicate as a duplicate at its cap", async () => {
		const store = createMemoryMfaTransactionStore({ now: () => T0, maxEntries: 1 });
		await store.create(TX("tx-1"));
		const refusal = await refusalOf(store.create(TX("tx-1")));
		expect(refusal).toBeInstanceOf(Error);
		expect(refusal).not.toBeInstanceOf(MfaTransactionStoreFullError);
	});

	it("has room again once a transaction is consumed", async () => {
		const store = createMemoryMfaTransactionStore({ now: () => T0, maxEntries: 1 });
		await store.create(TX("tx-1"));
		expect(await store.consume("tx-1", 1)).not.toBeNull();
		await store.create(TX("tx-2"));
		expect(store.transactions).toBe(1);
	});

	it("reclaims expired transactions before it refuses", async () => {
		let now = T0;
		const store = createMemoryMfaTransactionStore({
			now: () => now,
			maxEntries: 2,
			minSweepIntervalMs: 0,
		});
		await store.create(TX("short", T0 + 1_000));
		await store.create(TX("long"));
		now = T0 + 2_000;
		await store.create(TX("next"));
		expect(store.transactions).toBe(2);
		expect(await store.get("long")).not.toBeNull();
	});

	it("scans for expired transactions at its cap no more often than its sweep floor", async () => {
		let now = T0;
		const store = createMemoryMfaTransactionStore({
			now: () => now,
			maxEntries: 1,
			// The floor is on the monotonic clock, which this test cannot move:
			// an hour is a floor the test never passes.
			minSweepIntervalMs: 3_600_000,
		});
		await store.create(TX("first", T0 + 1_000));
		// The first scan at the cap is due; nothing has expired yet.
		expect(await refusalOf(store.create(TX("second")))).toBeInstanceOf(
			MfaTransactionStoreFullError,
		);
		now = T0 + 2_000;
		// "first" has expired, but the floor has not passed since that scan:
		// no second scan, so the store is still full.
		expect(await refusalOf(store.create(TX("third")))).toBeInstanceOf(MfaTransactionStoreFullError);
		expect(store.transactions).toBe(1);
	});

	it("refuses a cap above what a Map can hold, 2^24 entries", () => {
		expect(createMemoryMfaTransactionStore({ maxEntries: 2 ** 24 }).maxEntries).toBe(16_777_216);
		expect(() => createMemoryMfaTransactionStore({ maxEntries: 2 ** 24 + 1 })).toThrow(
			new RangeError(
				"createMemoryMfaTransactionStore: maxEntries must be at most 16777216, the most entries a Map holds (got 16777217)",
			),
		);
	});

	it("refuses a cap that is not a positive whole number, an explicit null included, rather than holding no cap", () => {
		for (const bad of [0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, null]) {
			expect(
				() => createMemoryMfaTransactionStore({ maxEntries: bad } as never),
				String(bad),
			).toThrow(
				new RangeError(
					`createMemoryMfaTransactionStore: maxEntries must be a positive whole number (got ${String(bad)})`,
				),
			);
		}
	});

	it("refuses a sweep setting it cannot use, naming itself", () => {
		expect(() => createMemoryMfaTransactionStore({ sweepInterval: 0 })).toThrow(
			new RangeError(
				"createMemoryMfaTransactionStore: sweepInterval must be a positive whole number (got 0)",
			),
		);
	});
});

describe("the MfaTransactionStore adapter factory — the memory adapter's cap", () => {
	it("builds the memory adapter with the cap its config gives, and the default without one", async () => {
		const factory = createMfaTransactionStoreFactory();
		registerBuiltinMfaTransactionStores(factory);
		const capped = (await factory.create({
			type: "memory",
			maxEntries: 5,
		})) as MemoryMfaTransactionStore;
		expect(capped.maxEntries).toBe(5);
		const fromText = (await factory.create({
			type: "memory",
			maxEntries: "7",
		})) as MemoryMfaTransactionStore;
		expect(fromText.maxEntries).toBe(7);
		const plain = (await factory.create({ type: "memory" })) as MemoryMfaTransactionStore;
		expect(plain.maxEntries).toBe(DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MAX_ENTRIES);
	});

	it("refuses a cap it cannot use, naming the key", async () => {
		const factory = createMfaTransactionStoreFactory();
		registerBuiltinMfaTransactionStores(factory);
		for (const bad of [0, null, "lots"]) {
			await expect(
				factory.create({ type: "memory", maxEntries: bad }),
				String(bad),
			).rejects.toThrow(
				new RangeError(
					`MfaTransactionStore memory adapter maxEntries must be a positive whole number (got ${JSON.stringify(bad)})`,
				),
			);
		}
	});
});

describe("mfaTransactionStore.memory.maxEntries", () => {
	const bootWith = (extra: Record<string, unknown>) =>
		createApp({
			modules: [
				memoryMfaTransactionStoreModule,
				defineModule({
					name: "test:reads-the-mfa-transaction-store",
					requires: ["mfaTransactionStore"] as const,
					// A contribution makes the module a root of the boot's
					// activation: its route reads the slot, so the provider runs.
					contributes: {
						routes: [
							() => ({
								id: "test:reads-the-mfa-transaction-store",
								mountPath: "/reads-the-mfa-transaction-store",
								handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
							}),
						],
					},
				}),
			],
			bootstrapComponents: {
				config: { ...makeValidCoreConfig(), ...extra } as never,
				pathResolver: (s: string) => s,
			} satisfies Record<string, unknown> as BootstrapMap,
		});

	const storeOf = async (extra: Record<string, unknown>): Promise<MemoryMfaTransactionStore> => {
		const handle = await bootWith(extra);
		const store = handle.components.mfaTransactionStore as MemoryMfaTransactionStore;
		await handle.dispose();
		return store;
	};

	it("survives the schema a composition root parses its config with", () => {
		// `AppConfigSchema` strips what it does not declare, before any module runs.
		const parsed = AppConfigSchema.parse({
			...makeValidAppConfig(),
			mfaTransactionStore: { adapter: "memory", memory: { maxEntries: "5000" } },
		});
		expect(parsed.mfaTransactionStore?.memory?.maxEntries).toBe("5000");
	});

	it("is read by the module, which requires config", async () => {
		expect(memoryMfaTransactionStoreModule.requires ?? []).toEqual(["config"]);
		expect((await storeOf({})).maxEntries).toBe(DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MAX_ENTRIES);
		expect(
			(await storeOf({ mfaTransactionStore: { memory: { maxEntries: 5000 } } })).maxEntries,
		).toBe(5000);
		expect(
			(await storeOf({ mfaTransactionStore: { memory: { maxEntries: "7000" } } })).maxEntries,
		).toBe(7000);
	});

	it("refuses a value it cannot use at boot, naming the key", async () => {
		for (const bad of [0, 1.5, "lots", null, 2 ** 24 + 1]) {
			const outcome = await bootWith({ mfaTransactionStore: { memory: { maxEntries: bad } } }).then(
				async (handle) => {
					await handle.dispose();
					return undefined;
				},
				(err: unknown) => err,
			);
			expect(outcome, String(bad)).toBeInstanceOf(BootError);
			expect((outcome as BootError).reason, String(bad)).toBe("provides-factory-failed");
			const cause = (outcome as BootError).cause;
			expect(cause, String(bad)).toBeInstanceOf(RangeError);
			expect((cause as Error).message, String(bad)).toMatch(
				/^mfaTransactionStore\.memory\.maxEntries must be /,
			);
		}
	});
});

describe("core barrel — the memory MFA transaction store's cap", () => {
	it("re-exports the default and the refusal, for a caller that tells a full store from another fault", async () => {
		const core = await import("#/index.mjs");
		expect(core.DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MAX_ENTRIES).toBe(
			DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MAX_ENTRIES,
		);
		expect(core.MfaTransactionStoreFullError).toBe(MfaTransactionStoreFullError);
	});
});
