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
 * transactions. One is opened at every password login that needs a second
 * factor and every step-up or enrollment a session starts, and an abandoned
 * one is reclaimed only by its expiry, so the login rate (anyone's, where the
 * Store lets anyone sign up) decides the store's size. At the cap it reclaims
 * what has expired, then refuses a new transaction as a store fault (the MFA
 * routes answer 503), as the challenge store and the replay seen-set do. It
 * never evicts a live transaction: that would end the ceremony of a user
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
import { MFA_MAX_TRANSACTIONS_PER_BINDING, type MfaTransaction } from "#/mfa/transactionStore.mjs";
import { defineModule } from "#/modules/manifest/index.mjs";
import { makeValidAppConfig, makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

const T0 = Date.UTC(2026, 8, 1);

const TX = (id: string, expiresAtMs = T0 + 600_000): MfaTransaction => ({
	id,
	purpose: "login",
	binding: { kind: "session", id: `express-session-${id}` },
	subject: "user-1",
	sid: undefined,
	continuation: {
		primary: {
			subject: "user-1",
			user: { id: "user-1" },
			claims: { email: "user-1@example.test" },
			recorded: {
				amr: ["pwd"],
				authentication: {
					primary: "pwd",
					federation: undefined,
					upstreamAmr: undefined,
					mfaAt: undefined,
				},
			},
			authTimeMs: T0,
			redirectTo: undefined,
			request: {},
		},
		done: [],
		interruptedBy: "mfa",
	},
	redirectTo: undefined,
	enrollment: "none",
	emailProof: "not_required",
	acrValues: undefined,
	challenge: undefined,
	pendingEnrollment: undefined,
	attempts: 0,
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
			"memory MfaTransactionStore is at its cap of 2 resident entries — transactions, session email proofs, first-binding marks, subject leases and recovery authorizations, expired ones not yet swept included; refusing a new one rather than evicting one",
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

	it("counts a session's email proofs against its cap beside its transactions: at the cap a new proof is refused as a store fault, recording nothing", async () => {
		const store = createMemoryMfaTransactionStore({ now: () => T0, maxEntries: 2 });
		await store.create(TX("tx-1"));
		await store.recordSessionEmailProof("user-1", "sid-1", T0, T0 + 300_000);
		expect(store.sessionEmailProofs).toBe(1);
		const refusal = await refusalOf(
			store.recordSessionEmailProof("user-1", "sid-2", T0, T0 + 300_000),
		);
		expect(refusal).toBeInstanceOf(MfaTransactionStoreFullError);
		expect(await store.sessionEmailProofAt("user-1", "sid-2", T0)).toBeNull();
		// Nor is a transaction let past the cap the proofs share.
		expect(await refusalOf(store.create(TX("tx-2")))).toBeInstanceOf(MfaTransactionStoreFullError);
		expect(store.transactions).toBe(1);
		expect(store.sessionEmailProofs).toBe(1);
	});

	it("replaces a session's proof at its cap: a replacement is no new entry", async () => {
		const store = createMemoryMfaTransactionStore({ now: () => T0, maxEntries: 1 });
		await store.recordSessionEmailProof("user-1", "sid-1", T0, T0 + 300_000);
		await store.recordSessionEmailProof("user-1", "sid-1", T0 + 1_000, T0 + 300_000);
		expect(await store.sessionEmailProofAt("user-1", "sid-1", T0 + 1_000)).toBe(T0 + 1_000);
		expect(store.sessionEmailProofs).toBe(1);
	});

	it("reclaims expired proofs before it refuses", async () => {
		let now = T0;
		const store = createMemoryMfaTransactionStore({
			now: () => now,
			maxEntries: 2,
			minSweepIntervalMs: 0,
		});
		await store.recordSessionEmailProof("user-1", "sid-short", T0, T0 + 1_000);
		await store.create(TX("long"));
		now = T0 + 2_000;
		await store.recordSessionEmailProof("user-1", "sid-next", T0 + 2_000, T0 + 300_000);
		expect(store.sessionEmailProofs).toBe(1);
		expect(store.transactions).toBe(1);
		expect(await store.sessionEmailProofAt("user-1", "sid-next", now)).toBe(T0 + 2_000);
	});

	it("counts first-binding marks against its cap beside its transactions and proofs: at the cap a new mark is refused as a store fault, recording nothing", async () => {
		const store = createMemoryMfaTransactionStore({ now: () => T0, maxEntries: 3 });
		await store.create(TX("tx-1"));
		await store.recordSessionEmailProof("user-1", "sid-1", T0, T0 + 300_000);
		await store.noteFirstBinding("user-1", T0, T0 + 300_000);
		expect(store.firstBindingMarks).toBe(1);
		const refusal = await refusalOf(store.noteFirstBinding("user-2", T0, T0 + 300_000));
		expect(refusal).toBeInstanceOf(MfaTransactionStoreFullError);
		expect(await store.firstBindingAt("user-2", T0)).toBeNull();
		// Nor is a transaction or a proof let past the cap the marks share.
		expect(await refusalOf(store.create(TX("tx-2")))).toBeInstanceOf(MfaTransactionStoreFullError);
		expect(
			await refusalOf(store.recordSessionEmailProof("user-1", "sid-2", T0, T0 + 300_000)),
		).toBeInstanceOf(MfaTransactionStoreFullError);
		expect(store.firstBindingMarks).toBe(1);
	});

	it("takes a subject's later note, and an earlier one, at its cap: a note for a subject with a mark is no new entry", async () => {
		const store = createMemoryMfaTransactionStore({ now: () => T0, maxEntries: 1 });
		await store.noteFirstBinding("user-1", T0, T0 + 300_000);
		await store.noteFirstBinding("user-1", T0 + 1_000, T0 + 300_000);
		await store.noteFirstBinding("user-1", T0 - 1_000, T0 + 300_000);
		expect(await store.firstBindingAt("user-1", T0)).toBe(T0 + 1_000);
		expect(store.firstBindingMarks).toBe(1);
	});

	it("reclaims expired marks before it refuses", async () => {
		let now = T0;
		const store = createMemoryMfaTransactionStore({
			now: () => now,
			maxEntries: 2,
			minSweepIntervalMs: 0,
		});
		await store.noteFirstBinding("user-short", T0, T0 + 1_000);
		await store.create(TX("long"));
		now = T0 + 2_000;
		await store.noteFirstBinding("user-next", T0 + 2_000, T0 + 300_000);
		expect(store.firstBindingMarks).toBe(1);
		expect(store.transactions).toBe(1);
		expect(await store.firstBindingAt("user-next", now)).toBe(T0 + 2_000);
	});

	it("counts subject leases against its cap beside its other entries: at the cap a new lease is refused as a store fault, holding nothing", async () => {
		const store = createMemoryMfaTransactionStore({ now: () => T0, maxEntries: 2 });
		await store.create(TX("tx-1"));
		const held = await store.acquireSubjectLease("user-1", { ttlMs: 60_000, generation: 0 });
		expect(held.outcome).toBe("acquired");
		expect(store.subjectLeases).toBe(1);
		const refusal = await refusalOf(
			store.acquireSubjectLease("user-2", { ttlMs: 60_000, generation: 0 }),
		);
		expect(refusal).toBeInstanceOf(MfaTransactionStoreFullError);
		expect(store.subjectLeases).toBe(1);
		expect(await refusalOf(store.create(TX("tx-2")))).toBeInstanceOf(MfaTransactionStoreFullError);
		// Asked again while it stands, the held lease is busy, not refused.
		expect(
			(await store.acquireSubjectLease("user-1", { ttlMs: 60_000, generation: 0 })).outcome,
		).toBe("busy");
	});

	it("reclaims a lapsed lease before it refuses, and takes a subject's next lease in its place", async () => {
		let now = T0;
		const store = createMemoryMfaTransactionStore({
			now: () => now,
			maxEntries: 2,
			minSweepIntervalMs: 0,
		});
		await store.acquireSubjectLease("user-short", { ttlMs: 1_000, generation: 0 });
		await store.create(TX("long"));
		now = T0 + 2_000;
		expect(
			(await store.acquireSubjectLease("user-short", { ttlMs: 1_000, generation: 0 })).outcome,
		).toBe("acquired");
		now = T0 + 4_000;
		expect(
			(await store.acquireSubjectLease("user-next", { ttlMs: 60_000, generation: 0 })).outcome,
		).toBe("acquired");
		expect(store.subjectLeases).toBe(1);
		expect(store.transactions).toBe(1);
	});

	it("counts recovery authorizations against its cap: at the cap a new one is refused as a store fault, and one replacing another's slot is no new entry", async () => {
		const store = createMemoryMfaTransactionStore({ now: () => T0, maxEntries: 2 });
		const authorization = (sid: string, recoveryId: string) => ({
			operation: "recover" as const,
			sid,
			recoveryId,
			expiresAtMs: T0 + 600_000,
		});
		await store.create(TX("tx-1"));
		await store.authorizeSubjectRecovery("user-1", authorization("sid-1", "r-1"));
		await store.authorizeSubjectRecovery("user-1", authorization("sid-1", "r-2"));
		const refusal = await refusalOf(
			store.authorizeSubjectRecovery("user-1", authorization("sid-2", "r-3")),
		);
		expect(refusal).toBeInstanceOf(MfaTransactionStoreFullError);
		expect(await refusalOf(store.create(TX("tx-2")))).toBeInstanceOf(MfaTransactionStoreFullError);
	});

	it("reclaims lapsed authorizations before it refuses", async () => {
		let now = T0;
		const store = createMemoryMfaTransactionStore({
			now: () => now,
			maxEntries: 2,
			minSweepIntervalMs: 0,
		});
		await store.authorizeSubjectRecovery("user-1", {
			operation: "recover",
			sid: "sid-1",
			recoveryId: "r-1",
			expiresAtMs: T0 + 1_000,
		});
		await store.create(TX("long"));
		now = T0 + 2_000;
		await store.create(TX("next"));
		expect(store.transactions).toBe(2);
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

describe("createMemoryMfaTransactionStore — the live transactions one binding holds", () => {
	const N = MFA_MAX_TRANSACTIONS_PER_BINDING;

	/** `TX(id)` bound to the session `session`. */
	const BOUND = (id: string, session: string, expiresAtMs = T0 + 600_000): MfaTransaction => ({
		...TX(id, expiresAtMs),
		binding: { kind: "session", id: session },
	});

	it("is five, a core constant", () => {
		expect(N).toBe(5);
	});

	it("takes one more at its cap for a binding at N: replacing the binding's oldest is no new entry", async () => {
		const store = createMemoryMfaTransactionStore({ now: () => T0, maxEntries: N });
		for (let i = 0; i < N; i++) await store.create(BOUND(`tab-${i}`, "s", T0 + 600_000 + i));
		await store.create(BOUND("next", "s", T0 + 700_000));
		expect(store.transactions).toBe(N);
		expect(await store.get("tab-0")).toBeNull();
		expect(await store.get("next")).not.toBeNull();
		// A binding below N still asks for a new entry, and is refused.
		expect(await refusalOf(store.create(BOUND("else", "t")))).toBeInstanceOf(
			MfaTransactionStoreFullError,
		);
		expect(store.transactions).toBe(N);
	});

	it("keeps no binding with no transaction: consumed, ended by its attempts, expired or swept", async () => {
		let now = T0;
		const store = createMemoryMfaTransactionStore({
			now: () => now,
			sweepInterval: 1,
			minSweepIntervalMs: 0,
		});
		await store.create(BOUND("consumed", "a"));
		await store.create(BOUND("spent", "b"));
		await store.create(BOUND("read-late", "c", T0 + 1_000));
		await store.create(BOUND("swept", "d", T0 + 1_000));
		expect(store.bindings).toBe(4);

		await store.consume("consumed", 1);
		await store.reserveAttempt("spent", 1);
		await store.reserveAttempt("spent", 1);
		expect(store.bindings).toBe(2);

		now = T0 + 2_000;
		expect(await store.get("read-late")).toBeNull();
		// A write sweeps "swept" away; the binding it opens is the one left.
		await store.create(BOUND("last", "e"));
		expect(store.transactions).toBe(1);
		expect(store.bindings).toBe(1);
		await store.consume("last", 1);
		expect(store.bindings).toBe(0);
	});

	it("ends at most the one binding's oldest, and holds N per binding across many bindings", async () => {
		const store = createMemoryMfaTransactionStore({ now: () => T0 });
		for (let s = 0; s < 3; s++) {
			for (let i = 0; i <= N; i++) await store.create(BOUND(`s${s}-${i}`, `s${s}`, T0 + 600_000 + i));
		}
		expect(store.transactions).toBe(3 * N);
		expect(store.bindings).toBe(3);
		for (let s = 0; s < 3; s++) expect(await store.get(`s${s}-0`)).toBeNull();
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

describe("core-mfa-transaction-store-memory.maxEntries", () => {
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

	it("keeps the path the cap moved from through the schema a composition root parses with, for the refusal", () => {
		// `AppConfigSchema` strips what it does not declare, before any module runs.
		const parsed = AppConfigSchema.parse({
			...makeValidAppConfig(),
			mfaTransactionStore: { adapter: "memory", memory: { maxEntries: "5000" } },
		});
		expect(parsed.mfaTransactionStore).toEqual({
			adapter: "memory",
			memory: { maxEntries: "5000" },
		});
	});

	it("is read from the module's own section", async () => {
		expect(memoryMfaTransactionStoreModule.requires ?? []).toEqual([]);
		expect((await storeOf({})).maxEntries).toBe(DEFAULT_MEMORY_MFA_TRANSACTION_STORE_MAX_ENTRIES);
		expect(
			(await storeOf({ "core-mfa-transaction-store-memory": { maxEntries: 5000 } })).maxEntries,
		).toBe(5000);
		expect(
			(await storeOf({ "core-mfa-transaction-store-memory": { maxEntries: "7000" } })).maxEntries,
		).toBe(7000);
	});

	it("refuses mfaTransactionStore.memory.maxEntries at boot, naming core-mfa-transaction-store-memory.maxEntries", async () => {
		const outcome = await bootWith({ mfaTransactionStore: { memory: { maxEntries: 5000 } } }).then(
			async (handle) => {
				await handle.dispose();
				return undefined;
			},
			(err: unknown) => err,
		);
		expect(outcome).toBeInstanceOf(BootError);
		expect((outcome as BootError).details).toEqual({
			reason: "config-path-relocated",
			relocated: [
				{
					module: "core-mfa-transaction-store-memory",
					from: "mfaTransactionStore.memory.maxEntries",
					to: "core-mfa-transaction-store-memory.maxEntries",
				},
			],
		});
	});

	it("refuses a value it cannot use at boot, naming the key", async () => {
		for (const bad of [0, 1.5, "lots", null, 2 ** 24 + 1]) {
			const outcome = await bootWith({
				"core-mfa-transaction-store-memory": { maxEntries: bad },
			}).then(
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
				/^core-mfa-transaction-store-memory\.maxEntries must be /,
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
