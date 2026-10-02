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
import { BUNDLED_STORE_WRITE_LIFETIME_MS } from "#/adapters/conditionalWrite.mjs";
import { createApp, defineModule } from "#/index.mjs";
import type { Logger } from "#/logging/Logger.mjs";
import type { MfaFactorRecord, MfaFactorStore } from "#/mfa/factorStore.mjs";
import { createMfaFactorStoreFactory, registerBuiltinMfaFactorStores } from "#/mfa/factory.mjs";
import { createMemoryMfaFactorStore } from "#/mfa/memoryFactorStore.mjs";
import { memoryMfaFactorStoreModule } from "#/mfa/module.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";

const RECORD: MfaFactorRecord = {
	id: "factor-1",
	subject: "user-1",
	kind: "totp",
	label: "Phone",
	binding: "password",
	createdAt: new Date("2026-09-01T00:00:00.000Z"),
	lastUsedAt: new Date("2026-09-02T00:00:00.000Z"),
	version: 1,
	data: "v2.opaque",
};

const spyLogger = () => ({
	debug: vi.fn(),
	info: vi.fn(),
	warn: vi.fn(),
	error: vi.fn(),
});

describe("the in-process MfaFactorStore", () => {
	it("is kind memory", () => {
		expect(createMemoryMfaFactorStore().kind).toBe("memory");
	});

	it("hands out copies: changing what it returned changes nothing it holds", async () => {
		const store = createMemoryMfaFactorStore();
		const written = { ...RECORD, createdAt: new Date(RECORD.createdAt) };
		await store.create(written);
		written.createdAt.setTime(0);
		const [listed] = await store.list("user-1");
		listed?.createdAt.setTime(0);
		listed?.lastUsedAt?.setTime(0);
		expect(await store.list("user-1")).toStrictEqual([RECORD]);
	});
});

describe("the in-process store's factor set generation", () => {
	// test-kit's mfaFactorStoreConditionalContract holds this store to the
	// whole of it; these name the store's own steps.
	const second = { ...RECORD, id: "factor-2" };

	it("answers no generation for a set never written, and a fresh one at each membership write", async () => {
		const store = createMemoryMfaFactorStore();
		expect(await store.listVersioned?.("user-1")).toStrictEqual({ generation: null, items: [] });
		const first = await store.createIf?.(RECORD, null);
		if (first?.outcome !== "created") throw new Error("the first binding was refused");
		const next = await store.createIf?.(second, first.generation);
		if (next?.outcome !== "created") throw new Error("the second binding was refused");
		expect(next.generation).not.toBe(first.generation);
		expect(await store.listVersioned?.("user-1")).toStrictEqual({
			generation: next.generation,
			items: [RECORD, second],
		});
	});

	it("writes nothing at a generation that moved, and keeps the set when its last record goes", async () => {
		const store = createMemoryMfaFactorStore();
		const first = await store.createIf?.(RECORD, null);
		if (first?.outcome !== "created") throw new Error("the first binding was refused");
		expect(await store.createIf?.(RECORD, null)).toStrictEqual({ outcome: "conflict" });
		const removed = await store.removeIf?.("user-1", RECORD.id, first.generation);
		if (removed?.outcome !== "removed") throw new Error("the removal was refused");
		expect(await store.removeIf?.("user-1", RECORD.id, first.generation)).toStrictEqual({
			outcome: "conflict",
		});
		expect(await store.listVersioned?.("user-1")).toStrictEqual({
			generation: removed.generation,
			items: [],
		});
		expect(await store.createIf?.(second, first.generation)).toStrictEqual({
			outcome: "conflict",
		});
		expect(await store.list("user-1")).toStrictEqual([]);
	});

	it("keeps the generation through an update, and moves it at a reset, even of a set never written", async () => {
		const store = createMemoryMfaFactorStore();
		await store.create(RECORD);
		const before = await store.listVersioned?.("user-1");
		await store.update("user-1", RECORD.id, 1, {
			data: "v2.next",
			label: undefined,
			lastUsedAt: undefined,
		});
		expect((await store.listVersioned?.("user-1"))?.generation).toBe(before?.generation);
		await store.removeAllForSubject("user-1");
		const after = await store.listVersioned?.("user-1");
		expect(after?.items).toStrictEqual([]);
		expect(after?.generation).not.toBe(before?.generation);
		expect(after?.generation).not.toBeNull();
		await store.removeAllForSubject("nobody");
		expect((await store.listVersioned?.("nobody"))?.generation).not.toBeNull();
	});
});

describe("the in-process store's tombstone", () => {
	const DAY = 24 * 60 * 60 * 1000;
	const clocked = () => {
		let nowMs = Date.parse("2026-10-02T00:00:00.000Z");
		const store = createMemoryMfaFactorStore({ now: () => nowMs });
		return {
			store,
			advance: (ms: number) => {
				nowMs += ms;
			},
		};
	};

	it("keeps the write-lifetime bound a bundled store keeps a tombstone for: 24 hours", () => {
		expect(BUNDLED_STORE_WRITE_LIFETIME_MS).toBe(DAY);
	});

	it("keeps a reset's tombstone until the bound has passed on its clock, then reads it as never written", async () => {
		const { store, advance } = clocked();
		await store.create(RECORD);
		const read = await store.listVersioned?.("user-1");
		const stale = read?.generation;
		if (stale === null || stale === undefined) throw new Error("the create left no generation");
		await store.removeAllForSubject("user-1");
		const tombstone = await store.listVersioned?.("user-1");
		advance(BUNDLED_STORE_WRITE_LIFETIME_MS - 1);
		expect(await store.listVersioned?.("user-1")).toStrictEqual(tombstone);
		expect(await store.createIf?.(RECORD, null)).toStrictEqual({ outcome: "conflict" });
		expect(await store.createIf?.(RECORD, stale)).toStrictEqual({ outcome: "conflict" });
		expect(await store.removeIf?.("user-1", RECORD.id, stale)).toStrictEqual({
			outcome: "conflict",
		});
		expect(await store.listVersioned?.("user-1")).toStrictEqual(tombstone);
		advance(1);
		expect(await store.listVersioned?.("user-1")).toStrictEqual({ generation: null, items: [] });
	});

	it("expires a set its last removal emptied the same way, and a reset of a subject never written", async () => {
		const { store, advance } = clocked();
		const first = await store.createIf?.(RECORD, null);
		if (first?.outcome !== "created") throw new Error("the first binding was refused");
		await store.removeIf?.("user-1", RECORD.id, first.generation);
		await store.removeAllForSubject("nobody");
		advance(BUNDLED_STORE_WRITE_LIFETIME_MS);
		expect(await store.listVersioned?.("user-1")).toStrictEqual({ generation: null, items: [] });
		expect(await store.listVersioned?.("nobody")).toStrictEqual({ generation: null, items: [] });
	});

	it("holds no expiry on a set written to after it was emptied, and counts the bound again from a later reset", async () => {
		const { store, advance } = clocked();
		await store.removeAllForSubject("user-1");
		const tombstone = await store.listVersioned?.("user-1");
		const bound = await store.createIf?.(RECORD, tombstone?.generation ?? null);
		if (bound?.outcome !== "created") throw new Error("the binding on the tombstone was refused");
		advance(2 * BUNDLED_STORE_WRITE_LIFETIME_MS);
		expect(await store.listVersioned?.("user-1")).toStrictEqual({
			generation: bound.generation,
			items: [RECORD],
		});
		advance(BUNDLED_STORE_WRITE_LIFETIME_MS / 2);
		await store.removeAllForSubject("user-1");
		advance(BUNDLED_STORE_WRITE_LIFETIME_MS - 1);
		expect((await store.listVersioned?.("user-1"))?.generation).not.toBeNull();
	});
});

describe("memoryMfaFactorStoreModule", () => {
	it("declares itself replica-unsafe, saying what forks and what a restart loses", () => {
		expect(memoryMfaFactorStoreModule.name).toBe("core-mfa-factor-store-memory");
		expect(memoryMfaFactorStoreModule.replicaSafety?.unsafe).toBe(true);
		expect(memoryMfaFactorStoreModule.replicaSafety?.reason).toMatch(/fork per replica/);
		expect(memoryMfaFactorStoreModule.replicaSafety?.reason).toMatch(/restart/);
	});

	it("provides an in-process mfaFactorStore, and says once, at warn, that a restart empties it", async () => {
		const logger = spyLogger();
		let seen: MfaFactorStore | undefined;
		const reader = defineModule({
			name: "test:mfa-factor-store-reader",
			requires: ["mfaFactorStore"] as const,
			contributes: {
				routes: [
					(deps) => {
						seen = deps.mfaFactorStore;
						return {
							id: "test-mfa-factor-store-reader",
							mountPath: "/__test_mfa_factor_store_reader__",
							handler: ((_req: unknown, _res: unknown, next: () => void) => next()) as never,
						};
					},
				],
			},
		});
		const handle = await createApp({
			modules: [memoryMfaFactorStoreModule, reader],
			bootstrapComponents: {
				config: makeValidCoreConfig(),
				pathResolver: (p: string) => p,
				logger: logger as unknown as Logger,
			} as never,
		});
		try {
			expect(seen?.kind).toBe("memory");
			const warned = logger.warn.mock.calls.filter(
				([, event]) => event === "mfa_factor_store_in_memory",
			);
			expect(warned).toEqual([
				[{ store: "mfaFactorStore", adapter: "memory" }, "mfa_factor_store_in_memory"],
			]);
			expect(logger.error).not.toHaveBeenCalled();
		} finally {
			await handle.dispose();
		}
	});
});

describe("the MfaFactorStore adapter factory", () => {
	it("builds the memory adapter by name", async () => {
		const factory = createMfaFactorStoreFactory();
		registerBuiltinMfaFactorStores(factory, spyLogger() as unknown as Logger);
		const store = await factory.create({ type: "memory" });
		expect(store.kind).toBe("memory");
	});
});
