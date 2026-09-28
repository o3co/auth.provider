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
import { createApp, defineModule } from "#/index.mjs";
import type { Logger } from "#/logging/Logger.mjs";
import type { MfaFactorRecord, MfaFactorStore } from "#/mfa/factorStore.mjs";
import { createMfaFactorStoreFactory, registerBuiltinMfaFactorStores } from "#/mfa/factory.mjs";
import { createMemoryMfaFactorStore } from "#/mfa/memoryFactorStore.mjs";
import { memoryMfaFactorStoreModule } from "#/mfa/module.mjs";
import { makeValidCoreConfig } from "#/testing/fixtures/valid-config.mjs";
import { runMfaFactorStoreContract } from "./factorStore.contract.mjs";

runMfaFactorStoreContract(async () => createMemoryMfaFactorStore());

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
