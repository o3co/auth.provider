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

import { describe, expect, it } from "vitest";
import { replicaUnsafeReason } from "#/boot/replica-safety.mjs";
import { createConsentStoreFactory, registerBuiltinConsentStores } from "#/consents/factory.mjs";
import { createMemoryConsentStore } from "#/consents/memory.mjs";
import { memoryConsentStoreModule } from "#/consents/module.mjs";
import { consentCovers } from "#/consents/types.mjs";
import { runConsentStoreContract } from "./adapters.contract.mjs";

runConsentStoreContract("memory", { create: async () => createMemoryConsentStore() });

describe("createMemoryConsentStore (#527)", () => {
	it("is bounded by population: one record per subject and client, expired ones dropped on read", async () => {
		const store = createMemoryConsentStore();
		await store.grant({ sub: "u-1", clientId: "app", scopes: ["read"], grantedAt: 1 });
		await store.grant({ sub: "u-1", clientId: "app", scopes: ["write"], grantedAt: 2 });
		await store.grant({
			sub: "u-1",
			clientId: "other",
			scopes: ["read"],
			grantedAt: 3,
			expiresAt: Date.now() - 1,
		});
		expect(store.size).toBe(2);
		expect(await store.find("u-1", "other")).toBeNull();
		expect(store.size).toBe(1);
	});

	it("keys the pair unambiguously whatever characters the ids carry", async () => {
		const store = createMemoryConsentStore();
		await store.grant({ sub: "a|b", clientId: "c", scopes: ["read"], grantedAt: 1 });
		expect(await store.find("a", "b|c")).toBeNull();
		expect(await store.find("a|b", "c")).not.toBeNull();
	});
});

describe("memoryConsentStoreModule (#527)", () => {
	it("provides the slot and declares why it forks per replica", () => {
		expect(memoryConsentStoreModule.name).toBe("core-consent-store-memory");
		expect(Object.keys(memoryConsentStoreModule.provides ?? {})).toEqual(["consentStore"]);
		expect(replicaUnsafeReason(memoryConsentStoreModule)).toMatch(/fork/);
	});
});

describe("consent store factory (#527)", () => {
	it("registers the memory builtin", async () => {
		const factory = createConsentStoreFactory();
		registerBuiltinConsentStores(factory);
		const store = await factory.create({ type: "memory" });
		expect(store.kind).toBe("memory");
	});
});

describe("consentCovers (#527)", () => {
	const record = { sub: "u", clientId: "c", scopes: ["read", "write"], grantedAt: 0 };

	it("covers a subset, an equal set and an empty request; not a superset", () => {
		expect(consentCovers(record, ["read"])).toBe(true);
		expect(consentCovers(record, ["write", "read"])).toBe(true);
		expect(consentCovers(record, [])).toBe(true);
		expect(consentCovers(record, ["read", "admin"])).toBe(false);
	});

	it("covers nothing when there is no record or it has expired", () => {
		expect(consentCovers(null, [])).toBe(false);
		expect(consentCovers({ ...record, expiresAt: 100 }, ["read"], 100)).toBe(false);
		expect(consentCovers({ ...record, expiresAt: 100 }, ["read"], 99)).toBe(true);
	});
});
