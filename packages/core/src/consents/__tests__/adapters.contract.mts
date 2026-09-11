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

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ConsentStore } from "#/consents/types.mjs";

export interface ConsentStoreContractFactory {
	create(): Promise<ConsentStore>;
	teardown?(store: ConsentStore): Promise<void>;
}

/**
 * The behaviour every {@link ConsentStore} adapter shares (#527). The memory
 * adapter runs this in-tree; a Redis adapter runs the same suite against a
 * real Redis, so the two cannot disagree about what a record means.
 */
export function runConsentStoreContract(name: string, factory: ConsentStoreContractFactory): void {
	describe(`ConsentStore contract — ${name}`, () => {
		let store: ConsentStore;

		beforeEach(async () => {
			vi.useFakeTimers();
			vi.setSystemTime(new Date("2026-09-11T00:00:00Z"));
			store = await factory.create();
		});

		afterEach(async () => {
			await factory.teardown?.(store);
			vi.useRealTimers();
		});

		it("declares a non-empty kind", () => {
			expect(store.kind).toBeTruthy();
		});

		it("finds nothing for a pair never granted", async () => {
			expect(await store.find("u-1", "app")).toBeNull();
		});

		it("finds what was granted, keyed by subject and client, and returns it intact", async () => {
			const record = {
				sub: "u-1",
				clientId: "app",
				scopes: ["read", "write"],
				grantedAt: Date.now(),
			};
			await store.grant(record);
			expect(await store.find("u-1", "app")).toEqual(record);
			expect(await store.find("u-1", "other-app")).toBeNull();
			expect(await store.find("u-2", "app")).toBeNull();
		});

		it("replaces the record for the same pair on a later grant", async () => {
			await store.grant({ sub: "u-1", clientId: "app", scopes: ["read"], grantedAt: 1 });
			await store.grant({ sub: "u-1", clientId: "app", scopes: ["read", "write"], grantedAt: 2 });
			expect((await store.find("u-1", "app"))?.scopes).toEqual(["read", "write"]);
		});

		it("stops finding an expired record", async () => {
			const expiresAt = Date.now() + 1_000;
			await store.grant({
				sub: "u-1",
				clientId: "app",
				scopes: ["read"],
				grantedAt: Date.now(),
				expiresAt,
			});
			expect(await store.find("u-1", "app")).not.toBeNull();
			vi.setSystemTime(new Date(expiresAt + 1));
			expect(await store.find("u-1", "app")).toBeNull();
		});

		it("revokes, and says whether there was anything to revoke", async () => {
			await store.grant({ sub: "u-1", clientId: "app", scopes: ["read"], grantedAt: Date.now() });
			expect(await store.revoke("u-1", "app")).toBe(true);
			expect(await store.find("u-1", "app")).toBeNull();
			expect(await store.revoke("u-1", "app")).toBe(false);
		});

		it("keeps a record the caller mutates afterwards intact", async () => {
			const scopes = ["read"];
			await store.grant({ sub: "u-1", clientId: "app", scopes, grantedAt: Date.now() });
			scopes.push("admin");
			expect((await store.find("u-1", "app"))?.scopes).toEqual(["read"]);
		});
	});
}
