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
import type { PendingConsentRecord, PendingConsentStore } from "#/consents/types.mjs";

export interface PendingConsentStoreContractFactory {
	create(): Promise<PendingConsentStore>;
	teardown?(store: PendingConsentStore): Promise<void>;
}

const record = (overrides: Partial<PendingConsentRecord> = {}): PendingConsentRecord => ({
	challenge: "ch-1",
	sessionId: "sess-1",
	sub: "u-1",
	clientId: "app",
	scopes: ["read", "write"],
	grantedScopes: ["read"],
	authorizeUrl: "https://issuer.example/oauth/authorize?client_id=app",
	redirectUri: "https://app.example/cb",
	state: "xyz",
	createdAt: Date.now(),
	expiresAt: Date.now() + 600_000,
	...overrides,
});

/**
 * The behaviour every {@link PendingConsentStore} adapter shares (#552). The
 * memory adapter runs this in-tree; an adapter over a shared store runs the
 * same suite against the real thing, so the two cannot disagree about what
 * "consumed" means — and "consumed" is the whole point of the port.
 */
export function runPendingConsentStoreContract(
	name: string,
	factory: PendingConsentStoreContractFactory,
): void {
	describe(`PendingConsentStore contract — ${name}`, () => {
		let store: PendingConsentStore;

		beforeEach(async () => {
			vi.useFakeTimers();
			vi.setSystemTime(new Date("2026-09-12T00:00:00Z"));
			store = await factory.create();
		});

		afterEach(async () => {
			await factory.teardown?.(store);
			vi.useRealTimers();
		});

		it("declares a non-empty kind", () => {
			expect(store.kind).toBeTruthy();
		});

		it("has nothing for a challenge never parked, whether read or consumed", async () => {
			expect(await store.get("ch-unknown")).toBeNull();
			expect(await store.consume("ch-unknown")).toBeNull();
		});

		it("returns a parked record intact, keyed by its challenge, and reading does not spend it", async () => {
			const parked = record();
			await store.set(parked);
			expect(await store.get("ch-1")).toEqual(parked);
			// The page reads what is being asked before it answers, possibly
			// more than once. Only the answer spends the record.
			expect(await store.get("ch-1")).toEqual(parked);
			expect(await store.get("ch-2")).toBeNull();
		});

		it("consume returns the record and removes it in the same step, so a second answer finds nothing", async () => {
			const parked = record();
			await store.set(parked);
			expect(await store.consume("ch-1")).toEqual(parked);
			// This is the property the port exists for: two answers to one
			// challenge cannot both be applied, because only one of them can be
			// handed the record.
			expect(await store.consume("ch-1")).toBeNull();
			expect(await store.get("ch-1")).toBeNull();
		});

		it("keeps records for different challenges apart", async () => {
			await store.set(record({ challenge: "ch-1", clientId: "app" }));
			await store.set(record({ challenge: "ch-2", clientId: "other" }));
			expect((await store.consume("ch-1"))?.clientId).toBe("app");
			expect((await store.get("ch-2"))?.clientId).toBe("other");
		});

		it("neither returns nor consumes a record past its expiry", async () => {
			const expiresAt = Date.now() + 1_000;
			await store.set(record({ expiresAt }));
			expect(await store.get("ch-1")).not.toBeNull();
			vi.setSystemTime(new Date(expiresAt));
			expect(await store.get("ch-1")).toBeNull();
			expect(await store.consume("ch-1")).toBeNull();
		});

		it("keeps a record the caller mutates afterwards intact", async () => {
			const scopes = ["read"];
			await store.set(record({ scopes }));
			scopes.push("admin");
			expect((await store.get("ch-1"))?.scopes).toEqual(["read"]);
		});
	});
}
