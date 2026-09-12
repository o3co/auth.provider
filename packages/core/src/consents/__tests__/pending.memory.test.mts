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
import { createMemoryPendingConsentStore } from "#/consents/memory.mjs";
import { memoryConsentStoreModule } from "#/consents/module.mjs";
import type { PendingConsentRecord } from "#/consents/types.mjs";
import { runPendingConsentStoreContract } from "./pending.contract.mjs";

runPendingConsentStoreContract("memory", { create: async () => createMemoryPendingConsentStore() });

const record = (challenge: string, expiresAt = Date.now() + 600_000): PendingConsentRecord => ({
	challenge,
	sessionId: "sess-1",
	sub: "u-1",
	clientId: "app",
	scopes: ["read"],
	grantedScopes: [],
	authorizeUrl: "https://issuer.example/oauth/authorize?client_id=app",
	redirectUri: "https://app.example/cb",
	createdAt: Date.now(),
	expiresAt,
});

describe("createMemoryPendingConsentStore (#552)", () => {
	it("counts what is parked, and drops an expired record when it is next touched", async () => {
		const store = createMemoryPendingConsentStore();
		await store.set(record("ch-1"));
		await store.set(record("ch-2", Date.now() - 1));
		expect(store.size).toBe(2);
		expect(await store.get("ch-2")).toBeNull();
		expect(store.size).toBe(1);
		expect(await store.consume("ch-1")).not.toBeNull();
		expect(store.size).toBe(0);
	});

	it("is one step from read to gone: interleaved consumers cannot both be handed the record", async () => {
		// Single-threaded, so the only way two callers could both win is an
		// `await` between the read and the delete. There is none — which is
		// what the port asks of every adapter, and what GETDEL is for elsewhere.
		const store = createMemoryPendingConsentStore();
		await store.set(record("ch-1"));
		const [first, second] = await Promise.all([store.consume("ch-1"), store.consume("ch-1")]);
		expect([first, second].filter((r) => r !== null)).toHaveLength(1);
	});
});

describe("memoryConsentStoreModule provides the pending-consent slot too (#552)", () => {
	it("hands both stores to the composition under the one adapter switch", () => {
		// One feature, one switch: a deployment that turns consent on gets the
		// record store the consent step needs with it, rather than a second
		// slot to configure and to get wrong.
		expect(Object.keys(memoryConsentStoreModule.provides ?? {}).sort()).toEqual([
			"consentStore",
			"pendingConsentStore",
		]);
	});
});

describe("createMemoryPendingConsentStore sweeps the records nobody came back for (#552)", () => {
	it("drops expired records it was never asked about again once the map has grown past the floor", async () => {
		// A page that is closed unanswered leaves a record nobody touches, and
		// touch-on-read alone would keep it for the life of the process.
		const store = createMemoryPendingConsentStore();
		const expiresAt = Date.now() + 1_000;
		for (let i = 0; i < 1024; i += 1) await store.set(record(`ch-${i}`, expiresAt));
		expect(store.size).toBe(1024);
		vi.useFakeTimers();
		try {
			vi.setSystemTime(new Date(expiresAt + 1));
			await store.set(record("ch-late", Date.now() + 1_000));
			expect(store.size).toBe(1);
		} finally {
			vi.useRealTimers();
		}
	});
});

describe("memoryConsentStoreModule's providers (#552)", () => {
	it("builds a live store from each thunk", async () => {
		const provides = memoryConsentStoreModule.provides as unknown as Record<
			string,
			() => { kind: string }
		>;
		expect(provides.consentStore?.().kind).toBe("memory");
		const pending = provides.pendingConsentStore?.() as ReturnType<
			typeof createMemoryPendingConsentStore
		>;
		expect(pending.kind).toBe("memory");
		await pending.set(record("ch-1"));
		expect(pending.size).toBe(1);
	});
});
