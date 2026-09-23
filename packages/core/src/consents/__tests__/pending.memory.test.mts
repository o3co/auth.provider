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
import {
	createPendingConsentStoreFactory,
	registerBuiltinPendingConsentStores,
} from "#/consents/factory.mjs";
import {
	createMemoryPendingConsentStore,
	PENDING_CONSENT_PER_SESSION_LIMIT,
} from "#/consents/memory.mjs";
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
	state: undefined,
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
		// Across many sessions, as abandoned pages are: one session alone is held
		// to its own bound long before the floor.
		for (let i = 0; i < 1024; i += 1) {
			await store.set({ ...record(`ch-${i}`, expiresAt), sessionId: `sess-${i}` });
		}
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

describe("the pending-consent store has a factory and a bound per session (#527 audit)", () => {
	it("registers the memory builtin on a factory of its own", async () => {
		// Every port with a factory has one; the consent store did and the
		// pending store did not, so a composition following the factory
		// pattern built one slot and not the other — which `createOAuthRouter`
		// then refuses.
		const factory = createPendingConsentStoreFactory();
		registerBuiltinPendingConsentStores(factory);
		const store = await factory.create({ type: "memory" });
		expect(store.kind).toBe("memory");
	});

	it("keeps at most a bounded number of outstanding requests per session", async () => {
		// Records are keyed by challenge and swept only on expiry, so one
		// authenticated session could park an unbounded number inside the
		// ten-minute window. A browser has no use for more than a handful at
		// once; the oldest goes.
		const store = createMemoryPendingConsentStore();
		const ids: string[] = [];
		for (let i = 0; i < PENDING_CONSENT_PER_SESSION_LIMIT + 4; i += 1) {
			const id = `ch-${i}`;
			ids.push(id);
			await store.set({ ...record(id), sessionId: "sess-busy" });
		}
		expect(store.size).toBe(PENDING_CONSENT_PER_SESSION_LIMIT);
		expect(await store.get(ids[0] as string)).toBeNull();
		expect(await store.get(ids.at(-1) as string)).not.toBeNull();

		// Another session's requests are untouched by the first one's bound.
		await store.set({ ...record("ch-other"), sessionId: "sess-quiet" });
		expect(await store.get("ch-other")).not.toBeNull();
	});

	it("keeps the per-session index in step when a record is consumed, re-parked or expires", async () => {
		// The bound counts the index, so an index that kept a consumed or expired
		// challenge would evict live requests early, and one that counted a
		// re-parked challenge twice would do the same.
		const store = createMemoryPendingConsentStore();
		const fill = async (prefix: string) => {
			for (let i = 0; i < PENDING_CONSENT_PER_SESSION_LIMIT; i += 1) {
				await store.set({ ...record(`${prefix}-${i}`), sessionId: "sess-a" });
			}
		};
		await fill("a");
		// Spend one and re-park another under the same challenge: room for one more.
		expect(await store.consume("a-0")).not.toBeNull();
		await store.set({ ...record("a-1"), sessionId: "sess-a" });
		await store.set({ ...record("a-new"), sessionId: "sess-a" });
		expect(await store.get("a-2")).not.toBeNull();
		expect(await store.get("a-new")).not.toBeNull();

		// An expired record leaves the index when it is next touched.
		const expiring = createMemoryPendingConsentStore();
		await expiring.set({ ...record("old", Date.now() - 1), sessionId: "sess-b" });
		expect(await expiring.get("old")).toBeNull();
		for (let i = 0; i < PENDING_CONSENT_PER_SESSION_LIMIT; i += 1) {
			await expiring.set({ ...record(`b-${i}`), sessionId: "sess-b" });
		}
		expect(await expiring.get("b-0")).not.toBeNull();
	});
});
