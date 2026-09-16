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
 * Conformance suite for `PendingConsentStore` (#552) — the copy
 * `@o3co/auth-provider-redis` runs against its adapter (#561).
 *
 * Duplicated from `packages/core/src/consents/__tests__/pending.contract.mts`,
 * differing only in how it imports the port: a contract file cannot be
 * imported across a package boundary (see `docs/adapter-surface.md`, "Proving
 * an implementation"). Keep the two in step.
 */

import {
	PENDING_CONSENT_PER_SESSION_LIMIT,
	type PendingConsentRecord,
	type PendingConsentStore,
} from "@o3co/auth-provider-core";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

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

		it("hands the record to exactly one of two answers racing for one challenge", async () => {
			// The sequential case above, under concurrency: an adapter whose
			// one step is a round trip — a `GET` then a `DEL` — passes that one
			// and fails this one against a real server.
			await store.set(record());
			const answers = await Promise.all([store.consume("ch-1"), store.consume("ch-1")]);
			expect(answers.filter((answer) => answer !== null)).toHaveLength(1);
		});

		// The per-session bound (#527 audit), held by every adapter since a
		// shared one exists (#561): records are keyed by challenge and reclaimed
		// only on expiry, so without it one authenticated session could park an
		// unbounded number inside the ten-minute window. "Oldest" is the order
		// the requests were parked in — every record below carries the same
		// `createdAt`, as requests parked within one millisecond do.

		it("keeps at most the per-session bound parked, the first parked going first, and no other session's", async () => {
			const parked = Array.from(
				{ length: PENDING_CONSENT_PER_SESSION_LIMIT + 2 },
				(_, i) => `busy-${i}`,
			);
			for (const challenge of parked) {
				await store.set(record({ challenge, sessionId: "sess-busy" }));
			}
			expect(await store.get("busy-0")).toBeNull();
			expect(await store.get("busy-1")).toBeNull();
			for (const challenge of parked.slice(2)) {
				expect(await store.get(challenge), challenge).not.toBeNull();
			}

			await store.set(record({ challenge: "quiet", sessionId: "sess-quiet" }));
			expect(await store.get("quiet")).not.toBeNull();
			expect(await store.get("busy-2")).not.toBeNull();
		});

		it("does not evict a live request while one of the same session that has expired still counts", async () => {
			// An expired record that is not the oldest must leave the count
			// before the bound is judged; otherwise the eviction takes a live
			// request — an open consent page — while the dead one stays.
			await store.set(record({ challenge: "live-oldest", sessionId: "sess-c" }));
			await store.set(
				record({ challenge: "dead", sessionId: "sess-c", expiresAt: Date.now() + 1_000 }),
			);
			for (let i = 0; i < PENDING_CONSENT_PER_SESSION_LIMIT - 2; i += 1) {
				await store.set(record({ challenge: `live-${i}`, sessionId: "sess-c" }));
			}
			vi.setSystemTime(new Date(Date.now() + 1_000));
			// The session is at the bound only if the dead one still counts.
			await store.set(record({ challenge: "live-newest", sessionId: "sess-c" }));
			expect(await store.get("live-oldest")).not.toBeNull();
			expect(await store.get("live-newest")).not.toBeNull();
		});

		it("frees a place when a request is consumed, and counts a re-parked challenge once", async () => {
			for (let i = 0; i < PENDING_CONSENT_PER_SESSION_LIMIT; i += 1) {
				await store.set(record({ challenge: `a-${i}`, sessionId: "sess-a" }));
			}
			expect(await store.consume("a-0")).not.toBeNull();
			await store.set(record({ challenge: "a-1", sessionId: "sess-a" }));
			// One place is free only if the consumed request left the count and
			// the re-parked one is counted once.
			await store.set(record({ challenge: "a-new", sessionId: "sess-a" }));
			expect(await store.get("a-1")).not.toBeNull();
			expect(await store.get("a-2")).not.toBeNull();
			expect(await store.get("a-new")).not.toBeNull();
		});
	});
}
