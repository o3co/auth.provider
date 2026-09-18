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

import { afterEach, describe, expect, it, vi } from "vitest";
import { replicaUnsafeReason } from "#/boot/replica-safety.mjs";
import {
	createFederationGrantIntentStoreFactory,
	registerBuiltinFederationGrantIntentStores,
} from "#/federation-grants/intentFactory.mjs";
import {
	createMemoryFederationGrantIntentStore,
	MEMORY_FEDERATION_GRANT_INTENT_STORE_SWEEP_FLOOR,
	type MemoryFederationGrantIntentStore,
} from "#/federation-grants/intentMemory.mjs";
import {
	FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT,
	FEDERATION_GRANT_FLOW_BUDGET_MS,
	type FederationGrantIntent,
} from "#/federation-grants/intentStore.mjs";
import { memoryFederationGrantIntentStoreModule } from "#/federation-grants/module.mjs";
import type { Logger } from "#/logging/Logger.mjs";
import { runFederationGrantIntentStoreContract } from "./intentStore.contract.mjs";

runFederationGrantIntentStoreContract<MemoryFederationGrantIntentStore>("memory", {
	create: async () => createMemoryFederationGrantIntentStore(),
	intentResident: async (store, handle) => store.holdsIntent(handle),
	consentResident: async (store, challenge) => store.holdsConsent(challenge),
	transactionResident: async (store, state) => store.holdsTransaction(state),
	reservations: async (store, clientId, subject) => store.reservations(clientId, subject),
});

const MIN = 60_000;
const DAY = 86_400_000;
const T0 = new Date("2026-09-19T00:00:00.000Z");
const at = (ms: number): Date => new Date(T0.getTime() + ms);

const intent = (over: Partial<FederationGrantIntent> = {}): FederationGrantIntent => ({
	handle: "h-1",
	kind: "initial",
	grantId: "g-1",
	clientId: "agent",
	subject: "u-1",
	connection: "okta-calendar",
	federation: "okta",
	identityRevision: "identity-1",
	authorizationRevision: "authorization-1",
	callbackUri: "https://provider.test/session/federation-grants/callback/okta-calendar",
	scopes: ["openid", "offline_access"],
	authorizationParams: {},
	redirectUri: "https://client.test/connected",
	clientState: "client-state-1",
	lifetimeMs: 30 * DAY,
	createdAt: T0,
	expiresAt: at(FEDERATION_GRANT_FLOW_BUDGET_MS),
	correlationId: "corr-1",
	...over,
});

afterEach(() => {
	vi.useRealTimers();
	vi.restoreAllMocks();
});

describe("the in-memory intent store's own clock", () => {
	it("reclaims a lapsed record and its place against the bound, without a caller asking", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(T0);
		const store = createMemoryFederationGrantIntentStore();
		for (let i = 0; i < FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT; i += 1) {
			expect(
				(await store.putIntent(intent({ handle: `h-${i}`, grantId: `g-${i}` }), T0)).outcome,
			).toBe("created");
		}
		// Full, on the caller's clock and the adapter's alike.
		expect(
			(await store.putIntent(intent({ handle: "h-over", grantId: "g-over" }), at(MIN))).outcome,
		).toBe("refused");

		// The adapter's clock passes every deadline. Nothing has been read or
		// written in between: reclamation is not a caller's doing.
		vi.setSystemTime(at(FEDERATION_GRANT_FLOW_BUDGET_MS + MIN));
		expect(store.reservations("agent", "u-1")).toBe(0);
		expect(
			(
				await store.putIntent(
					intent({
						handle: "h-after",
						grantId: "g-after",
						createdAt: at(FEDERATION_GRANT_FLOW_BUDGET_MS + MIN),
						expiresAt: at(2 * FEDERATION_GRANT_FLOW_BUDGET_MS + MIN),
					}),
					at(FEDERATION_GRANT_FLOW_BUDGET_MS + MIN),
				)
			).outcome,
		).toBe("created");
	});

	it("keeps a record a caller's fast clock cannot see", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(T0);
		const store = createMemoryFederationGrantIntentStore();
		await store.putIntent(intent(), T0);
		// A caller an hour ahead is told it has lapsed...
		expect(await store.getIntent("h-1", at(60 * MIN))).toBeNull();
		// ...and the record is still there for one with the right time.
		expect(store.holdsIntent("h-1")).toBe(true);
		expect(await store.getIntent("h-1", at(MIN))).not.toBeNull();
	});

	it("sweeps once it holds enough records, so an abandoned flow is not kept for ever", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(T0);
		const store = createMemoryFederationGrantIntentStore();
		const many = MEMORY_FEDERATION_GRANT_INTENT_STORE_SWEEP_FLOOR;
		// Reauthorizations, which take no place against the bound: an initial
		// intent walks the reservations and reclaims what it passes on the way,
		// so the sweep would never be the thing under test. Mutation found that —
		// removing the sweep altogether left this test green.
		for (let i = 0; i < many; i += 1) {
			await store.putIntent(
				intent({
					handle: `h-${i}`,
					grantId: `g-${i}`,
					subject: `u-${i}`,
					kind: "reauthorization",
				}),
				T0,
			);
		}
		expect(store.size).toBe(many);
		vi.setSystemTime(at(FEDERATION_GRANT_FLOW_BUDGET_MS + MIN));
		await store.putIntent(
			intent({
				handle: "h-last",
				grantId: "g-last",
				subject: "u-last",
				kind: "reauthorization",
				createdAt: at(FEDERATION_GRANT_FLOW_BUDGET_MS + MIN),
				expiresAt: at(2 * FEDERATION_GRANT_FLOW_BUDGET_MS),
			}),
			at(FEDERATION_GRANT_FLOW_BUDGET_MS + MIN),
		);
		expect(store.size).toBe(1);
	});

	it("sweeps what has lapsed and nothing else", async () => {
		vi.useFakeTimers();
		vi.setSystemTime(T0);
		const store = createMemoryFederationGrantIntentStore();
		const many = MEMORY_FEDERATION_GRANT_INTENT_STORE_SWEEP_FLOOR;
		for (let i = 0; i < many; i += 1) {
			await store.putIntent(
				intent({
					handle: `h-${i}`,
					grantId: `g-${i}`,
					subject: `u-${i}`,
					kind: "reauthorization",
				}),
				T0,
			);
		}
		// The sweep runs on this write, with every record still live: a sweep
		// that reclaimed by residency rather than by deadline would empty the
		// store here, and every flow in progress with it.
		await store.putIntent(
			intent({
				handle: "h-extra",
				grantId: "g-extra",
				subject: "u-extra",
				kind: "reauthorization",
			}),
			at(MIN),
		);
		expect(store.size).toBe(many + 1);
		expect(await store.getIntent("h-0", at(MIN))).not.toBeNull();
	});

	it("does not hand over a transaction its own clock has reclaimed", async () => {
		// The caller's clock decides what it is TOLD, and an adapter reclaims on
		// its own — so a caller whose clock is behind must not be handed a
		// transaction a Redis TTL would already have dropped. Mutation found this:
		// the caller-time check alone leaves it reachable.
		vi.useFakeTimers();
		vi.setSystemTime(T0);
		const store = createMemoryFederationGrantIntentStore();
		await store.putIntent(intent(), T0);
		await store.parkConsent({
			handle: "h-1",
			challenge: "challenge-1",
			binding: { sessionId: "express-1", sid: "sid-1", subject: "u-1" },
			now: at(MIN),
		});
		const answered = await store.answerConsent({
			challenge: "challenge-1",
			binding: { sessionId: "express-1", sid: "sid-1", subject: "u-1" },
			answer: {
				decision: "accept",
				state: "upstream-state-1",
				codeVerifier: "verifier-1",
				nonce: "nonce-1",
			},
			now: at(2 * MIN),
		});
		expect(answered.outcome).toBe("accepted");

		// This store's clock is past the flow's deadline; the callback's is not.
		vi.setSystemTime(at(FEDERATION_GRANT_FLOW_BUDGET_MS + MIN));
		expect(
			await store.consumeTransaction({
				state: "upstream-state-1",
				connection: "okta-calendar",
				now: at(3 * MIN),
			}),
		).toBeNull();
		expect(store.holdsTransaction("upstream-state-1")).toBe(false);
	});
});

describe("the memory intent store's builder and module", () => {
	it("is registered as `memory`, and says what it is not for when it is built", async () => {
		const factory = createFederationGrantIntentStoreFactory();
		const warn = vi.fn();
		registerBuiltinFederationGrantIntentStores(factory, { warn } as unknown as Logger);
		expect(factory.registeredTypes()).toEqual(["memory"]);
		// Registering says nothing; building is what a deployment did.
		expect(warn).not.toHaveBeenCalled();

		expect((await factory.create({ type: "memory" })).kind).toBe("memory");
		expect(warn).toHaveBeenCalledTimes(1);
		expect(warn.mock.calls[0]?.[0]).toMatch(/dev\/test only/);
	});

	it("provides the component and is refused by name on a multi-replica boot", () => {
		expect(memoryFederationGrantIntentStoreModule.name).toBe(
			"core-federation-grant-intent-store-memory",
		);
		const reason = replicaUnsafeReason(memoryFederationGrantIntentStoreModule);
		expect(reason).toEqual(expect.any(String));
		expect(reason).toContain("intent");
		const provided = memoryFederationGrantIntentStoreModule.provides?.federationGrantIntentStore as
			| ((deps: unknown) => MemoryFederationGrantIntentStore)
			| undefined;
		expect(provided).toBeTypeOf("function");
		expect(provided?.({}).kind).toBe("memory");
	});
});
