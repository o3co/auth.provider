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
 * Conformance suite for `FederationGrantIntentStore` (#593, D16) — every rule
 * both adapters owe, and nothing an adapter may decide for itself.
 *
 * Copied into `@o3co/auth-provider-redis` and held in step mechanically, as the
 * grant store's is: a contract file cannot be imported across a package
 * boundary. Nothing but the import block may differ between the two.
 */

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
	FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT,
	FEDERATION_GRANT_FLOW_BUDGET_MS,
	type FederationGrantBrowserBinding,
	type FederationGrantConnectTransaction,
	type FederationGrantIntent,
	type FederationGrantIntentStore,
} from "#/federation-grants/intentStore.mjs";

export interface FederationGrantIntentStoreContractFactory<
	S extends FederationGrantIntentStore = FederationGrantIntentStore,
> {
	create(): Promise<S>;
	teardown?(store: S): Promise<void>;
	/**
	 * Whether a record is still THERE under the handle — looked at from outside
	 * the port, because through it a record invisible to the caller's clock and
	 * one that was never written read the same. An adapter that let a second
	 * write replace a resident record would otherwise pass every other test here.
	 */
	intentResident(store: S, handle: string): Promise<boolean>;
	/** Whether the challenge's record is still held. */
	consentResident(store: S, challenge: string): Promise<boolean>;
	/**
	 * Whether the transaction's record — and with it the PKCE verifier and the
	 * nonce — is still held. What a consumed transaction must no longer be.
	 */
	transactionResident(store: S, state: string): Promise<boolean>;
	/** Reservations held against the bound for the pair, on the adapter's own clock. */
	reservations(store: S, clientId: string, subject: string): Promise<number>;
}

const MIN = 60_000;
const DAY = 86_400_000;

/**
 * The real clock, and not a fixed date, taken per test: an adapter hangs a key
 * TTL on a stored deadline, and a fixture dated in the past would be reclaimed
 * partway through the suite. Not on a whole second, so that an adapter
 * truncating an instant to seconds does not hand every fixture back unchanged.
 */
let T0 = new Date(Math.floor(Date.now() / 1000) * 1000 + 137);
const at = (ms: number): Date => new Date(T0.getTime() + ms);
const INVALID = new Date(Number.NaN);

/** Never handed out by reference: a fixture that shared it would hide a store that does too. */
const SCOPES: readonly string[] = ["openid", "offline_access", "calendar.read"];

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
	scopes: [...SCOPES],
	authorizationParams: { access_type: "offline" },
	redirectUri: "https://client.test/connected",
	clientState: "client-state-1",
	lifetimeMs: 30 * DAY,
	createdAt: T0,
	expiresAt: at(FEDERATION_GRANT_FLOW_BUDGET_MS),
	correlationId: "corr-1",
	...over,
});

const binding = (
	over: Partial<FederationGrantBrowserBinding> = {},
): FederationGrantBrowserBinding => ({
	sessionId: "express-1",
	sid: "sid-1",
	subject: "u-1",
	...over,
});

const accept = (tag = "1") =>
	({
		decision: "accept",
		state: `upstream-state-${tag}`,
		codeVerifier: `verifier-${tag}`,
		nonce: `nonce-${tag}`,
	}) as const;

const deny = { decision: "deny" } as const;

export function runFederationGrantIntentStoreContract<S extends FederationGrantIntentStore>(
	label: string,
	factory: FederationGrantIntentStoreContractFactory<S>,
): void {
	describe(`FederationGrantIntentStore contract (${label})`, () => {
		let store: S;

		beforeEach(async () => {
			T0 = new Date(Math.floor(Date.now() / 1000) * 1000 + 137);
			store = await factory.create();
		});

		afterEach(async () => {
			await factory.teardown?.(store);
		});

		/** Lodge, and assert it was admitted: the premise of nearly every test below. */
		const lodge = async (over: Partial<FederationGrantIntent> = {}, now = T0) => {
			const record = intent(over);
			expect(await store.putIntent(record, now)).toEqual({ outcome: "created" });
			return record;
		};

		/** Lodge, start, and approve — the state the callback works from. */
		const approved = async (tag = "1") => {
			const record = await lodge();
			const parked = await store.parkConsent({
				handle: record.handle,
				challenge: `challenge-${tag}`,
				binding: binding(),
				now: at(MIN),
			});
			expect(parked).not.toBeNull();
			const answer = accept(tag);
			const result = await store.answerConsent({
				challenge: `challenge-${tag}`,
				binding: binding(),
				answer,
				now: at(2 * MIN),
			});
			expect(result.outcome).toBe("accepted");
			if (result.outcome !== "accepted") throw new Error("unreachable");
			return { record, transaction: result.transaction, answer };
		};

		describe("kind", () => {
			it("names the adapter", () => {
				expect(store.kind).toEqual(expect.any(String));
				expect(store.kind.length).toBeGreaterThan(0);
			});
		});

		describe("putIntent", () => {
			it("admits a record and hands back a copy that is not the stored one", async () => {
				const record = await lodge();
				const read = await store.getIntent(record.handle, at(MIN));
				expect(read).toEqual(record);
				expect(read).not.toBe(record);
				if (read === null) throw new Error("unreachable");

				// A caller that changes what it read changes nothing, and neither
				// does one that changes what it wrote.
				(read as { clientId: string }).clientId = "someone-else";
				(read.scopes as string[]).push("admin");
				expect(await store.getIntent(record.handle, at(MIN))).toEqual(intent());
			});

			it("refuses a record whose deadline is not after the caller's now", async () => {
				expect(await store.putIntent(intent({ expiresAt: at(MIN) }), at(MIN))).toEqual({
					outcome: "refused",
					reason: "expired",
				});
				expect(await factory.intentResident(store, "h-1")).toBe(false);
				expect(await factory.reservations(store, "agent", "u-1")).toBe(0);
			});

			it("refuses a time that is not a date rather than comparing it", async () => {
				await expect(store.putIntent(intent(), INVALID)).rejects.toThrow(RangeError);
				await expect(store.putIntent(intent({ expiresAt: INVALID }), T0)).rejects.toThrow(
					RangeError,
				);
				await expect(store.putIntent(intent({ createdAt: INVALID }), T0)).rejects.toThrow(
					RangeError,
				);
				expect(await factory.intentResident(store, "h-1")).toBe(false);
			});

			it("is idempotent for the same record: no second place against the bound, no later deadline", async () => {
				const record = await lodge();
				expect(await store.putIntent(record, at(MIN))).toEqual({ outcome: "unchanged" });
				expect(await factory.reservations(store, "agent", "u-1")).toBe(1);
				expect(await store.getIntent(record.handle, at(MIN))).toEqual(record);
				// The deadline is the one it was admitted with, not one the retry moved.
				expect(await store.getIntent(record.handle, record.expiresAt)).toBeNull();
			});

			it("reads a retry whose parameters were written in another order as the same record", async () => {
				await lodge({ authorizationParams: { prompt: "consent", access_type: "offline" } });
				expect(
					await store.putIntent(
						intent({ authorizationParams: { access_type: "offline", prompt: "consent" } }),
						at(MIN),
					),
				).toEqual({ outcome: "unchanged" });
				expect(await factory.reservations(store, "agent", "u-1")).toBe(1);
			});

			it("refuses a different record under a resident handle", async () => {
				await lodge();
				expect(await store.putIntent(intent({ subject: "u-2", grantId: "g-2" }), at(MIN))).toEqual({
					outcome: "refused",
					reason: "collision",
				});
				expect(await store.getIntent("h-1", at(MIN))).toEqual(intent());
				expect(await factory.reservations(store, "agent", "u-2")).toBe(0);
			});

			it("refuses a collision the caller's clock cannot see", async () => {
				await lodge();
				// Past the record's deadline for this caller, so it reads as absent —
				// and is still there, so the handle is still taken.
				expect(await store.getIntent("h-1", at(FEDERATION_GRANT_FLOW_BUDGET_MS))).toBeNull();
				expect(
					await store.putIntent(
						intent({ grantId: "g-2", createdAt: at(FEDERATION_GRANT_FLOW_BUDGET_MS) }),
						at(FEDERATION_GRANT_FLOW_BUDGET_MS),
					),
				).toEqual({ outcome: "refused", reason: "collision" });
			});

			it("holds one client to the bound for one subject, and counts no other pair", async () => {
				for (let i = 0; i < FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT; i += 1) {
					expect(
						await store.putIntent(intent({ handle: `h-${i}`, grantId: `g-${i}` }), T0),
					).toEqual({
						outcome: "created",
					});
				}
				expect(await factory.reservations(store, "agent", "u-1")).toBe(
					FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT,
				);
				expect(await store.putIntent(intent({ handle: "h-over", grantId: "g-over" }), T0)).toEqual({
					outcome: "refused",
					reason: "limit",
				});
				expect(await factory.intentResident(store, "h-over")).toBe(false);

				// Another client for the same subject, and the same client for another
				// subject, are untouched: the bound is on the pair.
				expect(
					await store.putIntent(intent({ handle: "h-other-client", clientId: "worker" }), T0),
				).toEqual({ outcome: "created" });
				expect(
					await store.putIntent(intent({ handle: "h-other-sub", subject: "u-2" }), T0),
				).toEqual({
					outcome: "created",
				});
			});

			it("keeps the pairs apart when a separator could make two of them one", async () => {
				// Mutation found this: a key of `${clientId}:${subject}` makes
				// ("agent:x", "u-1") and ("agent", "x:u-1") one bucket, so one
				// client's abandoned attempts would exhaust another's places.
				for (let i = 0; i < FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT; i += 1) {
					expect(
						(
							await store.putIntent(
								intent({
									handle: `h-${i}`,
									grantId: `g-${i}`,
									clientId: "agent:x",
									subject: "u-1",
								}),
								T0,
							)
						).outcome,
					).toBe("created");
				}
				expect(
					await store.putIntent(
						intent({ handle: "h-other", grantId: "g-other", clientId: "agent", subject: "x:u-1" }),
						T0,
					),
				).toEqual({ outcome: "created" });
				expect(await factory.reservations(store, "agent", "x:u-1")).toBe(1);
				expect(await factory.reservations(store, "agent:x", "u-1")).toBe(
					FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT,
				);
			});

			it("does not count a reauthorization against the bound", async () => {
				for (let i = 0; i < FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT; i += 1) {
					await store.putIntent(intent({ handle: `h-${i}`, grantId: `g-${i}` }), T0);
				}
				expect(
					await store.putIntent(
						intent({ handle: "h-renew", kind: "reauthorization", grantId: "g-established" }),
						T0,
					),
				).toEqual({ outcome: "created" });
				expect(await factory.reservations(store, "agent", "u-1")).toBe(
					FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT,
				);
			});

			it("refuses a handle that was answered, so a retried write cannot resurrect it", async () => {
				const record = await lodge();
				await store.parkConsent({
					handle: record.handle,
					challenge: "challenge-1",
					binding: binding(),
					now: at(MIN),
				});
				await store.answerConsent({
					challenge: "challenge-1",
					binding: binding(),
					answer: deny,
					now: at(2 * MIN),
				});
				expect(await store.putIntent(record, at(3 * MIN))).toEqual({
					outcome: "refused",
					reason: "closed",
				});
				expect(await store.getIntent(record.handle, at(3 * MIN))).toBeNull();
			});

			it("refuses a handle that was finished", async () => {
				const record = await lodge();
				await store.finishIntent(record.handle, at(MIN));
				expect(await store.putIntent(record, at(2 * MIN))).toEqual({
					outcome: "refused",
					reason: "closed",
				});
			});
		});

		describe("getIntent", () => {
			it("is visible up to its deadline and not on it", async () => {
				const record = await lodge();
				expect(
					await store.getIntent(record.handle, new Date(record.expiresAt.getTime() - 1)),
				).toEqual(record);
				expect(await store.getIntent(record.handle, record.expiresAt)).toBeNull();
			});

			it("hides a record from a caller whose clock is ahead without reclaiming it", async () => {
				const record = await lodge();
				expect(
					await store.getIntent(record.handle, at(FEDERATION_GRANT_FLOW_BUDGET_MS)),
				).toBeNull();
				// The next caller, with the right time, still finds it.
				expect(await store.getIntent(record.handle, at(MIN))).toEqual(record);
			});

			it("is null for an unknown handle, and refuses an invalid now", async () => {
				expect(await store.getIntent("nobody", T0)).toBeNull();
				await expect(store.getIntent("nobody", INVALID)).rejects.toThrow(RangeError);
			});
		});

		describe("parkConsent", () => {
			it("parks one challenge, on the intent's deadline, and reads without spending it", async () => {
				const record = await lodge();
				const parked = await store.parkConsent({
					handle: record.handle,
					challenge: "challenge-1",
					binding: binding(),
					now: at(MIN),
				});
				expect(parked).toEqual({
					challenge: "challenge-1",
					intentHandle: record.handle,
					binding: binding(),
					scopes: [...SCOPES],
					lifetimeMs: record.lifetimeMs,
					createdAt: at(MIN),
					expiresAt: record.expiresAt,
				});
				expect(await store.getConsent("challenge-1", at(2 * MIN))).toEqual(parked);
				// Twice: a page that reloads must still find its question.
				expect(await store.getConsent("challenge-1", at(3 * MIN))).toEqual(parked);
			});

			it("gives a second start from the same browser the challenge already parked", async () => {
				const record = await lodge();
				const first = await store.parkConsent({
					handle: record.handle,
					challenge: "challenge-1",
					binding: binding(),
					now: at(MIN),
				});
				const second = await store.parkConsent({
					handle: record.handle,
					challenge: "challenge-2",
					binding: binding(),
					now: at(2 * MIN),
				});
				expect(second).toEqual(first);
				expect(await factory.consentResident(store, "challenge-2")).toBe(false);
			});

			it("gives another browser nothing, and leaves the parked challenge alone", async () => {
				const record = await lodge();
				await store.parkConsent({
					handle: record.handle,
					challenge: "challenge-1",
					binding: binding(),
					now: at(MIN),
				});
				expect(
					await store.parkConsent({
						handle: record.handle,
						challenge: "challenge-2",
						binding: binding({ sessionId: "express-2", sid: "sid-2" }),
						now: at(2 * MIN),
					}),
				).toBeNull();
				expect(await factory.consentResident(store, "challenge-1")).toBe(true);
				expect(await factory.consentResident(store, "challenge-2")).toBe(false);
			});

			it("never takes a challenge another intent is holding", async () => {
				// Mutation found this: without the guard, the second park replaces
				// the first intent's challenge, and the browser holding it answers
				// a question that is now somebody else's.
				const first = await lodge();
				const second = await lodge({ handle: "h-2", grantId: "g-2" });
				await store.parkConsent({
					handle: first.handle,
					challenge: "challenge-1",
					binding: binding(),
					now: at(MIN),
				});
				expect(
					await store.parkConsent({
						handle: second.handle,
						challenge: "challenge-1",
						binding: binding(),
						now: at(2 * MIN),
					}),
				).toBeNull();
				expect((await store.getConsent("challenge-1", at(3 * MIN)))?.intentHandle).toBe(
					first.handle,
				);
				// And the second intent is still startable under a challenge of its own.
				expect(
					await store.parkConsent({
						handle: second.handle,
						challenge: "challenge-2",
						binding: binding(),
						now: at(3 * MIN),
					}),
				).not.toBeNull();
			});

			it("parks nothing for an intent that is unknown, spent, finished or lapsed", async () => {
				expect(
					await store.parkConsent({
						handle: "nobody",
						challenge: "challenge-1",
						binding: binding(),
						now: T0,
					}),
				).toBeNull();

				const record = await lodge({ handle: "h-lapsed" });
				expect(
					await store.parkConsent({
						handle: record.handle,
						challenge: "challenge-2",
						binding: binding(),
						now: record.expiresAt,
					}),
				).toBeNull();

				const finished = await lodge({ handle: "h-finished", grantId: "g-2" });
				await store.finishIntent(finished.handle, at(MIN));
				expect(
					await store.parkConsent({
						handle: finished.handle,
						challenge: "challenge-3",
						binding: binding(),
						now: at(2 * MIN),
					}),
				).toBeNull();
			});

			it("refuses an invalid now", async () => {
				const record = await lodge();
				await expect(
					store.parkConsent({
						handle: record.handle,
						challenge: "challenge-1",
						binding: binding(),
						now: INVALID,
					}),
				).rejects.toThrow(RangeError);
			});
		});

		describe("getConsent", () => {
			it("is null past the deadline, for an unknown challenge, and refuses an invalid now", async () => {
				const record = await lodge();
				await store.parkConsent({
					handle: record.handle,
					challenge: "challenge-1",
					binding: binding(),
					now: at(MIN),
				});
				expect(await store.getConsent("challenge-1", record.expiresAt)).toBeNull();
				expect(await store.getConsent("nobody", at(MIN))).toBeNull();
				await expect(store.getConsent("challenge-1", INVALID)).rejects.toThrow(RangeError);
			});

			it("hands back a copy", async () => {
				const record = await lodge();
				await store.parkConsent({
					handle: record.handle,
					challenge: "challenge-1",
					binding: binding(),
					now: at(MIN),
				});
				const read = await store.getConsent("challenge-1", at(MIN));
				if (read === null) throw new Error("unreachable");
				(read.scopes as string[]).push("admin");
				expect((await store.getConsent("challenge-1", at(MIN)))?.scopes).toEqual([...SCOPES]);
			});
		});

		describe("answerConsent", () => {
			it("approves once: the transaction carries what the callback needs, and the intent is spent", async () => {
				const record = await lodge();
				await store.parkConsent({
					handle: record.handle,
					challenge: "challenge-1",
					binding: binding(),
					now: at(MIN),
				});
				const answer = accept();
				const result = await store.answerConsent({
					challenge: "challenge-1",
					binding: binding(),
					answer,
					now: at(2 * MIN),
				});
				expect(result).toEqual({
					outcome: "accepted",
					transaction: {
						state: answer.state,
						intent: record,
						binding: binding(),
						codeVerifier: answer.codeVerifier,
						nonce: answer.nonce,
						consent: { at: at(2 * MIN), sid: "sid-1", scopes: [...SCOPES] },
						// Dated from the answer, by the store: the grant's expiry is not
						// the callback's to choose (D3).
						grantExpiresAt: new Date(at(2 * MIN).getTime() + record.lifetimeMs),
						createdAt: at(2 * MIN),
						expiresAt: record.expiresAt,
					},
				});
				expect(await store.getIntent(record.handle, at(3 * MIN))).toBeNull();
				expect(await factory.consentResident(store, "challenge-1")).toBe(false);
				// The flow is still running, so its place against the bound is kept.
				expect(await factory.reservations(store, "agent", "u-1")).toBe(1);
			});

			it("releases the bound's capacity on a denial and creates no transaction", async () => {
				const record = await lodge();
				await store.parkConsent({
					handle: record.handle,
					challenge: "challenge-1",
					binding: binding(),
					now: at(MIN),
				});
				const result = await store.answerConsent({
					challenge: "challenge-1",
					binding: binding(),
					answer: deny,
					now: at(2 * MIN),
				});
				expect(result).toEqual({ outcome: "denied", intent: record });
				expect(await factory.reservations(store, "agent", "u-1")).toBe(0);
				expect(await store.getIntent(record.handle, at(3 * MIN))).toBeNull();
				expect(await factory.consentResident(store, "challenge-1")).toBe(false);
			});

			it("answers one way for every challenge it may not have, and spends nothing", async () => {
				const record = await lodge();
				await store.parkConsent({
					handle: record.handle,
					challenge: "challenge-1",
					binding: binding(),
					now: at(MIN),
				});

				// Unknown.
				expect(
					await store.answerConsent({
						challenge: "nobody",
						binding: binding(),
						answer: accept(),
						now: at(2 * MIN),
					}),
				).toEqual({ outcome: "empty" });

				// Another browser's, in either half of the binding.
				for (const other of [
					binding({ sessionId: "express-2" }),
					binding({ sid: "sid-2" }),
					binding({ subject: "u-2" }),
				]) {
					expect(
						await store.answerConsent({
							challenge: "challenge-1",
							binding: other,
							answer: accept(),
							now: at(2 * MIN),
						}),
					).toEqual({ outcome: "empty" });
				}

				// Past the deadline.
				expect(
					await store.answerConsent({
						challenge: "challenge-1",
						binding: binding(),
						answer: accept(),
						now: record.expiresAt,
					}),
				).toEqual({ outcome: "empty" });

				expect(await factory.consentResident(store, "challenge-1")).toBe(true);
				expect(await store.getIntent(record.handle, at(2 * MIN))).toEqual(record);
				expect(await factory.transactionResident(store, accept().state)).toBe(false);
			});

			it("answers a challenge once, whichever way the answers went", async () => {
				const record = await lodge();
				await store.parkConsent({
					handle: record.handle,
					challenge: "challenge-1",
					binding: binding(),
					now: at(MIN),
				});
				expect(
					(
						await store.answerConsent({
							challenge: "challenge-1",
							binding: binding(),
							answer: accept("a"),
							now: at(2 * MIN),
						})
					).outcome,
				).toBe("accepted");
				expect(
					await store.answerConsent({
						challenge: "challenge-1",
						binding: binding(),
						answer: deny,
						now: at(3 * MIN),
					}),
				).toEqual({ outcome: "empty" });
				expect(
					await store.answerConsent({
						challenge: "challenge-1",
						binding: binding(),
						answer: accept("b"),
						now: at(3 * MIN),
					}),
				).toEqual({ outcome: "empty" });
				expect(await factory.transactionResident(store, accept("a").state)).toBe(true);
				expect(await factory.transactionResident(store, accept("b").state)).toBe(false);
			});

			it("refuses an approval whose state is a resident transaction's, and spends nothing", async () => {
				const first = await approved("a");
				const record = await lodge({ handle: "h-2", grantId: "g-2" });
				await store.parkConsent({
					handle: record.handle,
					challenge: "challenge-2",
					binding: binding(),
					now: at(3 * MIN),
				});
				expect(
					await store.answerConsent({
						challenge: "challenge-2",
						binding: binding(),
						// The same upstream state the first flow is holding.
						answer: accept("a"),
						now: at(4 * MIN),
					}),
				).toEqual({ outcome: "refused", reason: "state_collision" });

				// Neither flow moved.
				expect(await store.getIntent(record.handle, at(5 * MIN))).toEqual(record);
				expect(await factory.consentResident(store, "challenge-2")).toBe(true);
				const consumed = await store.consumeTransaction({
					state: first.answer.state,
					connection: first.record.connection,
					now: at(5 * MIN),
				});
				expect(consumed?.intent.handle).toBe(first.record.handle);
			});

			it("refuses an invalid now", async () => {
				const record = await lodge();
				await store.parkConsent({
					handle: record.handle,
					challenge: "challenge-1",
					binding: binding(),
					now: at(MIN),
				});
				await expect(
					store.answerConsent({
						challenge: "challenge-1",
						binding: binding(),
						answer: accept(),
						now: INVALID,
					}),
				).rejects.toThrow(RangeError);
			});
		});

		describe("consumeTransaction", () => {
			it("hands the transaction over once, and keeps its secrets nowhere afterwards", async () => {
				const { record, answer, transaction } = await approved();
				const consumed = await store.consumeTransaction({
					state: answer.state,
					connection: record.connection,
					now: at(3 * MIN),
				});
				expect(consumed).toEqual(transaction);
				expect(await factory.transactionResident(store, answer.state)).toBe(false);
				expect(
					await store.consumeTransaction({
						state: answer.state,
						connection: record.connection,
						now: at(4 * MIN),
					}),
				).toBeNull();
			});

			it("leaves another connection's transaction exactly where it is", async () => {
				const { record, answer } = await approved();
				expect(
					await store.consumeTransaction({
						state: answer.state,
						connection: "google-drive",
						now: at(3 * MIN),
					}),
				).toBeNull();
				expect(await factory.transactionResident(store, answer.state)).toBe(true);
				expect(
					(
						await store.consumeTransaction({
							state: answer.state,
							connection: record.connection,
							now: at(4 * MIN),
						})
					)?.state,
				).toBe(answer.state);
			});

			it("is null past the deadline, for an unknown state, and refuses an invalid now", async () => {
				const { record, answer } = await approved();
				expect(
					await store.consumeTransaction({
						state: answer.state,
						connection: record.connection,
						now: record.expiresAt,
					}),
				).toBeNull();
				// Hidden, not reclaimed: the record is still there for a caller with
				// the right time.
				expect(await factory.transactionResident(store, answer.state)).toBe(true);
				expect(
					await store.consumeTransaction({
						state: "nobody",
						connection: record.connection,
						now: at(3 * MIN),
					}),
				).toBeNull();
				await expect(
					store.consumeTransaction({
						state: answer.state,
						connection: record.connection,
						now: INVALID,
					}),
				).rejects.toThrow(RangeError);
			});
		});

		describe("finishIntent", () => {
			it("closes the handle, drops what is left under it, and releases capacity once", async () => {
				const { record, answer } = await approved();
				await store.finishIntent(record.handle, at(3 * MIN));
				expect(await factory.transactionResident(store, answer.state)).toBe(false);
				expect(await factory.reservations(store, "agent", "u-1")).toBe(0);

				// Again: idempotent, and the capacity is not released twice.
				await store.finishIntent(record.handle, at(4 * MIN));
				expect(await factory.reservations(store, "agent", "u-1")).toBe(0);
				await lodge({ handle: "h-2", grantId: "g-2" }, at(4 * MIN));
				expect(await factory.reservations(store, "agent", "u-1")).toBe(1);
			});

			it("drops a parked challenge that was never answered", async () => {
				const record = await lodge();
				await store.parkConsent({
					handle: record.handle,
					challenge: "challenge-1",
					binding: binding(),
					now: at(MIN),
				});
				await store.finishIntent(record.handle, at(2 * MIN));
				expect(await factory.consentResident(store, "challenge-1")).toBe(false);
				expect(await store.getConsent("challenge-1", at(3 * MIN))).toBeNull();
			});

			it("touches no other handle, and does not mind an unknown one", async () => {
				const kept = await lodge({ handle: "h-keep", grantId: "g-keep" });
				await store.finishIntent("nobody", at(MIN));
				await store.finishIntent("h-other", at(MIN));
				expect(await store.getIntent(kept.handle, at(2 * MIN))).toEqual(kept);
				expect(await factory.reservations(store, "agent", "u-1")).toBe(1);
			});

			it("refuses an invalid now", async () => {
				await expect(store.finishIntent("h-1", INVALID)).rejects.toThrow(RangeError);
			});
		});

		// -------------------------------------------------------------------
		// Concurrency. Each case runs in both start orders: an adapter whose
		// check and write are two steps passes one order and fails the other.
		// What is asserted is the set of outcomes and the final state, never
		// which call won.
		// -------------------------------------------------------------------
		describe.each([
			{ order: "as written", swapped: false },
			{ order: "reversed", swapped: true },
		])("concurrently ($order)", ({ swapped }) => {
			const both = async <T,>(a: () => Promise<T>, b: () => Promise<T>): Promise<[T, T]> => {
				const [first, second] = swapped
					? await Promise.all([b(), a()])
					: await Promise.all([a(), b()]);
				return swapped ? [second, first] : [first, second];
			};

			it("admits one of two records competing for the last place", async () => {
				for (let i = 0; i < FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT - 1; i += 1) {
					await store.putIntent(intent({ handle: `h-${i}`, grantId: `g-${i}` }), T0);
				}
				const [a, b] = await both(
					() => store.putIntent(intent({ handle: "h-a", grantId: "g-a" }), T0),
					() => store.putIntent(intent({ handle: "h-b", grantId: "g-b" }), T0),
				);
				expect([a.outcome, b.outcome].sort()).toEqual(["created", "refused"]);
				expect(await factory.reservations(store, "agent", "u-1")).toBe(
					FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT,
				);
				const resident = [
					await factory.intentResident(store, "h-a"),
					await factory.intentResident(store, "h-b"),
				];
				expect(resident.filter(Boolean)).toHaveLength(1);
			});

			it("writes one record for two identical insertions, and refuses a conflicting one", async () => {
				const record = intent();
				const [a, b] = await both(
					() => store.putIntent(record, T0),
					() => store.putIntent(record, T0),
				);
				expect([a.outcome, b.outcome].sort()).toEqual(["created", "unchanged"]);
				expect(await factory.reservations(store, "agent", "u-1")).toBe(1);

				const [c, d] = await both(
					() => store.putIntent(intent({ handle: "h-2", grantId: "g-2" }), T0),
					() => store.putIntent(intent({ handle: "h-2", grantId: "g-3" }), T0),
				);
				expect([c.outcome, d.outcome].sort()).toEqual(["created", "refused"]);
			});

			it("parks one challenge for two starts of one intent", async () => {
				const record = await lodge();
				const park = (challenge: string) => () =>
					store.parkConsent({ handle: record.handle, challenge, binding: binding(), now: at(MIN) });
				const [a, b] = await both(park("challenge-a"), park("challenge-b"));
				expect(a).toEqual(b);
				const resident = [
					await factory.consentResident(store, "challenge-a"),
					await factory.consentResident(store, "challenge-b"),
				];
				expect(resident.filter(Boolean)).toHaveLength(1);
			});

			it.each([
				{ pair: "accept and accept", first: accept("a"), second: accept("b") },
				{ pair: "accept and deny", first: accept("a"), second: deny },
				{ pair: "deny and deny", first: deny, second: deny },
			])("applies one answer for $pair", async ({ first, second }) => {
				const record = await lodge();
				await store.parkConsent({
					handle: record.handle,
					challenge: "challenge-1",
					binding: binding(),
					now: at(MIN),
				});
				const answer = (which: typeof first) => () =>
					store.answerConsent({
						challenge: "challenge-1",
						binding: binding(),
						answer: which,
						now: at(2 * MIN),
					});
				const [a, b] = await both(answer(first), answer(second));
				const outcomes = [a.outcome, b.outcome].sort();
				expect(outcomes).toHaveLength(2);
				expect(outcomes[1]).toBe("empty");
				expect(["accepted", "denied"]).toContain(outcomes[0]);

				const transactions = [
					await factory.transactionResident(store, accept("a").state),
					await factory.transactionResident(store, accept("b").state),
				].filter(Boolean);
				expect(transactions.length).toBe(outcomes[0] === "accepted" ? 1 : 0);
				expect(await store.getIntent(record.handle, at(3 * MIN))).toBeNull();
			});

			it("does not both answer a challenge and finish its intent", async () => {
				const record = await lodge();
				await store.parkConsent({
					handle: record.handle,
					challenge: "challenge-1",
					binding: binding(),
					now: at(MIN),
				});
				const [answered] = await both<unknown>(
					() =>
						store.answerConsent({
							challenge: "challenge-1",
							binding: binding(),
							answer: accept(),
							now: at(2 * MIN),
						}),
					() => store.finishIntent(record.handle, at(2 * MIN)).then(() => "finished" as const),
				);
				const outcome = (answered as { outcome?: string }).outcome;
				expect(["accepted", "empty", undefined]).toContain(outcome);
				// Whichever won, nothing is left that a callback could still spend.
				await store.finishIntent(record.handle, at(3 * MIN));
				expect(await factory.transactionResident(store, accept().state)).toBe(false);
				expect(await factory.reservations(store, "agent", "u-1")).toBe(0);
			});

			it("hands one transaction to one of two callbacks", async () => {
				const { record, answer } = await approved();
				const consume = () => () =>
					store.consumeTransaction({
						state: answer.state,
						connection: record.connection,
						now: at(3 * MIN),
					});
				const [a, b] = await both(consume(), consume());
				expect([a, b].filter((result) => result !== null)).toHaveLength(1);
				expect(await factory.transactionResident(store, answer.state)).toBe(false);
			});

			it("does not hand over a transaction it also finished", async () => {
				const { record, answer } = await approved();
				const [consumed] = await both<FederationGrantConnectTransaction | null>(
					() =>
						store.consumeTransaction({
							state: answer.state,
							connection: record.connection,
							now: at(3 * MIN),
						}),
					() => store.finishIntent(record.handle, at(3 * MIN)).then(() => null),
				);
				// Either the callback took it or the finish dropped it. Whichever
				// won, nothing is left and no second consumer can find it — and if
				// the callback did win, what it got is this flow's transaction and
				// not a record the finish had already emptied.
				expect(await factory.transactionResident(store, answer.state)).toBe(false);
				expect(await factory.reservations(store, "agent", "u-1")).toBe(0);
				expect(
					await store.consumeTransaction({
						state: answer.state,
						connection: record.connection,
						now: at(4 * MIN),
					}),
				).toBeNull();
				if (consumed !== null) {
					expect(consumed.state).toBe(answer.state);
					expect(consumed.intent.handle).toBe(record.handle);
					expect(consumed.codeVerifier).toBe(answer.codeVerifier);
				}
			});

			it("releases one place when a finish races an admission at capacity", async () => {
				for (let i = 0; i < FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT; i += 1) {
					await store.putIntent(intent({ handle: `h-${i}`, grantId: `g-${i}` }), T0);
				}
				const [, admitted] = await both<unknown>(
					() => store.finishIntent("h-0", at(MIN)).then(() => null),
					() => store.putIntent(intent({ handle: "h-new", grantId: "g-new" }), at(MIN)),
				);
				const outcome = (admitted as { outcome?: string }).outcome;
				expect(["created", "refused"]).toContain(outcome);
				expect(await factory.reservations(store, "agent", "u-1")).toBeLessThanOrEqual(
					FEDERATION_GRANT_FIRST_INTENTS_PER_CLIENT_SUBJECT_LIMIT,
				);
				// Whether or not the racing admission got in, the place the finish
				// released is available to the next one.
				const next = await store.putIntent(
					intent({ handle: "h-next", grantId: "g-next" }),
					at(2 * MIN),
				);
				expect(next.outcome === "created" || outcome === "created").toBe(true);
			});
		});
	});
}
