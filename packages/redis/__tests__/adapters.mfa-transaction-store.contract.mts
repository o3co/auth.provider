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

import {
	DEFAULT_CLOCK_SKEW_MS,
	getBoundMfaTransaction,
	MFA_CLOCK_SKEW_ALLOWANCE_MS,
	MFA_RECOVERY_AUTHORIZATION_MAX_MS,
	MFA_WEEKLY_WINDOW_MS,
	type MfaLockoutPolicy,
	type MfaSubjectAttemptReservation,
	type MfaSubjectRecoveryAnswer,
	type MfaSubjectRecoveryApplication,
	type MfaSubjectRecoveryAuthorization,
	type MfaTransaction,
	type MfaTransactionBinding,
	type MfaTransactionStore,
} from "@o3co/auth-provider-core";
import { describe, expect, it } from "vitest";

/**
 * The `MfaTransactionStore` contract (the MFA ADR's D8 and D21), for every
 * adapter.
 *
 * Two halves. The transaction: a short-lived, single-use record of one
 * second-factor ceremony, whose every operation a race could split —
 * attempts reserved before a proof is checked, a challenge answered once,
 * one winner among verifications in flight. And the subject state, which
 * bounds guessable proofs across transactions: the consecutive run with its
 * short backoff and hard limit, and the weekly budget no success refunds.
 * Beside them, what a first binding asks of the store: the email proof an
 * operator reset requires, the account-email proof given in one session,
 * and the subject's first-binding mark.
 *
 * The subject state is judged on the time its caller passes, so D21's
 * schedule is driven here by an injected clock; a transaction, a session's
 * proof and a first-binding mark expire on the store's own clock, read
 * through {@link ExpiryClock} as the session-store suite does.
 */
export type MfaTransactionStoreContractFactory = () => Promise<MfaTransactionStore>;

/** How a test reaches a transaction's expiry on the store's own terms (see the session-store suite). */
export interface ExpiryClock {
	/** Epoch milliseconds on the clock the store expires records by. */
	now(): Promise<number>;
	/** Resolves once the store has let everything expiring at `at` go. */
	passed(at: number): Promise<void>;
}

const hostExpiry: ExpiryClock = {
	now: async () => Date.now(),
	passed: async (at) => {
		while (Date.now() <= at) {
			await new Promise((r) => setTimeout(r, at - Date.now() + 1));
		}
	},
};

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const WEEK = 7 * DAY;

/** The MFA ADR's D19 defaults. */
const POLICY: MfaLockoutPolicy = {
	threshold: 5,
	baseSeconds: 900,
	maxSeconds: 86_400,
	memorySeconds: 86_400,
	weeklyBudget: 10,
	hardLimit: 100,
};

/**
 * The session a transaction is bound to: an express session id as
 * express-session mints one — 32 characters of base64url, mixed case, with
 * `-` and `_` — so a store that folds case, trims or re-encodes the id fails
 * the round-trip.
 */
const SESSION_ID = "Qx7-dP_2mZkL9vRt3YbN8cW-4sHj_E1a";

const TX = (overrides: Partial<MfaTransaction> = {}): MfaTransaction => {
	const now = Date.now();
	return {
		id: "tx-1",
		purpose: "login",
		binding: { kind: "session", id: SESSION_ID },
		subject: "user-1",
		sid: undefined,
		continuation: {
			primary: {
				subject: "user-1",
				user: { id: "user-1", username: "alice", groups: ["staff"] },
				claims: { email: "user-1@example.test" },
				recorded: {
					amr: ["pwd"],
					authentication: {
						primary: "pwd",
						federation: undefined,
						upstreamAmr: undefined,
						mfaAt: undefined,
					},
				},
				authTimeMs: now - 1_000,
				redirectTo: "https://app.example/after",
				request: { ip: "198.51.100.7", userAgent: "contract" },
			},
			done: [],
			interruptedBy: "mfa",
		},
		redirectTo: "https://app.example/after",
		enrollment: "none",
		emailProof: "not_required",
		acrValues: undefined,
		challenge: undefined,
		pendingEnrollment: undefined,
		attempts: 0,
		createdAtMs: now,
		expiresAtMs: now + 10 * MINUTE,
		version: 1,
		...overrides,
	};
};

/**
 * A challenge a verification takes (a WebAuthn assertion's, the MFA ADR's
 * F7). An email code is read, not taken, and stays across attempts (the same
 * ADR's F5): the store offers both, and the factor's `reusableChallenge`
 * (absent: taken) decides which the coordinator calls.
 */
const CHALLENGE = {
	factorId: "factor-1",
	kind: "webauthn",
	state: "sealed-challenge-state",
	expiresAtMs: Date.now() + 10 * MINUTE,
};

export function runMfaTransactionStoreContract(
	factory: MfaTransactionStoreContractFactory,
	options: { readonly expiry?: ExpiryClock } = {},
): void {
	const expiry = options.expiry ?? hostExpiry;

	describe("MfaTransactionStore contract: the transaction", () => {
		it("refuses a login transaction whose subject or redirectTo is not the continuation's primary's: one record, one login", async () => {
			const store = await factory();
			await expect(store.create(TX({ subject: "user-2" }))).rejects.toThrow(RangeError);
			await expect(store.create(TX({ redirectTo: undefined }))).rejects.toThrow(RangeError);
			await expect(store.create(TX({ redirectTo: "https://evil.example/" }))).rejects.toThrow(
				RangeError,
			);
		});

		it("returns a created transaction whole, as plain data, its undefined fields named", async () => {
			const store = await factory();
			const login = TX();
			const stepUp = TX({
				id: "tx-2",
				purpose: "step_up",
				sid: "sid-1",
				continuation: undefined,
				redirectTo: undefined,
				enrollment: "allowed",
				emailProof: { provedAtMs: Date.now() },
				acrValues: ["urn:o3co:acr:mfa"],
				challenge: CHALLENGE,
				pendingEnrollment: {
					kind: "totp",
					state: "sealed-pending",
					expiresAtMs: CHALLENGE.expiresAtMs,
				},
				version: 7,
			});
			await store.create(login);
			await store.create(stepUp);
			expect(await store.get("tx-1")).toStrictEqual(login);
			expect(await store.get("tx-2")).toStrictEqual(stepUp);
		});

		it("answers null for an id it never held", async () => {
			const store = await factory();
			expect(await store.get("never")).toBeNull();
		});

		it("keeps the binding whole: a transaction is not readable through a binding of another kind or id", async () => {
			const store = await factory();
			const tx = TX();
			await store.create(tx);
			const bound: MfaTransactionBinding = { kind: "session", id: SESSION_ID };
			expect((await store.get("tx-1"))?.binding).toStrictEqual(bound);
			expect(await getBoundMfaTransaction(store, "tx-1", bound)).toStrictEqual(tx);
			const others: [string, unknown][] = [
				["another id", { kind: "session", id: "Rk2_aW-9pLmX3vQt7ZbN0cY-5sJh_F8b" }],
				["another kind, the same id", { kind: "client", id: SESSION_ID }],
				["the id case-folded", { kind: "session", id: SESSION_ID.toLowerCase() }],
				["the id padded", { kind: "session", id: ` ${SESSION_ID} ` }],
				["the id and more", { kind: "session", id: `${SESSION_ID}x` }],
				["a prefix of the id", { kind: "session", id: SESSION_ID.slice(0, -1) }],
				["the id alone, as a bare session id", SESSION_ID],
				["the id without a kind", { id: SESSION_ID }],
				["nothing", undefined],
			];
			for (const [name, other] of others) {
				expect(
					await getBoundMfaTransaction(store, "tx-1", other as MfaTransactionBinding),
					name,
				).toBeNull();
			}
			// A read through another binding changes nothing.
			expect(await store.get("tx-1")).toStrictEqual(tx);
			expect(await getBoundMfaTransaction(store, "never", bound)).toBeNull();
		});

		it("keeps a binding to its known fields", async () => {
			const store = await factory();
			await store.create(TX({ binding: { kind: "session", id: SESSION_ID, note: "x" } as never }));
			expect((await store.get("tx-1"))?.binding).toStrictEqual({
				kind: "session",
				id: SESSION_ID,
			});
		});

		it("lets exactly one of N concurrent creates of one id through", async () => {
			// Ten transactions every record rule admits — step-ups, so no
			// continuation ties the subject — under one id: only the store's
			// insert-only rule can refuse nine of them.
			const store = await factory();
			const racing = Array.from({ length: 10 }, (_, i) =>
				TX({
					purpose: "step_up",
					sid: `sid-${i}`,
					continuation: undefined,
					redirectTo: undefined,
					subject: `user-${i}`,
					binding: { kind: "session", id: `express-session-${i}` },
				}),
			);
			const results = await Promise.allSettled(racing.map((tx) => store.create(tx)));
			const created = results.filter((r) => r.status === "fulfilled");
			expect(created).toHaveLength(1);
			for (const result of results) {
				if (result.status === "rejected") expect(result.reason).not.toBeInstanceOf(RangeError);
			}
			const winner = results.indexOf(created[0] as PromiseSettledResult<void>);
			expect(await store.get("tx-1")).toStrictEqual(racing[winner]);
		});

		it("refuses a new transaction whose counters are not a fresh record's, with a RangeError, and records nothing", async () => {
			// A limit is only as good as the count it starts from: NaN + 1 > max
			// is false, so a transaction created with attempts NaN would pass every
			// reservation.
			const store = await factory();
			const bad: [string, Partial<Record<keyof MfaTransaction, unknown>>][] = [
				["attempts 1", { attempts: 1 }],
				["attempts -1000", { attempts: -1000 }],
				["attempts NaN", { attempts: Number.NaN }],
				["attempts missing", { attempts: undefined }],
				["version -1", { version: -1 }],
				["version 1.5", { version: 1.5 }],
				["version NaN", { version: Number.NaN }],
				["version past 2^53", { version: 2 ** 53 }],
			];
			for (const [name, overrides] of bad) {
				await expect(store.create(TX(overrides as Partial<MfaTransaction>)), name).rejects.toThrow(
					RangeError,
				);
			}
			expect(await store.get("tx-1")).toBeNull();
			// A fresh record: no attempt reserved, any version.
			await store.create(TX({ version: 0 }));
			expect((await store.get("tx-1"))?.version).toBe(0);
		});

		it("refuses, with a RangeError, a new transaction with a field its type does not admit, and records nothing", async () => {
			// The same value rules as a patch: a transaction created with
			// `emailProof` missing would carry no email-proof gate (the MFA
			// ADR's D24) at all.
			const store = await factory();
			const bad: [string, unknown][] = [
				["purpose unknown", { purpose: "admin" }],
				["enrollment unknown", { enrollment: "maybe" }],
				["enrollment missing", { enrollment: undefined }],
				["emailProof missing", { emailProof: undefined }],
				["emailProof unknown", { emailProof: "yes" }],
				["emailProof NaN", { emailProof: { provedAtMs: Number.NaN } }],
				["challenge not a challenge", { challenge: "x" }],
				["challenge missing its state", { challenge: { ...CHALLENGE, state: undefined } }],
				[
					"pendingEnrollment missing its state",
					{ pendingEnrollment: { kind: "totp", expiresAtMs: 9 } },
				],
				["id not a string", { id: 7 }],
				["binding missing", { binding: undefined }],
				["binding a bare session id", { binding: SESSION_ID }],
				["binding a list", { binding: ["session", SESSION_ID] }],
				["binding of a kind it does not know", { binding: { kind: "client", id: "c-1" } }],
				["binding without a kind", { binding: { id: SESSION_ID } }],
				["binding whose id is not a string", { binding: { kind: "session", id: 7 } }],
				["binding whose id is empty", { binding: { kind: "session", id: "" } }],
				[
					"binding whose id holds a lone high surrogate",
					{ binding: { kind: "session", id: "s\uD800" } },
				],
				[
					"binding whose id holds a lone low surrogate",
					{ binding: { kind: "session", id: "s\uDC00" } },
				],
				["binding whose id ends in half a pair", { binding: { kind: "session", id: "s\uDBFF" } }],
				["subject not a string", { subject: {} }],
				["sid not a string", { sid: 7 }],
				["redirectTo not a string", { redirectTo: ["/"] }],
				["continuation not an object", { continuation: "pwd" }],
				["continuation without a primary", { continuation: { done: [] } }],
				[
					"continuation whose primary records an mfaAt",
					{
						continuation: {
							...TX().continuation,
							primary: {
								...TX().continuation?.primary,
								recorded: {
									amr: ["pwd"],
									authentication: {
										primary: "pwd",
										federation: undefined,
										upstreamAmr: undefined,
										mfaAt: new Date(),
									},
								},
							},
						},
					},
				],
				[
					"continuation whose done adds a primary's marker",
					{
						continuation: {
							...TX().continuation,
							done: [{ requirement: "mfa", adds: { amr: ["pwd"] } }],
						},
					},
				],
				["acrValues not a list", { acrValues: "urn:x" }],
				["acrValues not strings", { acrValues: [1] }],
			];
			for (const [name, overrides] of bad) {
				await expect(store.create(TX(overrides as Partial<MfaTransaction>)), name).rejects.toThrow(
					RangeError,
				);
			}
			expect(await store.get("tx-1")).toBeNull();
		});

		it("keeps only the fields a transaction has, and only the known fields of each sub-object", async () => {
			// A send count and a last send are no transaction's fields: a limit on
			// sending is the mail sender's.
			const store = await factory();
			const tx = TX({
				emailProof: { provedAtMs: 1234 },
				challenge: CHALLENGE,
				pendingEnrollment: { kind: "totp", state: "sealed", expiresAtMs: 99 },
			});
			await store.create({
				...tx,
				admin: true,
				sends: 3,
				lastSentAtMs: 5,
				continuation: {
					...tx.continuation,
					primary: { ...tx.continuation?.primary, password: "hunter2" },
					done: [],
					extra: true,
				},
				emailProof: { provedAtMs: 1234, by: "operator" },
				challenge: { ...CHALLENGE, secret: "123456" },
				pendingEnrollment: { kind: "totp", state: "sealed", expiresAtMs: 99, secret: "JBSW" },
			} as never);
			expect(await store.get("tx-1")).toStrictEqual(tx);
		});

		it("is insert-only: a live id is refused, and the first record stands", async () => {
			const store = await factory();
			const first = TX();
			await store.create(first);
			await expect(store.create(TX({ subject: "user-2" }))).rejects.toThrow();
			expect(await store.get("tx-1")).toStrictEqual(first);
		});

		it("refuses an expiry that is not a future instant with a RangeError, and records nothing", async () => {
			const store = await factory();
			for (const expiresAtMs of [Date.now() - 1, Number.NaN, Number.POSITIVE_INFINITY, 1e17]) {
				await expect(store.create(TX({ expiresAtMs })), String(expiresAtMs)).rejects.toThrow(
					RangeError,
				);
			}
			expect(await store.get("tx-1")).toBeNull();
		});

		it("forgets a transaction once it expires: every operation answers as if it never was", async () => {
			const store = await factory();
			const at = Math.max(Date.now(), await expiry.now()) + 300;
			await store.create(TX({ expiresAtMs: at, challenge: CHALLENGE }));
			await expiry.passed(at);
			expect(await store.get("tx-1")).toBeNull();
			expect(await store.update("tx-1", 1, { enrollment: "allowed" })).toBeNull();
			expect(await store.reserveAttempt("tx-1", 5)).toEqual({ ok: false, attempts: 0 });
			expect(await store.takeChallenge("tx-1", 1)).toBeNull();
			expect(await store.consume("tx-1", 1)).toBeNull();
			// Gone, so the id may be used again.
			await store.create(TX());
			expect(await store.get("tx-1")).not.toBeNull();
		});

		it("updates at the current version: a present key sets, null clears, an absent key keeps; version + 1", async () => {
			const store = await factory();
			const tx = TX({ challenge: CHALLENGE });
			await store.create(tx);
			const updated = await store.update("tx-1", 1, {
				challenge: null,
				emailProof: { provedAtMs: 1234 },
				enrollment: "required",
			});
			const expected = {
				...tx,
				challenge: undefined,
				emailProof: { provedAtMs: 1234 },
				enrollment: "required" as const,
				version: 2,
			};
			expect(updated).toStrictEqual(expected);
			expect(await store.get("tx-1")).toStrictEqual(expected);
			const again = await store.update("tx-1", 2, {
				pendingEnrollment: { kind: "totp", state: "sealed", expiresAtMs: 99 },
			});
			expect(again).toStrictEqual({
				...expected,
				pendingEnrollment: { kind: "totp", state: "sealed", expiresAtMs: 99 },
				version: 3,
			});
			expect(await store.update("tx-1", 3, { pendingEnrollment: null })).toStrictEqual({
				...expected,
				version: 4,
			});
		});

		it("reads a key present with undefined as absent: it keeps the field, and never clears a requirement", async () => {
			// `{ emailProof: undefined }` compiles, and read as a write it would
			// clear the email-proof gate (the MFA ADR's D24). Only null clears,
			// and only a field that may be empty.
			const store = await factory();
			const tx = TX({
				challenge: CHALLENGE,
				pendingEnrollment: { kind: "totp", state: "sealed", expiresAtMs: 99 },
				emailProof: "required",
				enrollment: "required",
			});
			await store.create(tx);
			const updated = await store.update("tx-1", 1, {
				challenge: undefined,
				pendingEnrollment: undefined,
				emailProof: undefined,
				enrollment: undefined,
			});
			expect(updated).toStrictEqual({ ...tx, version: 2 });
		});

		it("refuses, with a RangeError, a value a field does not admit, and changes nothing", async () => {
			const store = await factory();
			const tx = TX({ challenge: CHALLENGE });
			await store.create(tx);
			const bad: [string, unknown][] = [
				["enrollment null", { enrollment: null }],
				["enrollment unknown", { enrollment: "maybe" }],
				["emailProof null", { emailProof: null }],
				["emailProof unknown", { emailProof: "yes" }],
				["emailProof NaN", { emailProof: { provedAtMs: Number.NaN } }],
				["challenge not a challenge", { challenge: "sealed" }],
				["challenge missing its state", { challenge: { ...CHALLENGE, state: undefined } }],
				["challenge expiry NaN", { challenge: { ...CHALLENGE, expiresAtMs: Number.NaN } }],
				[
					"pendingEnrollment missing its kind",
					{ pendingEnrollment: { state: "s", expiresAtMs: 9 } },
				],
				["pendingEnrollment not an enrollment", { pendingEnrollment: "sealed" }],
			];
			for (const [name, patch] of bad) {
				await expect(store.update("tx-1", 1, patch as never), name).rejects.toThrow(RangeError);
			}
			// A patch that is no object at all is refused the same way.
			for (const patch of [null, "enrollment", 3]) {
				await expect(store.update("tx-1", 1, patch as never), String(patch)).rejects.toThrow(
					RangeError,
				);
			}
			expect(await store.get("tx-1")).toStrictEqual(tx);
		});

		it("refuses, with a RangeError, a patch that would undo a requirement, and changes nothing", async () => {
			// A required email proof is only ever met, never waived (the MFA
			// ADR's D24), and a met one stays met. An enrollment requirement is
			// never lowered.
			const store = await factory();
			const tx = TX({ emailProof: "required", enrollment: "required" });
			await store.create(tx);
			const bad: [string, unknown][] = [
				["email proof waived", { emailProof: "not_required" }],
				["enrollment lowered to none", { enrollment: "none" }],
				["enrollment lowered to allowed", { enrollment: "allowed" }],
			];
			for (const [name, patch] of bad) {
				await expect(store.update("tx-1", 1, patch as never), name).rejects.toThrow(RangeError);
			}
			expect(await store.get("tx-1")).toStrictEqual(tx);
			// What may move: the proof met, the requirements kept.
			const moved = await store.update("tx-1", 1, {
				emailProof: { provedAtMs: 1234 },
				enrollment: "required",
			});
			expect(moved).toStrictEqual({
				...tx,
				emailProof: { provedAtMs: 1234 },
				version: 2,
			});
			for (const [name, patch] of [
				["met proof back to required", { emailProof: "required" }],
				["met proof waived", { emailProof: "not_required" }],
			] as const) {
				await expect(store.update("tx-1", 2, patch as never), name).rejects.toThrow(RangeError);
			}
			// A proof met again (a later proof in the same transaction) stays met.
			expect(
				(await store.update("tx-1", 2, { emailProof: { provedAtMs: 5678 } }))?.emailProof,
			).toStrictEqual({ provedAtMs: 5678 });
		});

		it("lets a requirement be raised: none to allowed to required, and not_required to required", async () => {
			const store = await factory();
			await store.create(TX({ enrollment: "none", emailProof: "not_required" }));
			const raised = await store.update("tx-1", 1, {
				enrollment: "allowed",
				emailProof: "required",
			});
			expect(raised).toMatchObject({ enrollment: "allowed", emailProof: "required" });
			expect(await store.update("tx-1", 2, { enrollment: "required" })).toMatchObject({
				enrollment: "required",
			});
		});

		it("copies only the known fields of a patch's sub-objects", async () => {
			const store = await factory();
			await store.create(TX());
			const updated = await store.update("tx-1", 1, {
				emailProof: { provedAtMs: 1234, by: "operator" },
				challenge: { ...CHALLENGE, secret: "123456" },
				pendingEnrollment: { kind: "totp", state: "sealed", expiresAtMs: 99, secret: "JBSW" },
			} as never);
			expect(updated).toMatchObject({ version: 2 });
			expect(updated?.emailProof).toStrictEqual({ provedAtMs: 1234 });
			expect(updated?.challenge).toStrictEqual(CHALLENGE);
			expect(updated?.pendingEnrollment).toStrictEqual({
				kind: "totp",
				state: "sealed",
				expiresAtMs: 99,
			});
			expect(await store.get("tx-1")).toStrictEqual(updated);
		});

		it("changes only the patch keys: a patch that carries any other field moves none of them", async () => {
			// A patch spread from a transaction compiles; an adapter that wrote the
			// whole object would refund attempts, rebind the session, extend the
			// expiry or swap the user.
			const store = await factory();
			const tx = TX();
			await store.create(tx);
			await store.reserveAttempt("tx-1", 5);
			const updated = await store.update("tx-1", 1, {
				enrollment: "allowed",
				sends: 1,
				lastSentAtMs: 5,
				id: "tx-other",
				purpose: "enroll",
				attempts: 0,
				version: 99,
				binding: { kind: "session", id: "attacker-session" },
				subject: "user-2",
				sid: "sid-other",
				user: { id: "user-2" },
				redirectTo: "https://evil.example/",
				createdAtMs: 0,
				expiresAtMs: tx.expiresAtMs + 86_400_000,
			} as never);
			const expected = { ...tx, attempts: 1, enrollment: "allowed" as const, version: 2 };
			expect(updated).toStrictEqual(expected);
			expect(await store.get("tx-1")).toStrictEqual(expected);
			expect(await store.get("tx-other")).toBeNull();
		});

		it("answers null for a version that moved or a transaction that is gone, and changes nothing", async () => {
			const store = await factory();
			const tx = TX();
			await store.create(tx);
			expect(await store.update("tx-1", 2, { enrollment: "allowed" })).toBeNull();
			expect(await store.update("tx-1", 0, { enrollment: "allowed" })).toBeNull();
			expect(await store.update("gone", 1, { enrollment: "allowed" })).toBeNull();
			expect(await store.get("tx-1")).toStrictEqual(tx);
			expect(await store.get("gone")).toBeNull();
		});

		it("refuses, with a RangeError, an update at Number.MAX_SAFE_INTEGER — the next version would be no safe integer — and changes nothing, whatever the stored version; the update that reaches it passes", async () => {
			const store = await factory();
			const max = Number.MAX_SAFE_INTEGER;
			const tx = TX({ version: max - 1 });
			await store.create(tx);
			const reached = await store.update("tx-1", max - 1, { enrollment: "allowed" });
			expect(reached).toStrictEqual({ ...tx, enrollment: "allowed", version: max });
			await expect(store.update("tx-1", max, { enrollment: "required" })).rejects.toThrow(
				RangeError,
			);
			expect(await store.get("tx-1")).toStrictEqual(reached);
			await expect(store.update("gone", max, { enrollment: "required" })).rejects.toThrow(
				RangeError,
			);
			// The version stays usable for what does not move it.
			expect(await store.consume("tx-1", max)).toStrictEqual(reached);
		});

		it("lets exactly one of N concurrent updates at one version win", async () => {
			const store = await factory();
			await store.create(TX());
			const results = await Promise.all(
				Array.from({ length: 10 }, (_, i) =>
					store.update("tx-1", 1, {
						pendingEnrollment: { kind: "totp", state: `sealed-${i}`, expiresAtMs: 99 },
					}),
				),
			);
			const winners = results.filter((r) => r !== null);
			expect(winners).toHaveLength(1);
			expect(await store.get("tx-1")).toStrictEqual(winners[0]);
		});

		it("treats a transaction whose strings hold a lone surrogate as any other: a reservation spends, a take takes, for as long as a read answers it", async () => {
			// Core admits any string; a store that judges the transaction by a
			// reading of it stricter than its own read would refuse, for the
			// transaction's whole life, what every read calls live.
			const store = await factory();
			const tx = TX({
				purpose: "step_up",
				subject: "user-\udc00",
				sid: "sid-\ud800",
				continuation: undefined,
				redirectTo: undefined,
				acrValues: ["urn:x:\ud800"],
				challenge: CHALLENGE,
			});
			await store.create(tx);
			expect(await store.get("tx-1")).toStrictEqual(tx);
			expect(await store.reserveAttempt("tx-1", 5)).toEqual({ ok: true, attempts: 1 });
			expect(await store.takeChallenge("tx-1", 1)).toStrictEqual(CHALLENGE);
			expect(await store.get("tx-1")).toStrictEqual({ ...tx, attempts: 1, challenge: undefined });
		});

		it("reserves attempts up to max, then deletes the transaction", async () => {
			const store = await factory();
			await store.create(TX());
			for (let n = 1; n <= 5; n++) {
				expect(await store.reserveAttempt("tx-1", 5)).toEqual({ ok: true, attempts: n });
			}
			expect((await store.get("tx-1"))?.attempts).toBe(5);
			expect(await store.reserveAttempt("tx-1", 5)).toEqual({ ok: false, attempts: 5 });
			expect(await store.get("tx-1")).toBeNull();
		});

		it("answers a refused reservation with the attempts the transaction had reserved, even under a lower max", async () => {
			// A max lowered by configuration while a transaction is in flight.
			const store = await factory();
			await store.create(TX());
			for (let n = 1; n <= 4; n++) await store.reserveAttempt("tx-1", 5);
			expect(await store.reserveAttempt("tx-1", 3)).toEqual({ ok: false, attempts: 4 });
			expect(await store.get("tx-1")).toBeNull();
		});

		it("answers a reservation on an unknown transaction as refused, with no attempts", async () => {
			const store = await factory();
			expect(await store.reserveAttempt("never", 5)).toEqual({ ok: false, attempts: 0 });
		});

		it("spends N attempts for N reservations in flight: at most max succeed", async () => {
			// Fifty guesses sent at once spend fifty attempts, not one (the MFA
			// ADR's F1).
			const store = await factory();
			await store.create(TX());
			const results = await Promise.all(
				Array.from({ length: 50 }, () => store.reserveAttempt("tx-1", 5)),
			);
			expect(results.filter((r) => r.ok)).toHaveLength(5);
			expect(
				results
					.filter((r) => r.ok)
					.map((r) => r.attempts)
					.sort(),
			).toEqual([1, 2, 3, 4, 5]);
			expect(await store.get("tx-1")).toBeNull();
		});

		it("leaves the version where it was: a verification that reserved an attempt still consumes at the version it read", async () => {
			const store = await factory();
			await store.create(TX({ challenge: CHALLENGE }));
			await store.reserveAttempt("tx-1", 5);
			expect((await store.get("tx-1"))?.version).toBe(1);
			expect(await store.update("tx-1", 1, { enrollment: "allowed" })).not.toBeNull();
			expect((await store.update("tx-1", 2, { enrollment: "required" }))?.attempts).toBe(1);
		});

		it("refuses a max that is not a positive whole number with a RangeError", async () => {
			const store = await factory();
			await store.create(TX());
			for (const max of [0, -1, 1.5, Number.NaN]) {
				await expect(store.reserveAttempt("tx-1", max), String(max)).rejects.toThrow(RangeError);
			}
			expect((await store.get("tx-1"))?.attempts).toBe(0);
		});

		it("takes a challenge once: read and cleared in one step, the version left where it was", async () => {
			const store = await factory();
			await store.create(TX({ challenge: CHALLENGE }));
			expect(await store.takeChallenge("tx-1", 1)).toStrictEqual(CHALLENGE);
			expect(await store.takeChallenge("tx-1", 1)).toBeNull();
			const after = await store.get("tx-1");
			expect(after).toHaveProperty("challenge", undefined);
			expect(after?.version).toBe(1);
			expect(await store.consume("tx-1", 1)).not.toBeNull();
		});

		it("answers a challenge to exactly one of N takes in flight", async () => {
			const store = await factory();
			await store.create(TX({ challenge: CHALLENGE }));
			const results = await Promise.all(
				Array.from({ length: 10 }, () => store.takeChallenge("tx-1", 1)),
			);
			expect(results.filter((r) => r !== null)).toStrictEqual([CHALLENGE]);
		});

		it("takes nothing at a version that moved, and leaves the challenge for the version that holds it", async () => {
			// A challenge replaced since the verification read the transaction
			// (new request options): only the latest counts.
			const store = await factory();
			await store.create(TX({ challenge: CHALLENGE }));
			const resent = { ...CHALLENGE, state: "sealed-resent" };
			await store.update("tx-1", 1, { challenge: resent });
			expect(await store.takeChallenge("tx-1", 1)).toBeNull();
			expect(await store.takeChallenge("tx-1", 2)).toStrictEqual(resent);
		});

		it("answers null when there is no challenge to take", async () => {
			const store = await factory();
			await store.create(TX());
			expect(await store.takeChallenge("tx-1", 1)).toBeNull();
			expect(await store.takeChallenge("never", 1)).toBeNull();
		});

		it("consumes at the current version: the one winner gets the record, and it is gone", async () => {
			const store = await factory();
			const tx = TX();
			await store.create(tx);
			expect(await store.consume("tx-1", 1)).toStrictEqual(tx);
			expect(await store.get("tx-1")).toBeNull();
			expect(await store.consume("tx-1", 1)).toBeNull();
		});

		it("consumes nothing at a version that moved, and the transaction stays", async () => {
			const store = await factory();
			await store.create(TX());
			await store.update("tx-1", 1, { enrollment: "allowed" });
			expect(await store.consume("tx-1", 1)).toBeNull();
			expect((await store.get("tx-1"))?.version).toBe(2);
			expect(await store.consume("never", 1)).toBeNull();
		});

		it("gives the record to exactly one of N consumes in flight", async () => {
			// Two verifications in flight produce one session (the MFA ADR's F1).
			const store = await factory();
			await store.create(TX());
			const results = await Promise.all(Array.from({ length: 10 }, () => store.consume("tx-1", 1)));
			expect(results.filter((r) => r !== null)).toHaveLength(1);
			expect(await store.get("tx-1")).toBeNull();
		});
	});

	describe("MfaTransactionStore contract: the subject state, under an injected clock", () => {
		/** An instant near the host's clock, so an adapter that expires state on its own clock keeps it. */
		const start = () => Math.floor(Date.now() / 1000) * 1000;

		/** The MFA ADR's D19 defaults with the week out of the way, for the cases about the run alone. */
		const RUN_ONLY: MfaLockoutPolicy = { ...POLICY, weeklyBudget: 1000 };

		const check = (
			store: MfaTransactionStore,
			at: number,
			policy: MfaLockoutPolicy = POLICY,
			subject = "user-1",
		): Promise<MfaSubjectAttemptReservation> => store.reserveSubjectAttempt(subject, at, policy);

		async function reserved(
			store: MfaTransactionStore,
			at: number,
			policy: MfaLockoutPolicy = POLICY,
			subject = "user-1",
		): Promise<string> {
			const result = await check(store, at, policy, subject);
			if (!result.ok) {
				throw new Error(`expected a reservation for ${subject}, held: ${result.hold}`);
			}
			return result.reservation;
		}

		async function fail(
			store: MfaTransactionStore,
			at: number,
			policy: MfaLockoutPolicy = POLICY,
			subject = "user-1",
		): Promise<void> {
			const reservation = await reserved(store, at, policy, subject);
			await store.settleSubjectAttempt(subject, reservation, "failure");
		}

		async function settled(
			store: MfaTransactionStore,
			at: number,
			outcome: "success" | "void",
			subject = "user-1",
		): Promise<void> {
			const reservation = await reserved(store, at, POLICY, subject);
			await store.settleSubjectAttempt(subject, reservation, outcome);
		}

		/**
		 * `count` failures a minute apart, in runs of four each ended by a
		 * success, so that no backoff lock is reached; answers the next free
		 * minute.
		 */
		async function failures(
			store: MfaTransactionStore,
			from: number,
			count: number,
			subject = "user-1",
		): Promise<number> {
			let at = from;
			for (let i = 1; i <= count; i++) {
				await fail(store, at, POLICY, subject);
				at += MINUTE;
				if (i % 4 === 0) {
					await settled(store, at, "success", subject);
					at += MINUTE;
				}
			}
			return at;
		}

		/** weeklyBudget failures inside half an hour, the victim's own successes between them. */
		const fillTheWeek = (store: MfaTransactionStore, from: number, subject = "user-1") =>
			failures(store, from, 10, subject);

		const held = (
			result: MfaSubjectAttemptReservation,
		): { hold: string; retryAfterMs: number | null } | "ok" =>
			result.ok ? "ok" : { hold: result.hold, retryAfterMs: result.retryAfterMs };

		it("locks guessable proofs for baseSeconds from the fifth consecutive failure", async () => {
			const store = await factory();
			const t = start();
			for (let i = 0; i < 5; i++) await fail(store, t + i * 1000);
			expect(held(await check(store, t + 5000))).toEqual({
				hold: "backoff",
				retryAfterMs: 4000 + 900_000 - 5000,
			});
			// A refused attempt is not an attempt: it counts for nothing.
			for (let i = 0; i < 20; i++) await check(store, t + 6000 + i);
			expect((await check(store, t + 4000 + 900_000)).ok).toBe(true);
		});

		it("doubles the lock with each further failure, up to maxSeconds", async () => {
			const store = await factory();
			let at = start();
			for (let i = 0; i < 4; i++) await fail(store, at + i, RUN_ONLY);
			at += 4;
			const seconds: number[] = [];
			for (let i = 0; i < 9; i++) {
				await fail(store, at, RUN_ONLY);
				const result = await check(store, at + 1, RUN_ONLY);
				if (result.ok || result.retryAfterMs === null) throw new Error("expected a backoff lock");
				expect(result.hold).toBe("backoff");
				seconds.push((result.retryAfterMs + 1) / 1000);
				at += result.retryAfterMs + 1;
			}
			expect(seconds).toEqual([900, 1800, 3600, 7200, 14_400, 28_800, 57_600, 86_400, 86_400]);
		});

		it("forgets the backoff memorySeconds after the last lock ends, and not before", async () => {
			const store = await factory();
			const t = start();
			for (let i = 0; i < 5; i++) await fail(store, t + i, RUN_ONLY);
			const lockEnds = t + 4 + 900_000;
			// A day after the lock ends, the next failure is the first of a new
			// backoff: four pass without a lock, and the fifth locks for
			// baseSeconds again.
			const forgotten = lockEnds + DAY;
			for (let i = 0; i < 5; i++) await fail(store, forgotten + i, RUN_ONLY);
			expect(held(await check(store, forgotten + 5, RUN_ONLY))).toEqual({
				hold: "backoff",
				retryAfterMs: 900_000 - 1,
			});

			const other = await factory();
			for (let i = 0; i < 5; i++) await fail(other, t + i, RUN_ONLY);
			// A millisecond short of that, the next failure is the sixth.
			await fail(other, forgotten - 1, RUN_ONLY);
			expect(held(await check(other, forgotten, RUN_ONLY))).toEqual({
				hold: "backoff",
				retryAfterMs: 1_800_000 - 1,
			});
		});

		it("starts the count again after memorySeconds without a failure, before any lock too", async () => {
			// The MFA ADR's D21 forgets the backoff memorySeconds after the last
			// lock ends; before any lock, the same quiet period after the previous
			// failure forgets the failures that did not reach it.
			const store = await factory();
			const t = start();
			for (let i = 0; i < 4; i++) await fail(store, t + i, RUN_ONLY);
			const quiet = t + 3 + DAY;
			for (let i = 0; i < 4; i++) await fail(store, quiet + i, RUN_ONLY);
			expect((await check(store, quiet + 4, RUN_ONLY)).ok).toBe(true);

			const other = await factory();
			for (let i = 0; i < 4; i++) await fail(other, t + i, RUN_ONLY);
			// A millisecond short of that, the next failure is the fifth: a lock.
			await fail(other, quiet - 1, RUN_ONLY);
			expect(held(await check(other, quiet, RUN_ONLY))).toEqual({
				hold: "backoff",
				retryAfterMs: 900_000 - 1,
			});
		});

		it("reports the backoff when it ends after the weekly hold", async () => {
			const long: MfaLockoutPolicy = {
				...POLICY,
				baseSeconds: 8 * 86_400,
				maxSeconds: 8 * 86_400,
				weeklyBudget: 5,
			};
			const store = await factory();
			const t = start();
			for (let i = 0; i < 5; i++) await fail(store, t + i, long);
			expect(held(await check(store, t + 5, long))).toEqual({
				hold: "backoff",
				retryAfterMs: 4 + 8 * DAY - 5,
			});
		});

		it("counts a reservation as a failure until it is settled", async () => {
			const store = await factory();
			const t = start();
			for (let i = 0; i < 5; i++) await reserved(store, t + i);
			expect(held(await check(store, t + 5))).toEqual({
				hold: "backoff",
				retryAfterMs: 4 + 900_000 - 5,
			});
		});

		it("spends N reservations for N attempts in flight: the lock holds the rest", async () => {
			const store = await factory();
			const t = start();
			const results = await Promise.all(Array.from({ length: 20 }, () => check(store, t)));
			expect(results.filter((r) => r.ok)).toHaveLength(5);
			expect(results.filter((r) => !r.ok).map((r) => held(r))).toEqual(
				Array.from({ length: 15 }, () => ({ hold: "backoff", retryAfterMs: 900_000 })),
			);
		});

		/** Whether `result` is a refusal answered as its episode's first. */
		const first = (result: MfaSubjectAttemptReservation): boolean | "ok" =>
			result.ok ? "ok" : result.first;

		it("answers the refusal that begins an episode as first, and every later one of it not", async () => {
			const store = await factory();
			const t = start();
			for (let i = 0; i < 5; i++) await fail(store, t + i);
			expect(first(await check(store, t + 5))).toBe(true);
			expect(first(await check(store, t + 6))).toBe(false);
			expect(first(await check(store, t + 7))).toBe(false);
		});

		it("begins another episode after an attempt is let through, and after clearSubjectState", async () => {
			const store = await factory();
			const t = start();
			for (let i = 0; i < 5; i++) await fail(store, t + i);
			expect(first(await check(store, t + 5))).toBe(true);
			// The backoff ends: an attempt is let through, and fails, so the
			// next lock is a new episode.
			const after = t + 4 + 900_000;
			await fail(store, after);
			expect(first(await check(store, after + 1))).toBe(true);
			expect(first(await check(store, after + 2))).toBe(false);
			await store.clearSubjectState("user-1");
			for (let i = 0; i < 5; i++) await fail(store, after + 10 + i);
			expect(first(await check(store, after + 15))).toBe(true);
		});

		it("keeps an episode through an exempt success that lifts no hold, and each subject's apart", async () => {
			const store = await factory();
			const t = start();
			const at = await fillTheWeek(store, t);
			expect(first(await check(store, at))).toBe(true);
			await store.noteExemptSuccess("user-1", at + 1, POLICY);
			expect(first(await check(store, at + 2))).toBe(false);
			const other = await fillTheWeek(store, t, "user-2");
			expect(first(await check(store, other, POLICY, "user-2"))).toBe(true);
		});

		it("answers one refusal as first among N in flight", async () => {
			const store = await factory();
			const t = start();
			for (let i = 0; i < 5; i++) await fail(store, t + i);
			const results = await Promise.all(Array.from({ length: 10 }, () => check(store, t + 5)));
			expect(results.map(first).filter((answer) => answer === true)).toHaveLength(1);
			expect(results.every((result) => !result.ok)).toBe(true);
		});

		it("ends the run, and its lock, on a guessable success", async () => {
			const store = await factory();
			const t = start();
			for (let i = 0; i < 4; i++) await fail(store, t + i);
			const fifth = await reserved(store, t + 4);
			// Pending, the fifth holds everyone else.
			expect((await check(store, t + 5)).ok).toBe(false);
			await store.settleSubjectAttempt("user-1", fifth, "success");
			// A new run: four failures pass, the fifth locks.
			for (let i = 0; i < 5; i++) await fail(store, t + 10 + i);
			expect(held(await check(store, t + 15))).toEqual({
				hold: "backoff",
				retryAfterMs: 14 + 900_000 - 15,
			});
		});

		it("ends the run only up to a success: an attempt reserved after it, still in flight, stays", async () => {
			const store = await factory();
			const t = start();
			for (let i = 0; i < 3; i++) await fail(store, t + i);
			const success = await reserved(store, t + 3);
			const inFlight = await reserved(store, t + 4);
			await store.settleSubjectAttempt("user-1", success, "success");
			await store.settleSubjectAttempt("user-1", inFlight, "failure");
			// The run is the failure reserved after the success: four more lock.
			for (let i = 0; i < 4; i++) await fail(store, t + 5 + i);
			expect(held(await check(store, t + 9))).toEqual({
				hold: "backoff",
				retryAfterMs: 8 + 900_000 - 9,
			});
		});

		it("ends the run at an exempt success only up to its time: an attempt reserved later stays", async () => {
			const store = await factory();
			const t = start();
			for (let i = 0; i < 3; i++) await fail(store, t + i);
			const later = await reserved(store, t + 10);
			await store.noteExemptSuccess("user-1", t + 5, POLICY);
			await store.settleSubjectAttempt("user-1", later, "failure");
			for (let i = 0; i < 4; i++) await fail(store, t + 11 + i);
			expect(held(await check(store, t + 15))).toEqual({
				hold: "backoff",
				retryAfterMs: 14 + 900_000 - 15,
			});
		});

		it("settles a reservation only under the subject that made it", async () => {
			const store = await factory();
			const t = start();
			for (let i = 0; i < 4; i++) await fail(store, t + i);
			const fifth = await reserved(store, t + 4);
			await store.settleSubjectAttempt("user-2", fifth, "void");
			await store.settleSubjectAttempt("user-2", fifth, "success");
			// Still pending under user-1: it holds the lock.
			expect(held(await check(store, t + 5))).toEqual({
				hold: "backoff",
				retryAfterMs: 4 + 900_000 - 5,
			});
		});

		it("refuses an outcome it does not know with a RangeError, and settles nothing", async () => {
			const store = await factory();
			const t = start();
			const first = await reserved(store, t);
			for (const outcome of ["maybe", "", "SUCCESS", undefined]) {
				await expect(
					store.settleSubjectAttempt("user-1", first, outcome as never),
					String(outcome),
				).rejects.toThrow(RangeError);
			}
			// Still pending: with four more failures the run is five.
			for (let i = 1; i <= 4; i++) await fail(store, t + i);
			expect((await check(store, t + 5)).ok).toBe(false);
		});

		it("removes an attempt settled void — the proof was right, the write lost — without ending the run", async () => {
			const store = await factory();
			const t = start();
			for (let i = 0; i < 4; i++) await fail(store, t + i);
			const fifth = await reserved(store, t + 4);
			await store.settleSubjectAttempt("user-1", fifth, "void");
			// The lock the pending fifth held is gone, and the run is at four:
			// one more failure locks.
			await fail(store, t + 5);
			expect(held(await check(store, t + 6))).toEqual({
				hold: "backoff",
				retryAfterMs: 5 + 900_000 - 6,
			});
		});

		it("settles a reservation once: settling it again, or one it never made, changes nothing", async () => {
			const store = await factory();
			const t = start();
			for (let i = 0; i < 3; i++) await fail(store, t + i);
			const fourth = await reserved(store, t + 3);
			await store.settleSubjectAttempt("user-1", fourth, "failure");
			await store.settleSubjectAttempt("user-1", fourth, "void");
			await store.settleSubjectAttempt("user-1", fourth, "success");
			await store.settleSubjectAttempt("user-1", "never-reserved", "success");
			await store.settleSubjectAttempt("nobody", "never-reserved", "void");
			await fail(store, t + 4);
			expect((await check(store, t + 5)).ok).toBe(false);
		});

		it("holds guessable proofs past weeklyBudget failures in any seven days: no success refunds one, and an exempt success lets no attempt through", async () => {
			const store = await factory();
			const t = start();
			const at = await fillTheWeek(store, t);
			expect(held(await check(store, at))).toEqual({ hold: "weekly", retryAfterMs: t + WEEK - at });
			// An exempt success answers nothing, and the week stands for every
			// guessable attempt after it.
			expect(await store.noteExemptSuccess("user-1", at + 1, POLICY)).toBeUndefined();
			expect(held(await check(store, at + 2))).toEqual({
				hold: "weekly",
				retryAfterMs: t + WEEK - (at + 2),
			});
		});

		it("rolls the week: a failure stops counting seven days after it was made", async () => {
			expect(MFA_WEEKLY_WINDOW_MS).toBe(WEEK);
			const store = await factory();
			const t = start();
			await fillTheWeek(store, t);
			expect((await check(store, t + WEEK - 1)).ok).toBe(false);
			expect((await check(store, t + WEEK)).ok).toBe(true);
		});

		it("judges each caller on its own time, and lets none erase a failure another still counts", async () => {
			// A caller whose clock runs ahead — within a day of the others — is
			// answered on its time, but the failures it cannot see are kept for
			// the callers that still count them.
			const store = await factory();
			const t = start();
			const at = await fillTheWeek(store, t);
			expect((await check(store, t + WEEK + HOUR)).ok).toBe(true);
			expect(held(await check(store, at + 1))).toMatchObject({ hold: "weekly" });
		});

		it("lets no caller far ahead erase what a caller on time still counts, for its subject or another", async () => {
			// A replica whose clock is ten days ahead is answered on its time, but
			// the week it cannot see stands for every caller on time — the
			// subject it asked about and every other — and keeps standing once
			// its clock is corrected.
			const store = await factory();
			const t = start();
			const at = await fillTheWeek(store, t);
			await fillTheWeek(store, t, "user-2");
			expect((await check(store, t + 10 * DAY, POLICY, "user-3")).ok).toBe(true);
			expect((await check(store, t + 10 * DAY)).ok).toBe(true);
			expect(held(await check(store, at + 1))).toMatchObject({ hold: "weekly" });
			expect(held(await check(store, at + 1, POLICY, "user-2"))).toMatchObject({
				hold: "weekly",
			});
		});

		it("takes an attempt settled void out of the week", async () => {
			const store = await factory();
			const t = start();
			const at = await failures(store, t, 9);
			await settled(store, at, "void");
			expect((await check(store, at + 1)).ok).toBe(true);
		});

		it("ends the run and lifts a backoff lock on an exempt success, and the week stands", async () => {
			const store = await factory();
			const t = start();
			for (let i = 0; i < 5; i++) await fail(store, t + i);
			expect((await check(store, t + 5)).ok).toBe(false);
			await store.noteExemptSuccess("user-1", t + 6, POLICY);
			// A new run: four failures pass. The week holds the first five, so
			// the tenth failure is the last it takes.
			for (let i = 0; i < 4; i++) await fail(store, t + 7 + i);
			await store.noteExemptSuccess("user-1", t + 11, POLICY);
			await fail(store, t + 12);
			expect(held(await check(store, t + 13))).toEqual({
				hold: "weekly",
				retryAfterMs: t + WEEK - (t + 13),
			});
		});

		/** A hard limit of six, reached a minute apart without a weekly hold or a backoff in the way. */
		const SMALL_HARD: MfaLockoutPolicy = {
			...POLICY,
			threshold: 2,
			baseSeconds: 60,
			maxSeconds: 60,
			weeklyBudget: 1000,
			hardLimit: 6,
		};

		it("holds guessable proofs at hardLimit consecutive failures: an exempt success does not lift it, clearSubjectState does", async () => {
			const store = await factory();
			let at = start();
			for (let i = 0; i < 6; i++) {
				at += MINUTE;
				await fail(store, at, SMALL_HARD);
			}
			at += DAY;
			expect(held(await check(store, at, SMALL_HARD))).toEqual({
				hold: "hard",
				retryAfterMs: null,
			});
			await store.noteExemptSuccess("user-1", at, SMALL_HARD);
			expect(held(await check(store, at + 1, SMALL_HARD))).toEqual({
				hold: "hard",
				retryAfterMs: null,
			});
			// Nor does another, a week on: the run stands until the subject is cleared.
			await store.noteExemptSuccess("user-1", at + WEEK, SMALL_HARD);
			expect(held(await check(store, at + WEEK + 1, SMALL_HARD))).toEqual({
				hold: "hard",
				retryAfterMs: null,
			});
			await store.clearSubjectState("user-1");
			expect((await check(store, at + WEEK + 2, SMALL_HARD)).ok).toBe(true);
		});

		it("ends a run one short of hardLimit at an exempt success, so the hard hold does not come", async () => {
			const store = await factory();
			let at = start();
			for (let i = 0; i < 5; i++) {
				at += MINUTE;
				await fail(store, at, SMALL_HARD);
			}
			await store.noteExemptSuccess("user-1", at, SMALL_HARD);
			// Five more failures: a run of five, not ten.
			for (let i = 0; i < 5; i++) {
				at += MINUTE;
				await fail(store, at, SMALL_HARD);
			}
			at += DAY;
			expect((await check(store, at, SMALL_HARD)).ok).toBe(true);
		});

		it("counts at an exempt success only the attempts up to its time: they end, and an attempt reserved later stays", async () => {
			const store = await factory();
			let at = start();
			for (let i = 0; i < 4; i++) {
				at += MINUTE;
				await fail(store, at, SMALL_HARD);
			}
			const later = await reserved(store, at + 10 * MINUTE, SMALL_HARD);
			// Five in the run, four of them up to the exempt success's time.
			await store.noteExemptSuccess("user-1", at + MINUTE, SMALL_HARD);
			await store.settleSubjectAttempt("user-1", later, "failure");
			// The run is the later attempt and five more: six, the hard hold.
			at += 10 * MINUTE;
			for (let i = 0; i < 5; i++) {
				at += MINUTE;
				await fail(store, at, SMALL_HARD);
			}
			at += DAY;
			expect(held(await check(store, at, SMALL_HARD))).toEqual({
				hold: "hard",
				retryAfterMs: null,
			});
		});

		it("holds at hardLimit through an exempt success, a reservation in flight up to its time counted", async () => {
			const store = await factory();
			let at = start();
			for (let i = 0; i < 5; i++) {
				at += MINUTE;
				await fail(store, at, SMALL_HARD);
			}
			const inFlight = await reserved(store, at + MINUTE, SMALL_HARD);
			await store.noteExemptSuccess("user-1", at + 2 * MINUTE, SMALL_HARD);
			// Settled a failure after it, the run is six: it stood.
			await store.settleSubjectAttempt("user-1", inFlight, "failure");
			expect(held(await check(store, at + DAY, SMALL_HARD))).toEqual({
				hold: "hard",
				retryAfterMs: null,
			});
		});

		it("holds at hardLimit through an exempt success dated before every attempt of the run", async () => {
			const store = await factory();
			const t = start();
			let at = t + HOUR;
			for (let i = 0; i < 6; i++) {
				at += MINUTE;
				await fail(store, at, SMALL_HARD);
			}
			await store.noteExemptSuccess("user-1", t, SMALL_HARD);
			expect(held(await check(store, at + DAY, SMALL_HARD))).toEqual({
				hold: "hard",
				retryAfterMs: null,
			});
		});

		it("reads hardLimit once at an exempt success: the value it checks is the value it applies", async () => {
			// Five failures, below SMALL_HARD's six, and a policy whose hardLimit
			// answers 5 once and 1000 after: checked and applied apart, it would
			// either be refused or end the five.
			const store = await factory();
			let at = start();
			for (let i = 0; i < 5; i++) {
				at += MINUTE;
				await fail(store, at, SMALL_HARD);
			}
			let reads = 0;
			const shifting = new Proxy(
				{ ...SMALL_HARD, hardLimit: 5 },
				{
					get: (target, key, receiver) => {
						if (key !== "hardLimit") return Reflect.get(target, key, receiver);
						reads += 1;
						return reads === 1 ? 5 : 1000;
					},
				},
			);
			await store.noteExemptSuccess("user-1", at, shifting);
			expect(held(await check(store, at + DAY, { ...SMALL_HARD, hardLimit: 5 }))).toEqual({
				hold: "hard",
				retryAfterMs: null,
			});
		});

		/** Six failures a minute apart under SMALL_HARD: the run at its hardLimit. Answers the last one's time. */
		async function toTheHardLimit(store: MfaTransactionStore): Promise<number> {
			let at = start();
			for (let i = 0; i < 6; i++) {
				at += MINUTE;
				await fail(store, at, SMALL_HARD);
			}
			return at;
		}

		const HARD = { hold: "hard", retryAfterMs: null };

		it("holds at hardLimit through an exempt success dated before, at or after the last failure, whether or not a refusal came first", async () => {
			for (const offset of [-1, 0, 1]) {
				for (const refusedFirst of [false, true]) {
					const store = await factory();
					const last = await toTheHardLimit(store);
					if (refusedFirst) expect(held(await check(store, last + 1, SMALL_HARD))).toEqual(HARD);
					await store.noteExemptSuccess("user-1", last + offset, SMALL_HARD);
					expect(
						held(await check(store, last + DAY, SMALL_HARD)),
						JSON.stringify({ offset, refusedFirst }),
					).toEqual(HARD);
				}
			}
		});

		it("holds from the reservation that brings the run to hardLimit: settling it, or one before it, a success or a void lifts nothing", async () => {
			for (const outcome of ["success", "void"] as const) {
				const store = await factory();
				let at = start();
				for (let i = 0; i < 5; i++) {
					at += MINUTE;
					await fail(store, at, SMALL_HARD);
				}
				const sixth = await reserved(store, at + MINUTE, SMALL_HARD);
				expect(held(await check(store, at + MINUTE + 1, SMALL_HARD)), outcome).toEqual(HARD);
				await store.settleSubjectAttempt("user-1", sixth, outcome);
				expect(held(await check(store, at + DAY, SMALL_HARD)), outcome).toEqual(HARD);
			}
			// Two in flight at the limit: the later settled a success, ending the
			// run up to it, and the earlier a void.
			const store = await factory();
			let at = start();
			for (let i = 0; i < 4; i++) {
				at += MINUTE;
				await fail(store, at, SMALL_HARD);
			}
			const fifth = await reserved(store, at + MINUTE, SMALL_HARD);
			const sixth = await reserved(store, at + 2 * MINUTE, SMALL_HARD);
			await store.settleSubjectAttempt("user-1", sixth, "success");
			await store.settleSubjectAttempt("user-1", fifth, "void");
			expect(held(await check(store, at + DAY, SMALL_HARD))).toEqual(HARD);
		});

		it("lets one of two reservations racing to hardLimit through, refuses the other hard, and holds after the one let through succeeds", async () => {
			const store = await factory();
			let at = start();
			for (let i = 0; i < 5; i++) {
				at += MINUTE;
				await fail(store, at, SMALL_HARD);
			}
			at += MINUTE;
			const results = await Promise.all([
				check(store, at, SMALL_HARD),
				check(store, at, SMALL_HARD),
			]);
			const through = results.filter((r) => r.ok);
			expect(through).toHaveLength(1);
			expect(results.filter((r) => !r.ok).map((r) => held(r))).toEqual([HARD]);
			const [won] = through;
			if (won === undefined || !won.ok) throw new Error("expected a reservation");
			await store.settleSubjectAttempt("user-1", won.reservation, "success");
			expect(held(await check(store, at + DAY, SMALL_HARD))).toEqual(HARD);
		});

		it("keeps the hard hold whatever hardLimit a later call is handed: a higher one, and an exempt success under a lower or a higher one, lift nothing", async () => {
			const higher: MfaLockoutPolicy = { ...SMALL_HARD, hardLimit: 7 };
			const lower: MfaLockoutPolicy = { ...SMALL_HARD, hardLimit: 5 };
			const store = await factory();
			const last = await toTheHardLimit(store);
			expect(held(await check(store, last + DAY, higher))).toEqual(HARD);
			await store.noteExemptSuccess("user-1", last + DAY, higher);
			expect(held(await check(store, last + DAY + 1, higher))).toEqual(HARD);
			await store.noteExemptSuccess("user-1", last + DAY + 2, lower);
			// The lower limit asked last: asked first, it would hold a run the
			// latch had let go.
			for (const policy of [SMALL_HARD, higher, { ...SMALL_HARD, hardLimit: 100 }, lower]) {
				expect(held(await check(store, last + 2 * DAY, policy)), String(policy.hardLimit)).toEqual(
					HARD,
				);
			}
		});

		it("holds a campaign the victim never interrupts at hardLimit, across weeks and forgotten backoffs", async () => {
			// The attacker spends every attempt the moment the store allows it; the
			// run is never ended, so it reaches the hard limit however it is paced.
			const store = await factory();
			let at = start();
			let spent = 0;
			let last: MfaSubjectAttemptReservation | undefined;
			for (let step = 0; step < 1000; step++) {
				last = await check(store, at);
				if (last.ok) {
					await store.settleSubjectAttempt("user-1", last.reservation, "failure");
					spent++;
					continue;
				}
				if (last.retryAfterMs === null) break;
				at += last.retryAfterMs;
			}
			expect(spent).toBe(100);
			expect(last && held(last)).toEqual({ hold: "hard", retryAfterMs: null });
		});

		it("clears the run and the week on clearSubjectState", async () => {
			const store = await factory();
			const t = start();
			let at = await fillTheWeek(store, t);
			await store.clearSubjectState("user-1");
			await store.clearSubjectState("user-1");
			await store.clearSubjectState("nobody");
			// The week starts empty: five failures reach the backoff, not the
			// weekly hold, and clearing again lifts the backoff.
			for (let i = 0; i < 5; i++) await fail(store, ++at);
			expect(held(await check(store, at + 1))).toMatchObject({ hold: "backoff" });
			await store.clearSubjectState("user-1");
			await settled(store, at + 1, "void");
		});

		it("keeps subjects apart", async () => {
			const store = await factory();
			const t = start();
			const at = await fillTheWeek(store, t, "user-1");
			// user-1's week is not user-2's.
			await settled(store, at, "success", "user-2");
			// user-2's exempt success ends no run of user-3's.
			for (let i = 0; i < 5; i++) await fail(store, at + i, RUN_ONLY, "user-3");
			await store.noteExemptSuccess("user-2", at + 5, RUN_ONLY);
			expect(held(await check(store, at + 6, RUN_ONLY, "user-3"))).toMatchObject({
				hold: "backoff",
			});
			// Clearing one subject leaves the other held.
			const next = await fillTheWeek(store, at + MINUTE, "user-2");
			await store.clearSubjectState("user-2");
			expect(held(await check(store, next, POLICY, "user-1"))).toMatchObject({ hold: "weekly" });
			await settled(store, next, "void", "user-2");
		});

		it("holds a run that a lower hardLimit finds at it, at a reservation or an exempt success, under every higher limit after", async () => {
			const lower: MfaLockoutPolicy = { ...SMALL_HARD, hardLimit: 5 };
			const higher: MfaLockoutPolicy = { ...SMALL_HARD, hardLimit: 7 };
			for (const finds of ["reservation", "exempt success"] as const) {
				const store = await factory();
				let at = start();
				for (let i = 0; i < 5; i++) {
					at += MINUTE;
					await fail(store, at, SMALL_HARD);
				}
				if (finds === "reservation") {
					expect(held(await check(store, at + DAY, lower)), finds).toEqual(HARD);
				} else {
					await store.noteExemptSuccess("user-1", at + DAY, lower);
				}
				for (const policy of [SMALL_HARD, higher]) {
					expect(
						held(await check(store, at + 2 * DAY, policy)),
						`${finds}, then ${policy.hardLimit}`,
					).toEqual(HARD);
				}
			}
		});

		it("reads the policy once at a reservation: the hardLimit it checks is the one it holds at", async () => {
			// Each call's policy answers hardLimit 3 to its first read and 100
			// after: read apart, the third reservation would not hold.
			const shifting = (): MfaLockoutPolicy => {
				let reads = 0;
				return new Proxy(
					{ ...SMALL_HARD, hardLimit: 3 },
					{
						get: (target, key, receiver) => {
							if (key !== "hardLimit") return Reflect.get(target, key, receiver);
							reads += 1;
							return reads === 1 ? 3 : 100;
						},
					},
				);
			};
			const store = await factory();
			let at = start();
			for (let i = 0; i < 3; i++) {
				at += MINUTE;
				await fail(store, at, shifting());
			}
			expect(held(await check(store, at + DAY, shifting()))).toEqual(HARD);
		});

		it("refuses a lockout policy it cannot apply, and an instant that is not one, with a RangeError", async () => {
			const store = await factory();
			const t = start();
			for (const bad of [
				{ threshold: 0 },
				{ threshold: 1.5 },
				{ baseSeconds: 0 },
				{ maxSeconds: 899 },
				{ memorySeconds: -1 },
				{ weeklyBudget: Number.NaN },
				{ hardLimit: 0 },
				{ maxSeconds: 1e17 },
				// Safe integers whose duration runs past the Date range once in ms.
				{ maxSeconds: 9e12 },
				{ memorySeconds: 9e12 },
				// The backoff would never engage before the hard hold.
				{ threshold: 10, hardLimit: 6 },
				// NIST SP 800-63B-4 caps consecutive failures at 100, as the MFA
				// ADR's D21 cites.
				{ hardLimit: 101 },
			] satisfies Partial<MfaLockoutPolicy>[]) {
				const policy = { ...POLICY, ...bad };
				await expect(check(store, t, policy), JSON.stringify(bad)).rejects.toThrow(RangeError);
				await expect(
					store.noteExemptSuccess("user-1", t, policy),
					`noteExemptSuccess ${JSON.stringify(bad)}`,
				).rejects.toThrow(RangeError);
			}
			for (const notAPolicy of [null, undefined, "mfa.lockout", 5]) {
				await expect(
					store.reserveSubjectAttempt("user-1", t, notAPolicy as never),
					String(notAPolicy),
				).rejects.toThrow(RangeError);
				await expect(
					store.noteExemptSuccess("user-1", t, notAPolicy as never),
					String(notAPolicy),
				).rejects.toThrow(RangeError);
			}
			await expect(check(store, Number.NaN)).rejects.toThrow(RangeError);
			await expect(store.noteExemptSuccess("user-1", Number.NaN, POLICY)).rejects.toThrow(
				RangeError,
			);
		});

		describe("authorized recovery", () => {
			// A recovery is authorized once (an exempt proof's, or the operator
			// reset's) and applied once, under the subject's lease. `recover`
			// gives the attempt budget back only after a revocation later than
			// the attack's first failure the week still counts.
			const SKEW = DEFAULT_CLOCK_SKEW_MS;

			async function leased(store: MfaTransactionStore, subject = "user-1"): Promise<string> {
				const answer = await store.acquireSubjectLease(subject, { ttlMs: 60_000 });
				if (answer.outcome !== "acquired") throw new Error(`expected a lease: ${answer.outcome}`);
				return answer.token;
			}

			const authorization = (
				overrides: Partial<MfaSubjectRecoveryAuthorization> = {},
			): MfaSubjectRecoveryAuthorization => ({
				operation: "recover",
				sid: "sid-1",
				recoveryId: "recovery-1",
				expiresAtMs: Date.now() + 10 * MINUTE,
				...overrides,
			});

			/** Applies a recover of `subject` in the session sid-1 at `nowMs`, under a lease of its own unless one is given. */
			async function recover(
				store: MfaTransactionStore,
				nowMs: number,
				overrides: Partial<MfaSubjectRecoveryApplication> = {},
				subject = "user-1",
			): Promise<MfaSubjectRecoveryAnswer> {
				const own = overrides.leaseToken === undefined;
				const leaseToken = overrides.leaseToken ?? (await leased(store, subject));
				try {
					return await store.applySubjectRecovery(subject, {
						operation: "recover",
						sid: "sid-1",
						nowMs,
						leaseToken,
						sessionsBoundaryMs: undefined,
						guessableBoundSinceMs: undefined,
						...overrides,
					});
				} finally {
					if (own) await store.releaseSubjectLease(subject, leaseToken);
				}
			}

			const RELEASED = {
				outcome: "applied",
				recoveryId: "recovery-1",
				generation: 1,
				cleared: { week: true, run: true, hard: false },
				hard: false,
			};

			/** The week filled an hour before the host's clock: answers when its first failure was. */
			async function attacked(store: MfaTransactionStore, subject = "user-1"): Promise<number> {
				const from = start() - HOUR;
				await fillTheWeek(store, from, subject);
				return from;
			}

			it("answers unauthorized with nothing authorized, and for another session, operation or subject", async () => {
				const store = await factory();
				const now = start();
				expect(await recover(store, now)).toEqual({
					outcome: "refused",
					reason: "unauthorized",
					hard: false,
				});
				await store.authorizeSubjectRecovery("user-1", authorization());
				expect(await recover(store, now, { sid: "sid-2" })).toMatchObject({
					reason: "unauthorized",
				});
				expect(await recover(store, now, { operation: "reset", sid: undefined })).toMatchObject({
					reason: "unauthorized",
				});
				expect(await recover(store, now, {}, "user-2")).toMatchObject({ reason: "unauthorized" });
				expect(await store.subjectGeneration("user-1")).toBe(0);
				expect(await recover(store, now)).toEqual(RELEASED);
			});

			it("refuses an apply without the subject's lease: none, another holder's token, or another subject's", async () => {
				const store = await factory();
				const now = start();
				await store.authorizeSubjectRecovery("user-1", authorization());
				const refused = { outcome: "refused", reason: "lease_not_held", hard: false };
				expect(await recover(store, now, { leaseToken: "no-such-lease" })).toEqual(refused);
				const other = await leased(store, "user-2");
				expect(await recover(store, now, { leaseToken: other })).toEqual(refused);
				const held = await leased(store);
				expect(await recover(store, now, { leaseToken: `${held}x` })).toEqual(refused);
				// The authorization stands for the apply that holds the lease.
				expect(await recover(store, now, { leaseToken: held })).toEqual(RELEASED);
			});

			it("refuses an apply under a lease that lapsed on the store's clock", async () => {
				const store = await factory();
				await store.authorizeSubjectRecovery("user-1", authorization());
				const answer = await store.acquireSubjectLease("user-1", { ttlMs: 1_000 });
				if (answer.outcome !== "acquired") throw new Error("expected a lease");
				await expiry.passed((await expiry.now()) + 1_000);
				expect(await recover(store, start(), { leaseToken: answer.token })).toMatchObject({
					reason: "lease_not_held",
				});
			});

			it("applies a recover once: the week and the run end, the generation is 1, and the same authorization answers already_applied", async () => {
				const store = await factory();
				const from = await attacked(store);
				const now = start();
				expect(held(await check(store, now))).toMatchObject({ hold: "weekly" });
				await store.authorizeSubjectRecovery("user-1", authorization());
				expect(await recover(store, now, { sessionsBoundaryMs: from + SKEW + 1 })).toEqual(
					RELEASED,
				);
				expect(await store.subjectGeneration("user-1")).toBe(1);
				expect(await recover(store, now, { sessionsBoundaryMs: from + SKEW + 1 })).toEqual({
					outcome: "already_applied",
					recoveryId: "recovery-1",
					generation: 1,
					hard: false,
				});
				expect(await store.subjectGeneration("user-1")).toBe(1);
				// Ten failures fit the week again: the next five reach the backoff, not the weekly hold.
				for (let i = 0; i < 5; i++) await fail(store, now + 1 + i);
				expect(held(await check(store, now + 6))).toMatchObject({ hold: "backoff" });
			});

			it("applies a new authorization after an applied one, under its own recoveryId: the generation is 2", async () => {
				const store = await factory();
				const now = start();
				await store.authorizeSubjectRecovery("user-1", authorization());
				expect(await recover(store, now)).toEqual(RELEASED);
				await store.authorizeSubjectRecovery("user-1", authorization({ recoveryId: "recovery-2" }));
				expect(await recover(store, now)).toEqual({
					...RELEASED,
					recoveryId: "recovery-2",
					generation: 2,
				});
				expect(await store.subjectGeneration("user-1")).toBe(2);
			});

			it("replaces a pending authorization of the same session and operation: the apply answers the newer recoveryId", async () => {
				const store = await factory();
				await store.authorizeSubjectRecovery("user-1", authorization());
				await store.authorizeSubjectRecovery("user-1", authorization({ recoveryId: "recovery-2" }));
				await store.authorizeSubjectRecovery(
					"user-1",
					authorization({ sid: "sid-2", recoveryId: "recovery-3" }),
				);
				expect(await recover(store, start())).toMatchObject({
					outcome: "applied",
					recoveryId: "recovery-2",
				});
				expect(await recover(store, start(), { sid: "sid-2" })).toMatchObject({
					outcome: "applied",
					recoveryId: "recovery-3",
					generation: 2,
				});
			});

			it("refuses not_revoked_since without a boundary later than the first counted failure by more than the skew, changing nothing, and applies once there is one", async () => {
				const store = await factory();
				const from = await attacked(store);
				const now = start();
				await store.authorizeSubjectRecovery("user-1", authorization());
				const refused = { outcome: "refused", reason: "not_revoked_since", hard: false };
				expect(await recover(store, now)).toEqual(refused);
				expect(await recover(store, now, { sessionsBoundaryMs: from - 1 })).toEqual(refused);
				expect(await recover(store, now, { sessionsBoundaryMs: from + SKEW })).toEqual(refused);
				expect(held(await check(store, now))).toMatchObject({ hold: "weekly" });
				expect(await store.subjectGeneration("user-1")).toBe(0);
				expect(await recover(store, now, { sessionsBoundaryMs: from + SKEW + 1 })).toEqual(
					RELEASED,
				);
			});

			it("counts a reservation in flight as a failure the boundary must follow", async () => {
				const store = await factory();
				const now = start();
				await reserved(store, now - HOUR);
				await store.authorizeSubjectRecovery("user-1", authorization());
				expect(await recover(store, now)).toMatchObject({ reason: "not_revoked_since" });
				expect(await recover(store, now, { sessionsBoundaryMs: now - HOUR + SKEW })).toMatchObject({
					reason: "not_revoked_since",
				});
				expect(await recover(store, now, { sessionsBoundaryMs: now - HOUR + SKEW + 1 })).toEqual(
					RELEASED,
				);
			});

			it("applies without a boundary when the week counts no failure at its time", async () => {
				const store = await factory();
				const now = start();
				// A failure a week and a minute before: the week no longer counts it.
				await fail(store, now - WEEK - MINUTE);
				await store.authorizeSubjectRecovery("user-1", authorization());
				expect(await recover(store, now)).toEqual(RELEASED);
			});

			it("refuses boundary_ahead for a boundary later than its time by more than the skew, changing nothing, and takes one at the skew", async () => {
				const store = await factory();
				await attacked(store);
				const now = start();
				await store.authorizeSubjectRecovery("user-1", authorization());
				expect(await recover(store, now, { sessionsBoundaryMs: now + SKEW + 1 })).toEqual({
					outcome: "refused",
					reason: "boundary_ahead",
					hard: false,
				});
				expect(await store.subjectGeneration("user-1")).toBe(0);
				expect(held(await check(store, now))).toMatchObject({ hold: "weekly" });
				expect(await recover(store, now, { sessionsBoundaryMs: now + SKEW })).toEqual(RELEASED);
			});

			it("answers expired at a time at or past the authorization's end, and unauthorized once the store's clock passes it", async () => {
				const store = await factory();
				const ends = Date.now() + 10 * MINUTE;
				await store.authorizeSubjectRecovery("user-1", authorization({ expiresAtMs: ends }));
				expect(await recover(store, ends)).toEqual({
					outcome: "refused",
					reason: "expired",
					hard: false,
				});
				expect(await recover(store, ends - 1)).toEqual(RELEASED);

				const other = await factory();
				const soon = Math.floor(await expiry.now()) + 1_000;
				await other.authorizeSubjectRecovery("user-1", authorization({ expiresAtMs: soon }));
				await expiry.passed(soon);
				expect(await recover(other, soon - 500)).toMatchObject({ reason: "unauthorized" });
			});

			it("ends only the attempts dated up to its time: an attempt reserved later stays in the week", async () => {
				const store = await factory();
				const now = start();
				await store.authorizeSubjectRecovery("user-1", authorization());
				const later = await reserved(store, now + MINUTE);
				expect(await recover(store, now)).toEqual(RELEASED);
				await store.settleSubjectAttempt("user-1", later, "failure");
				// A success ends the run, not the week: the later one and nine more fill it.
				await settled(store, now + 2 * MINUTE, "success");
				const at = await failures(store, now + 3 * MINUTE, 9);
				expect(held(await check(store, at))).toMatchObject({ hold: "weekly" });
			});

			it("moves the generation a writer captured: its lease is answered stale, and one under the new generation is given", async () => {
				const store = await factory();
				const captured = await store.subjectGeneration("user-1");
				await store.authorizeSubjectRecovery("user-1", authorization());
				expect(await recover(store, start())).toEqual(RELEASED);
				expect(
					await store.acquireSubjectLease("user-1", { ttlMs: 60_000, generation: captured }),
				).toEqual({ outcome: "stale" });
				expect(
					(await store.acquireSubjectLease("user-1", { ttlMs: 60_000, generation: 1 })).outcome,
				).toBe("acquired");
			});

			it("keeps each subject's authorizations and generation apart", async () => {
				const store = await factory();
				await store.authorizeSubjectRecovery("user-1", authorization());
				await store.authorizeSubjectRecovery("user-2", authorization({ recoveryId: "recovery-2" }));
				expect(await recover(store, start(), {}, "user-2")).toMatchObject({
					outcome: "applied",
					recoveryId: "recovery-2",
					generation: 1,
				});
				expect(await store.subjectGeneration("user-1")).toBe(0);
				expect(await recover(store, start())).toEqual(RELEASED);
			});

			it("refuses, with a RangeError, an authorization it cannot keep, and records nothing", async () => {
				const store = await factory();
				const now = Math.floor(Math.max(Date.now(), await expiry.now()));
				for (const [label, subject, value] of [
					["an empty subject", "", authorization()],
					["no authorization", "user-1", undefined],
					[
						"an operation it does not know",
						"user-1",
						authorization({ operation: "undo" as never }),
					],
					["a recover without a session", "user-1", authorization({ sid: undefined })],
					["a recover with an empty session", "user-1", authorization({ sid: "" })],
					["a reset with a session", "user-1", authorization({ operation: "reset" })],
					["an empty recoveryId", "user-1", authorization({ recoveryId: "" })],
					[
						"a recoveryId that is not well-formed",
						"user-1",
						authorization({ recoveryId: "\ud800" }),
					],
					[
						"an end that is not whole",
						"user-1",
						authorization({ expiresAtMs: now + MINUTE + 0.5 }),
					],
					["an end that is not a number", "user-1", authorization({ expiresAtMs: Number.NaN })],
					[
						"an end already past on the store's clock",
						"user-1",
						authorization({ expiresAtMs: now - MINUTE }),
					],
					[
						"an end further ahead of the store's clock than MFA_RECOVERY_AUTHORIZATION_MAX_MS and the skew",
						"user-1",
						authorization({
							expiresAtMs: now + MFA_RECOVERY_AUTHORIZATION_MAX_MS + SKEW + MINUTE,
						}),
					],
				] as const) {
					await expect(
						store.authorizeSubjectRecovery(subject as never, value as never),
						label,
					).rejects.toThrow(RangeError);
				}
				expect(await recover(store, start())).toMatchObject({ reason: "unauthorized" });
			});

			it("refuses, with a RangeError, an apply it cannot make, and changes nothing", async () => {
				const store = await factory();
				await store.authorizeSubjectRecovery("user-1", authorization());
				const now = start();
				for (const [label, overrides] of [
					["an operation it does not know", { operation: "undo" as never }],
					["a recover without a session", { sid: undefined }],
					["a reset with a session", { operation: "reset" as const }],
					["a time that is not a number", { nowMs: Number.NaN }],
					["an empty lease token", { leaseToken: "" }],
					["a boundary before the epoch", { sessionsBoundaryMs: -1 }],
					["a boundary that is not whole", { sessionsBoundaryMs: now + 0.5 }],
					["a rebind time that is not a number", { guessableBoundSinceMs: Number.NaN }],
					[
						"a reset with a boundary",
						{ operation: "reset" as const, sid: undefined, sessionsBoundaryMs: now },
					],
					[
						"a reset with a rebind time",
						{ operation: "reset" as const, sid: undefined, guessableBoundSinceMs: now },
					],
				] as const) {
					await expect(
						recover(store, now, overrides as Partial<MfaSubjectRecoveryApplication>),
						label,
					).rejects.toThrow(RangeError);
				}
				await expect(
					store.applySubjectRecovery("", {
						operation: "recover",
						sid: "sid-1",
						nowMs: now,
						leaseToken: "token",
						sessionsBoundaryMs: undefined,
						guessableBoundSinceMs: undefined,
					}),
				).rejects.toThrow(RangeError);
				expect(await store.subjectGeneration("user-1")).toBe(0);
				expect(await recover(store, now)).toEqual(RELEASED);
			});
		});
	});

	describe("MfaTransactionStore contract: the email proof at the next first binding", () => {
		// The operator reset's `requireEmailProof: true` must hold until the
		// subject's next first binding. The factor store has been emptied, the
		// witness is a boolean, and the lock state is cleared by the same reset,
		// so the requirement is a flag of its own.
		it("records the requirement for one subject, idempotently, and reads it", async () => {
			const store = await factory();
			expect(await store.emailProofRequiredAtNextBinding("user-1")).toBe(false);
			await store.requireEmailProofAtNextBinding("user-1");
			await store.requireEmailProofAtNextBinding("user-1");
			expect(await store.emailProofRequiredAtNextBinding("user-1")).toBe(true);
			expect(await store.emailProofRequiredAtNextBinding("user-2")).toBe(false);
		});

		it("keeps it through clearSubjectState, which the reset calls", async () => {
			const store = await factory();
			await store.requireEmailProofAtNextBinding("user-1");
			await store.clearSubjectState("user-1");
			expect(await store.emailProofRequiredAtNextBinding("user-1")).toBe(true);
		});

		it("is consumed once: of N consumes in flight one answers true, and it is gone", async () => {
			const store = await factory();
			await store.requireEmailProofAtNextBinding("user-1");
			await store.requireEmailProofAtNextBinding("user-2");
			const results = await Promise.all(
				Array.from({ length: 10 }, () => store.consumeEmailProofRequirement("user-1")),
			);
			expect(results.filter(Boolean)).toHaveLength(1);
			expect(await store.emailProofRequiredAtNextBinding("user-1")).toBe(false);
			expect(await store.consumeEmailProofRequirement("user-1")).toBe(false);
			expect(await store.emailProofRequiredAtNextBinding("user-2")).toBe(true);
		});

		it("answers false to a consume when nothing required the proof", async () => {
			const store = await factory();
			expect(await store.consumeEmailProofRequirement("user-1")).toBe(false);
			expect(await store.emailProofRequiredAtNextBinding("user-1")).toBe(false);
		});
	});

	describe("MfaTransactionStore contract: a session's account-email proof", () => {
		// The proof a subject with no counting factor gives in a session before
		// a first binding there (the MFA ADR's D24): it stands for that session
		// of that subject alone, until its end, and a later one replaces it.

		/** A whole millisecond at or after both clocks: the host's, which a write is checked against, and the store's. */
		const nowOnBoth = async (): Promise<number> =>
			Math.floor(Math.max(Date.now(), await expiry.now()));

		it("records a proof, and answers when it was given while it stands", async () => {
			const store = await factory();
			const now = await nowOnBoth();
			expect(await store.sessionEmailProofAt("user-1", "sid-1", now)).toBeNull();
			await store.recordSessionEmailProof("user-1", "sid-1", now, now + 10 * MINUTE);
			expect(await store.sessionEmailProofAt("user-1", "sid-1", now)).toBe(now);
			expect(await store.sessionEmailProofAt("user-1", "sid-1", now + 10 * MINUTE - 1)).toBe(now);
		});

		it("answers no proof at a time at or past its end, though the store still holds it", async () => {
			const store = await factory();
			const now = await nowOnBoth();
			await store.recordSessionEmailProof("user-1", "sid-1", now, now + 10 * MINUTE);
			expect(await store.sessionEmailProofAt("user-1", "sid-1", now + 10 * MINUTE)).toBeNull();
			expect(await store.sessionEmailProofAt("user-1", "sid-1", now + 11 * MINUTE)).toBeNull();
			// Still held for a caller whose time is inside it.
			expect(await store.sessionEmailProofAt("user-1", "sid-1", now)).toBe(now);
		});

		it("forgets a proof once the store's clock passes its end, whatever time a caller asks about", async () => {
			const store = await factory();
			const now = await nowOnBoth();
			const until = now + 300;
			await store.recordSessionEmailProof("user-1", "sid-1", now, until);
			await expiry.passed(until);
			expect(await store.sessionEmailProofAt("user-1", "sid-1", now)).toBeNull();
		});

		it("records a proof given a little ahead of the store's clock, and answers it no later than the time asked about", async () => {
			// A caller's clock may run ahead of the store's by up to the skew
			// allowance; the proof is kept, and never read as still to come.
			const store = await factory();
			const now = await nowOnBoth();
			await store.recordSessionEmailProof("user-1", "sid-1", now + MINUTE, now + 10 * MINUTE);
			expect(await store.sessionEmailProofAt("user-1", "sid-1", now)).toBe(now);
		});

		it("answers when a proof was given no later than the time asked about", async () => {
			// A caller whose clock runs behind the one that recorded it is never
			// told of a proof still to come.
			const store = await factory();
			const now = await nowOnBoth();
			await store.recordSessionEmailProof("user-1", "sid-1", now, now + 10 * MINUTE);
			expect(await store.sessionEmailProofAt("user-1", "sid-1", now - 1_000)).toBe(now - 1_000);
		});

		it("answers another session of the subject, and that session under another subject, no proof", async () => {
			const store = await factory();
			const now = await nowOnBoth();
			await store.recordSessionEmailProof("user-1", "sid-1", now, now + 10 * MINUTE);
			expect(await store.sessionEmailProofAt("user-1", "sid-2", now)).toBeNull();
			expect(await store.sessionEmailProofAt("user-2", "sid-1", now)).toBeNull();
			// A subject and a sid whose texts join to the same text are still two.
			await store.recordSessionEmailProof("user-1:a", "b", now, now + 10 * MINUTE);
			expect(await store.sessionEmailProofAt("user-1", "a:b", now)).toBeNull();
			expect(await store.sessionEmailProofAt("user-1:a", "b", now)).toBe(now);
		});

		it("replaces an earlier proof for the session with a later one: its time, and its end", async () => {
			const store = await factory();
			const now = await nowOnBoth();
			await store.recordSessionEmailProof("user-1", "sid-1", now - 2 * MINUTE, now + 10 * MINUTE);
			await store.recordSessionEmailProof("user-1", "sid-1", now - MINUTE, now + 5 * MINUTE);
			expect(await store.sessionEmailProofAt("user-1", "sid-1", now)).toBe(now - MINUTE);
			expect(await store.sessionEmailProofAt("user-1", "sid-1", now + 6 * MINUTE)).toBeNull();
			// Another session's proof stands beside it, untouched.
			await store.recordSessionEmailProof("user-1", "sid-2", now, now + 10 * MINUTE);
			await store.recordSessionEmailProof("user-1", "sid-1", now, now + 10 * MINUTE);
			expect(await store.sessionEmailProofAt("user-1", "sid-2", now)).toBe(now);
		});

		it("refuses, with a RangeError, a proof it cannot keep, and records nothing", async () => {
			const store = await factory();
			const now = await nowOnBoth();
			const later = now + 10 * MINUTE;
			for (const [label, subject, sid, provedAtMs, untilMs] of [
				["an empty subject", "", "sid-1", now, later],
				["a subject that is not a string", 7, "sid-1", now, later],
				["an empty sid", "user-1", "", now, later],
				["a sid that is not a string", "user-1", undefined, now, later],
				["a proof time that is not a number", "user-1", "sid-1", Number.NaN, later],
				["a proof time before the epoch", "user-1", "sid-1", -1, later],
				["a proof time that is not whole", "user-1", "sid-1", now + 0.5, later],
				["a proof time as text", "user-1", "sid-1", String(now), later],
				["an end at the proof's time", "user-1", "sid-1", now, now],
				["an end before the proof's time", "user-1", "sid-1", now, now - 1],
				[
					"an end already past on the store's clock",
					"user-1",
					"sid-1",
					now - 2 * MINUTE,
					now - MINUTE,
				],
				["an end that is not a number", "user-1", "sid-1", now, Number.NaN],
				["an end that is not whole", "user-1", "sid-1", now, later + 0.5],
				["an end past the Date range", "user-1", "sid-1", now, 1e17],
				[
					"a proof time further ahead of the store's clock than the skew allowance",
					"user-1",
					"sid-1",
					now + MFA_CLOCK_SKEW_ALLOWANCE_MS + MINUTE,
					now + MFA_CLOCK_SKEW_ALLOWANCE_MS + 10 * MINUTE,
				],
			] as const) {
				await expect(
					store.recordSessionEmailProof(
						subject as never,
						sid as never,
						provedAtMs as never,
						untilMs as never,
					),
					label,
				).rejects.toThrow(RangeError);
			}
			expect(await store.sessionEmailProofAt("user-1", "sid-1", now)).toBeNull();
		});

		it("refuses, with a RangeError, a question it cannot answer: no subject, no sid, or a time that is no instant", async () => {
			const store = await factory();
			const now = await nowOnBoth();
			for (const [label, subject, sid, nowMs] of [
				["an empty subject", "", "sid-1", now],
				["an empty sid", "user-1", "", now],
				["a time that is not a number", "user-1", "sid-1", Number.NaN],
				["a time before the epoch", "user-1", "sid-1", -1],
				["a time as text", "user-1", "sid-1", String(now)],
			] as const) {
				await expect(
					store.sessionEmailProofAt(subject, sid, nowMs as never),
					label,
				).rejects.toThrow(RangeError);
			}
		});
	});

	describe("MfaTransactionStore contract: a subject's first-binding mark", () => {
		// When a first counting factor was last bound for a subject, or its
		// witness marked (the MFA ADR's D12): a session or a login authenticated
		// no later than it may hold a stale witness. A mark distrusts, so every
		// doubt keeps it: it stands until its end on the store's clock alone,
		// and of two marks the store keeps the later time and the later end.

		/** A whole millisecond at or after both clocks: the host's, which a write is checked against, and the store's. */
		const nowOnBoth = async (): Promise<number> =>
			Math.floor(Math.max(Date.now(), await expiry.now()));

		it("notes a mark, and answers when it was noted while it stands", async () => {
			const store = await factory();
			const now = await nowOnBoth();
			expect(await store.firstBindingAt("user-1", now)).toBeNull();
			await store.noteFirstBinding("user-1", now, now + 10 * MINUTE);
			expect(await store.firstBindingAt("user-1", now)).toBe(now);
		});

		it("answers a mark while it stands on the store's clock, whatever time a caller asks about", async () => {
			// A caller whose clock runs ahead never ends a mark early.
			const store = await factory();
			const now = await nowOnBoth();
			await store.noteFirstBinding("user-1", now, now + 10 * MINUTE);
			expect(await store.firstBindingAt("user-1", now + 10 * MINUTE)).toBe(now);
			expect(await store.firstBindingAt("user-1", now + 11 * MINUTE)).toBe(now);
		});

		it("keeps the later time of the mark held and the one noted: an earlier note never moves it back", async () => {
			const store = await factory();
			const now = await nowOnBoth();
			await store.noteFirstBinding("user-1", now - 2 * MINUTE, now + 10 * MINUTE);
			await store.noteFirstBinding("user-1", now - MINUTE, now + 10 * MINUTE);
			expect(await store.firstBindingAt("user-1", now)).toBe(now - MINUTE);
			await store.noteFirstBinding("user-1", now - 3 * MINUTE, now + 10 * MINUTE);
			expect(await store.firstBindingAt("user-1", now)).toBe(now - MINUTE);
		});

		it("keeps the later end of the mark held and the one noted: a note that ends sooner never shortens it", async () => {
			const store = await factory();
			const now = await nowOnBoth();
			await store.noteFirstBinding("user-1", now - 2 * MINUTE, now + 2_000);
			// Later, and ending sooner: its time is kept, the held end stands.
			await store.noteFirstBinding("user-1", now - MINUTE, now + 1_000);
			await expiry.passed(now + 1_000);
			expect(await store.firstBindingAt("user-1", now)).toBe(now - MINUTE);
			await expiry.passed(now + 2_000);
			expect(await store.firstBindingAt("user-1", now)).toBeNull();
		});

		it("keeps the latest time and the latest end of N notes in flight", async () => {
			const store = await factory();
			const now = await nowOnBoth();
			// The latest time is the last step's; the latest end is the first's.
			const steps = [3, 9, 1, 7, 5, 0, 8, 2, 6, 4];
			await Promise.all(
				steps.map((i) =>
					store.noteFirstBinding(
						"user-1",
						now - (10 - i) * 1_000,
						i === 0 ? now + 10 * MINUTE : now + 2_000,
					),
				),
			);
			expect(await store.firstBindingAt("user-1", now)).toBe(now - 1_000);
			await expiry.passed(now + 2_000);
			expect(await store.firstBindingAt("user-1", now)).toBe(now - 1_000);
		});

		it("forgets a mark once the store's clock passes its end, whatever time a caller asks about", async () => {
			const store = await factory();
			const now = await nowOnBoth();
			const until = now + 300;
			await store.noteFirstBinding("user-1", now, until);
			await expiry.passed(until);
			expect(await store.firstBindingAt("user-1", now)).toBeNull();
		});

		it("takes any note once the mark it held has ended on the store's clock, an earlier time included", async () => {
			const store = await factory();
			const now = await nowOnBoth();
			const until = now + 300;
			await store.noteFirstBinding("user-1", now, until);
			await expiry.passed(until);
			const later = await nowOnBoth();
			await store.noteFirstBinding("user-1", now - MINUTE, later + 10 * MINUTE);
			expect(await store.firstBindingAt("user-1", later)).toBe(now - MINUTE);
		});

		it("answers a mark noted a little ahead of the store's clock as noted, never earlier", async () => {
			// A caller's clock may run ahead of the store's by up to the skew
			// allowance. The mark bounds which sessions are trusted, so an
			// earlier answer would trust one it should not.
			const store = await factory();
			const now = await nowOnBoth();
			await store.noteFirstBinding("user-1", now + MINUTE, now + 10 * MINUTE);
			expect(await store.firstBindingAt("user-1", now)).toBe(now + MINUTE);
		});

		it("keeps each subject's mark apart, and through clearSubjectState", async () => {
			const store = await factory();
			const now = await nowOnBoth();
			await store.noteFirstBinding("user-1", now, now + 10 * MINUTE);
			expect(await store.firstBindingAt("user-2", now)).toBeNull();
			await store.noteFirstBinding("user-2", now - MINUTE, now + 10 * MINUTE);
			expect(await store.firstBindingAt("user-1", now)).toBe(now);
			expect(await store.firstBindingAt("user-2", now)).toBe(now - MINUTE);
			// The mark is not lock state: clearing the lock trusts no stale session.
			await store.clearSubjectState("user-1");
			expect(await store.firstBindingAt("user-1", now)).toBe(now);
			// Nor is a session's proof of a subject its mark.
			await store.recordSessionEmailProof("user-3", "sid-1", now, now + 10 * MINUTE);
			expect(await store.firstBindingAt("user-3", now)).toBeNull();
		});

		it("refuses, with a RangeError, a note it cannot keep, and records nothing", async () => {
			const store = await factory();
			const now = await nowOnBoth();
			const later = now + 10 * MINUTE;
			for (const [label, subject, atMs, untilMs] of [
				["an empty subject", "", now, later],
				["a subject that is not a string", 7, now, later],
				["a time that is not a number", "user-1", Number.NaN, later],
				["a time before the epoch", "user-1", -1, later],
				["a time that is not whole", "user-1", now + 0.5, later],
				["a time as text", "user-1", String(now), later],
				["an end at the mark's time", "user-1", now, now],
				["an end before the mark's time", "user-1", now, now - 1],
				["an end already past on the store's clock", "user-1", now - 2 * MINUTE, now - MINUTE],
				["an end that is not a number", "user-1", now, Number.NaN],
				["an end that is not whole", "user-1", now, later + 0.5],
				["an end past the Date range", "user-1", now, 1e17],
				[
					"an end further after its time than MFA_CLOCK_SKEW_ALLOWANCE_MS",
					"user-1",
					now,
					now + MFA_CLOCK_SKEW_ALLOWANCE_MS + 1,
				],
				[
					"a time further ahead of the store's clock than the clock skew allowed",
					"user-1",
					now + DEFAULT_CLOCK_SKEW_MS + MINUTE,
					now + DEFAULT_CLOCK_SKEW_MS + 10 * MINUTE,
				],
				[
					"a time further behind the store's clock than the clock skew allowed",
					"user-1",
					now - DEFAULT_CLOCK_SKEW_MS - MINUTE,
					later,
				],
			] as const) {
				await expect(
					store.noteFirstBinding(subject as never, atMs as never, untilMs as never),
					label,
				).rejects.toThrow(RangeError);
			}
			expect(await store.firstBindingAt("user-1", now)).toBeNull();
		});

		it("refuses, with a RangeError, a question it cannot answer: no subject, or a time that is no instant", async () => {
			const store = await factory();
			const now = await nowOnBoth();
			for (const [label, subject, nowMs] of [
				["an empty subject", "", now],
				["a subject that is not a string", 7, now],
				["a time that is not a number", "user-1", Number.NaN],
				["a time before the epoch", "user-1", -1],
				["a time past the Date range", "user-1", 1e17],
				["a time as text", "user-1", String(now)],
			] as const) {
				await expect(store.firstBindingAt(subject as never, nowMs as never), label).rejects.toThrow(
					RangeError,
				);
			}
		});
	});

	describe("MfaTransactionStore contract: a subject's lease and generation", () => {
		// One writer at a time to a subject's factor set: a lease on the
		// store's clock, freed by its holder's token alone. The generation is
		// what a writer captured before it began; a lease asked for under any
		// other is refused.
		const TTL = 60_000;

		const token = async (
			store: MfaTransactionStore,
			subject = "user-1",
			generation?: number,
		): Promise<string> => {
			const answer = await store.acquireSubjectLease(subject, {
				ttlMs: TTL,
				...(generation === undefined ? {} : { generation }),
			});
			if (answer.outcome !== "acquired") throw new Error(`expected a lease: ${answer.outcome}`);
			return answer.token;
		};

		it("answers generation 0 for a subject that never recovered", async () => {
			const store = await factory();
			expect(await store.subjectGeneration("user-1")).toBe(0);
		});

		it("lets one holder at a time: busy while it stands, with the time left, and free again once its holder releases it", async () => {
			const store = await factory();
			const held = await token(store);
			expect(held).toEqual(expect.any(String));
			expect(held.length).toBeGreaterThan(0);
			const busy = await store.acquireSubjectLease("user-1", { ttlMs: TTL });
			expect(busy.outcome).toBe("busy");
			if (busy.outcome !== "busy") return;
			expect(busy.retryAfterMs).toBeGreaterThan(0);
			expect(busy.retryAfterMs).toBeLessThanOrEqual(TTL);
			expect(await store.releaseSubjectLease("user-1", `${held}x`)).toBe(false);
			expect((await store.acquireSubjectLease("user-1", { ttlMs: TTL })).outcome).toBe("busy");
			expect(await store.releaseSubjectLease("user-1", held)).toBe(true);
			expect(await store.releaseSubjectLease("user-1", held)).toBe(false);
			const next = await token(store);
			expect(next).not.toBe(held);
		});

		it("gives the lease to exactly one of N acquires in flight", async () => {
			const store = await factory();
			const answers = await Promise.all(
				Array.from({ length: 10 }, () => store.acquireSubjectLease("user-1", { ttlMs: TTL })),
			);
			expect(answers.filter((a) => a.outcome === "acquired")).toHaveLength(1);
			expect(answers.filter((a) => a.outcome === "busy")).toHaveLength(9);
		});

		it("lets a lease lapse at its end on the store's clock: another acquires it, and the first holder's release answers false", async () => {
			const store = await factory();
			const answer = await store.acquireSubjectLease("user-1", { ttlMs: 1_000 });
			if (answer.outcome !== "acquired") throw new Error("expected a lease");
			const after = await expiry.now();
			await expiry.passed(after + 1_000);
			const next = await token(store);
			expect(await store.releaseSubjectLease("user-1", answer.token)).toBe(false);
			expect(await store.releaseSubjectLease("user-1", next)).toBe(true);
		});

		it("keeps each subject's lease apart", async () => {
			const store = await factory();
			const one = await token(store, "user-1");
			const two = await token(store, "user-2");
			expect(await store.releaseSubjectLease("user-2", one)).toBe(false);
			expect(await store.releaseSubjectLease("user-1", two)).toBe(false);
			expect(await store.releaseSubjectLease("user-1", one)).toBe(true);
			expect((await store.acquireSubjectLease("user-2", { ttlMs: TTL })).outcome).toBe("busy");
		});

		it("acquires under the generation the caller captured, and answers stale under any other, holding nothing", async () => {
			const store = await factory();
			const held = await token(store, "user-1", 0);
			expect(await store.releaseSubjectLease("user-1", held)).toBe(true);
			for (const generation of [1, 7]) {
				expect(
					await store.acquireSubjectLease("user-1", { ttlMs: TTL, generation }),
					String(generation),
				).toEqual({ outcome: "stale" });
			}
			// Stale is answered before busy: a writer that will never commit is not asked to wait.
			const other = await token(store);
			expect(await store.acquireSubjectLease("user-1", { ttlMs: TTL, generation: 1 })).toEqual({
				outcome: "stale",
			});
			expect(await store.releaseSubjectLease("user-1", other)).toBe(true);
			expect((await store.acquireSubjectLease("user-1", { ttlMs: TTL })).outcome).toBe("acquired");
		});

		it("refuses, with a RangeError, a lease it cannot give or a question it cannot answer, and holds nothing", async () => {
			const store = await factory();
			for (const [label, subject, request] of [
				["an empty subject", "", { ttlMs: TTL }],
				["a subject that is not a string", 7, { ttlMs: TTL }],
				["no request", "user-1", undefined],
				["a lease shorter than MFA_SUBJECT_LEASE_MIN_MS", "user-1", { ttlMs: 999 }],
				["a lease longer than MFA_SUBJECT_LEASE_MAX_MS", "user-1", { ttlMs: 600_001 }],
				["a lease that is not whole", "user-1", { ttlMs: 1_000.5 }],
				["a lease that is not a number", "user-1", { ttlMs: Number.NaN }],
				["a lease as text", "user-1", { ttlMs: "60000" }],
				["a negative generation", "user-1", { ttlMs: TTL, generation: -1 }],
				["a generation that is not whole", "user-1", { ttlMs: TTL, generation: 0.5 }],
				["a generation as text", "user-1", { ttlMs: TTL, generation: "0" }],
				["a generation past the safe integers", "user-1", { ttlMs: TTL, generation: 2 ** 53 }],
			] as const) {
				await expect(
					store.acquireSubjectLease(subject as never, request as never),
					label,
				).rejects.toThrow(RangeError);
			}
			for (const [label, subject, held] of [
				["an empty subject", "", "token"],
				["an empty token", "user-1", ""],
				["a token that is not a string", "user-1", 7],
			] as const) {
				await expect(
					store.releaseSubjectLease(subject as never, held as never),
					`release: ${label}`,
				).rejects.toThrow(RangeError);
			}
			await expect(store.subjectGeneration("" as never)).rejects.toThrow(RangeError);
			expect((await store.acquireSubjectLease("user-1", { ttlMs: TTL })).outcome).toBe("acquired");
		});
	});
}
