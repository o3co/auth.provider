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
import {
	MFA_WEEKLY_WINDOW_MS,
	type MfaLockoutPolicy,
	type MfaSubjectAttemptReservation,
	type MfaTransaction,
	type MfaTransactionStore,
} from "#/mfa/transactionStore.mjs";

/**
 * The `MfaTransactionStore` contract (the MFA ADR's D8 and D21), for every
 * adapter.
 *
 * Two halves. The transaction: a short-lived, single-use record of one
 * second-factor ceremony, whose every operation a race could split —
 * attempts reserved before a proof is checked, a challenge answered once,
 * one winner among verifications in flight. And the subject state, which
 * bounds guessable proofs across transactions: the consecutive run with its
 * short backoff and hard limit, the weekly budget no success refunds, and
 * the browsers an exempt success trusts against the weekly hold.
 *
 * The subject state is judged on the time its caller passes, so D21's
 * schedule is driven here by an injected clock; a transaction expires on the
 * store's own clock, read through {@link ExpiryClock} as the session-store
 * suite does.
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

/** D19's defaults. */
const POLICY: MfaLockoutPolicy = {
	threshold: 5,
	baseSeconds: 900,
	maxSeconds: 86_400,
	memorySeconds: 86_400,
	weeklyBudget: 10,
	hardLimit: 100,
	trustedBrowsers: 5,
	trustedBrowserDays: 30,
};

const TX = (overrides: Partial<MfaTransaction> = {}): MfaTransaction => {
	const now = Date.now();
	return {
		id: "tx-1",
		purpose: "login",
		sessionId: "express-session-1",
		subject: "user-1",
		sid: undefined,
		primary: { method: "pwd", authTimeMs: now - 1_000 },
		user: { id: "user-1", username: "alice", groups: ["staff"] },
		redirectTo: "https://app.example/after",
		enrollment: "none",
		emailProof: "not_required",
		acrValues: undefined,
		challenge: undefined,
		pendingEnrollment: undefined,
		attempts: 0,
		sends: 0,
		lastSentAtMs: undefined,
		createdAtMs: now,
		expiresAtMs: now + 10 * MINUTE,
		version: 1,
		...overrides,
	};
};

/**
 * A challenge a verification takes (a WebAuthn assertion's, F7). An email
 * code is read, not taken, and stays across attempts (F5): the store offers
 * both, and the factor's `reusableChallenge` (absent: taken) decides which
 * the coordinator calls.
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
		it("returns a created transaction whole, as plain data, its undefined fields named", async () => {
			const store = await factory();
			const login = TX();
			const stepUp = TX({
				id: "tx-2",
				purpose: "step_up",
				sid: "sid-1",
				primary: undefined,
				user: undefined,
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
				sends: 2,
				lastSentAtMs: Date.now(),
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

		it("lets exactly one of N concurrent creates of one id through", async () => {
			const store = await factory();
			const results = await Promise.allSettled(
				Array.from({ length: 10 }, (_, i) => store.create(TX({ subject: `user-${i}` }))),
			);
			const created = results.filter((r) => r.status === "fulfilled");
			expect(created).toHaveLength(1);
			const winner = results.indexOf(created[0] as PromiseSettledResult<void>);
			expect((await store.get("tx-1"))?.subject).toBe(`user-${winner}`);
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
				["sends -1", { sends: -1 }],
				["sends 0.5", { sends: 0.5 }],
				["sends missing", { sends: undefined }],
			];
			for (const [name, overrides] of bad) {
				await expect(store.create(TX(overrides as Partial<MfaTransaction>)), name).rejects.toThrow(
					RangeError,
				);
			}
			expect(await store.get("tx-1")).toBeNull();
			// A fresh record: no attempt reserved, any count of sends, any version.
			await store.create(TX({ sends: 0, version: 0 }));
			expect((await store.get("tx-1"))?.version).toBe(0);
		});

		it("refuses, with a RangeError, a new transaction with a field its type does not admit, and records nothing", async () => {
			// The same value rules as a patch: a transaction created with
			// `emailProof` missing would carry no D24 gate at all.
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
				["lastSentAtMs NaN", { lastSentAtMs: Number.NaN }],
				["lastSentAtMs text", { lastSentAtMs: "5" }],
			];
			for (const [name, overrides] of bad) {
				await expect(store.create(TX(overrides as Partial<MfaTransaction>)), name).rejects.toThrow(
					RangeError,
				);
			}
			expect(await store.get("tx-1")).toBeNull();
		});

		it("keeps only the fields a transaction has, and only the known fields of each sub-object", async () => {
			const store = await factory();
			const tx = TX({
				emailProof: { provedAtMs: 1234 },
				challenge: CHALLENGE,
				pendingEnrollment: { kind: "totp", state: "sealed", expiresAtMs: 99 },
			});
			await store.create({
				...tx,
				admin: true,
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
			expect(await store.update("tx-1", 1, { sends: 1 })).toBeNull();
			expect(await store.reserveAttempt("tx-1", 5)).toEqual({ ok: false, attempts: 0 });
			expect(await store.takeChallenge("tx-1", 1)).toBeNull();
			expect(await store.consume("tx-1", 1)).toBeNull();
			// Gone, so the id may be used again.
			await store.create(TX());
			expect(await store.get("tx-1")).not.toBeNull();
		});

		it("updates at the current version: a present key sets, null clears, an absent key keeps; version + 1", async () => {
			const store = await factory();
			const tx = TX({ challenge: CHALLENGE, sends: 1, lastSentAtMs: 5 });
			await store.create(tx);
			const updated = await store.update("tx-1", 1, {
				challenge: null,
				emailProof: { provedAtMs: 1234 },
				enrollment: "required",
				sends: 2,
			});
			const expected = {
				...tx,
				challenge: undefined,
				emailProof: { provedAtMs: 1234 },
				enrollment: "required" as const,
				sends: 2,
				version: 2,
			};
			expect(updated).toStrictEqual(expected);
			expect(await store.get("tx-1")).toStrictEqual(expected);
			const again = await store.update("tx-1", 2, {
				pendingEnrollment: { kind: "totp", state: "sealed", expiresAtMs: 99 },
				lastSentAtMs: null,
			});
			expect(again).toStrictEqual({
				...expected,
				pendingEnrollment: { kind: "totp", state: "sealed", expiresAtMs: 99 },
				lastSentAtMs: undefined,
				version: 3,
			});
			expect(await store.update("tx-1", 3, { pendingEnrollment: null })).toStrictEqual({
				...expected,
				version: 4,
				lastSentAtMs: undefined,
			});
		});

		it("reads a key present with undefined as absent: it keeps the field, and never clears a limit", async () => {
			// `{ sends: undefined }` compiles, and read as a write it would clear the
			// send count (D21) or the email-proof gate (D24). Only null clears, and
			// only a field that may be empty.
			const store = await factory();
			const tx = TX({
				challenge: CHALLENGE,
				emailProof: "required",
				enrollment: "required",
				sends: 2,
				lastSentAtMs: 5,
			});
			await store.create(tx);
			const updated = await store.update("tx-1", 1, {
				challenge: undefined,
				pendingEnrollment: undefined,
				emailProof: undefined,
				enrollment: undefined,
				sends: undefined,
				lastSentAtMs: undefined,
			});
			expect(updated).toStrictEqual({ ...tx, version: 2 });
		});

		it("refuses, with a RangeError, a value a field does not admit, and changes nothing", async () => {
			const store = await factory();
			const tx = TX({ challenge: CHALLENGE, sends: 1 });
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
				["sends null", { sends: null }],
				["sends negative", { sends: -1 }],
				["sends fractional", { sends: 1.5 }],
				["lastSentAtMs NaN", { lastSentAtMs: Number.NaN }],
				["lastSentAtMs text", { lastSentAtMs: "5" }],
			];
			for (const [name, patch] of bad) {
				await expect(store.update("tx-1", 1, patch as never), name).rejects.toThrow(RangeError);
			}
			expect(await store.get("tx-1")).toStrictEqual(tx);
		});

		it("refuses, with a RangeError, a patch that would refund a limit or undo a requirement, and changes nothing", async () => {
			// Sends only count up (D21's send limit). A required email proof is
			// only ever met, never waived (D24), and a met one stays met. An
			// enrollment requirement is never lowered.
			const store = await factory();
			const tx = TX({ sends: 2, emailProof: "required", enrollment: "required", lastSentAtMs: 5 });
			await store.create(tx);
			const bad: [string, unknown][] = [
				["sends down", { sends: 1 }],
				["the last send moved back", { lastSentAtMs: 4 }],
				["email proof waived", { emailProof: "not_required" }],
				["enrollment lowered to none", { enrollment: "none" }],
				["enrollment lowered to allowed", { enrollment: "allowed" }],
			];
			for (const [name, patch] of bad) {
				await expect(store.update("tx-1", 1, patch as never), name).rejects.toThrow(RangeError);
			}
			expect(await store.get("tx-1")).toStrictEqual(tx);
			// What may move: sends up, the last send later, the proof met, the
			// requirements kept.
			const moved = await store.update("tx-1", 1, {
				sends: 3,
				lastSentAtMs: 6,
				emailProof: { provedAtMs: 1234 },
				enrollment: "required",
			});
			expect(moved).toStrictEqual({
				...tx,
				sends: 3,
				lastSentAtMs: 6,
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
				sends: 1,
				id: "tx-other",
				purpose: "enroll",
				attempts: 0,
				version: 99,
				sessionId: "attacker-session",
				subject: "user-2",
				sid: "sid-other",
				user: { id: "user-2" },
				redirectTo: "https://evil.example/",
				createdAtMs: 0,
				expiresAtMs: tx.expiresAtMs + 86_400_000,
			} as never);
			const expected = { ...tx, attempts: 1, sends: 1, version: 2 };
			expect(updated).toStrictEqual(expected);
			expect(await store.get("tx-1")).toStrictEqual(expected);
			expect(await store.get("tx-other")).toBeNull();
		});

		it("answers null for a version that moved or a transaction that is gone, and changes nothing", async () => {
			const store = await factory();
			const tx = TX();
			await store.create(tx);
			expect(await store.update("tx-1", 2, { sends: 9 })).toBeNull();
			expect(await store.update("tx-1", 0, { sends: 9 })).toBeNull();
			expect(await store.update("gone", 1, { sends: 9 })).toBeNull();
			expect(await store.get("tx-1")).toStrictEqual(tx);
			expect(await store.get("gone")).toBeNull();
		});

		it("lets exactly one of N concurrent updates at one version win", async () => {
			const store = await factory();
			await store.create(TX());
			const results = await Promise.all(
				Array.from({ length: 10 }, (_, i) => store.update("tx-1", 1, { sends: i + 1 })),
			);
			const winners = results.filter((r) => r !== null);
			expect(winners).toHaveLength(1);
			expect(await store.get("tx-1")).toStrictEqual(winners[0]);
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
			// Fifty guesses sent at once spend fifty attempts, not one (F1).
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
			expect(await store.update("tx-1", 1, { sends: 1 })).not.toBeNull();
			expect((await store.update("tx-1", 2, { sends: 2 }))?.attempts).toBe(1);
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
			await store.update("tx-1", 1, { challenge: resent, sends: 1 });
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
			await store.update("tx-1", 1, { sends: 1 });
			expect(await store.consume("tx-1", 1)).toBeNull();
			expect((await store.get("tx-1"))?.version).toBe(2);
			expect(await store.consume("never", 1)).toBeNull();
		});

		it("gives the record to exactly one of N consumes in flight", async () => {
			// Two verifications in flight produce one session (F1).
			const store = await factory();
			await store.create(TX());
			const results = await Promise.all(Array.from({ length: 10 }, () => store.consume("tx-1", 1)));
			expect(results.filter((r) => r !== null)).toHaveLength(1);
			expect(await store.get("tx-1")).toBeNull();
		});
	});

	describe("MfaTransactionStore contract: the subject state (D21), under an injected clock", () => {
		/** An instant near the host's clock, so an adapter that expires state on its own clock keeps it. */
		const start = () => Math.floor(Date.now() / 1000) * 1000;

		/** D19's defaults with the week out of the way, for the cases about the run alone. */
		const RUN_ONLY: MfaLockoutPolicy = { ...POLICY, weeklyBudget: 1000 };

		const check = (
			store: MfaTransactionStore,
			at: number,
			browser?: string,
			policy: MfaLockoutPolicy = POLICY,
			subject = "user-1",
		): Promise<MfaSubjectAttemptReservation> =>
			store.reserveSubjectAttempt(subject, at, policy, browser);

		async function reserved(
			store: MfaTransactionStore,
			at: number,
			browser?: string,
			policy: MfaLockoutPolicy = POLICY,
			subject = "user-1",
		): Promise<string> {
			const result = await check(store, at, browser, policy, subject);
			if (!result.ok) {
				throw new Error(`expected a reservation for ${subject}, held: ${result.hold}`);
			}
			return result.reservation;
		}

		async function fail(
			store: MfaTransactionStore,
			at: number,
			browser?: string,
			policy: MfaLockoutPolicy = POLICY,
			subject = "user-1",
		): Promise<void> {
			const reservation = await reserved(store, at, browser, policy, subject);
			await store.settleSubjectAttempt(subject, reservation, "failure");
		}

		async function settled(
			store: MfaTransactionStore,
			at: number,
			outcome: "success" | "void",
			browser?: string,
			subject = "user-1",
		): Promise<void> {
			const reservation = await reserved(store, at, browser, POLICY, subject);
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
				await fail(store, at, undefined, POLICY, subject);
				at += MINUTE;
				if (i % 4 === 0) {
					await settled(store, at, "success", undefined, subject);
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
			for (let i = 0; i < 4; i++) await fail(store, at + i, undefined, RUN_ONLY);
			at += 4;
			const seconds: number[] = [];
			for (let i = 0; i < 9; i++) {
				await fail(store, at, undefined, RUN_ONLY);
				const result = await check(store, at + 1, undefined, RUN_ONLY);
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
			for (let i = 0; i < 5; i++) await fail(store, t + i, undefined, RUN_ONLY);
			const lockEnds = t + 4 + 900_000;
			// A day after the lock ends, the next failure is the first of a new
			// backoff: four pass without a lock, and the fifth locks for
			// baseSeconds again.
			const forgotten = lockEnds + DAY;
			for (let i = 0; i < 5; i++) await fail(store, forgotten + i, undefined, RUN_ONLY);
			expect(held(await check(store, forgotten + 5, undefined, RUN_ONLY))).toEqual({
				hold: "backoff",
				retryAfterMs: 900_000 - 1,
			});

			const other = await factory();
			for (let i = 0; i < 5; i++) await fail(other, t + i, undefined, RUN_ONLY);
			// A millisecond short of that, the next failure is the sixth.
			await fail(other, forgotten - 1, undefined, RUN_ONLY);
			expect(held(await check(other, forgotten, undefined, RUN_ONLY))).toEqual({
				hold: "backoff",
				retryAfterMs: 1_800_000 - 1,
			});
		});

		it("starts the count again after memorySeconds without a failure, before any lock too", async () => {
			// D21 forgets the backoff memorySeconds after the last lock ends; before
			// any lock, the same quiet period after the previous failure forgets
			// the failures that did not reach it.
			const store = await factory();
			const t = start();
			for (let i = 0; i < 4; i++) await fail(store, t + i, undefined, RUN_ONLY);
			const quiet = t + 3 + DAY;
			for (let i = 0; i < 4; i++) await fail(store, quiet + i, undefined, RUN_ONLY);
			expect((await check(store, quiet + 4, undefined, RUN_ONLY)).ok).toBe(true);

			const other = await factory();
			for (let i = 0; i < 4; i++) await fail(other, t + i, undefined, RUN_ONLY);
			// A millisecond short of that, the next failure is the fifth: a lock.
			await fail(other, quiet - 1, undefined, RUN_ONLY);
			expect(held(await check(other, quiet, undefined, RUN_ONLY))).toEqual({
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
			for (let i = 0; i < 5; i++) await fail(store, t + i, undefined, long);
			expect(held(await check(store, t + 5, undefined, long))).toEqual({
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
			await store.noteExemptSuccess("user-1", t + 5, POLICY, undefined);
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

		it("holds guessable proofs past weeklyBudget failures in any seven days, and no success refunds one", async () => {
			const store = await factory();
			const t = start();
			const at = await fillTheWeek(store, t);
			expect(held(await check(store, at))).toEqual({ hold: "weekly", retryAfterMs: t + WEEK - at });
			// An exempt success does not refund the week either, for any browser
			// but the one it trusts.
			await store.noteExemptSuccess("user-1", at + 1, POLICY, undefined);
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
			expect((await check(store, t + 10 * DAY, undefined, POLICY, "user-3")).ok).toBe(true);
			expect((await check(store, t + 10 * DAY)).ok).toBe(true);
			expect(held(await check(store, at + 1))).toMatchObject({ hold: "weekly" });
			expect(held(await check(store, at + 1, undefined, POLICY, "user-2"))).toMatchObject({
				hold: "weekly",
			});
		});

		it("keeps a trust through a caller less than a day ahead of its end", async () => {
			const store = await factory();
			const t = start();
			const at = await fillTheWeek(store, t);
			const { browser } = await store.noteExemptSuccess("user-1", at, POLICY, undefined);
			// The trust ends when the week empties, a week after the last failure
			// (at - 2 minutes); a caller twelve hours past that sees it ended…
			const ends = at - 2 * MINUTE + WEEK;
			expect((await check(store, ends + 12 * HOUR)).ok).toBe(true);
			// …and a caller on time is still let through the weekly hold by it.
			await settled(store, at + HOUR, "void", browser);
		});

		it("takes an attempt settled void out of the week", async () => {
			const store = await factory();
			const t = start();
			const at = await failures(store, t, 9);
			await settled(store, at, "void");
			expect((await check(store, at + 1)).ok).toBe(true);
		});

		it("lets the browser an exempt success trusted through the weekly hold, and no other", async () => {
			const store = await factory();
			const t = start();
			const at = await fillTheWeek(store, t);
			const { browser } = await store.noteExemptSuccess("user-1", at, POLICY, undefined);
			expect(browser).toMatch(/^[A-Za-z0-9_-]{43}$/);
			await settled(store, at + 1, "success", browser);
			const altered = `${browser.slice(0, -1)}${browser.endsWith("A") ? "B" : "A"}`;
			for (const other of [undefined, "", altered, "not-a-browser"]) {
				expect(held(await check(store, at + 2, other)), String(other)).toEqual({
					hold: "weekly",
					retryAfterMs: t + WEEK - (at + 2),
				});
			}
		});

		it("holds a trusted browser to the backoff, and counts its failures", async () => {
			const store = await factory();
			const t = start();
			let at = await fillTheWeek(store, t);
			const { browser } = await store.noteExemptSuccess("user-1", at, POLICY, undefined);
			for (let i = 0; i < 5; i++) await fail(store, ++at, browser);
			expect(held(await check(store, at + 1, browser))).toEqual({
				hold: "backoff",
				retryAfterMs: 900_000 - 1,
			});
			// Its five failures joined the week: fifteen, the oldest ten of which
			// have to leave before an untrusted browser is let through.
			const untrusted = await check(store, at + 1);
			expect(held(untrusted)).toMatchObject({ hold: "weekly" });
			expect(untrusted.ok ? 0 : untrusted.retryAfterMs).toBeGreaterThan(900_000);
		});

		it("stops trusting a browser once the weekly window next empties", async () => {
			const store = await factory();
			const t = start();
			const at = await fillTheWeek(store, t);
			const { browser } = await store.noteExemptSuccess("user-1", at, POLICY, undefined);
			// Every failure has aged out: the window is empty, and the episode the
			// trust was for is over.
			const later = at + WEEK + MINUTE;
			const next = await fillTheWeek(store, later);
			expect(held(await check(store, next, browser))).toMatchObject({ hold: "weekly" });
		});

		it("keeps trusting a browser trusted while the window was empty, until the window fills and empties", async () => {
			// An exempt login on a quiet account, then someone starts guessing: the
			// user's browser is trusted through the hold that follows.
			const store = await factory();
			const t = start();
			const { browser } = await store.noteExemptSuccess("user-1", t, POLICY, undefined);
			const at = await fillTheWeek(store, t + DAY);
			await settled(store, at, "success", browser);
			// The guessing stops, the window empties, and a new hold is a new
			// episode.
			const later = at + WEEK + MINUTE;
			const next = await fillTheWeek(store, later);
			expect(held(await check(store, next, browser))).toMatchObject({ hold: "weekly" });
		});

		it("trusts a browser for trustedBrowserDays at most, however long the guessing goes on", async () => {
			const store = await factory();
			const t = start();
			const { browser } = await store.noteExemptSuccess("user-1", t, POLICY, undefined);
			// One failure every five days keeps the window from emptying.
			for (let day = 1; day <= 26; day += 5) await fail(store, t + day * DAY);
			// With the one at day 26, nine more fill the week.
			const at = await failures(store, t + 29 * DAY, 9);
			expect(at).toBeLessThan(t + 30 * DAY - 1);
			expect((await check(store, at)).ok).toBe(false);
			await settled(store, t + 30 * DAY - 1, "success", browser);
			expect(held(await check(store, t + 30 * DAY, browser))).toMatchObject({ hold: "weekly" });
		});

		it("trusts at most trustedBrowsers browsers: the oldest gives way", async () => {
			const store = await factory();
			const t = start();
			const at = await fillTheWeek(store, t);
			const browsers: string[] = [];
			for (let i = 0; i < 6; i++) {
				browsers.push((await store.noteExemptSuccess("user-1", at + i, POLICY, undefined)).browser);
			}
			expect(new Set(browsers).size).toBe(6);
			expect(held(await check(store, at + 10, browsers[0]))).toMatchObject({ hold: "weekly" });
			for (const browser of browsers.slice(1)) await settled(store, at + 10, "void", browser);
		});

		it("renews the trust of the browser an exempt success came from, rather than trusting one more", async () => {
			// A user who signs in with WebAuthn every day must not push the other
			// browsers they trusted out of the list.
			const store = await factory();
			const t = start();
			const at = await fillTheWeek(store, t);
			const browsers: string[] = [];
			for (let i = 0; i < 5; i++) {
				browsers.push((await store.noteExemptSuccess("user-1", at + i, POLICY, undefined)).browser);
			}
			let current = browsers[0] as string;
			for (let i = 0; i < 3; i++) {
				const { browser } = await store.noteExemptSuccess("user-1", at + 10 + i, POLICY, current);
				// A fresh value each time: the old one stops being trusted.
				expect(browser).not.toBe(current);
				current = browser;
			}
			for (const browser of [...browsers.slice(1), current]) {
				await settled(store, at + 20, "void", browser);
			}
			expect(held(await check(store, at + 21, browsers[0]))).toMatchObject({ hold: "weekly" });
		});

		it("renews only a browser the subject itself trusts: another subject's value, or an unknown one, is a new browser", async () => {
			const store = await factory();
			const t = start();
			const at = await fillTheWeek(store, t);
			await fillTheWeek(store, t, "user-2");
			const mine: string[] = [];
			for (let i = 0; i < 5; i++) {
				mine.push((await store.noteExemptSuccess("user-1", at + i, POLICY, undefined)).browser);
			}
			const { browser: theirs } = await store.noteExemptSuccess("user-2", at, POLICY, undefined);
			// Neither value is one user-1 trusts: each is a new browser, and the two
			// oldest of user-1's give way.
			await store.noteExemptSuccess("user-1", at + 10, POLICY, theirs);
			await store.noteExemptSuccess("user-1", at + 11, POLICY, "not-a-browser");
			for (const browser of mine.slice(0, 2)) {
				expect(held(await check(store, at + 20, browser))).toMatchObject({ hold: "weekly" });
			}
			for (const browser of mine.slice(2)) await settled(store, at + 20, "void", browser);
			// user-2's trust is untouched by user-1's calls.
			await settled(store, at + 20, "void", theirs, "user-2");
		});

		it("ends the run and lifts a backoff lock on an exempt success, and the week stands", async () => {
			const store = await factory();
			const t = start();
			for (let i = 0; i < 5; i++) await fail(store, t + i);
			expect((await check(store, t + 5)).ok).toBe(false);
			await store.noteExemptSuccess("user-1", t + 6, POLICY, undefined);
			// A new run: four failures pass. The week holds the first five, so
			// the tenth failure is the last it takes.
			for (let i = 0; i < 4; i++) await fail(store, t + 7 + i);
			await store.noteExemptSuccess("user-1", t + 11, POLICY, undefined);
			await fail(store, t + 12);
			expect(held(await check(store, t + 13))).toEqual({
				hold: "weekly",
				retryAfterMs: t + WEEK - (t + 13),
			});
		});

		it("holds guessable proofs at hardLimit consecutive failures, for every browser, until an exempt success", async () => {
			const small: MfaLockoutPolicy = {
				...POLICY,
				threshold: 2,
				baseSeconds: 60,
				maxSeconds: 60,
				weeklyBudget: 1000,
				hardLimit: 6,
			};
			const store = await factory();
			let at = start();
			const { browser } = await store.noteExemptSuccess("user-1", at, small, undefined);
			for (let i = 0; i < 6; i++) {
				at += MINUTE;
				await fail(store, at, browser, small);
			}
			at += DAY;
			for (const b of [undefined, browser]) {
				expect(held(await check(store, at, b, small))).toEqual({
					hold: "hard",
					retryAfterMs: null,
				});
			}
			const { browser: next } = await store.noteExemptSuccess("user-1", at, small, undefined);
			expect(next).not.toBe(browser);
			expect((await check(store, at + 1, undefined, small)).ok).toBe(true);
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

		it("clears everything on clearSubjectState: the run, the week and the trusted browsers", async () => {
			const store = await factory();
			const t = start();
			let at = await fillTheWeek(store, t);
			const { browser } = await store.noteExemptSuccess("user-1", at, POLICY, undefined);
			for (let i = 0; i < 5; i++) await fail(store, ++at, browser);
			await store.clearSubjectState("user-1");
			await store.clearSubjectState("user-1");
			await store.clearSubjectState("nobody");
			await settled(store, ++at, "void");
			// The week starts empty, and the browser is not trusted any more.
			at = await fillTheWeek(store, at + MINUTE);
			expect(held(await check(store, at, browser))).toMatchObject({ hold: "weekly" });
		});

		it("keeps subjects apart", async () => {
			const store = await factory();
			const t = start();
			const at = await fillTheWeek(store, t, "user-1");
			const { browser } = await store.noteExemptSuccess("user-1", at, POLICY, undefined);
			// user-1's week is not user-2's.
			await settled(store, at, "success", undefined, "user-2");
			// user-1's browser is nobody else's.
			const next = await fillTheWeek(store, at + MINUTE, "user-2");
			expect(held(await check(store, next, browser, POLICY, "user-2"))).toMatchObject({
				hold: "weekly",
			});
			// Clearing one subject leaves the other held.
			await store.clearSubjectState("user-2");
			expect(held(await check(store, next, undefined, POLICY, "user-1"))).toMatchObject({
				hold: "weekly",
			});
			expect((await check(store, next, browser, POLICY, "user-1")).ok).toBe(true);
		});

		it("answers a fresh browser value on every exempt success: 32 random bytes, base64url", async () => {
			const store = await factory();
			const t = start();
			const seen = new Set<string>();
			for (let i = 0; i < 5; i++) {
				const { browser } = await store.noteExemptSuccess("user-1", t + i, POLICY, undefined);
				expect(browser).toMatch(/^[A-Za-z0-9_-]{43}$/);
				seen.add(browser);
			}
			expect(seen.size).toBe(5);
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
				{ trustedBrowsers: 0 },
				{ trustedBrowserDays: 0 },
				{ maxSeconds: 1e17 },
				// The backoff would never engage before the hard hold.
				{ threshold: 10, hardLimit: 6 },
				// NIST SP 800-63B-4 caps consecutive failures at 100, as D21 cites.
				{ hardLimit: 101 },
			] satisfies Partial<MfaLockoutPolicy>[]) {
				const policy = { ...POLICY, ...bad };
				await expect(check(store, t, undefined, policy), JSON.stringify(bad)).rejects.toThrow(
					RangeError,
				);
				await expect(
					store.noteExemptSuccess("user-1", t, policy, undefined),
					JSON.stringify(bad),
				).rejects.toThrow(RangeError);
			}
			for (const notAPolicy of [null, undefined, "mfa.lockout", 5]) {
				await expect(
					store.reserveSubjectAttempt("user-1", t, notAPolicy as never, undefined),
					String(notAPolicy),
				).rejects.toThrow(RangeError);
			}
			await expect(check(store, Number.NaN)).rejects.toThrow(RangeError);
			await expect(
				store.noteExemptSuccess("user-1", Number.NaN, POLICY, undefined),
			).rejects.toThrow(RangeError);
		});
	});

	describe("MfaTransactionStore contract: the email proof at the next first binding (D25)", () => {
		// The operator reset's `requireEmailProof: true` must hold until the
		// subject's next first binding. The factor store has been emptied, the
		// witness is a boolean, and the lock state is cleared by the same reset
		// and by every password change, so the requirement is a flag of its own.
		it("records the requirement for one subject, idempotently, and reads it", async () => {
			const store = await factory();
			expect(await store.emailProofRequiredAtNextBinding("user-1")).toBe(false);
			await store.requireEmailProofAtNextBinding("user-1");
			await store.requireEmailProofAtNextBinding("user-1");
			expect(await store.emailProofRequiredAtNextBinding("user-1")).toBe(true);
			expect(await store.emailProofRequiredAtNextBinding("user-2")).toBe(false);
		});

		it("keeps it through clearSubjectState, which the reset and a password change call", async () => {
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
}
