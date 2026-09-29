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
 * The login's MFA transaction: opened after the login route regenerated the
 * express session, bound to that session's id, carrying the continuation core
 * built (never a `user` or `primary` field of its own), and living
 * `mfa.transactionTtlSeconds`, its expiry derived from that alone. See ADR
 * 2026-09-25-multi-factor-authentication, as ADR 2026-09-28-session-admission
 * amends it.
 */

import {
	createMemoryMfaTransactionStore,
	type MfaTransactionStore,
	type PrimaryContinuation,
	passwordSessionAuthentication,
} from "@o3co/auth-provider-core";
import { describe, expect, it, vi } from "vitest";
import { createLoginTransactions } from "#/transactions.mjs";

const NOW = 1_900_000_000_000;

const CONTINUATION: PrimaryContinuation = {
	primary: {
		subject: "u-alice",
		user: { id: "u-alice", username: "alice" },
		claims: {},
		recorded: passwordSessionAuthentication(),
		authTimeMs: NOW - 1_000,
		redirectTo: "https://app.example/after",
		request: { ip: "203.0.113.7", userAgent: "test" },
	},
	done: [],
	interruptedBy: "mfa",
};

const opened = (
	ttlSeconds = 600,
	store: MfaTransactionStore = createMemoryMfaTransactionStore(),
) => ({
	store,
	transactions: createLoginTransactions({ store, ttlSeconds, now: () => NOW }),
});

describe("the login's transaction (D8)", () => {
	it("is opened bound to the session id it is given, carrying the continuation, the primary's subject and redirect, for mfa.transactionTtlSeconds", async () => {
		const { store, transactions } = opened();
		const answer = await transactions.open("sess-regenerated", CONTINUATION, {
			error: "mfa_required",
		});
		const id = answer.body.transaction as string;
		expect(await store.get(id)).toEqual({
			id,
			purpose: "login",
			binding: { kind: "session", id: "sess-regenerated" },
			subject: "u-alice",
			sid: undefined,
			continuation: CONTINUATION,
			redirectTo: "https://app.example/after",
			enrollment: "none",
			emailProof: "not_required",
			acrValues: undefined,
			challenge: undefined,
			pendingEnrollment: undefined,
			attempts: 0,
			sends: 0,
			lastSentAtMs: undefined,
			createdAtMs: NOW,
			expiresAtMs: NOW + 600_000,
			version: 0,
		});
	});

	it("answers the closed 403 body — error, transaction, expires_in — with no hints for mfa_required", async () => {
		const { transactions } = opened();
		const answer = await transactions.open("sess-1", CONTINUATION, { error: "mfa_required" });
		expect(answer).toEqual({
			status: 403,
			body: {
				error: "mfa_required",
				transaction: expect.any(String),
				expires_in: 600,
			},
		});
		expect(Object.keys(answer.body).sort()).toEqual(["error", "expires_in", "transaction"]);
	});

	it("opens a first binding as enrollment required, answering what may be enrolled and whether an email proof comes first", async () => {
		const { store, transactions } = opened();
		const answer = await transactions.open("sess-1", CONTINUATION, {
			error: "mfa_enrollment_required",
			enrollable: ["totp", "webauthn"],
			emailProof: false,
		});
		expect(answer).toEqual({
			status: 403,
			body: {
				error: "mfa_enrollment_required",
				transaction: expect.any(String),
				expires_in: 600,
				hints: { enrollable: ["totp", "webauthn"], email_proof: false },
			},
		});
		expect(await store.get(answer.body.transaction as string)).toMatchObject({
			enrollment: "required",
			emailProof: "not_required",
		});
	});

	it("offers no email proof before step 9 can require one: the type admits only false, and anything else is refused before a transaction is stored", async () => {
		const store = createMemoryMfaTransactionStore();
		const create = vi.fn(store.create);
		const { transactions } = opened(600, { ...store, create });
		const typed = () =>
			transactions.open("sess-1", CONTINUATION, {
				error: "mfa_enrollment_required",
				enrollable: ["totp"],
				// @ts-expect-error — the account-email proof is step 9's: until then the answer cannot advertise one the transaction does not require
				emailProof: true,
			});
		await expect(typed()).rejects.toThrow(RangeError);
		for (const emailProof of [true, "false", 0, undefined, null]) {
			await expect(
				transactions.open("sess-1", CONTINUATION, {
					error: "mfa_enrollment_required",
					enrollable: ["totp"],
					emailProof: emailProof as never,
				}),
				String(emailProof),
			).rejects.toThrow(/email_proof/);
		}
		expect(create).not.toHaveBeenCalled();
	});

	it("is named by 32 bytes from the CSPRNG, base64url, a new id each time", async () => {
		const { transactions } = opened();
		const ids = new Set<string>();
		for (let i = 0; i < 8; i++) {
			const answer = await transactions.open(`sess-${i}`, CONTINUATION, { error: "mfa_required" });
			const id = answer.body.transaction as string;
			expect(id).toMatch(/^[A-Za-z0-9_-]{43}$/);
			expect(Buffer.from(id, "base64url")).toHaveLength(32);
			ids.add(id);
		}
		expect(ids.size).toBe(8);
	});

	it("derives the expiry from the transaction's life alone, and answers it as expires_in", async () => {
		for (const ttlSeconds of [60, 1800]) {
			const { store, transactions } = opened(ttlSeconds);
			const answer = await transactions.open("sess-1", CONTINUATION, { error: "mfa_required" });
			expect(answer.body.expires_in).toBe(ttlSeconds);
			expect((await store.get(answer.body.transaction as string))?.expiresAtMs).toBe(
				NOW + ttlSeconds * 1000,
			);
		}
	});

	it("refuses a life outside 60-1800 seconds, or not a whole number, when it is built", () => {
		for (const ttlSeconds of [59, 1801, 0, 600.5, Number.NaN]) {
			expect(
				() =>
					createLoginTransactions({
						store: createMemoryMfaTransactionStore(),
						ttlSeconds,
					}),
				String(ttlSeconds),
			).toThrow(RangeError);
		}
	});

	it("rejects when the store cannot keep it: the route answers the open as an outage", async () => {
		const store = createMemoryMfaTransactionStore();
		const failing: MfaTransactionStore = {
			...store,
			create: async () => {
				throw new Error("transaction store unreachable");
			},
		};
		const { transactions } = opened(600, failing);
		await expect(
			transactions.open("sess-1", CONTINUATION, { error: "mfa_required" }),
		).rejects.toThrow("transaction store unreachable");
	});
});
