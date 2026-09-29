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
 * The MFA transaction a login opens (the MFA ADR's D8 and F1 step 2, F3 step
 * 1, as the session-admission ADR's D5 amends them), and the answer the
 * login is interrupted with.
 *
 * - **Opened after the regeneration**, bound to the session the login route
 *   regenerated — `binding: { kind: "session", id }` (#742) — so the browser
 *   holding the new cookie is the one that may continue; the record carries
 *   the continuation core built — the primary and what earlier requirements
 *   added — never a `user` or `primary` field of its own, and the primary's
 *   subject and `redirectTo`, which the store holds it to.
 * - **Its id is 32 bytes from the CSPRNG, base64url** (D22). It is not a
 *   bearer: every later use compares the whole binding, kind included
 *   (core's `isMfaTransactionBoundTo`).
 * - **Its life is `mfa.transactionTtlSeconds`**, from which `expiresAtMs` is
 *   derived and nothing else — the store has no ceiling of its own (step 3's
 *   obligation).
 * - **The answer is the closed 403 body** core validates: `error`,
 *   `transaction`, `expires_in`, and — for a first binding alone —
 *   `hints.enrollable` and `hints.email_proof`.
 *
 * A store that cannot create it rejects the open, which the route answers as
 * an outage. Reading a transaction back — through the binding, a mismatch
 * read as an unknown id (core's `getBoundMfaTransaction`) — is the routes'
 * (build-order step 8's third part).
 */

import { randomBytes } from "node:crypto";
import type {
	InterruptionAnswer,
	MfaTransaction,
	MfaTransactionStore,
	PrimaryContinuation,
} from "@o3co/auth-provider-core";

/** The bytes of a transaction's id (D22): 256 bits. */
const TRANSACTION_ID_BYTES = 32;

/** The shortest and the longest a transaction may live, in seconds (the step-8 owner decision; the ADR states no bounds). */
export const MFA_TRANSACTION_TTL_SECONDS = { min: 60, max: 1800 } as const;

/** A new transaction id: 32 bytes from the CSPRNG, base64url. Never in a URL. */
const newTransactionId = (): string => randomBytes(TRANSACTION_ID_BYTES).toString("base64url");

/** What the login is interrupted for: a second factor, or a first binding with what it may bind. */
export type LoginInterruption =
	| { readonly error: "mfa_required" }
	| {
			readonly error: "mfa_enrollment_required";
			/** The kinds this user may enroll, in registration order: `hints.enrollable`. */
			readonly enrollable: readonly string[];
			/**
			 * Whether the account-email proof comes before the binding (D24):
			 * `hints.email_proof`. `false` alone until build-order step 9 can
			 * require one: the transaction records `emailProof: "not_required"`,
			 * and the answer must not advertise a proof the server does not
			 * enforce.
			 */
			readonly emailProof: false;
	  };

/** Opens a login's transaction and answers the interruption. */
export interface LoginTransactions {
	/**
	 * Creates the `login` transaction bound to the session `sessionId` names
	 * (`{ kind: "session", id: sessionId }`), carrying `continuation`, and
	 * answers the closed 403 body. Rejects when the store cannot keep it.
	 */
	open(
		sessionId: string,
		continuation: PrimaryContinuation,
		interruption: LoginInterruption,
	): Promise<InterruptionAnswer>;
}

export interface LoginTransactionsOptions {
	readonly store: MfaTransactionStore;
	/** `mfa.transactionTtlSeconds`: a whole number of seconds, 60 to 1800. */
	readonly ttlSeconds: number;
	/** The clock, in epoch milliseconds. Defaults to `Date.now`; a test seam. */
	readonly now?: () => number;
}

/**
 * The login's transactions over `store`, each living `ttlSeconds` — refused
 * with a `RangeError` when it is not a whole number from 60 to 1800.
 */
export function createLoginTransactions({
	store,
	ttlSeconds,
	now = Date.now,
}: LoginTransactionsOptions): LoginTransactions {
	if (
		!Number.isSafeInteger(ttlSeconds) ||
		ttlSeconds < MFA_TRANSACTION_TTL_SECONDS.min ||
		ttlSeconds > MFA_TRANSACTION_TTL_SECONDS.max
	) {
		throw new RangeError(
			`mfa.transactionTtlSeconds must be a whole number from ${MFA_TRANSACTION_TTL_SECONDS.min} to ${MFA_TRANSACTION_TTL_SECONDS.max} seconds`,
		);
	}
	return {
		async open(sessionId, continuation, interruption) {
			// The type admits `false` alone; held at run time too, before anything
			// is stored, so no caller can advertise a proof nothing requires.
			if (interruption.error === "mfa_enrollment_required" && interruption.emailProof !== false) {
				throw new RangeError(
					"a first binding's email_proof must be false until the account-email proof can be required (build-order step 9)",
				);
			}
			const id = newTransactionId();
			const createdAtMs = now();
			const firstBinding = interruption.error === "mfa_enrollment_required";
			const transaction: MfaTransaction = {
				id,
				purpose: "login",
				binding: { kind: "session", id: sessionId },
				subject: continuation.primary.subject,
				sid: undefined,
				continuation,
				redirectTo: continuation.primary.redirectTo,
				enrollment: firstBinding ? "required" : "none",
				// The account-email proof (D24) is step 9's: no mail is wired before it.
				emailProof: "not_required",
				acrValues: undefined,
				challenge: undefined,
				pendingEnrollment: undefined,
				attempts: 0,
				sends: 0,
				lastSentAtMs: undefined,
				createdAtMs,
				expiresAtMs: createdAtMs + ttlSeconds * 1000,
				version: 0,
			};
			await store.create(transaction);
			return {
				status: 403,
				body: {
					error: interruption.error,
					transaction: id,
					expires_in: ttlSeconds,
					...(interruption.error === "mfa_enrollment_required"
						? {
								hints: {
									enrollable: [...interruption.enrollable],
									email_proof: interruption.emailProof,
								},
							}
						: {}),
				},
			};
		},
	};
}
