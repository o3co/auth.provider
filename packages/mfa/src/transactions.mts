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
 * The MFA transactions a ceremony runs on: the one a login opens, with the
 * answer the login is interrupted with, and the `enroll` one a signed-in
 * session opens. See README, "The login's interruption", and ADR
 * 2026-09-25-multi-factor-authentication, as ADR 2026-09-28-session-admission
 * amends it.
 *
 * A login's is opened after the regeneration and bound to the regenerated
 * session, so the browser holding the new cookie is the one that may
 * continue. The id is not a bearer: every later use compares the whole
 * binding, kind included (`isMfaTransactionBoundTo`). The record carries
 * core's continuation, never a `user` or `primary` field of its own, and the
 * primary's subject and `redirectTo`, which the store holds it to. An
 * `enroll` one is bound to the browser session and records the session's
 * `sid` and subject, which every use compares with the session admitted.
 * `expiresAtMs` is derived from `mfa.transactionTtlSeconds` and nothing else;
 * the store has no ceiling of its own. A store that cannot create one rejects,
 * answered as an outage.
 */

import { randomBytes } from "node:crypto";
import type {
	InterruptionAnswer,
	MfaTransaction,
	MfaTransactionStore,
	PrimaryContinuation,
} from "@o3co/auth-provider-core";

/** The bytes of a transaction's id: 256 bits. */
const TRANSACTION_ID_BYTES = 32;

/** The shortest and the longest a transaction may live, in seconds. */
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
			 * Whether the account-email proof comes before the binding
			 * (`firstBinding.mts`): `hints.email_proof`, and the transaction's
			 * `emailProof` — `required` or `not_required` — so the answer
			 * advertises exactly the proof the transaction enforces.
			 */
			readonly emailProof: boolean;
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
			// Held at run time too, before anything is stored: the answer and the
			// transaction say the same.
			if (
				interruption.error === "mfa_enrollment_required" &&
				typeof interruption.emailProof !== "boolean"
			) {
				throw new RangeError("a first binding's email_proof must be true or false");
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
				emailProof: firstBinding && interruption.emailProof ? "required" : "not_required",
				acrValues: undefined,
				challenge: undefined,
				pendingEnrollment: undefined,
				attempts: 0,
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

/** What an `enroll` transaction is opened for. */
export interface EnrollTransactionShape {
	/** The express session id of the browser that opened it. */
	readonly sessionId: string;
	/** The `UserSession` it was opened in, and its subject. */
	readonly sid: string;
	readonly subject: string;
	/** `required`: the subject's first counting factor; `allowed`: one beside a factor that may count. */
	readonly enrollment: "required" | "allowed";
	/** Whether the account-email proof is owed on it. */
	readonly emailProof: "required" | "not_required";
	readonly nowMs: number;
	/** `mfa.transactionTtlSeconds`. */
	readonly ttlSeconds: number;
}

/**
 * Creates a new `enroll` transaction for `shape` in `store` — a fresh id, no
 * continuation, bound to the session `sessionId` names — and answers it.
 * Rejects when the store cannot keep it.
 */
export async function openEnrollTransaction(
	store: MfaTransactionStore,
	shape: EnrollTransactionShape,
): Promise<MfaTransaction> {
	const transaction: MfaTransaction = {
		id: newTransactionId(),
		purpose: "enroll",
		binding: { kind: "session", id: shape.sessionId },
		subject: shape.subject,
		sid: shape.sid,
		continuation: undefined,
		redirectTo: undefined,
		enrollment: shape.enrollment,
		emailProof: shape.emailProof,
		acrValues: undefined,
		challenge: undefined,
		pendingEnrollment: undefined,
		attempts: 0,
		createdAtMs: shape.nowMs,
		expiresAtMs: shape.nowMs + shape.ttlSeconds * 1000,
		version: 0,
	};
	await store.create(transaction);
	return transaction;
}
