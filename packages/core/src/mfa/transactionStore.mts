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
 * The MFA transaction, the subject state that bounds guessable proofs, and
 * the port that keeps both (the MFA ADR's D8 and D21), with its
 * `mfaTransactionStore` slot.
 *
 * A transaction is the short-lived, single-use record of one second-factor
 * ceremony, bound to the browser session that started it. Every operation a
 * race could split is atomic in the store: attempts are reserved before a
 * proof is checked, a challenge is taken once, and of the verifications in
 * flight one consumes the transaction.
 *
 * The subject state is D21's lock, for guessable proofs only: the
 * consecutive run with its short backoff and hard limit, the weekly budget
 * no success refunds, and the browsers an exempt success trusts against the
 * weekly hold. It is judged on the time the caller passes, so one clock
 * decides a subject's schedule whichever replica answers.
 */

import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";
import { isStorableLifetime } from "../adapters/expiry.mjs";

/** One second-factor ceremony. Every field is a required key: a store that drops one does not compile. */
export interface MfaTransaction {
	/** 32 bytes from the CSPRNG, base64url. Never in a URL. */
	readonly id: string;
	readonly purpose: "login" | "step_up" | "enroll";
	/** The express session it is bound to; every use compares it with the request's. */
	readonly sessionId: string;
	readonly subject: string;
	/** `step_up` / `enroll`: the `UserSession` it upgrades. */
	readonly sid: string | undefined;
	/** `login`: how the primary authentication was made, and when. */
	readonly primary: { readonly method: string; readonly authTimeMs: number } | undefined;
	/** `login`: the `User` the session will be built from, for at most the transaction's life. */
	readonly user: Readonly<Record<string, unknown>> | undefined;
	/** `login`: where the page goes afterwards, already held to `session.redirectAllowlist`. */
	readonly redirectTo: string | undefined;
	readonly enrollment: "none" | "allowed" | "required";
	readonly emailProof: "not_required" | "required" | { readonly provedAtMs: number };
	/** `step_up`: the `acr_values` hinted, for offering factors. */
	readonly acrValues: readonly string[] | undefined;
	/** A challenge sent and not yet taken; `state` sealed or digested (D11). */
	readonly challenge:
		| {
				readonly factorId: string;
				readonly kind: string;
				readonly state: string;
				readonly expiresAtMs: number;
		  }
		| undefined;
	/** An enrollment begun and not yet completed; `state` sealed (D11). */
	readonly pendingEnrollment:
		| { readonly kind: string; readonly state: string; readonly expiresAtMs: number }
		| undefined;
	/** Attempts reserved: only `reserveAttempt` moves it. */
	readonly attempts: number;
	readonly sends: number;
	readonly lastSentAtMs: number | undefined;
	readonly createdAtMs: number;
	readonly expiresAtMs: number;
	/** The compare-and-set token: `update` alone moves it. */
	readonly version: number;
}

/**
 * What `update` may change. A key present sets the field — to `undefined`
 * where the field allows it, which clears it; a key absent leaves the field
 * as it is. Nothing else about a transaction changes after `create`.
 */
export interface MfaTransactionPatch {
	readonly enrollment?: MfaTransaction["enrollment"];
	readonly emailProof?: MfaTransaction["emailProof"];
	readonly challenge?: MfaTransaction["challenge"];
	readonly pendingEnrollment?: MfaTransaction["pendingEnrollment"];
	readonly sends?: number;
	readonly lastSentAtMs?: number | undefined;
}

/** The keys an {@link MfaTransactionPatch} may carry, for an adapter that copies one field by field. */
export const MFA_TRANSACTION_PATCH_KEYS = [
	"enrollment",
	"emailProof",
	"challenge",
	"pendingEnrollment",
	"sends",
	"lastSentAtMs",
] as const satisfies readonly (keyof MfaTransactionPatch)[];

/**
 * D21's subject lock (`mfa.lockout`). Every field is a positive whole number;
 * {@link checkMfaLockoutPolicy} is the rule.
 */
export interface MfaLockoutPolicy {
	/** Consecutive failures that start the short backoff (5). */
	readonly threshold: number;
	/** The first backoff lock, in seconds (900); each further failure doubles it. */
	readonly baseSeconds: number;
	/** The longest backoff lock, in seconds (86400). */
	readonly maxSeconds: number;
	/** How long after the last lock ends the backoff is forgotten, in seconds (86400). */
	readonly memorySeconds: number;
	/** Failures allowed in any rolling seven days (10). */
	readonly weeklyBudget: number;
	/** Consecutive failures that hold guessable proofs until an exempt success (100). */
	readonly hardLimit: number;
	/** Browsers trusted at once (5). */
	readonly trustedBrowsers: number;
	/** The longest a browser stays trusted, in days (30). */
	readonly trustedBrowserDays: number;
}

/** The weekly budget's window: any rolling seven days (D21). */
export const MFA_WEEKLY_WINDOW_MS = 7 * 86_400_000;

/** Which hold refused a guessable attempt. `hard` lifts only on an exempt success, a credential change or an operator reset. */
export type MfaSubjectHold = "backoff" | "weekly" | "hard";

/** What `reserveSubjectAttempt` answers. */
export type MfaSubjectAttemptReservation =
	| { readonly ok: true; readonly reservation: string }
	| {
			readonly ok: false;
			readonly hold: MfaSubjectHold;
			/** Milliseconds from the time asked about until an attempt may be reserved; `null` for the hard hold. */
			readonly retryAfterMs: number | null;
	  };

/**
 * How a reserved attempt ended. `failure`: it stands. `success`: a guessable
 * proof verified — it ends the consecutive run, and is not a failure. `void`:
 * the proof was right but the factor's write lost or failed — the attempt is
 * removed, and the run goes on.
 */
export type MfaSubjectAttemptOutcome = "failure" | "success" | "void";

/**
 * Where MFA transactions and the subject lock state are kept.
 *
 * Every operation is atomic on its own. A store that cannot answer throws:
 * an outage is `503`, never a verdict on a proof (D28).
 */
export interface MfaTransactionStore {
	readonly kind: string;

	/** Insert-only: a live id is refused. Refuses an `expiresAtMs` that is not a future instant with a `RangeError`. */
	create(tx: MfaTransaction): Promise<void>;
	/** The transaction, or `null` once it expired. */
	get(id: string): Promise<MfaTransaction | null>;
	/**
	 * Compare-and-set on `version`: applies `patch` and bumps `version` by one,
	 * only if the transaction is still at `expectedVersion`. Answers the
	 * transaction as written, or `null` when the version moved or it is gone.
	 */
	update(
		id: string,
		expectedVersion: number,
		patch: MfaTransactionPatch,
	): Promise<MfaTransaction | null>;
	/**
	 * Atomic: `attempts` + 1, whatever the version. Answers `ok` while the
	 * count is within `max`; the reservation past `max` deletes the
	 * transaction and answers `{ ok: false, attempts: max }`. No live
	 * transaction answers `{ ok: false, attempts: 0 }`. Refuses a `max` that is
	 * not a positive whole number with a `RangeError`.
	 */
	reserveAttempt(
		id: string,
		max: number,
	): Promise<{ readonly ok: boolean; readonly attempts: number }>;
	/**
	 * Atomic read-and-clear of the pending challenge, only at
	 * `expectedVersion`; the version stays where it was. `null` when there is
	 * none, the version moved, or the transaction is gone.
	 */
	takeChallenge(id: string, expectedVersion: number): Promise<MfaTransaction["challenge"] | null>;
	/** Atomic delete if still at `expectedVersion`: the one winner gets the transaction. */
	consume(id: string, expectedVersion: number): Promise<MfaTransaction | null>;

	/**
	 * Refuse while a hold applies at `nowMs` — the hard limit, the short
	 * backoff, or the weekly budget unless `browser` is one an exempt success
	 * trusted — and otherwise count a pending failure, which stands until
	 * settled. A refusal records nothing.
	 */
	reserveSubjectAttempt(
		subject: string,
		nowMs: number,
		policy: MfaLockoutPolicy,
		browser: string | undefined,
	): Promise<MfaSubjectAttemptReservation>;
	/** Settle a reservation, once; settling one already settled, or one never made, changes nothing. */
	settleSubjectAttempt(
		subject: string,
		reservation: string,
		outcome: MfaSubjectAttemptOutcome,
	): Promise<void>;
	/**
	 * An exempt success (a recovery code, WebAuthn, the 80-bit email proof):
	 * ends the run and a hard hold, and trusts a new browser against the
	 * weekly hold. Answers the value the browser presents from then on — 32
	 * bytes from the CSPRNG, base64url — of which the store keeps a digest.
	 * The week stands.
	 */
	noteExemptSuccess(
		subject: string,
		nowMs: number,
		policy: MfaLockoutPolicy,
	): Promise<{ readonly browser: string }>;
	/** Forget everything about `subject`'s lock: the operator reset and a credential change (D21, D25). */
	clearSubjectState(subject: string): Promise<void>;
}

/** Domain-specific AdapterFactory alias for {@link MfaTransactionStore}. */
export type MfaTransactionStoreFactory = AdapterFactory<MfaTransactionStore>;

const isPositiveWhole = (value: unknown): value is number =>
	typeof value === "number" && Number.isSafeInteger(value) && value > 0;

/**
 * Refuses a lockout policy a store cannot apply as written, with a
 * `RangeError` naming `setting` and the field: every field a positive whole
 * number, `maxSeconds` at least `baseSeconds`, and every duration one that
 * ends within the Date range.
 *
 * @param setting - where the policy was read from, for the message.
 */
export function checkMfaLockoutPolicy(policy: MfaLockoutPolicy, setting = "mfa.lockout"): void {
	for (const field of [
		"threshold",
		"baseSeconds",
		"maxSeconds",
		"memorySeconds",
		"weeklyBudget",
		"hardLimit",
		"trustedBrowsers",
		"trustedBrowserDays",
	] as const) {
		if (!isPositiveWhole(policy[field])) {
			throw new RangeError(`${setting}.${field} must be a positive whole number`);
		}
	}
	if (policy.maxSeconds < policy.baseSeconds) {
		throw new RangeError(`${setting}.maxSeconds must be at least ${setting}.baseSeconds`);
	}
	for (const [field, ms] of [
		["maxSeconds", policy.maxSeconds * 1000],
		["memorySeconds", policy.memorySeconds * 1000],
		["trustedBrowserDays", policy.trustedBrowserDays * 86_400_000],
	] as const) {
		if (!isStorableLifetime(ms)) {
			throw new RangeError(`${setting}.${field} must end within the Date range`);
		}
	}
}

// ---------------------------------------------------------------------------
// ComponentMap declaration-merge
// ---------------------------------------------------------------------------
declare module "@o3co/auth-provider-core" {
	interface ComponentMap {
		/** MFA transactions and the subject lock state (the MFA ADR's D8, D21). */
		readonly mfaTransactionStore?: MfaTransactionStore;
	}
}
