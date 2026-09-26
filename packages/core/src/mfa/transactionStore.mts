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
 * weekly hold. Each answer is judged on the time its caller passes, not on
 * the store's clock, so the callers' clocks must agree — the provider's is
 * NTP-synced (D22). A caller whose clock runs ahead is answered on its own
 * time, but what it erases is bounded: a store forgets a failure, or a trust,
 * only {@link MFA_CLOCK_SKEW_ALLOWANCE_MS} after it stops counting, judged no
 * later than the store's own clock. A caller ahead by less than the allowance
 * erases nothing a caller on time still counts, and one far ahead — on any
 * subject — erases nothing either.
 *
 * What bounds it: a subject is a user the Store authenticated, but where the
 * Store lets anyone sign up anyone can mint subjects, and a subject's run
 * never expires — only a success, an exempt success or `clearSubjectState`
 * ends it (D21's hard limit counts it across weeks). Transactions are bounded
 * by their expiry and the login rate limit, not per subject: one account can
 * open as many as it logs in, so the coordinator must bound the transactions
 * one session holds (the MFA package's concern, not the store's).
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
 * What `update` may change. A key with a value sets the field; `null` clears
 * a field that may be empty (`challenge`, `pendingEnrollment`,
 * `lastSentAtMs`); a key absent — or present with `undefined`, which a spread
 * or an optional property produces — leaves the field as it is, so a patch
 * can never clear a limit by omission. A value a field does not admit is a
 * `RangeError` ({@link mfaTransactionPatchWrites}), and so is `null` for a
 * field that may not be empty. Nothing else about a transaction changes after
 * `create`: any other key a patch carries is ignored.
 */
export interface MfaTransactionPatch {
	readonly enrollment?: MfaTransaction["enrollment"];
	readonly emailProof?: MfaTransaction["emailProof"];
	readonly challenge?: NonNullable<MfaTransaction["challenge"]> | null;
	readonly pendingEnrollment?: NonNullable<MfaTransaction["pendingEnrollment"]> | null;
	readonly sends?: number;
	readonly lastSentAtMs?: number | null;
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

const isCount = (value: unknown): value is number =>
	typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

const isInstant = (value: unknown): value is number =>
	typeof value === "number" && Number.isFinite(value);

const isText = (value: unknown): value is string => typeof value === "string";

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * Each patch field's rule: the value as the store keeps it — sub-objects
 * copied to their known fields only — or `undefined` when the field does not
 * admit it. `null` is decided before this.
 */
const PATCH_VALUE_RULES: Readonly<
	Record<keyof MfaTransactionPatch, (value: unknown) => { readonly value: unknown } | undefined>
> = {
	enrollment: (v) =>
		v === "none" || v === "allowed" || v === "required" ? { value: v } : undefined,
	emailProof: (v) => {
		if (v === "not_required" || v === "required") return { value: v };
		return isRecord(v) && isInstant(v.provedAtMs)
			? { value: { provedAtMs: v.provedAtMs } }
			: undefined;
	},
	challenge: (v) =>
		isRecord(v) &&
		isText(v.factorId) &&
		isText(v.kind) &&
		isText(v.state) &&
		isInstant(v.expiresAtMs)
			? {
					value: {
						factorId: v.factorId,
						kind: v.kind,
						state: v.state,
						expiresAtMs: v.expiresAtMs,
					},
				}
			: undefined,
	pendingEnrollment: (v) =>
		isRecord(v) && isText(v.kind) && isText(v.state) && isInstant(v.expiresAtMs)
			? { value: { kind: v.kind, state: v.state, expiresAtMs: v.expiresAtMs } }
			: undefined,
	sends: (v) => (isCount(v) ? { value: v } : undefined),
	lastSentAtMs: (v) => (isInstant(v) ? { value: v } : undefined),
};

/** The fields `null` may clear. */
const CLEARABLE: ReadonlySet<keyof MfaTransactionPatch> = new Set([
	"challenge",
	"pendingEnrollment",
	"lastSentAtMs",
]);

/**
 * What a patch writes, field by field, after the rules of
 * {@link MfaTransactionPatch}: each entry a patch key and its new value as the
 * store keeps it — a sub-object copied to its known fields only — or
 * `undefined` for a field `null` clears. A key absent or present with
 * `undefined` is not an entry, and neither is a key outside
 * {@link MFA_TRANSACTION_PATCH_KEYS}. Throws a `RangeError` naming the key for
 * a value its field does not admit, before anything is written — every
 * adapter calls it first, and {@link checkMfaTransactionTransitions} once it
 * holds the record at the expected version.
 */
export function mfaTransactionPatchWrites(
	patch: MfaTransactionPatch,
): readonly (readonly [keyof MfaTransactionPatch, unknown])[] {
	if (!isRecord(patch)) {
		throw new RangeError("MfaTransactionStore.update: the patch must be an object");
	}
	const writes: (readonly [keyof MfaTransactionPatch, unknown])[] = [];
	for (const key of MFA_TRANSACTION_PATCH_KEYS) {
		if (!Object.hasOwn(patch, key)) continue;
		const value = (patch as Readonly<Record<string, unknown>>)[key];
		if (value === undefined) continue;
		if (value === null) {
			if (!CLEARABLE.has(key)) {
				throw new RangeError(`MfaTransactionStore.update: ${key} cannot be cleared`);
			}
			writes.push([key, undefined]);
			continue;
		}
		const admitted = PATCH_VALUE_RULES[key](value);
		if (admitted === undefined) {
			throw new RangeError(`MfaTransactionStore.update: ${key} is not a value it admits`);
		}
		writes.push([key, admitted.value]);
	}
	return writes;
}

const ENROLLMENT_RANK: Readonly<Record<MfaTransaction["enrollment"], number>> = {
	none: 0,
	allowed: 1,
	required: 2,
};

/**
 * Refuses, with a `RangeError`, writes that would refund a limit or undo a
 * requirement of `current`: `sends` going down (D21's send limit counts up
 * only); an email proof moving from `"required"` to anything but met, or from
 * met to anything but met (D24: a required proof is met, never waived);
 * `enrollment` going down (`none` < `allowed` < `required`). A requirement may
 * be raised. Every adapter calls it on the record at the expected version,
 * before it writes.
 */
export function checkMfaTransactionTransitions(
	current: MfaTransaction,
	writes: readonly (readonly [keyof MfaTransactionPatch, unknown])[],
): void {
	for (const [key, next] of writes) {
		if (key === "sends" && (next as number) < current.sends) {
			throw new RangeError("MfaTransactionStore.update: sends cannot go down");
		}
		if (
			key === "enrollment" &&
			ENROLLMENT_RANK[next as MfaTransaction["enrollment"]] < ENROLLMENT_RANK[current.enrollment]
		) {
			throw new RangeError("MfaTransactionStore.update: enrollment cannot be lowered");
		}
		if (key === "emailProof") {
			const met = typeof next === "object";
			if (typeof current.emailProof === "object" && !met) {
				throw new RangeError("MfaTransactionStore.update: a met email proof stays met");
			}
			if (current.emailProof === "required" && next !== "required" && !met) {
				throw new RangeError("MfaTransactionStore.update: a required email proof can only be met");
			}
		}
	}
}

const isTextOrAbsent = (value: unknown): boolean => value === undefined || isText(value);

/**
 * The record a store keeps for a new transaction, or a `RangeError`: every
 * field of {@link MfaTransaction} held to its type — the patch fields to the
 * same rules as a patch, `enrollment` and `emailProof` required — and the
 * counters a fresh record's: `attempts` `0`, and a `version` or `sends` that is
 * a safe non-negative integer. A limit is only as good as the count it starts
 * from: with `attempts` NaN, `NaN + 1 > max` is false and every reservation
 * would pass; with `emailProof` missing, no D24 gate. The record holds only
 * the fields a transaction has, sub-objects copied to their known fields.
 * Every adapter calls it in `create`, beside its own check of the expiry
 * against its clock.
 */
export function newMfaTransactionRecord(tx: MfaTransaction): MfaTransaction {
	const refuse = (what: string): never => {
		throw new RangeError(`MfaTransactionStore.create: ${what}`);
	};
	if (!isRecord(tx)) refuse("the transaction must be an object");
	if (tx.attempts !== 0) refuse("attempts must be 0");
	if (!isCount(tx.version)) refuse("version must be a safe non-negative integer");
	if (!isCount(tx.sends)) refuse("sends must be a safe non-negative integer");
	if (!isText(tx.id) || !isText(tx.sessionId) || !isText(tx.subject)) {
		refuse("id, sessionId and subject must be strings");
	}
	if (tx.purpose !== "login" && tx.purpose !== "step_up" && tx.purpose !== "enroll") {
		refuse("purpose is not a value it admits");
	}
	if (!isTextOrAbsent(tx.sid) || !isTextOrAbsent(tx.redirectTo)) {
		refuse("sid and redirectTo must be strings or absent");
	}
	if (
		tx.primary !== undefined &&
		!(isRecord(tx.primary) && isText(tx.primary.method) && isInstant(tx.primary.authTimeMs))
	) {
		refuse("primary is not a value it admits");
	}
	if (tx.user !== undefined && !isRecord(tx.user)) refuse("user must be an object or absent");
	if (tx.acrValues !== undefined && !(Array.isArray(tx.acrValues) && tx.acrValues.every(isText))) {
		refuse("acrValues must be a list of strings or absent");
	}
	if (!isInstant(tx.createdAtMs)) refuse("createdAtMs must be an instant");
	const field = (key: keyof MfaTransactionPatch, optional: boolean): unknown => {
		const value = (tx as unknown as Readonly<Record<string, unknown>>)[key];
		if (value === undefined && optional) return undefined;
		const admitted = PATCH_VALUE_RULES[key](value);
		if (admitted === undefined) return refuse(`${key} is not a value it admits`);
		return admitted.value;
	};
	return {
		id: tx.id,
		purpose: tx.purpose,
		sessionId: tx.sessionId,
		subject: tx.subject,
		sid: tx.sid,
		primary:
			tx.primary === undefined
				? undefined
				: { method: tx.primary.method, authTimeMs: tx.primary.authTimeMs },
		user: tx.user === undefined ? undefined : structuredClone(tx.user),
		redirectTo: tx.redirectTo,
		enrollment: field("enrollment", false) as MfaTransaction["enrollment"],
		emailProof: field("emailProof", false) as MfaTransaction["emailProof"],
		acrValues: tx.acrValues === undefined ? undefined : [...tx.acrValues],
		challenge: field("challenge", true) as MfaTransaction["challenge"],
		pendingEnrollment: field("pendingEnrollment", true) as MfaTransaction["pendingEnrollment"],
		attempts: 0,
		sends: tx.sends,
		lastSentAtMs: field("lastSentAtMs", true) as number | undefined,
		createdAtMs: tx.createdAtMs,
		expiresAtMs: tx.expiresAtMs,
		version: tx.version,
	};
}

/**
 * D21's subject lock (`mfa.lockout`). Every field is a positive whole number;
 * {@link checkMfaLockoutPolicy} is the rule.
 */
export interface MfaLockoutPolicy {
	/** Consecutive failures that start the short backoff (5); at most `hardLimit`. */
	readonly threshold: number;
	/** The first backoff lock, in seconds (900); each further failure doubles it. */
	readonly baseSeconds: number;
	/** The longest backoff lock, in seconds (86400). */
	readonly maxSeconds: number;
	/**
	 * How long after the last lock ends the backoff is forgotten, in seconds
	 * (86400). Before any lock, the same quiet period after the previous
	 * failure starts the count again: failures that never reached the
	 * threshold are forgotten as a lock would be. Neither ends the run the
	 * hard limit counts.
	 */
	readonly memorySeconds: number;
	/** Failures allowed in any rolling seven days (10). */
	readonly weeklyBudget: number;
	/** Consecutive failures that hold guessable proofs until an exempt success (100); at most {@link MFA_LOCKOUT_MAX_HARD_LIMIT}. */
	readonly hardLimit: number;
	/** Browsers trusted at once (5). */
	readonly trustedBrowsers: number;
	/** The longest a browser stays trusted, in days (30). */
	readonly trustedBrowserDays: number;
}

/** The weekly budget's window: any rolling seven days (D21). */
export const MFA_WEEKLY_WINDOW_MS = 7 * 86_400_000;

/**
 * How long a store keeps a failure, or a trust, after it stops counting: a
 * day, measured on the store's clock and never on a later one. A caller whose
 * clock runs ahead by less than this erases nothing a caller on time still
 * counts. Clocks are NTP-synced (D22), so a day is far more than a working
 * deployment needs; it costs one more day of state.
 */
export const MFA_CLOCK_SKEW_ALLOWANCE_MS = 86_400_000;

/** The most consecutive failures a lockout policy may allow: NIST SP 800-63B-4's cap, which D21 cites. */
export const MFA_LOCKOUT_MAX_HARD_LIMIT = 100;

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
 * proof verified — it ends the consecutive run up to and including this
 * reservation (an attempt reserved after it, still in flight, starts the
 * next), and is not a failure. `void`: the proof was right but the factor's
 * write lost or failed — the attempt is removed, and the run goes on.
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

	/**
	 * Insert-only: a live id is refused. Refuses with a `RangeError` an
	 * `expiresAtMs` that is not a future instant, and a field its type does not
	 * admit or counters that are not a fresh record's
	 * ({@link newMfaTransactionRecord}). It keeps only the fields a transaction
	 * has. The lifetime has no ceiling here: it is `mfa.transactionTtlSeconds`,
	 * which the MFA module refuses at boot when it is out of range, and the
	 * coordinator derives `expiresAtMs` from nothing else.
	 */
	create(tx: MfaTransaction): Promise<void>;
	/** The transaction, or `null` once it expired. */
	get(id: string): Promise<MfaTransaction | null>;
	/**
	 * Compare-and-set on `version`: applies `patch` by the rules of
	 * {@link MfaTransactionPatch} and bumps `version` by one, only if the
	 * transaction is still at `expectedVersion`. Answers the transaction as
	 * written, or `null` when the version moved or it is gone. A patch value a
	 * field does not admit is a `RangeError`, whatever the version.
	 */
	update(
		id: string,
		expectedVersion: number,
		patch: MfaTransactionPatch,
	): Promise<MfaTransaction | null>;
	/**
	 * Atomic: `attempts` + 1, whatever the version. Answers `ok` while the
	 * count is within `max`; the reservation past `max` — or any the store
	 * cannot count, which fails closed — deletes the transaction and answers
	 * `{ ok: false, attempts }` with the attempts it had reserved (`max`, unless
	 * `max` was lowered in flight). No live transaction answers
	 * `{ ok: false, attempts: 0 }`. Refuses a `max` that is not a positive
	 * whole number with a `RangeError`.
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
	/**
	 * Settle a reservation, once, under the subject that made it; settling one
	 * already settled, one never made, or one under another subject changes
	 * nothing. An outcome it does not know is a `RangeError`.
	 */
	settleSubjectAttempt(
		subject: string,
		reservation: string,
		outcome: MfaSubjectAttemptOutcome,
	): Promise<void>;
	/**
	 * An exempt success (a recovery code, WebAuthn, the 80-bit email proof):
	 * ends the run up to `nowMs` (an attempt reserved later stays) and with it
	 * a hard hold, and trusts the browser against the weekly hold. Answers the
	 * value the browser presents from then on — 32 bytes from the CSPRNG,
	 * base64url — of which the store keeps a digest. When `browser` is one
	 * already trusted, its trust is renewed under the new value rather than a
	 * second one added, so a user's daily exempt sign-ins never push their
	 * other browsers out of the `trustedBrowsers` list. The week stands. Call
	 * it only after the transaction holding the exempt proof was consumed.
	 */
	noteExemptSuccess(
		subject: string,
		nowMs: number,
		policy: MfaLockoutPolicy,
		browser: string | undefined,
	): Promise<{ readonly browser: string }>;
	/**
	 * Forget everything about `subject`'s lock — the run, the week and the
	 * trusted browsers: the operator reset and a credential change (D21, D25).
	 * A password change clearing the weekly budget is the owner's decision:
	 * it is the remedy for an attacker who holds the password, and it ends
	 * the hold that attacker caused.
	 */
	clearSubjectState(subject: string): Promise<void>;

	// The email proof the operator reset requires (D25).
	/**
	 * Record that `subject`'s next first binding requires the 80-bit email
	 * proof, whatever `mfa.enrollment.requireEmailProof` says — the operator
	 * reset's `requireEmailProof: true`. Idempotent. It has no expiry, and
	 * `clearSubjectState` leaves it: the reset clears the lock state and a
	 * password change clears it again, and neither may lift the requirement.
	 */
	requireEmailProofAtNextBinding(subject: string): Promise<void>;
	/** Whether the requirement is recorded for `subject`. */
	emailProofRequiredAtNextBinding(subject: string): Promise<boolean>;
	/**
	 * Atomic read-and-clear, at the first binding the requirement was for:
	 * `true` for the one caller that cleared it, `false` when none was
	 * recorded or another caller cleared it first. Call it only after the
	 * email proof was verified and the first counting factor written — create,
	 * then consume — so a binding that fails leaves the requirement standing.
	 * The adapter that keeps it must be as durable as the factor store: a lost
	 * requirement lets a password holder bind without the proof.
	 */
	consumeEmailProofRequirement(subject: string): Promise<boolean>;
}

/** Domain-specific AdapterFactory alias for {@link MfaTransactionStore}. */
export type MfaTransactionStoreFactory = AdapterFactory<MfaTransactionStore>;

const isPositiveWhole = (value: unknown): value is number =>
	typeof value === "number" && Number.isSafeInteger(value) && value > 0;

/**
 * Refuses a lockout policy a store cannot apply as written, with a
 * `RangeError` naming `setting` and the field: an object, every field a
 * positive whole number, `maxSeconds` at least `baseSeconds`, `threshold` at
 * most `hardLimit` (else the backoff would never engage before the hard
 * hold), `hardLimit` at most {@link MFA_LOCKOUT_MAX_HARD_LIMIT}, and every
 * duration one that ends within the Date range. The MFA module calls it at
 * boot with `"mfa.lockout"`, so a bad setting refuses the boot; every store
 * operation that takes a policy calls it again.
 *
 * @param setting - where the policy was read from, for the message.
 */
export function checkMfaLockoutPolicy(policy: MfaLockoutPolicy, setting = "mfa.lockout"): void {
	if (!isRecord(policy)) {
		throw new RangeError(`${setting} must be an object`);
	}
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
	if (policy.threshold > policy.hardLimit) {
		throw new RangeError(`${setting}.threshold must be at most ${setting}.hardLimit`);
	}
	if (policy.hardLimit > MFA_LOCKOUT_MAX_HARD_LIMIT) {
		throw new RangeError(
			`${setting}.hardLimit must be at most ${MFA_LOCKOUT_MAX_HARD_LIMIT} (NIST SP 800-63B-4's cap on consecutive failures)`,
		);
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
