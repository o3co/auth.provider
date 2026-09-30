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
 * The MFA transaction, the subject lock state that bounds guessable proofs, a
 * session's account-email proof, the port that keeps them, and its
 * `mfaTransactionStore` slot. See ADR 2026-09-25-multi-factor-authentication
 * (the MFA transaction; attempts, lockout and rate limits; D24).
 *
 * A transaction is the short-lived, single-use record of one second-factor
 * ceremony, bound to what started it. Every operation a race could split is
 * atomic in the store: attempts are reserved before a proof is checked, a
 * challenge is taken once, and one verification in flight consumes it.
 *
 * Subject state is judged on the time each caller passes, not the store's
 * clock, so callers' clocks must agree (NTP); see
 * {@link MFA_CLOCK_SKEW_ALLOWANCE_MS} for what a fast clock can erase. A
 * subject's run never expires (only a success, an exempt success or
 * `clearSubjectState` ends it), and an open sign-up lets anyone mint subjects.
 * Transactions are bounded by expiry and the login rate, not per subject, so
 * the coordinator must bound the transactions one session holds.
 */

import type { AdapterFactory } from "../adapters/AdapterFactory.mjs";
import { isStorableExpiry, isStorableLifetime } from "../adapters/expiry.mjs";
import { constantTimeStringEqual } from "../security/timingSafe.mjs";
import { checkPrimaryContinuation } from "../session-admission/primary.mjs";
import type { PrimaryContinuation } from "../session-admission/requirement.mjs";

/**
 * A transaction bound to a browser session: `id` is the express session id the
 * login route regenerated, or the one a step-up or an enrollment began in.
 */
export interface MfaSessionBinding {
	readonly kind: "session";
	readonly id: string;
}

/**
 * What a transaction is bound to: the one party that may continue its ceremony.
 * Discriminated by `kind` (a browser session today; a browserless transport
 * adds its own kinds). A store keeps it whole, as data, reading neither field.
 * Every use compares the whole binding, kind included
 * ({@link isMfaTransactionBoundTo}), so another kind never matches, even with
 * the same id.
 */
export type MfaTransactionBinding = MfaSessionBinding;

/** One second-factor ceremony. Every field is a required key: a store that drops one does not compile. */
export interface MfaTransaction {
	/** 32 bytes from the CSPRNG, base64url. Never in a URL. */
	readonly id: string;
	readonly purpose: "login" | "step_up" | "enroll";
	/** What it is bound to; every use compares the whole binding, kind included, with the request's. */
	readonly binding: MfaTransactionBinding;
	readonly subject: string;
	/** `step_up` / `enroll`: the `UserSession` it upgrades. */
	readonly sid: string | undefined;
	/**
	 * `login`: the continuation `admitPrimary` answered (the primary, the `User`
	 * the session will be built from, and what earlier requirements added),
	 * presented to `resumePrimary` when the ceremony completes.
	 */
	readonly continuation: PrimaryContinuation | undefined;
	/** `login`: where the page goes afterwards, already held to `session.redirectAllowlist`. */
	readonly redirectTo: string | undefined;
	readonly enrollment: "none" | "allowed" | "required";
	readonly emailProof: "not_required" | "required" | { readonly provedAtMs: number };
	/** `step_up`: the `acr_values` hinted, for offering factors. */
	readonly acrValues: readonly string[] | undefined;
	/** A challenge sent and not yet taken; `state` sealed or digested. */
	readonly challenge:
		| {
				readonly factorId: string;
				readonly kind: string;
				readonly state: string;
				readonly expiresAtMs: number;
		  }
		| undefined;
	/** An enrollment begun and not yet completed; `state` sealed. */
	readonly pendingEnrollment:
		| { readonly kind: string; readonly state: string; readonly expiresAtMs: number }
		| undefined;
	/** Attempts reserved: only `reserveAttempt` moves it. */
	readonly attempts: number;
	readonly createdAtMs: number;
	readonly expiresAtMs: number;
	/** The compare-and-set token: `update` alone moves it. */
	readonly version: number;
}

/**
 * What `update` may change. A value sets the field; `null` clears a clearable
 * field (`challenge`, `pendingEnrollment`). An absent or `undefined` key leaves
 * the field alone, so a patch never clears a requirement by omission. A value
 * the field does not admit, or `null` for an unclearable field, is a
 * `RangeError` ({@link mfaTransactionPatchWrites}). Other keys are ignored.
 */
export interface MfaTransactionPatch {
	readonly enrollment?: MfaTransaction["enrollment"];
	readonly emailProof?: MfaTransaction["emailProof"];
	readonly challenge?: NonNullable<MfaTransaction["challenge"]> | null;
	readonly pendingEnrollment?: NonNullable<MfaTransaction["pendingEnrollment"]> | null;
}

/** The keys an {@link MfaTransactionPatch} may carry, for an adapter that copies one field by field. */
export const MFA_TRANSACTION_PATCH_KEYS = [
	"enrollment",
	"emailProof",
	"challenge",
	"pendingEnrollment",
] as const satisfies readonly (keyof MfaTransactionPatch)[];

const isCount = (value: unknown): value is number =>
	typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

const isInstant = (value: unknown): value is number =>
	typeof value === "number" && Number.isFinite(value);

const isText = (value: unknown): value is string => typeof value === "string";

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
	typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * `value` as an admitted binding, copied to its known fields, or `undefined`.
 * A session id must be a non-empty, well-formed string: lone surrogates all
 * encode as U+FFFD, so two different ids would compare alike. An unknown kind
 * is no binding. `kind` and `id` are read once, so a getter cannot pass the
 * check and hand over something else; a read that throws is no binding.
 */
const bindingOf = (value: unknown): MfaTransactionBinding | undefined => {
	try {
		if (!isRecord(value)) return undefined;
		const { kind, id } = value;
		return kind === "session" && isText(id) && id.length > 0 && id.isWellFormed()
			? { kind, id }
			: undefined;
	} catch {
		return undefined;
	}
};

/** The binding `holder` carries, read once through {@link bindingOf}; `undefined` when reading it throws. */
const heldBinding = (holder: unknown): MfaTransactionBinding | undefined => {
	try {
		return isRecord(holder) ? bindingOf(holder.binding) : undefined;
	} catch {
		return undefined;
	}
};

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
};

/** The fields `null` may clear. */
const CLEARABLE: ReadonlySet<keyof MfaTransactionPatch> = new Set([
	"challenge",
	"pendingEnrollment",
]);

/**
 * What a patch writes, per {@link MfaTransactionPatch}: each key with its value
 * as the store keeps it (sub-objects copied to known fields), or `undefined`
 * for a field `null` clears. Absent, `undefined` and unknown keys are skipped.
 * Throws a `RangeError` naming the key before anything is written. Every
 * adapter calls it first, then {@link checkMfaTransactionTransitions} on the
 * record at the expected version.
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
 * Refuses, with a `RangeError`, writes that would undo a requirement of
 * `current`: a required email proof becoming anything but met or a met one
 * undone (a required proof is met, never waived), `enrollment` lowered
 * (`none` < `allowed` < `required`). Every adapter calls it on the record at
 * the expected version, before writing.
 */
export function checkMfaTransactionTransitions(
	current: MfaTransaction,
	writes: readonly (readonly [keyof MfaTransactionPatch, unknown])[],
): void {
	for (const [key, next] of writes) {
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
 * The record a store keeps for a new transaction, or a `RangeError`. Every
 * field is held to its type (patch fields by the patch rules, `enrollment` and
 * `emailProof` required), `attempts` must be `0`, and `version` a safe
 * non-negative integer: a limit is only as good as the count it starts from
 * (with `attempts` NaN, `NaN + 1 > max` is false and every reservation
 * passes). Only a transaction's fields are kept, sub-objects copied to known
 * fields. Every adapter calls it in `create`, beside its own expiry check.
 */
export function newMfaTransactionRecord(tx: MfaTransaction): MfaTransaction {
	const refuse = (what: string): never => {
		throw new RangeError(`MfaTransactionStore.create: ${what}`);
	};
	if (!isRecord(tx)) refuse("the transaction must be an object");
	if (tx.attempts !== 0) refuse("attempts must be 0");
	if (!isCount(tx.version)) refuse("version must be a safe non-negative integer");
	if (!isText(tx.id) || !isText(tx.subject)) refuse("id and subject must be strings");
	const binding =
		heldBinding(tx) ??
		refuse('binding must be { kind: "session", id } with id a non-empty, well-formed string');
	if (tx.purpose !== "login" && tx.purpose !== "step_up" && tx.purpose !== "enroll") {
		refuse("purpose is not a value it admits");
	}
	if (!isTextOrAbsent(tx.sid) || !isTextOrAbsent(tx.redirectTo)) {
		refuse("sid and redirectTo must be strings or absent");
	}
	let continuation: PrimaryContinuation | undefined;
	if (tx.continuation !== undefined) {
		try {
			continuation = checkPrimaryContinuation(tx.continuation);
		} catch (cause) {
			throw new RangeError("MfaTransactionStore.create: continuation is not a value it admits", {
				cause,
			});
		}
		// One record, one login: the transaction's subject and redirectTo are
		// the continuation's primary's, so a record cannot resume one login
		// under another's name or send it elsewhere afterwards.
		if (continuation.primary.subject !== tx.subject) {
			refuse("subject must be the continuation's primary's");
		}
		if (continuation.primary.redirectTo !== tx.redirectTo) {
			refuse("redirectTo must be the continuation's primary's");
		}
	}
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
		binding,
		subject: tx.subject,
		sid: tx.sid,
		continuation,
		redirectTo: tx.redirectTo,
		enrollment: field("enrollment", false) as MfaTransaction["enrollment"],
		emailProof: field("emailProof", false) as MfaTransaction["emailProof"],
		acrValues: tx.acrValues === undefined ? undefined : [...tx.acrValues],
		challenge: field("challenge", true) as MfaTransaction["challenge"],
		pendingEnrollment: field("pendingEnrollment", true) as MfaTransaction["pendingEnrollment"],
		attempts: 0,
		createdAtMs: tx.createdAtMs,
		expiresAtMs: tx.expiresAtMs,
		version: tx.version,
	};
}

/**
 * Whether `tx` is bound to `binding`, the whole binding compared, kind
 * included. Another kind, a binding either side does not admit (such as an id
 * that is not a well-formed string), or one whose reading throws never matches.
 * Each side is read once and the ids compared in constant time. Every use of a
 * transaction makes this comparison, through {@link getBoundMfaTransaction}.
 *
 * Constant time holds only for ids of equal length (`security/timingSafe.mts`).
 * The session kind's length is public (an express session id is 32 characters,
 * carried in the cookie); a kind with secret-length ids must compare
 * fixed-length digests instead.
 */
export function isMfaTransactionBoundTo(
	tx: Pick<MfaTransaction, "binding">,
	binding: MfaTransactionBinding,
): boolean {
	const held = heldBinding(tx);
	const presented = bindingOf(binding);
	if (held === undefined || presented === undefined) return false;
	return held.kind === presented.kind && constantTimeStringEqual(held.id, presented.id);
}

/**
 * The transaction `id` names if it is bound to `binding`
 * ({@link isMfaTransactionBoundTo}), else `null`: a transaction bound to
 * anything else reads as an unknown id, so a mismatch reveals nothing. A store
 * that cannot answer rejects, as its `get` does.
 *
 * - **It comes first.** Every use of a transaction starts with this read, then
 *   calls only operations carrying the version it read (`update`,
 *   `takeChallenge`, `consume`), plus `reserveAttempt` once the read held: that
 *   deletes the transaction past `max`, so on a bare id anyone holding it could
 *   destroy the ceremony.
 * - **It is necessary, not sufficient.** A `step_up` or `enroll` transaction
 *   upgrades one `UserSession`; the route also compares `tx.sid` with the
 *   session's `sid`.
 */
export async function getBoundMfaTransaction(
	store: Pick<MfaTransactionStore, "get">,
	id: string,
	binding: MfaTransactionBinding,
): Promise<MfaTransaction | null> {
	const tx = await store.get(id);
	return tx !== null && isMfaTransactionBoundTo(tx, binding) ? tx : null;
}

/**
 * `answer`, what `reserveAttempt(id, max)` answered, as the port promises
 * it: `ok` the literal boolean, `attempts` a safe integer — from 1 to `max`
 * when reserved, from 0 when not. `undefined` for anything else, which the
 * caller answers as the store's outage before any proof is checked: a count
 * it cannot read limits nothing. Each field is read once.
 */
export function readMfaAttemptReservation(
	answer: unknown,
	max: number,
): { readonly ok: boolean; readonly attempts: number } | undefined {
	try {
		if (!isRecord(answer)) return undefined;
		const { ok, attempts } = answer;
		if (typeof ok !== "boolean" || !isCount(attempts)) return undefined;
		if (ok && (attempts < 1 || attempts > max)) return undefined;
		return { ok, attempts };
	} catch {
		return undefined;
	}
}

/**
 * `answer`, what `sessionEmailProofAt(subject, sid, nowMs)` answered, as the
 * port promises it: `null` for no proof, or when the proof was given — a
 * finite instant from the epoch to `nowMs`. `undefined` for anything else,
 * which the caller answers as the store's outage: a proof it cannot read
 * admits nothing.
 */
export function readSessionEmailProof(answer: unknown, nowMs: number): number | null | undefined {
	if (answer === null) return null;
	return typeof answer === "number" && Number.isFinite(answer) && answer >= 0 && answer <= nowMs
		? answer
		: undefined;
}

/** A non-empty string: a session's subject and `sid`, as a proof is kept for them. */
const isNonEmptyText = (value: unknown): value is string =>
	typeof value === "string" && value.length > 0;

/** Epoch milliseconds a proof is kept in: a safe integer at or after the epoch. */
const isEpochMs = (value: unknown): value is number =>
	typeof value === "number" && Number.isSafeInteger(value) && value >= 0;

/** A session's account-email proof as a store keeps it. */
export interface SessionEmailProof {
	readonly provedAtMs: number;
	readonly untilMs: number;
}

/**
 * Refuses, with a `RangeError` naming what is wrong, a session's
 * account-email proof a store cannot keep, on `storeNowMs`, its clock:
 * `subject` and `sid` non-empty strings; `provedAtMs` and `untilMs` epoch
 * milliseconds, `untilMs` after `provedAtMs` and after `storeNowMs`, within
 * the Date range; `provedAtMs` no further ahead of `storeNowMs` than
 * {@link MFA_CLOCK_SKEW_ALLOWANCE_MS}. Every adapter runs it before it
 * records a proof, and on one it reads back.
 */
export function checkSessionEmailProof(
	subject: unknown,
	sid: unknown,
	provedAtMs: unknown,
	untilMs: unknown,
	storeNowMs: number,
): void {
	const refuse = (what: string): never => {
		throw new RangeError(`MfaTransactionStore.recordSessionEmailProof: ${what}`);
	};
	if (!isNonEmptyText(subject) || !isNonEmptyText(sid)) {
		refuse("subject and sid must be non-empty strings");
	}
	if (!isEpochMs(provedAtMs)) refuse("provedAtMs must be epoch milliseconds");
	if (!isEpochMs(untilMs) || !isStorableExpiry(untilMs)) {
		refuse("untilMs must be epoch milliseconds within the Date range");
	}
	if ((untilMs as number) <= (provedAtMs as number)) refuse("untilMs must be after provedAtMs");
	if (!((untilMs as number) > storeNowMs)) refuse("untilMs must be after the store's clock");
	if (!((provedAtMs as number) <= storeNowMs + MFA_CLOCK_SKEW_ALLOWANCE_MS)) {
		refuse(
			"provedAtMs must be no further ahead of the store's clock than MFA_CLOCK_SKEW_ALLOWANCE_MS",
		);
	}
}

/**
 * What a store answers of `proof` asked about at `nowMs`, on `storeNowMs`,
 * its clock: when it was given, no later than `nowMs`, while its `untilMs`
 * is after both; else `null`. Every adapter answers through it.
 */
export function sessionEmailProofAnswer(
	proof: SessionEmailProof,
	nowMs: number,
	storeNowMs: number,
): number | null {
	return proof.untilMs > nowMs && proof.untilMs > storeNowMs
		? Math.min(proof.provedAtMs, nowMs)
		: null;
}

/**
 * Refuses, with a `RangeError`, a question `sessionEmailProofAt` cannot
 * answer: `subject` and `sid` non-empty strings, `nowMs` an instant from the
 * epoch within the Date range. Every adapter runs it first.
 */
export function checkSessionEmailProofQuestion(
	subject: unknown,
	sid: unknown,
	nowMs: unknown,
): void {
	if (!isNonEmptyText(subject) || !isNonEmptyText(sid)) {
		throw new RangeError(
			"MfaTransactionStore.sessionEmailProofAt: subject and sid must be non-empty strings",
		);
	}
	if (typeof nowMs !== "number" || !isStorableExpiry(nowMs) || nowMs < 0) {
		throw new RangeError(
			"MfaTransactionStore.sessionEmailProofAt: nowMs must be an instant from the epoch within the Date range",
		);
	}
}

/**
 * Whether `consumed`, what `consume(bound.id, bound.version)` answered other
 * than `null`, is the transaction the bound read returned: the same id,
 * version, purpose, subject and `redirectTo`, bound to the same binding, and
 * a continuation — when the read had one — for the same subject and
 * redirect. The caller answers anything else as the store's outage and writes
 * nothing, before a factor moves on or a login resumes.
 */
export function isConsumedMfaTransaction(
	consumed: unknown,
	bound: MfaTransaction,
): consumed is MfaTransaction {
	try {
		if (!isRecord(consumed)) return false;
		const { id, version, purpose, subject, redirectTo, continuation } = consumed;
		if (
			id !== bound.id ||
			version !== bound.version ||
			purpose !== bound.purpose ||
			subject !== bound.subject ||
			redirectTo !== bound.redirectTo ||
			!isMfaTransactionBoundTo(consumed as Pick<MfaTransaction, "binding">, bound.binding)
		) {
			return false;
		}
		const expected = bound.continuation;
		if (expected === undefined) return continuation === undefined;
		if (!isRecord(continuation) || !isRecord(continuation.primary)) return false;
		const { primary } = continuation;
		return (
			primary.subject === expected.primary.subject &&
			primary.redirectTo === expected.primary.redirectTo
		);
	} catch {
		return false;
	}
}

/**
 * The subject lock policy (`mfa.lockout`). Every field is a positive whole
 * number; {@link checkMfaLockoutPolicy} is the rule.
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
	 * (86400). Before any lock, the same quiet period after the previous failure
	 * restarts the count. Neither ends the run the hard limit counts.
	 */
	readonly memorySeconds: number;
	/** Failures allowed in any rolling seven days (10). */
	readonly weeklyBudget: number;
	/** Consecutive failures that hold guessable proofs until an exempt success (100); at most {@link MFA_LOCKOUT_MAX_HARD_LIMIT}. */
	readonly hardLimit: number;
}

/** The weekly budget's window: any rolling seven days. */
export const MFA_WEEKLY_WINDOW_MS = 7 * 86_400_000;

/**
 * How long a store keeps a failure after it stops counting: a day, on the
 * store's clock. A caller whose clock runs ahead by less erases nothing
 * a caller on time still counts. With NTP-synced clocks a day is ample; it
 * costs a day of extra state.
 */
export const MFA_CLOCK_SKEW_ALLOWANCE_MS = 86_400_000;

/** The most consecutive failures a lockout policy may allow: NIST SP 800-63B-4's cap. */
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
			/**
			 * Whether this refusal begins an episode: the refusals from the first
			 * after an attempt was let through, or after `clearSubjectState`, to
			 * the next attempt let through. One refusal among any in flight is first.
			 */
			readonly first: boolean;
	  };

/**
 * How a reserved attempt ended. `failure`: it stands. `success`: a guessable
 * proof verified; it ends the consecutive run up to and including this
 * reservation (a later one still in flight starts the next). `void`: the proof
 * was right but the factor's write lost or failed; the attempt is removed and
 * the run goes on.
 */
export type MfaSubjectAttemptOutcome = "failure" | "success" | "void";

/**
 * Where MFA transactions, the subject lock state and a session's
 * account-email proof are kept.
 *
 * Every operation is atomic on its own. A store that cannot answer throws:
 * an outage is `503`, never a verdict on a proof.
 */
export interface MfaTransactionStore {
	readonly kind: string;

	/**
	 * Insert-only: a live id is refused. A `RangeError` for an `expiresAtMs` that
	 * is not a future instant, or a record {@link newMfaTransactionRecord}
	 * refuses. No lifetime ceiling here: the coordinator derives `expiresAtMs`
	 * only from `mfa.transactionTtlSeconds`, which boot range-checks.
	 */
	create(tx: MfaTransaction): Promise<void>;
	/** The transaction, or `null` once it expired. */
	get(id: string): Promise<MfaTransaction | null>;
	/**
	 * Compare-and-set on `version`: applies `patch` ({@link MfaTransactionPatch})
	 * and bumps `version`, only if still at `expectedVersion`. Answers the
	 * transaction as written, or `null` when the version moved or it is gone. A
	 * value a field does not admit, or an `expectedVersion` of
	 * `Number.MAX_SAFE_INTEGER` (`checkMfaVersionAdvances`), is a `RangeError`
	 * whatever the version.
	 */
	update(
		id: string,
		expectedVersion: number,
		patch: MfaTransactionPatch,
	): Promise<MfaTransaction | null>;
	/**
	 * Atomic: `attempts` + 1, whatever the version. `ok` while within `max`; the
	 * reservation past `max`, or one the store cannot count (fails closed),
	 * deletes the transaction and answers `{ ok: false, attempts }` with the
	 * attempts already reserved. No live transaction: `{ ok: false, attempts: 0 }`.
	 * A `max` that is not a positive whole number is a `RangeError`.
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
	 * backoff or the weekly budget, for every attempt alike — and otherwise
	 * count a pending failure, which stands until settled. A refusal records
	 * only that its episode began (`first`); an attempt let through ends the
	 * episode.
	 */
	reserveSubjectAttempt(
		subject: string,
		nowMs: number,
		policy: MfaLockoutPolicy,
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
	 * An exempt success (a recovery code, WebAuthn, the 80-bit email proof): ends
	 * the run up to `nowMs` (a later reservation stays), and with it a hard hold.
	 * The week stands, and lets no attempt through. Call it only after the
	 * transaction holding the exempt proof was consumed.
	 */
	noteExemptSuccess(subject: string, nowMs: number): Promise<void>;
	/**
	 * Forget `subject`'s lock state (the run and the week):
	 * the operator reset and a credential change. Clearing the week on a
	 * password change is deliberate: it is the remedy for an attacker who holds
	 * the password, and it ends the hold that attacker caused.
	 */
	clearSubjectState(subject: string): Promise<void>;

	// The email proof the operator reset requires.
	/**
	 * Record that `subject`'s next first binding requires the 80-bit email proof,
	 * whatever `mfa.enrollment.requireEmailProof` says (the operator reset's
	 * `requireEmailProof: true`). Idempotent. No expiry, and `clearSubjectState`
	 * leaves it: neither the reset nor a password change may lift it.
	 */
	requireEmailProofAtNextBinding(subject: string): Promise<void>;
	/** Whether the requirement is recorded for `subject`. */
	emailProofRequiredAtNextBinding(subject: string): Promise<boolean>;
	/**
	 * Atomic read-and-clear at the first binding: `true` for the one caller that
	 * cleared it, `false` when none was recorded or another cleared it first.
	 * Call it only after the email proof was verified and the first counting
	 * factor written, so a failed binding leaves the requirement standing. Keep
	 * it as durably as the factor store: a lost requirement lets a password
	 * holder bind without the proof.
	 */
	consumeEmailProofRequirement(subject: string): Promise<boolean>;

	// A session's account-email proof: verification state whose loss fails
	// closed — the user proves again.
	/**
	 * Record the account-email proof (D24) given in the session `sid` of
	 * `subject` at `provedAtMs`, standing until `untilMs`; it replaces an
	 * earlier one for that session. A `RangeError`, nothing recorded, for what
	 * {@link checkSessionEmailProof} refuses on the store's clock.
	 */
	recordSessionEmailProof(
		subject: string,
		sid: string,
		provedAtMs: number,
		untilMs: number,
	): Promise<void>;
	/**
	 * What {@link sessionEmailProofAnswer} answers of the proof recorded for
	 * the session `sid` of `subject`, on the store's clock: when it was given,
	 * no later than `nowMs`, while it stands; else `null`. Another session's
	 * proof, or the same `sid` under another subject, never answers. A
	 * `RangeError` for what {@link checkSessionEmailProofQuestion} refuses.
	 */
	sessionEmailProofAt(subject: string, sid: string, nowMs: number): Promise<number | null>;
}

/** Domain-specific AdapterFactory alias for {@link MfaTransactionStore}. */
export type MfaTransactionStoreFactory = AdapterFactory<MfaTransactionStore>;

const isPositiveWhole = (value: unknown): value is number =>
	typeof value === "number" && Number.isSafeInteger(value) && value > 0;

/**
 * Refuses a lockout policy a store cannot apply as written, with a `RangeError`
 * naming `setting` and the field: an object, every field a positive whole
 * number, `maxSeconds` ≥ `baseSeconds`, `threshold` ≤ `hardLimit` (else the
 * backoff never engages before the hard hold), `hardLimit` ≤
 * {@link MFA_LOCKOUT_MAX_HARD_LIMIT}, and every duration ending within the
 * Date range. Called at boot and again by every store operation taking a policy.
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
		/** MFA transactions and the subject lock state. */
		readonly mfaTransactionStore?: MfaTransactionStore;
	}
}
