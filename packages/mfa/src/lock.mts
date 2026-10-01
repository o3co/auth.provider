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
 * The subject lock in the verify path (the MFA ADR's D21, F1 step 5), over
 * the transaction store's lock operations and `mfa.lockout`.
 *
 * - A guessable proof reserves one of its subject's attempts before it is
 *   checked, and settles it once. Only a factor that says it is not
 *   guessable is exempt: it reserves nothing, passes during every hold, and
 *   records an exempt success when it settles a success.
 * - A refusal names its hold, when an attempt may come back (none for the
 *   hard hold), and whether it begins an episode.
 * - A reservation the store cannot answer, or answers outside the port, is
 *   an outage: never a pass, never a hold.
 * - Settling never throws: a settle or an exempt success the store does not
 *   take is handed to `unsettled` once, and the answer stands. The attempt
 *   it leaves pending counts as a failure.
 */

import type {
	MfaFactor,
	MfaFactorRecord,
	MfaFactorResolver,
	MfaLockoutPolicy,
	MfaSubjectAttemptOutcome,
	MfaSubjectHold,
	MfaTransactionStore,
} from "@o3co/auth-provider-core";
import { type MfaStoreOutage, OUTSIDE_CONTRACT, outage } from "./ceremony.mjs";
import { recoveryCodesLeft } from "./recovery/factor.mjs";
import type { MfaSealing } from "./sealing.mjs";

/** An attempt let through: settle it once, `failure`, `success` or `void`. */
export interface MfaSubjectLockEntry {
	readonly outcome: "entered";
	settle(outcome: MfaSubjectAttemptOutcome): Promise<void>;
}

/** A guessable attempt the subject's hold refused. */
export interface MfaSubjectLocked {
	readonly outcome: "locked";
	readonly hold: MfaSubjectHold;
	/** Milliseconds until an attempt may be reserved; `null` for the hard hold. */
	readonly retryAfterMs: number | null;
	/** Whether this refusal begins an episode. */
	readonly first: boolean;
}

/** A settle or an exempt success the store did not take. */
export interface MfaSubjectLockUnsettled {
	readonly subject: string;
	readonly kind: string;
	readonly step: "settleSubjectAttempt" | "noteExemptSuccess";
	readonly outcome: MfaSubjectAttemptOutcome;
	readonly cause: unknown;
}

export interface MfaSubjectLock {
	/** An attempt of `subject` with a proof of `factor`'s: let through, refused by a hold, or the store's outage. */
	enter(
		subject: string,
		factor: Pick<MfaFactor, "kind" | "guessable">,
	): Promise<MfaSubjectLockEntry | MfaSubjectLocked | MfaStoreOutage>;
}

export interface MfaSubjectLockOptions {
	readonly store: Pick<
		MfaTransactionStore,
		"reserveSubjectAttempt" | "settleSubjectAttempt" | "noteExemptSuccess"
	>;
	/** `mfa.lockout`. */
	readonly policy: MfaLockoutPolicy;
	/** The clock, in epoch milliseconds. Defaults to `Date.now`. */
	readonly now?: () => number;
	readonly unsettled: (failure: MfaSubjectLockUnsettled) => void;
}

const HOLDS: ReadonlySet<unknown> = new Set<MfaSubjectHold>(["backoff", "weekly", "hard"]);

/**
 * What `reserveSubjectAttempt` answered, as the port promises it: a
 * reservation, or a hold with a time to come back (none for `hard`) and
 * `first`; `undefined` for anything else.
 */
function readReservation(
	answer: unknown,
): { readonly reservation: string } | Omit<MfaSubjectLocked, "outcome"> | undefined {
	try {
		if (typeof answer !== "object" || answer === null) return undefined;
		const { ok, reservation, hold, retryAfterMs, first } = answer as Readonly<
			Record<string, unknown>
		>;
		if (ok === true) {
			return typeof reservation === "string" && reservation !== "" ? { reservation } : undefined;
		}
		if (ok !== false || !HOLDS.has(hold) || typeof first !== "boolean") return undefined;
		const comesBack =
			hold === "hard"
				? retryAfterMs === null
				: typeof retryAfterMs === "number" && Number.isFinite(retryAfterMs) && retryAfterMs > 0;
		return comesBack
			? { hold: hold as MfaSubjectHold, retryAfterMs: retryAfterMs as number | null, first }
			: undefined;
	} catch {
		return undefined;
	}
}

/** The subject lock over `options` (see this file's header). */
export function createMfaSubjectLock(options: MfaSubjectLockOptions): MfaSubjectLock {
	const { store, policy, unsettled } = options;
	const now = options.now ?? (() => Date.now());

	/** `settle`, run once; what it throws is reported, never thrown. */
	const once = (
		subject: string,
		kind: string,
		step: MfaSubjectLockUnsettled["step"],
		settle: (outcome: MfaSubjectAttemptOutcome) => Promise<void>,
	): MfaSubjectLockEntry => {
		let settled = false;
		return {
			outcome: "entered",
			async settle(outcome) {
				if (settled) return;
				settled = true;
				try {
					await settle(outcome);
				} catch (cause) {
					unsettled({ subject, kind, step, outcome, cause });
				}
			},
		};
	};

	return {
		async enter(subject, factor) {
			if (factor.guessable === false) {
				return once(subject, factor.kind, "noteExemptSuccess", async (outcome) => {
					// Called after the consume, as the port requires: a success is settled only then.
					if (outcome === "success") await store.noteExemptSuccess(subject, now());
				});
			}
			let answer: unknown;
			try {
				answer = await store.reserveSubjectAttempt(subject, now(), policy);
			} catch (cause) {
				return outage("mfa_transaction", "reserveSubjectAttempt", cause);
			}
			const read = readReservation(answer);
			if (read === undefined) {
				return outage("mfa_transaction", "reserveSubjectAttempt", OUTSIDE_CONTRACT);
			}
			if (!("reservation" in read)) return { outcome: "locked", ...read };
			const { reservation } = read;
			return once(subject, factor.kind, "settleSubjectAttempt", (outcome) =>
				store.settleSubjectAttempt(subject, reservation, outcome),
			);
		},
	};
}

/**
 * The kinds that still work while `subject`'s guessable proofs are held:
 * installed, not guessable, held by the subject in a record whose data
 * opens — a recovery set only while it has a code left — oldest first.
 */
export function usableKindsDuringHold(options: {
	readonly subject: string;
	readonly records: readonly MfaFactorRecord[];
	readonly factors: MfaFactorResolver;
	readonly sealing: MfaSealing;
}): string[] {
	const { subject, records, factors, sealing } = options;
	const usable = records.filter((record) => {
		const factor = factors.get(record.kind);
		if (factor === undefined || factor.guessable !== false) return false;
		const opened = sealing.openFactorData(
			{ subject, id: record.id, kind: record.kind },
			record.data,
		);
		if (opened.state !== "ok") return false;
		const left = recoveryCodesLeft(factor, opened.value);
		return left === undefined || left > 0;
	});
	return [...new Set(usable.map((record) => record.kind))];
}
