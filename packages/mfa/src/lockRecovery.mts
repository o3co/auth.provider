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
 * The authorized-recovery entry: the one way the subject lock is given back
 * before its time, through core's `authorizeSubjectRecovery` and
 * `applySubjectRecovery`.
 *
 * - An authorization is minted when a factor that is not guessable (a
 *   recovery code, a passkey) verifies — at a login or a session's step-up —
 *   for that session, with a fresh 16-byte recovery id, ending
 *   `mfa.manage.maxAgeSeconds` after the verification; that lifetime is held
 *   to core's `MFA_RECOVERY_AUTHORIZATION_MAX_MS` here. A guessable factor,
 *   or a kind not installed, mints nothing.
 * - A release, in that session, reads the subjects' sessions boundary
 *   (`revokedBefore`) — none wired, none is handed — then, under the
 *   subject's lease (`factorSet.mts`), reads the subject's records and hands
 *   the store the earliest creation time of those of any kind but an
 *   installed exempt one (a record whose data does not open included, and
 *   one of a kind not installed, which may be installed again — fail-closed;
 *   a time that cannot be read as the earliest there is), and the
 *   store judges the rest in one step: whether the authorization stands,
 *   whether the boundary is later than the attack's first counted failure,
 *   and whether every guessable factor was bound after the hard hold.
 * - The answer is the store's, read for the page: `released`; `held` while
 *   the hard hold stands — never read as released; `refused` — no
 *   authorization standing (`exempt_proof_required`), the boundary not later
 *   than the attack (`not_revoked_since`), or none wired to be later
 *   (`no_revocation_boundary`); `busy`; or an outage. An authorization
 *   already applied answers what it came to, applying nothing more.
 * - The operator reset mints its own authorization here
 *   (`mintSubjectRecovery`) and applies it under the lease it holds across
 *   the reset (`reset.mts`).
 */

import { randomBytes } from "node:crypto";
import {
	MFA_RECOVERY_AUTHORIZATION_MAX_MS,
	type MfaFactorRecord,
	type MfaFactorResolver,
	type MfaSubjectRecoveryAnswer,
	type MfaSubjectRecoveryOperation,
	type MfaTransactionStore,
	type SubjectRevocation,
} from "@o3co/auth-provider-core";
import { OUTSIDE_CONTRACT } from "./ceremony.mjs";
import type { MfaFactorSet } from "./factorSet.mjs";

/** What minting an authorization came to. */
export type MfaRecoveryMint =
	| { readonly outcome: "minted" }
	/** The factor verified is guessable, or not installed: it authorizes nothing. */
	| { readonly outcome: "not_exempt" }
	| { readonly outcome: "unavailable"; readonly cause: unknown };

/** What the store gave back, as an applied recovery reports it. */
export interface MfaRecoveryCleared {
	readonly week: boolean;
	readonly run: boolean;
	readonly hard: boolean;
}

/** Whether a release applied its authorization now, with what it gave back, or found it applied before, applying nothing more. */
type Applied =
	| { readonly applied: true; readonly cleared: MfaRecoveryCleared }
	| { readonly applied: false };

/** What a release came to. */
export type MfaLockRelease =
	| ({ readonly outcome: "released"; readonly generation: number } & Applied)
	/** The hard hold stands, until every guessable factor is bound again: never read as released. */
	| ({ readonly outcome: "held"; readonly hold: "hard"; readonly generation: number } & Applied)
	| {
			readonly outcome: "refused";
			readonly reason: "exempt_proof_required" | "not_revoked_since" | "no_revocation_boundary";
	  }
	| { readonly outcome: "busy"; readonly retryAfterSeconds: number }
	| {
			readonly outcome: "unavailable";
			readonly store: "mfa_factor" | "mfa_transaction" | "subject_revocation";
			readonly step: string;
			readonly cause: unknown;
	  };

export interface MfaLockRecovery {
	/** An authorization for `sid` minted when a factor of `kind` verified at `nowMs`; nothing for a guessable one. Never throws. */
	authorize(subject: string, sid: string, kind: string, nowMs: number): Promise<MfaRecoveryMint>;
	/** The subject's lock released on the authorization minted in `sid`. Never throws. */
	release(subject: string, sid: string): Promise<MfaLockRelease>;
}

export interface MfaLockRecoveryOptions {
	readonly store: Pick<MfaTransactionStore, "authorizeSubjectRecovery">;
	/** Where the release is applied under the subject's lease. */
	readonly factorSet: Pick<MfaFactorSet, "recover">;
	readonly factors: MfaFactorResolver;
	/** The subjects' sessions boundary; none wired, a release has none to hand. */
	readonly subjectRevocation?: Pick<SubjectRevocation, "revokedBefore">;
	/** `mfa.manage.maxAgeSeconds`, in milliseconds: how long an authorization lasts. */
	readonly manageMaxAgeMs: number;
	/** The clock, in epoch milliseconds. Defaults to `Date.now`. */
	readonly now?: () => number;
}

/**
 * Records in `store` a one-time authorization of `operation` for `subject`
 * — in session `sid` for a recover, none for a reset — under a fresh 16-byte
 * recovery id, ending `lifetimeMs` after `nowMs`. Throws what the store throws.
 */
export async function mintSubjectRecovery(
	store: Pick<MfaTransactionStore, "authorizeSubjectRecovery">,
	subject: string,
	authorization: {
		readonly operation: MfaSubjectRecoveryOperation;
		readonly sid: string | undefined;
		readonly nowMs: number;
		readonly lifetimeMs: number;
	},
): Promise<void> {
	await store.authorizeSubjectRecovery(subject, {
		operation: authorization.operation,
		sid: authorization.sid,
		recoveryId: randomBytes(16).toString("base64url"),
		expiresAtMs: authorization.nowMs + authorization.lifetimeMs,
	});
}

/** The earliest of `records` not of an exempt kind installed here — a kind not installed counts — `null` for none; a time that cannot be read as the earliest there is. */
const guessableBoundSince =
	(factors: MfaFactorResolver) =>
	(records: readonly MfaFactorRecord[]): number | null => {
		let earliest: number | null = null;
		for (const record of records) {
			let since = 0;
			try {
				const factor = factors.get(record.kind);
				// A kind not installed may be installed again: its record counts, fail-closed.
				if (factor?.guessable === false) continue;
				const at = record.createdAt instanceof Date ? record.createdAt.getTime() : Number.NaN;
				since = Number.isSafeInteger(at) && at >= 0 ? at : 0;
			} catch {
				// A record whose fields cannot be read counts, as the earliest there is: fail-closed.
				since = 0;
			}
			earliest = earliest === null ? since : Math.min(earliest, since);
		}
		return earliest;
	};

/** The authorized-recovery entry over `options` (see this file's header). */
export function createMfaLockRecovery(options: MfaLockRecoveryOptions): MfaLockRecovery {
	const { store, factorSet, factors, subjectRevocation, manageMaxAgeMs } = options;
	if (
		!Number.isSafeInteger(manageMaxAgeMs) ||
		manageMaxAgeMs <= 0 ||
		manageMaxAgeMs > MFA_RECOVERY_AUTHORIZATION_MAX_MS
	) {
		throw new RangeError(
			`an authorized recovery lasts mfa.manage.maxAgeSeconds, which must be a whole number of milliseconds up to core's MFA_RECOVERY_AUTHORIZATION_MAX_MS (${MFA_RECOVERY_AUTHORIZATION_MAX_MS}); it was ${String(manageMaxAgeMs)}`,
		);
	}
	const now = options.now ?? (() => Date.now());
	const earliestGuessable = guessableBoundSince(factors);

	/** The subjects' sessions boundary as a time, `undefined` for none; an outage for one that cannot be read. */
	const boundary = async (
		subject: string,
	): Promise<
		{ readonly at: number | undefined } | Extract<MfaLockRelease, { outcome: "unavailable" }>
	> => {
		if (subjectRevocation === undefined) return { at: undefined };
		const outage = (cause: unknown) =>
			({
				outcome: "unavailable",
				store: "subject_revocation",
				step: "revokedBefore",
				cause,
			}) as const;
		let read: unknown;
		try {
			read = await subjectRevocation.revokedBefore(subject);
		} catch (cause) {
			return outage(cause);
		}
		if (read === null) return { at: undefined };
		if (!(read instanceof Date) || !Number.isSafeInteger(read.getTime()) || read.getTime() < 0) {
			return outage(OUTSIDE_CONTRACT);
		}
		return { at: read.getTime() };
	};

	/** The store's answer as the page reads it. */
	const answered = (answer: MfaSubjectRecoveryAnswer): MfaLockRelease => {
		switch (answer.outcome) {
			case "refused":
				switch (answer.reason) {
					case "unauthorized":
					case "expired":
						return { outcome: "refused", reason: "exempt_proof_required" };
					case "not_revoked_since":
						return {
							outcome: "refused",
							reason:
								subjectRevocation === undefined ? "no_revocation_boundary" : "not_revoked_since",
						};
					default:
						// A boundary ahead of the clock, or a lease the store did not find held: neither is the user's to mend.
						return {
							outcome: "unavailable",
							store: "mfa_transaction",
							step: "applySubjectRecovery",
							cause: new Error(`the store refused the release: ${answer.reason}`),
						};
				}
			case "applied":
				return answer.hard
					? {
							outcome: "held",
							hold: "hard",
							applied: true,
							generation: answer.generation,
							cleared: answer.cleared,
						}
					: {
							outcome: "released",
							applied: true,
							generation: answer.generation,
							cleared: answer.cleared,
						};
			case "already_applied":
				return answer.hard
					? { outcome: "held", hold: "hard", applied: false, generation: answer.generation }
					: { outcome: "released", applied: false, generation: answer.generation };
		}
	};

	return {
		async authorize(subject, sid, kind, nowMs) {
			if (factors.get(kind)?.guessable !== false) return { outcome: "not_exempt" };
			try {
				await mintSubjectRecovery(store, subject, {
					operation: "recover",
					sid,
					nowMs,
					lifetimeMs: manageMaxAgeMs,
				});
				return { outcome: "minted" };
			} catch (cause) {
				return { outcome: "unavailable", cause };
			}
		},

		async release(subject, sid) {
			const nowMs = now();
			const sessions = await boundary(subject);
			if ("outcome" in sessions) return sessions;
			const recovered = await factorSet.recover(subject, {
				sid,
				nowMs,
				sessionsBoundaryMs: sessions.at,
				guessableBoundSince: earliestGuessable,
			});
			return recovered.outcome === "answered" ? answered(recovered.answer) : recovered;
		},
	};
}
