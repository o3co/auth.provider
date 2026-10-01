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
 * The operator reset, `resetMfaForSubject`: for a subject who lost their
 * second factors, an identity the operator verified out of band.
 *
 * - Refused with a `RangeError`, nothing done, for a subject that is not a
 *   non-empty string, a federation-grant disposition other than `revoke` or
 *   `keep`, a `requestedBy` that is not a well-formed string of 1 to 256
 *   characters, or `requireEmailProof` with no mail sender wired — nobody
 *   could give the proof, so nobody could bind. A Store must also not ask it
 *   for an account with no address.
 * - Then, in this order: D25's flag set when asked; every session and token
 *   of the subject's ended (`revokeAllForSubject`, the federation grants as
 *   asked) — a revocation that throws or is not complete stops it, nothing
 *   more done; a one-time `reset` authorization recorded
 *   (`lockRecovery.mts`); and, under one lease of the subject's, waited for
 *   (`factorSet.mts`): the lock state reset whole — the hard hold, every
 *   authorization of the subject's, and the generation moved on, so a
 *   factor-set write begun before stops at its commit — every record removed
 *   (`removeAllForSubject`: one sealed under a retired key, of a kind not
 *   installed, or a recovery-code set alike), and the witness cleared last.
 * - Answers a report: whether it completed, where it stopped, the sessions'
 *   report, the kinds and count of the records removed as read before, the
 *   generation, the witness. It is idempotent: run again, it does it all
 *   again. Emits one `mfa.reset`, and no `mfa.lock.recovered`.
 * - Residual: a write admitted before the revocation that ran past its lease
 *   can land after the removal; the factor-set's lease is logical.
 */

import {
	type AuditSink,
	emitAuditEvent,
	type FederationGrantDisposition,
	type Logger,
	loggableError,
	MFA_RECOVERY_AUTHORIZATION_MAX_MS,
	type MfaFactorStore,
	type MfaTransactionStore,
	type SubjectRevocationReport,
	type SubjectRevocationService,
	type UserRepository,
} from "@o3co/auth-provider-core";
import { createMfaFactorSetReset } from "./factorSet.mjs";
import { mintSubjectRecovery } from "./lockRecovery.mjs";
import { createMfaEnrollmentWitness } from "./witness.mjs";

/** The longest `requestedBy` a reset records. */
const REQUESTED_BY_MAX = 256;

/** What the operator asks of a reset. */
export interface MfaResetRequest {
	/** D25: the subject's next first binding requires the account-email proof. */
	readonly requireEmailProof?: boolean;
	/** What becomes of the subject's federation grants; `revoke` when not given, and policy decides a `keep`. */
	readonly federationGrants?: FederationGrantDisposition;
	/** Who asked, as the operator's records name it: audited, never read. */
	readonly requestedBy?: string;
}

/** Where a reset stopped. */
export type MfaResetStop = "email_proof" | "sessions" | "lease" | "lock" | "factors" | "witness";

/** What a reset did. */
export interface MfaResetReport {
	readonly subject: string;
	/** Every step done: the sessions ended, the lock state reset, every record removed, the witness cleared or not writable here. */
	readonly complete: boolean;
	/** Where it stopped, when it did not complete: run it again. */
	readonly stoppedAt?: MfaResetStop;
	/** Why it stopped there. */
	readonly cause?: unknown;
	readonly requireEmailProof: boolean;
	/** What the revocation reported; none when it stopped before, or the revocation threw. */
	readonly sessions?: SubjectRevocationReport;
	/** The kinds, each once in code-unit order, and the count of the records removed, as read just before; none when they could not be read. */
	readonly removed?: { readonly kinds: readonly string[]; readonly count: number };
	/** The subject's generation once the lock state was reset. */
	readonly generation?: number;
	/** `cleared`, or `unwritable` when the directory cannot write the witness. */
	readonly witness?: "cleared" | "unwritable";
	/** The lease ended before the reset released it: another writer may have run beside it. */
	readonly overran?: true;
}

export interface MfaReset {
	/** The operator reset of `subject` (see this file's header). */
	resetMfaForSubject(subject: string, request?: MfaResetRequest): Promise<MfaResetReport>;
}

export interface MfaResetOptions {
	readonly factorStore: MfaFactorStore;
	readonly transactionStore: MfaTransactionStore;
	readonly subjectRevocationService: SubjectRevocationService;
	/** The directory the witness is cleared through; none, or one without `markMfaEnrolled`, clears nothing. */
	readonly userRepository?: UserRepository;
	/** Whether a mail sender is wired: `requireEmailProof` needs one. */
	readonly mailWired: boolean;
	/**
	 * One Store call's time under the reset's lease; by default the one whose
	 * lease is core's `DEFAULT_MFA_SUBJECT_LEASE_MS` (a minute).
	 */
	readonly storeTimeoutMs?: number;
	readonly auditSink?: AuditSink;
	readonly logger?: Logger;
	/** The clock, in epoch milliseconds. Defaults to `Date.now`. */
	readonly now?: () => number;
	/** A monotonic clock, in milliseconds. Defaults to `performance.now`. */
	readonly monotonicNow?: () => number;
}

/** `request` read once, or a `RangeError` naming what is wrong. */
function checkRequest(
	subject: unknown,
	request: unknown,
): Required<Omit<MfaResetRequest, "federationGrants" | "requestedBy">> &
	Pick<MfaResetRequest, "federationGrants" | "requestedBy"> {
	const refuse = (what: string): never => {
		throw new RangeError(`resetMfaForSubject: ${what}`);
	};
	if (typeof subject !== "string" || subject.length === 0)
		refuse("subject must be a non-empty string");
	if (typeof request !== "object" || request === null || Array.isArray(request)) {
		return refuse("the request must be an object");
	}
	const { requireEmailProof, federationGrants, requestedBy } = request as Record<string, unknown>;
	if (requireEmailProof !== undefined && typeof requireEmailProof !== "boolean") {
		refuse("requireEmailProof must be a boolean");
	}
	if (
		federationGrants !== undefined &&
		federationGrants !== "revoke" &&
		federationGrants !== "keep"
	) {
		refuse('federationGrants must be "revoke" or "keep"');
	}
	if (
		requestedBy !== undefined &&
		(typeof requestedBy !== "string" ||
			requestedBy.length === 0 ||
			requestedBy.length > REQUESTED_BY_MAX ||
			!requestedBy.isWellFormed())
	) {
		refuse(`requestedBy must be a well-formed string of 1 to ${REQUESTED_BY_MAX} characters`);
	}
	return {
		requireEmailProof: requireEmailProof === true,
		...(federationGrants === undefined
			? {}
			: { federationGrants: federationGrants as FederationGrantDisposition }),
		...(requestedBy === undefined ? {} : { requestedBy: requestedBy as string }),
	};
}

/** The operator reset over `options` (see this file's header). */
export function createMfaReset(options: MfaResetOptions): MfaReset {
	const { factorStore, transactionStore, subjectRevocationService, auditSink, logger } = options;
	const now = options.now ?? (() => Date.now());
	const witness = createMfaEnrollmentWitness(options.userRepository);
	const underLease = createMfaFactorSetReset({
		factorStore,
		witness,
		leases: transactionStore,
		...(options.storeTimeoutMs === undefined ? {} : { storeTimeoutMs: options.storeTimeoutMs }),
		...(options.monotonicNow === undefined ? {} : { monotonicNow: options.monotonicNow }),
	});

	return {
		async resetMfaForSubject(subject, request = {}) {
			const asked = checkRequest(subject, request);
			if (asked.requireEmailProof && !options.mailWired) {
				throw new RangeError(
					"resetMfaForSubject: requireEmailProof needs a mail sender, and none is wired: nobody could give the account-email proof, so nobody could bind a factor",
				);
			}
			const nowMs = now();

			/** `report` audited once, said once, and answered. */
			const finish = (report: MfaResetReport): MfaResetReport => {
				emitAuditEvent(auditSink, {
					timestamp: new Date(nowMs),
					type: "mfa.reset",
					subject,
					details: {
						by: "operator",
						...(report.removed === undefined
							? {}
							: { kinds: [...report.removed.kinds], count: report.removed.count }),
						requireEmailProof: asked.requireEmailProof,
						sessions: report.sessions?.complete === true,
						complete: report.complete,
						...(asked.requestedBy === undefined ? {} : { requestedBy: asked.requestedBy }),
					},
				});
				if (report.complete) {
					logger?.info({ sub: subject, generation: report.generation }, "mfa_reset");
				} else {
					logger?.warn(
						{
							sub: subject,
							stoppedAt: report.stoppedAt,
							...(report.cause === undefined ? {} : { err: loggableError(report.cause) }),
						},
						"mfa_reset_incomplete",
					);
				}
				if (report.overran === true) {
					logger?.error({ sub: subject }, "mfa_subject_lease_overrun");
				}
				return report;
			};
			const base = { subject, requireEmailProof: asked.requireEmailProof };
			const stopped = (
				at: MfaResetStop,
				more: Omit<MfaResetReport, "subject" | "complete" | "requireEmailProof" | "stoppedAt">,
			): MfaResetReport => finish({ ...base, complete: false, stoppedAt: at, ...more });

			if (asked.requireEmailProof) {
				try {
					await transactionStore.requireEmailProofAtNextBinding(subject);
				} catch (cause) {
					return stopped("email_proof", { cause });
				}
			}

			let sessions: SubjectRevocationReport;
			try {
				sessions = await subjectRevocationService.revokeAllForSubject({
					subject,
					...(asked.federationGrants === undefined
						? {}
						: { federationGrants: asked.federationGrants }),
				});
			} catch (cause) {
				return stopped("sessions", { cause });
			}
			if (sessions.complete !== true) {
				return stopped("sessions", {
					sessions,
					cause: new Error("the subject's sessions could not all be ended"),
				});
			}

			try {
				await mintSubjectRecovery(transactionStore, subject, {
					operation: "reset",
					sid: undefined,
					nowMs,
					lifetimeMs: MFA_RECOVERY_AUTHORIZATION_MAX_MS,
				});
			} catch (cause) {
				return stopped("lock", { sessions, cause });
			}

			const done = await underLease.reset(subject, nowMs);
			const removed =
				done.records === undefined
					? undefined
					: {
							kinds: [...new Set(done.records.map((record) => record.kind))].sort(),
							count: done.records.length,
						};
			const after = {
				sessions,
				...(removed === undefined ? {} : { removed }),
				...(done.generation === undefined ? {} : { generation: done.generation }),
				...(done.overran === true ? { overran: true as const } : {}),
			};
			if (done.outcome === "stopped") return stopped(done.at, { ...after, cause: done.cause });
			switch (done.witness.outcome) {
				case "marked":
					return finish({ ...base, complete: true, ...after, witness: "cleared" });
				case "unwritable":
					return finish({ ...base, complete: true, ...after, witness: "unwritable" });
				default:
					return stopped("witness", {
						...after,
						cause: done.witness.outcome === "unwritten" ? done.witness.cause : undefined,
					});
			}
		},
	};
}
