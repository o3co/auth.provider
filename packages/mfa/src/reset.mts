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
 * - Then, in this order: every session and token of the subject's ended
 *   (`revokeAllForSubject`, the federation grants as asked) — a revocation
 *   that throws or is not complete stops it, nothing more done; then, under
 *   one lease of the subject's, waited for (`factorSet.mts`), each write held
 *   to the lease's time: D25's flag set when asked — under the lease, so no
 *   binding that held it before can clear it — the reset's own one-time
 *   authorization recorded (`lockRecovery.mts`) and applied: the lock state
 *   reset whole — the hard hold, every authorization of the subject's, and
 *   the generation moved on, so a factor-set write begun before stops at its
 *   commit — then every record removed (`removeAllForSubject`: one sealed
 *   under a retired key, of a kind not installed, or a recovery-code set
 *   alike), and the witness cleared last; and, once the lease part is done,
 *   every session and token ended again: a login made with a factor before
 *   its removal ends too.
 * - Answers a report: whether it completed — both revocations complete, the
 *   lease held throughout — where it stopped, both sessions' reports, the
 *   kinds and count of the records removed (once the removal succeeded), the
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
import { createMfaFactorSetReset, type MfaSubjectLeases } from "./factorSet.mjs";
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
	/** Every step done under a lease held throughout: the sessions ended twice, the lock state reset, every record removed, the witness cleared or not writable here. */
	readonly complete: boolean;
	/** Where it stopped, when a step did not complete: run it again. One whose lease ended before its release says `overran` alone. */
	readonly stoppedAt?: MfaResetStop;
	/** Why it stopped there. */
	readonly cause?: unknown;
	readonly requireEmailProof: boolean;
	/** What the revocation reported; none when it stopped before, or the revocation threw. */
	readonly sessions?: SubjectRevocationReport;
	/** What the revocation once the lease part was done reported; none when it did not run, or threw. */
	readonly sessionsAgain?: SubjectRevocationReport;
	/** Once the removal succeeded: the kinds, each once in code-unit order, and the count of the records removed, as read just before; none when they could not be read. */
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
	/** The boot's lease owner, the one every writer of a subject's factor set holds (`mfaModule`'s `mfaSubjectLeases`). */
	readonly leases: MfaSubjectLeases;
	readonly auditSink?: AuditSink;
	readonly logger?: Logger;
	/** The clock, in epoch milliseconds. Defaults to `Date.now`. */
	readonly now?: () => number;
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

/** The kinds `records` name, each once in code-unit order; a record that is none, or whose kind cannot be read as a string, names none. */
function kindsOf(records: readonly unknown[]): string[] {
	const kinds = new Set<string>();
	for (const record of records) {
		try {
			const kind: unknown = (record as { readonly kind?: unknown } | null | undefined)?.kind;
			if (typeof kind === "string") kinds.add(kind);
		} catch {
			// A store's record whose field cannot be read names no kind; it was still removed.
		}
	}
	return [...kinds].sort();
}

/** The operator reset over `options` (see this file's header). */
export function createMfaReset(options: MfaResetOptions): MfaReset {
	const { factorStore, transactionStore, subjectRevocationService, auditSink, logger } = options;
	if (typeof subjectRevocationService?.revokeAllForSubject !== "function") {
		throw new TypeError(
			"the operator reset's subjectRevocationService is no service: it has no revokeAllForSubject",
		);
	}
	const now = options.now ?? (() => Date.now());
	const witness = createMfaEnrollmentWitness(options.userRepository);
	const underLease = createMfaFactorSetReset({
		factorStore,
		witness,
		leases: options.leases,
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
					timestamp: new Date(now()),
					type: "mfa.reset",
					subject,
					details: {
						by: "operator",
						...(report.removed === undefined
							? {}
							: { kinds: [...report.removed.kinds], count: report.removed.count }),
						requireEmailProof: asked.requireEmailProof,
						sessions: report.sessions?.complete === true,
						...(report.sessionsAgain === undefined
							? {}
							: { sessionsAgain: report.sessionsAgain.complete === true }),
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
							...(report.stoppedAt === undefined ? {} : { stoppedAt: report.stoppedAt }),
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

			/** Every session and token of the subject's ended: the report, or why not. */
			const revoke = async (): Promise<
				| { readonly report: SubjectRevocationReport }
				| { readonly cause: unknown; readonly report?: SubjectRevocationReport }
			> => {
				let report: SubjectRevocationReport;
				let complete: unknown;
				try {
					report = await subjectRevocationService.revokeAllForSubject({
						subject,
						...(asked.federationGrants === undefined
							? {}
							: { federationGrants: asked.federationGrants }),
					});
					// The service is the deployment's: a report that is none, or whose read throws, ends nothing.
					complete = (report as { readonly complete?: unknown } | null | undefined)?.complete;
				} catch (cause) {
					return { cause };
				}
				if (typeof report !== "object" || report === null) {
					return { cause: new TypeError("the subject revocation service answered no report") };
				}
				return complete === true
					? { report }
					: { report, cause: new Error("the subject's sessions could not all be ended") };
			};

			const first = await revoke();
			if ("cause" in first) {
				return finish({
					...base,
					complete: false,
					stoppedAt: "sessions",
					cause: first.cause,
					...(first.report === undefined ? {} : { sessions: first.report }),
				});
			}

			const done = await underLease.reset(subject, {
				nowMs,
				...(asked.requireEmailProof
					? { requireEmailProof: () => transactionStore.requireEmailProofAtNextBinding(subject) }
					: {}),
				authorize: () =>
					mintSubjectRecovery(transactionStore, subject, {
						operation: "reset",
						sid: undefined,
						nowMs,
						lifetimeMs: MFA_RECOVERY_AUTHORIZATION_MAX_MS,
					}),
			});

			// A login made with a factor before its removal ends too.
			const again = await revoke();
			const removed =
				done.removed === undefined
					? undefined
					: { kinds: kindsOf(done.removed), count: done.removed.length };
			const after = {
				sessions: first.report,
				...(again.report === undefined ? {} : { sessionsAgain: again.report }),
				...(removed === undefined ? {} : { removed }),
				...(done.generation === undefined ? {} : { generation: done.generation }),
				...(done.overran === true ? { overran: true as const } : {}),
			};
			if (done.outcome === "stopped") {
				return finish({
					...base,
					complete: false,
					stoppedAt: done.at,
					cause: done.cause,
					...after,
				});
			}
			if (done.witness.outcome !== "marked" && done.witness.outcome !== "unwritable") {
				return finish({
					...base,
					complete: false,
					stoppedAt: "witness",
					cause: done.witness.outcome === "unwritten" ? done.witness.cause : undefined,
					...after,
				});
			}
			const witness = done.witness.outcome === "marked" ? "cleared" : "unwritable";
			if ("cause" in again) {
				return finish({
					...base,
					complete: false,
					stoppedAt: "sessions",
					cause: again.cause,
					...after,
					witness,
				});
			}
			return finish({ ...base, complete: done.overran !== true, ...after, witness });
		},
	};
}
