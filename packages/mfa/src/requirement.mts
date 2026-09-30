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
 * The `mfa` session requirement: what MFA means to every consumer of a session,
 * through core's admission, reached through `sessionRequirements.mfa` only. It
 * declares the second-factor authority; the name `mfa` is this package's own.
 *
 * `reach` (the enabled factors' `amrValues`, plus `mfa` when one `addsMfa`) is
 * read once, after every factor has registered, and kept: boot refuses it unless
 * it equals what core recomputes from the same factors, and the requirement's own
 * verdicts read the same snapshot, so the two never disagree.
 *
 * `admit` decides by the mode and the action's grade, never its name
 * (`RECORD_RULES`). A token is judged on its own `amr` (`admitToken`) under
 * `required`, whatever the grade, and met under `optional`. A session a cookie,
 * code or link carries is held, under `required`, to its record's baseline,
 * except that an action graded `grants_nothing` is met on any live record;
 * under `optional` it is met. An action graded `credential_change` adds a way
 * into the account and is held to recent MFA (`isRecentMfa`) over a primary the
 * baseline knows — under `required` on top of the baseline, so it is never
 * looser than `use`: the subject's factor records say whether it may hold a
 * counting factor — a record of a kind no installed factor declares
 * non-counting counts — and a list that cannot answer throws.
 *
 * `admitPrimary` interrupts a password login for a second factor when the subject
 * has any factor record: a record it cannot use is never "none", and a `list`
 * that cannot answer throws, which admission answers `unavailable`. When no
 * record that may count stands, the login's `User` must not say the subject
 * enrolled: a witness `true` or malformed is recorded and thrown, under either
 * mode (D12). With no records, `optional` establishes and `required` interrupts
 * for a first binding offering the counting factors the user may enroll, the
 * account-email proof first where the one gate (`firstBinding.mts`) asks for
 * it. Other primaries establish without a read: the baseline applies after
 * `pwd` only.
 *
 * Every method is a closure: core calls them on a registered copy, and the
 * contract suite on a spread of the object.
 */

import {
	type AdmissionGrade,
	type AuditSink,
	DEFAULT_CLOCK_SKEW_MS,
	emitAuditEvent,
	FEDERATED_AMR,
	type Logger,
	MFA_AMR,
	type MfaFactorRecord,
	type MfaFactorResolver,
	type MfaFactorStore,
	normaliseMailAddress,
	PASSWORD_AMR,
	type PrimaryAuthentication,
	type RequirementInput,
	type RequirementInterruption,
	type RequirementVerdict,
	readMfaEnrollmentWitness,
	SECOND_FACTOR_AMR,
	type SessionAuthentication,
	type SessionRequirement,
	type SessionView,
	type StepUpPage,
} from "@o3co/auth-provider-core";
import { firstBindingGate, type RequireEmailProof } from "./firstBinding.mjs";
import type { LoginInterruption, LoginTransactions } from "./transactions.mjs";
import { MfaEnrollmentStateInconsistentError } from "./witness.mjs";

/** The name the requirement is registered under: `sessionRequirements.mfa`. */
export const MFA_REQUIREMENT_NAME = "mfa";

/** The remediation the MFA page's step-up call (`POST /session/mfa/step-up`) admits with. */
const MFA_STEP_UP_REMEDIATION = `${MFA_REQUIREMENT_NAME}.step_up`;

/** The hint keys a first binding's answer carries. */
const MFA_HINT_KEYS = ["enrollable", "email_proof"] as const;

/** The two modes the requirement is registered under: `off` is refused by the module. */
export type MfaRequirementMode = "optional" | "required";

export interface MfaRequirementOptions {
	readonly mode: MfaRequirementMode;
	/** The installed factors, read when asked: they register in the same pass as the requirement. */
	readonly factors: MfaFactorResolver;
	readonly factorStore: MfaFactorStore;
	readonly transactions: LoginTransactions;
	/** `mfa.page.url`, as the page a step-up starts on. */
	readonly stepUpPage: StepUpPage;
	/**
	 * Whether the session store can record a step-up (core's
	 * `supportsSecondFactorUpdate`): without it a stepped-up session could never be
	 * written, so the baseline sends it to log in instead.
	 */
	readonly stepUpRecordable: boolean;
	/** `mfa.manage.maxAgeSeconds`: how long a second factor verified in a session stays recent. */
	readonly recentMfaMaxAgeSeconds: number;
	/** Where a first binding that offers nothing is said (`mfa_enrollment_nothing_enrollable`). */
	readonly logger: Logger;
	/** Where `mfa.enrollment_state_inconsistent` is recorded; none, it is not. */
	readonly auditSink?: AuditSink;
	/** What the first-binding gate reads of the composition: `mfa.enrollment.requireEmailProof`, and whether a mail sender is wired. */
	readonly firstBinding: {
		readonly requireEmailProof: RequireEmailProof;
		readonly mailWired: boolean;
	};
	/** D25's flag for `subject` (`MfaTransactionStore.emailProofRequiredAtNextBinding`); rejects on an outage. */
	readonly emailProofRequiredAtNextBinding: (subject: string) => Promise<boolean>;
}

/** What recent MFA is read from: a live session's primary time and its last second factor. */
export interface RecentMfaSession {
	readonly authTime: Date;
	readonly mfaAt: Date | undefined;
}

/** What recent MFA is told of the session's subject. */
export interface RecentMfaSubject {
	/**
	 * Whether the subject holds a counting factor: without one, a recent
	 * primary stands in for a second factor. Admission answers it with
	 * `mayHoldCountingFactor`, which presumes a kind it cannot tell counts.
	 */
	readonly holdsCountingFactor: boolean;
}

/**
 * Whether `at` is at most `maxAgeMs` before `nowMs`. A time up to
 * `DEFAULT_CLOCK_SKEW_MS` ahead — another replica's clock — reads as now; one
 * further ahead, or one that is not a valid date, is not recent.
 */
function withinWindow(at: Date | undefined, maxAgeMs: number, nowMs: number): boolean {
	const atMs = at instanceof Date ? at.getTime() : Number.NaN;
	if (!Number.isFinite(atMs) || !Number.isFinite(nowMs) || !Number.isFinite(maxAgeMs)) {
		return false;
	}
	if (atMs - nowMs > DEFAULT_CLOCK_SKEW_MS) return false;
	return nowMs - Math.min(atMs, nowMs) <= maxAgeMs;
}

/**
 * Whether `session` has recent MFA at `nowMs`: a second factor verified
 * within `maxAgeSeconds` (`mfa.manage.maxAgeSeconds`) or, when `subject`
 * holds no counting factor, a primary that recent. The window's edge is
 * recent.
 */
export function isRecentMfa(
	session: RecentMfaSession,
	subject: RecentMfaSubject,
	maxAgeSeconds: number,
	nowMs: number,
): boolean {
	const maxAgeMs = maxAgeSeconds * 1_000;
	if (withinWindow(session.mfaAt, maxAgeMs, nowMs)) return true;
	return !subject.holdsCountingFactor && withinWindow(session.authTime, maxAgeMs, nowMs);
}

const MET: RequirementVerdict = Object.freeze({ outcome: "met" });
const REAUTHENTICATE: RequirementVerdict = Object.freeze({ outcome: "reauthenticate" });
const UNMET: RequirementVerdict = Object.freeze({ outcome: "unmet" });
/** A session that comes back from the step-up still unmet is sent to log in again. */
const STEP_UP: RequirementVerdict = Object.freeze({
	outcome: "step_up",
	whenStillUnmet: "reauthenticate",
});

/**
 * What a session a record carries is held to: `met` whatever it is, `live` met
 * on any live record, `baseline`, `recent` (recent MFA), or `baseline+recent`
 * (the baseline, then recent MFA on a session it meets).
 */
type RecordRule = "met" | "live" | "baseline" | "recent" | "baseline+recent";

/**
 * The rule by mode and grade — the session-admission ADR's D6 table,
 * exhaustive over core's grades. An action that grants nothing is met, so a
 * user can refuse a phished device request without a step-up; one that adds a
 * way into the account needs recent MFA, and under `required` the baseline
 * first; core never asks about a remediation.
 */
const RECORD_RULES: Readonly<
	Record<MfaRequirementMode, Readonly<Record<AdmissionGrade, RecordRule>>>
> = {
	optional: {
		use: "met",
		grants_nothing: "met",
		credential_change: "recent",
		remediation: "met",
	},
	required: {
		use: "baseline",
		grants_nothing: "live",
		credential_change: "baseline+recent",
		remediation: "baseline",
	},
};

/** The `amr` values a step-up through the installed factors can add: each one's `amrValues`, and `mfa` when one adds it. */
function reachOf(factors: MfaFactorResolver): ReadonlySet<string> {
	const reach = new Set<string>();
	for (const [, factor] of factors.entries()) {
		for (const value of factor.amrValues) reach.add(value);
		if (factor.addsMfa) reach.add(MFA_AMR);
	}
	return reach;
}

/** The `mfa` requirement over `options` (see this file's header). */
export function createMfaRequirement(options: MfaRequirementOptions): SessionRequirement {
	const {
		mode,
		factors,
		factorStore,
		transactions,
		stepUpPage,
		stepUpRecordable,
		recentMfaMaxAgeSeconds,
		logger,
		auditSink,
		firstBinding,
		emailProofRequiredAtNextBinding,
	} = options;

	/**
	 * The reach of the first read (boot's, after every factor registered), kept:
	 * core seals that read and merges with it at every request, so the verdicts here
	 * must read the same.
	 */
	let reachRead: ReadonlySet<string> | undefined;
	const reach = (): ReadonlySet<string> => {
		reachRead ??= reachOf(factors);
		return reachRead;
	};

	/**
	 * A token, judged on its own `amr`; the record beside it is only the live view.
	 * Federated is met; a factor's own second-factor value is met whatever the
	 * primary (the WebAuthn grant's `["hwk"]` has none); a password alone is unmet;
	 * anything else (no `amr`, an unknown value, `mfa` alone) is sent to log in
	 * again. `mfa` names no factor, so it meets nothing by itself.
	 */
	const admitToken = ({ authentication }: RequirementInput): RequirementVerdict => {
		const primary = authentication?.authentication?.primary;
		if (primary === FEDERATED_AMR) return MET;
		const amr = authentication?.amr ?? [];
		if (amr.some((value) => value !== MFA_AMR && SECOND_FACTOR_AMR.has(value))) return MET;
		return primary === PASSWORD_AMR ? UNMET : REAUTHENTICATE;
	};

	/** The subject's factor records; a store that cannot answer, or answers something other than a list, throws. */
	const listRecords = async (subject: string): Promise<readonly MfaFactorRecord[]> => {
		const records: unknown = await factorStore.list(subject);
		if (!Array.isArray(records)) {
			throw new TypeError("MfaFactorStore.list answered something that is not a list");
		}
		return records;
	};

	/**
	 * Whether the subject may hold a counting factor: a record counts unless an
	 * installed factor of its kind declares it does not, so a kind no longer
	 * installed is presumed to count. That fails closed for admission — a
	 * password never stands in for a factor it cannot see — and is the wrong
	 * answer for a last-factor check or clearing the witness.
	 */
	const mayCount = (record: MfaFactorRecord): boolean =>
		factors.get(record.kind)?.counting !== false;
	const mayHoldCountingFactor = async (subject: string): Promise<boolean> =>
		(await listRecords(subject)).some(mayCount);

	/**
	 * The witness the login's `User` carries, read when no record that may
	 * count stands: `true` or malformed is an outage — recorded, then thrown —
	 * never a first binding (D12).
	 */
	const checkWitness = (primary: PrimaryAuthentication): void => {
		const witness = readMfaEnrollmentWitness(primary.user);
		if (witness === "not_enrolled") return;
		emitAuditEvent(auditSink, {
			timestamp: new Date(),
			type: "mfa.enrollment_state_inconsistent",
			subject: primary.subject,
			ip: primary.request.ip,
			userAgent: primary.request.userAgent,
			details: { purpose: "login", witness },
		});
		throw new MfaEnrollmentStateInconsistentError(witness);
	};

	/** Where a second factor would meet the rule: a step-up, `unmet` when no factor could finish one, a new login when none could be recorded. */
	const stepUp = (): RequirementVerdict => {
		if (reach().size === 0) return UNMET;
		return stepUpRecordable ? STEP_UP : REAUTHENTICATE;
	};

	/** The baseline over a record: a federation, or a second factor after a password. */
	const baseline = (recorded: SessionAuthentication | undefined): RequirementVerdict => {
		if (recorded?.primary === FEDERATED_AMR) return MET;
		if (recorded?.primary !== PASSWORD_AMR) return REAUTHENTICATE;
		if (recorded.mfaAt !== undefined) return MET;
		return stepUp();
	};

	/**
	 * Recent MFA over a record whose primary the baseline knows; a subject with
	 * no counting factor and a stale primary logs in again.
	 */
	const recent = async (
		session: SessionView,
		recorded: SessionAuthentication | undefined,
		nowMs: number,
	): Promise<RequirementVerdict> => {
		if (recorded?.primary !== PASSWORD_AMR && recorded?.primary !== FEDERATED_AMR) {
			return REAUTHENTICATE;
		}
		const counting = await mayHoldCountingFactor(session.sub);
		const recentMfa = isRecentMfa(
			{ authTime: session.authTime, mfaAt: recorded.mfaAt },
			{ holdsCountingFactor: counting },
			recentMfaMaxAgeSeconds,
			nowMs,
		);
		if (recentMfa) return MET;
		return counting ? stepUp() : REAUTHENTICATE;
	};

	/** A session a cookie, a code or a link carries, held over its record to the rule its mode and grade name. */
	const admitRecord = async ({
		session,
		authentication,
		action,
		now,
	}: RequirementInput): Promise<RequirementVerdict> => {
		const rule = RECORD_RULES[mode][action.grade];
		if (rule === "met") return MET;
		if (session === null) return REAUTHENTICATE;
		const recorded = authentication?.authentication;
		switch (rule) {
			case "live":
				return MET;
			case "baseline":
				return baseline(recorded);
			case "recent":
				return recent(session, recorded, now.getTime());
			case "baseline+recent": {
				const verdict = baseline(recorded);
				return verdict.outcome === "met" ? recent(session, recorded, now.getTime()) : verdict;
			}
			default:
				throw new TypeError(`no record rule named ${rule satisfies never}`);
		}
	};

	/**
	 * Whether the account-email proof comes before `primary`'s first binding:
	 * the gate over the setting, the sender, the login's address and D25's
	 * flag. A flag that cannot be read, or reads other than a boolean, throws.
	 */
	const proofAsked = async (primary: PrimaryAuthentication): Promise<boolean> => {
		const flagged: unknown = await emailProofRequiredAtNextBinding(primary.subject);
		if (typeof flagged !== "boolean") {
			throw new TypeError(
				"MfaTransactionStore.emailProofRequiredAtNextBinding answered something that is not a boolean",
			);
		}
		const gate = firstBindingGate({
			requireEmailProof: firstBinding.requireEmailProof,
			mailWired: firstBinding.mailWired,
			hasAddress: normaliseMailAddress(primary.user.email) !== undefined,
			requiredAtNextBinding: flagged,
		});
		// `unprovable` asks for a proof nobody can give: the binding is refused, never skipped.
		return gate !== "bind";
	};

	/** The interruption that opens the login's transaction with `interruption`'s answer. */
	const interrupt = (interruption: LoginInterruption): RequirementInterruption => ({
		open: (sessionId, continuation) => transactions.open(sessionId, continuation, interruption),
	});

	/**
	 * The counting factors `user` may enroll, in registration order: what a
	 * first binding offers. When every one refuses this user, nothing can be
	 * bound: said at warn, each time, with the kinds alone — never the subject.
	 */
	const enrollableFor = (user: PrimaryAuthentication["user"]): string[] => {
		const counting = [...factors.entries()].filter(([, factor]) => factor.counting);
		const enrollable = counting
			.filter(([, factor]) => factor.enrollable?.(user) ?? true)
			.map(([kind]) => kind);
		if (enrollable.length === 0) {
			logger.warn({ kinds: counting.map(([kind]) => kind) }, "mfa_enrollment_nothing_enrollable");
		}
		return enrollable;
	};

	return {
		name: MFA_REQUIREMENT_NAME,
		secondFactorAuthority: true,
		get reach() {
			return reach();
		},
		stepUpPage,
		remediations: [MFA_STEP_UP_REMEDIATION],
		hintKeys: [...MFA_HINT_KEYS],
		admit: async (input) => {
			if (input.carrier === "token") return mode === "optional" ? MET : admitToken(input);
			return admitRecord(input);
		},
		admitPrimary: async (primary) => {
			if (primary.recorded.authentication.primary !== PASSWORD_AMR) return "establish";
			const records = await listRecords(primary.subject);
			if (!records.some(mayCount)) checkWitness(primary);
			if (records.length > 0) return interrupt({ error: "mfa_required" });
			if (mode === "optional") return "establish";
			const emailProof = await proofAsked(primary);
			return interrupt({
				error: "mfa_enrollment_required",
				enrollable: enrollableFor(primary.user),
				emailProof,
			});
		},
	};
}
