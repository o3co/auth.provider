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
 * under `optional` it is met. The baseline steps a password session without a
 * second factor up only when its subject may hold a counting factor to step
 * up with; without one it sends the session to log in, where the login's
 * first binding is made. An action graded `credential_change` changes the
 * ways into the account — adds one, or renames or removes a factor — and is
 * held to recent MFA (`isRecentMfa`) over a primary the
 * baseline knows — under `required` on top of the baseline, so it is never
 * looser than `use`: the subject's factor records say whether it may hold a
 * counting factor — a record of a kind no installed factor declares
 * non-counting counts — and a list that cannot answer throws.
 *
 * For a subject that holds none, the action is a first binding (D12, D24):
 * the view's recorded facts are read — none recorded sends the session to
 * log in; a witness `enrolled` or malformed sends a password session to log
 * in, whose own read of the `User` records a real loss, and is recorded and
 * thrown for any other primary, a federated login having no such read —
 * then a recent primary (`authTime`; a second factor does not stand in for
 * it), then the subject's first-binding mark (`firstBindingMark.mts`): a
 * session it distrusts, whose recorded witness may predate the subject's
 * enrollment, is sent to log in — said at info — and a mark that cannot be
 * read throws;
 * then the one gate, whose proof is the one given in that session and
 * still standing (`MfaTransactionStore.sessionEmailProofAt`, read no older
 * than `mfa.manage.maxAgeSeconds` and the clock skew). A proof nobody can
 * give steps the session up and never admits it.
 *
 * `admitPrimary` interrupts a password login for a second factor when the subject
 * holds a record it asks for one over (`factorState.mts`): a record it cannot use is
 * never "none", a recovery set with no code left is, and a `list` that cannot
 * answer throws, which admission answers `unavailable`. When no
 * record that may count stands, the login's `User` must not say the subject
 * enrolled: a witness `true` or malformed is recorded and thrown, under either
 * mode (D12). With none it asks over, `optional` establishes and `required` interrupts
 * for a first binding offering the counting factors the user may enroll, the
 * account-email proof first where the one gate (`firstBinding.mts`) asks for
 * it. Other primaries establish without a read: the baseline applies after
 * `pwd` only.
 *
 * Every method is a closure: core calls them on a registered copy, and the
 * contract suite on a spread of the object.
 */

import {
	type AdmissionAction,
	type AdmissionGrade,
	type AuditSink,
	DEFAULT_CLOCK_SKEW_MS,
	emitAuditEvent,
	FEDERATED_AMR,
	type Logger,
	type MailAddressFact,
	MFA_AMR,
	type MfaFactorRecord,
	type MfaFactorResolver,
	type MfaFactorStore,
	PASSWORD_AMR,
	type PrimaryAuthentication,
	type RequirementInput,
	type RequirementInterruption,
	type RequirementVerdict,
	readMfaEnrollmentWitness,
	readSessionEmailProof,
	SECOND_FACTOR_AMR,
	type SessionAuthentication,
	type SessionRequirement,
	type SessionView,
	type StepUpPage,
} from "@o3co/auth-provider-core";
import { asksForSecondFactor } from "./factorState.mjs";
import {
	countingKinds,
	enrollableKinds,
	type FirstBindingGate,
	firstBindingGate,
	mayCount,
	type RequireEmailProof,
} from "./firstBinding.mjs";
import { distrustedByFirstBinding, readFirstBindingMark } from "./firstBindingMark.mjs";
import type { MfaSealing } from "./sealing.mjs";
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
	/** Where a first binding that offers nothing, or asks a proof nobody can give, is said. */
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
	/**
	 * When the account-email proof was given in the session `sid` of
	 * `subject`, while it stands at `nowMs` (`MfaTransactionStore.sessionEmailProofAt`);
	 * rejects on an outage.
	 */
	readonly sessionEmailProofAt: (
		subject: string,
		sid: string,
		nowMs: number,
	) => Promise<number | null>;
	/**
	 * When `subject`'s first-binding mark was noted, while it stands
	 * (`MfaTransactionStore.firstBindingAt`); rejects on an outage.
	 */
	readonly firstBindingAt: (subject: string, nowMs: number) => Promise<number | null>;
	/** The key ring's sealing: what tells a recovery set with no code left (`factorState.mts`). */
	readonly sealing: MfaSealing;
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
		sessionEmailProofAt,
		firstBindingAt,
		sealing,
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

	const mayHoldCountingFactor = async (subject: string): Promise<boolean> =>
		(await listRecords(subject)).some((record) => mayCount(factors, record));

	/**
	 * A witness that says the subject enrolled, or says nothing readable,
	 * while no record that may count stands: an outage — recorded, then
	 * thrown — never a first binding (D12).
	 */
	const inconsistent = (
		subject: string,
		witness: "enrolled" | "malformed",
		details: Readonly<Record<string, string>>,
		request: { readonly ip?: string; readonly userAgent?: string } = {},
	): never => {
		emitAuditEvent(auditSink, {
			timestamp: new Date(),
			type: "mfa.enrollment_state_inconsistent",
			subject,
			ip: request.ip,
			userAgent: request.userAgent,
			details: { ...details, witness },
		});
		throw new MfaEnrollmentStateInconsistentError(witness);
	};

	/** The witness the login's `User` carries, read when no record that may count stands. */
	const checkWitness = (primary: PrimaryAuthentication): void => {
		const witness = readMfaEnrollmentWitness(primary.user);
		if (witness !== "not_enrolled") {
			inconsistent(primary.subject, witness, { purpose: "login" }, primary.request);
		}
	};

	/** D25's flag for `subject`; one that cannot be read, or reads other than a boolean, throws. */
	const flagged = async (subject: string): Promise<boolean> => {
		const flag: unknown = await emailProofRequiredAtNextBinding(subject);
		if (typeof flag !== "boolean") {
			throw new TypeError(
				"MfaTransactionStore.emailProofRequiredAtNextBinding answered something that is not a boolean",
			);
		}
		return flag;
	};

	/**
	 * The one gate over `subject`'s first binding, the account's address as
	 * core read it at login: a proof asked that nobody can give is said — the
	 * subject and why, never the address.
	 */
	const gateFor = async (
		subject: string,
		mailAddress: MailAddressFact,
	): Promise<FirstBindingGate> => {
		const gate = firstBindingGate({
			requireEmailProof: firstBinding.requireEmailProof,
			mailWired: firstBinding.mailWired,
			mailAddress,
			requiredAtNextBinding: await flagged(subject),
		});
		if (gate.outcome === "unprovable") {
			logger.warn({ sub: subject, reason: gate.reason }, "mfa_email_proof_unprovable");
		}
		return gate;
	};

	/**
	 * Whether the account-email proof given in the session `sid` of `subject`
	 * stands at `nowMs`: one given longer ago than the window and the clock
	 * skew is none, whatever the store answered; an answer the port does not
	 * promise throws.
	 */
	const provedInSession = async (subject: string, sid: string, nowMs: number): Promise<boolean> => {
		const proved = readSessionEmailProof(await sessionEmailProofAt(subject, sid, nowMs), nowMs);
		if (proved === undefined) {
			throw new TypeError(
				"MfaTransactionStore.sessionEmailProofAt answered something that is not a time or null",
			);
		}
		return (
			proved !== null && proved >= nowMs - recentMfaMaxAgeSeconds * 1_000 - DEFAULT_CLOCK_SKEW_MS
		);
	};

	/** Where a second factor would meet the rule: a step-up, `unmet` when no factor could finish one, a new login when none could be recorded. */
	const stepUp = (): RequirementVerdict => {
		if (reach().size === 0) return UNMET;
		return stepUpRecordable ? STEP_UP : REAUTHENTICATE;
	};

	/**
	 * The baseline over `session`'s record: a federation, or a second factor
	 * after a password. A password session without one is stepped up only
	 * when its subject may hold a counting factor to step up with; otherwise
	 * it logs in again, and the login binds its first factor.
	 */
	const baseline = async (
		session: SessionView,
		recorded: SessionAuthentication | undefined,
	): Promise<RequirementVerdict> => {
		if (recorded?.primary === FEDERATED_AMR) return MET;
		if (recorded?.primary !== PASSWORD_AMR) return REAUTHENTICATE;
		if (recorded.mfaAt !== undefined) return MET;
		const verdict = stepUp();
		if (verdict.outcome !== "step_up") return verdict;
		return (await mayHoldCountingFactor(session.sub)) ? verdict : REAUTHENTICATE;
	};

	/**
	 * A first binding in `session`, whose subject holds no record that may
	 * count: what the session recorded of its login's `User` — none is a new
	 * login; a witness other than `not_enrolled` is a new login for a
	 * password session, and recorded and thrown for any other — then a recent primary, then the subject's first-binding mark —
	 * a session it distrusts is a new login — then the gate, a proof asked
	 * for admitted only while one given in this session stands.
	 */
	const firstBindingIn = async (
		session: SessionView,
		primary: string,
		action: AdmissionAction,
		nowMs: number,
	): Promise<RequirementVerdict> => {
		const facts = session.enrollmentFacts;
		if (facts === undefined) return REAUTHENTICATE;
		if (facts.witness !== "not_enrolled") {
			// A password login's admitPrimary reads the User afresh and records a real loss;
			// a federated login never runs it, so any other session records it here.
			if (primary === PASSWORD_AMR) return REAUTHENTICATE;
			inconsistent(session.sub, facts.witness, { purpose: "session", action: action.name });
		}
		const recentPrimary = isRecentMfa(
			{ authTime: session.authTime, mfaAt: undefined },
			{ holdsCountingFactor: false },
			recentMfaMaxAgeSeconds,
			nowMs,
		);
		if (!recentPrimary) return REAUTHENTICATE;
		const mark = readFirstBindingMark(await firstBindingAt(session.sub, nowMs), nowMs);
		if (distrustedByFirstBinding(session.authTime.getTime(), mark)) {
			logger.info({ sub: session.sub, action: action.name }, "mfa_first_binding_distrusted");
			return REAUTHENTICATE;
		}
		const gate = await gateFor(session.sub, facts.mailAddress);
		if (gate.outcome === "bind") return MET;
		if (gate.outcome === "unprovable") return STEP_UP;
		return (await provedInSession(session.sub, session.sid, nowMs)) ? MET : STEP_UP;
	};

	/**
	 * Recent MFA over a record whose primary the baseline knows; a subject
	 * with no counting factor is a first binding.
	 */
	const recent = async (
		session: SessionView,
		recorded: SessionAuthentication | undefined,
		action: AdmissionAction,
		nowMs: number,
	): Promise<RequirementVerdict> => {
		if (recorded?.primary !== PASSWORD_AMR && recorded?.primary !== FEDERATED_AMR) {
			return REAUTHENTICATE;
		}
		if (!(await mayHoldCountingFactor(session.sub))) {
			return firstBindingIn(session, recorded.primary, action, nowMs);
		}
		const recentMfa = isRecentMfa(
			{ authTime: session.authTime, mfaAt: recorded.mfaAt },
			{ holdsCountingFactor: true },
			recentMfaMaxAgeSeconds,
			nowMs,
		);
		return recentMfa ? MET : stepUp();
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
				return baseline(session, recorded);
			case "recent":
				return recent(session, recorded, action, now.getTime());
			case "baseline+recent": {
				const verdict = await baseline(session, recorded);
				return verdict.outcome === "met"
					? recent(session, recorded, action, now.getTime())
					: verdict;
			}
			default:
				throw new TypeError(`no record rule named ${rule satisfies never}`);
		}
	};

	/**
	 * Whether the account-email proof comes before `primary`'s first binding:
	 * the gate over the login's address fact (core's reading, in its
	 * enrollment facts). One nobody can give is asked for too — the binding
	 * is refused, never skipped.
	 */
	const proofAsked = async (primary: PrimaryAuthentication): Promise<boolean> =>
		(await gateFor(primary.subject, primary.enrollmentFacts.mailAddress)).outcome !== "bind";

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
		const enrollable = enrollableKinds(factors, user);
		if (enrollable.length === 0) {
			logger.warn({ kinds: countingKinds(factors) }, "mfa_enrollment_nothing_enrollable");
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
			if (!records.some((record) => mayCount(factors, record))) checkWitness(primary);
			if (
				records.some((record) => asksForSecondFactor({ factors, sealing }, primary.subject, record))
			) {
				return interrupt({ error: "mfa_required" });
			}
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
