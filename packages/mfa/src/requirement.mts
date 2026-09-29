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
 * through core's admission, reached through `sessionRequirements.mfa` only.
 *
 * `reach` (the enabled factors' `amrValues`, plus `mfa` when one `addsMfa`) is
 * read once, after every factor has registered, and kept: boot refuses it unless
 * it equals what core recomputes from the same factors, and the requirement's own
 * verdicts read the same snapshot, so the two never disagree.
 *
 * `admit`: under `optional` everything is met; under `required` a token is judged
 * on its own `amr` (`admitToken`) and a session carried by a cookie, code or link
 * on its record's baseline (`admitRecord`). `credential_change` has no recent-MFA
 * rule yet and gets the same baseline.
 *
 * `admitPrimary` interrupts a password login for a second factor when the subject
 * has any factor record: a record it cannot use is never "none", and a `list`
 * that cannot answer throws, which admission answers `unavailable`. With no
 * records, `optional` establishes and `required` interrupts for a first binding
 * offering the counting factors the user may enroll. Other primaries establish
 * without a read: the baseline applies after `pwd` only.
 *
 * Every method is a closure: core calls them on a registered copy, and the
 * contract suite on a spread of the object.
 */

import {
	FEDERATED_AMR,
	type Logger,
	MFA_AMR,
	MFA_REQUIREMENT_NAME,
	type MfaFactorResolver,
	type MfaFactorStore,
	PASSWORD_AMR,
	type PrimaryAuthentication,
	type RequirementInput,
	type RequirementInterruption,
	type RequirementVerdict,
	SECOND_FACTOR_AMR,
	type SessionRequirement,
	type StepUpPage,
} from "@o3co/auth-provider-core";
import type { LoginInterruption, LoginTransactions } from "./transactions.mjs";

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
	/** `endpoints.mfa.url`, as the page a step-up starts on. */
	readonly stepUpPage: StepUpPage;
	/**
	 * Whether the session store can record a step-up (core's
	 * `supportsSecondFactorUpdate`): without it a stepped-up session could never be
	 * written, so the baseline sends it to log in instead.
	 */
	readonly stepUpRecordable: boolean;
	/** Where a first binding that offers nothing is said (`mfa_enrollment_nothing_enrollable`). */
	readonly logger: Logger;
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
 * The bundled actions that grant nothing, met on any live session: a user can
 * refuse a phished device request without a step-up.
 */
const GRANTS_NOTHING: ReadonlySet<string> = new Set(["device.lookup", "device.deny"]);

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
	const { mode, factors, factorStore, transactions, stepUpPage, stepUpRecordable, logger } =
		options;

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

	/** A session a cookie, a code or a link carries: the baseline over its record. */
	const admitRecord = ({
		session,
		authentication,
		action,
	}: RequirementInput): RequirementVerdict => {
		if (session === null) return REAUTHENTICATE;
		if (action.grade === "use" && GRANTS_NOTHING.has(action.name)) return MET;
		const recorded = authentication?.authentication;
		if (recorded?.primary === FEDERATED_AMR) return MET;
		if (recorded?.primary !== PASSWORD_AMR) return REAUTHENTICATE;
		if (recorded.mfaAt !== undefined) return MET;
		if (reach().size === 0) return UNMET;
		return stepUpRecordable ? STEP_UP : REAUTHENTICATE;
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
		get reach() {
			return reach();
		},
		stepUpPage,
		remediations: [MFA_STEP_UP_REMEDIATION],
		hintKeys: [...MFA_HINT_KEYS],
		admit: async (input) => {
			if (mode === "optional") return MET;
			return input.carrier === "token" ? admitToken(input) : admitRecord(input);
		},
		admitPrimary: async (primary) => {
			if (primary.recorded.authentication.primary !== PASSWORD_AMR) return "establish";
			const records: unknown = await factorStore.list(primary.subject);
			if (!Array.isArray(records)) {
				throw new TypeError("MfaFactorStore.list answered something that is not a list");
			}
			if (records.length > 0) return interrupt({ error: "mfa_required" });
			if (mode === "optional") return "establish";
			return interrupt({
				error: "mfa_enrollment_required",
				enrollable: enrollableFor(primary.user),
				// No account-email proof before a first binding yet: no mail is wired.
				emailProof: false,
			});
		},
	};
}
