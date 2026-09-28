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
 * The `mfa` session requirement (the session-admission ADR's D3, D5, D6, D7;
 * the MFA ADR's D13, D16, O3, F1 and F3): what MFA is to every consumer of a
 * session, through core's admission — the coordinator the MFA ADR planned,
 * reached through `sessionRequirements.mfa` and nothing else.
 *
 * - **`reach`** is the union of the enabled factors' `amrValues`, and `mfa`
 *   when one of them `addsMfa`, read from `mfaFactorResolver` each time it
 *   is asked: boot reads it once, after every factor registered, and refuses
 *   it unless it equals what core recomputes from the same factors (D7).
 * - **`stepUpPage`** is the page it is given (`endpoints.mfa.url`);
 *   **`remediations`** `mfa.step_up`, the step-up route; **`hintKeys`**
 *   `enrollable` and `email_proof`, what a first binding's answer carries.
 * - **`admit`** is D6's table for the `use` grade under `mfa.mode`:
 *   `optional` is met; under `required` a token is judged on its own `amr`
 *   (O3) — a primary that cannot be told is re-authenticated, `fed` or a
 *   second-factor value is met, a password alone is unmet — whether or not a
 *   record was read, the record being only the live view (D2 step 5, D9);
 *   otherwise no session is re-authenticated, `device.lookup` and
 *   `device.deny` are met on any live session, `fed` is met, a primary the
 *   baseline does not know is re-authenticated, `mfaAt` is met, and a
 *   password without it steps up — or is unmet when nothing is reached.
 *   `credential_change` is held to the same baseline until the recent-MFA
 *   rule arrives (build-order steps 12 and 14; the step-8 owner decision 1).
 * - **`admitPrimary`** is `decideAfterPrimary` behind one interruption: after
 *   a password login it lists the subject's factor records — a `list` that
 *   cannot answer is thrown, which admission answers `unavailable` — and
 *   any record at all interrupts for a second factor (`mfa_required`): a
 *   record it cannot use is never "none" (F3). Zero records establish under
 *   `optional`, and under `required` interrupt for a first binding
 *   (`mfa_enrollment_required`) with the counting factors the user may
 *   enroll; no enrollment witness is read before step 12 (owner decision 2).
 *   A primary that is not a password login is established without a read:
 *   the baseline applies after `pwd` only (D13).
 *
 * Every method is a closure: core calls them on a registered copy, and the
 * contract suite on a spread of the object.
 */

import {
	FEDERATED_AMR,
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

/** The remediation the MFA page's step-up call admits with (D4): `POST /session/mfa/step-up`, build-order step 11. */
const MFA_STEP_UP_REMEDIATION = `${MFA_REQUIREMENT_NAME}.step_up`;

/** The hint keys a first binding's answer carries (D5; the MFA ADR's F3). */
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
}

const MET: RequirementVerdict = Object.freeze({ outcome: "met" });
const REAUTHENTICATE: RequirementVerdict = Object.freeze({ outcome: "reauthenticate" });
const UNMET: RequirementVerdict = Object.freeze({ outcome: "unmet" });
/** A session that comes back from the step-up still unmet is sent to log in again (the baseline's, D2's mapping). */
const STEP_UP: RequirementVerdict = Object.freeze({
	outcome: "step_up",
	whenStillUnmet: "reauthenticate",
});

/** The bundled actions that grant nothing, met on any live session (D6): a user refuses a phished device request without a step-up. */
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
	const { mode, factors, factorStore, transactions, stepUpPage } = options;

	/** A token, judged on its own `amr` (O3): the record read beside it is only the live view. */
	const admitToken = ({ authentication }: RequirementInput): RequirementVerdict => {
		const primary = authentication?.authentication?.primary;
		if (primary === FEDERATED_AMR) return MET;
		if (primary !== PASSWORD_AMR) return REAUTHENTICATE;
		return authentication?.amr.some((value) => SECOND_FACTOR_AMR.has(value)) ? MET : UNMET;
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
		return reachOf(factors).size > 0 ? STEP_UP : UNMET;
	};

	/** The interruption that opens the login's transaction with `interruption`'s answer. */
	const interrupt = (interruption: LoginInterruption): RequirementInterruption => ({
		open: (sessionId, continuation) => transactions.open(sessionId, continuation, interruption),
	});

	/** The counting factors `user` may enroll, in registration order: what a first binding offers. */
	const enrollableFor = (user: PrimaryAuthentication["user"]): string[] =>
		[...factors.entries()]
			.filter(([, factor]) => factor.counting && (factor.enrollable?.(user) ?? true))
			.map(([kind]) => kind);

	return {
		name: MFA_REQUIREMENT_NAME,
		get reach() {
			return reachOf(factors);
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
				// The account-email proof before a first binding (D24) is step 9's:
				// no mail is wired before it.
				emailProof: false,
			});
		},
	};
}
